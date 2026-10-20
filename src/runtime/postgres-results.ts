import { realpathSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import type { Pool, PoolClient, QueryResultRow } from 'pg';
import { z } from 'zod';
import { auditResultRecords } from './result-audit.js';
import { contentHash, ResultRecordReader, readResultState, resultIdentity } from './result-records.js';
import { prepareReviewNote, prepareReviewNoteBatch, readLocalReviewNotes, REVIEW_NOTES_BACKEND_FILE, ReviewNoteInputSchema, validateReviewNoteHistory, type ReviewNoteHistory } from './review-notes.js';
import { ManualReviewBatchSchema } from './review-note-schema.js';
import { createManualResponseTemplate, readManualReviewStatus } from './manual-review-view.js';
import { collectReviewSubmissions, readReviewConflicts } from './review-intake.js';
import { RunEventSchema, replayRunEvents } from './workflow/state-store.js';
import { acquireRunLock } from './workflow/run-lock.js';
import { atomicPrivateWrite } from './workflow/storage-files.js';
import { readStandardFindingRecordReceipts } from './finding-contract.js';

export type ResultStateSource = { backend: 'file' } | { backend: 'postgres'; runId: string };
const Binding = z.object({ schemaVersion: z.literal(1), backend: z.literal('postgres'), catalogId: z.uuid(),
  runId: z.string().min(1), sourceManifestFileSha256: z.string().regex(/^[a-f0-9]{64}$/),
  initialOperationSha256: z.string().regex(/^[a-f0-9]{64}$/).optional() }).strict();

export class ResultStorageError extends Error { override name = 'ResultStorageError'; }
async function database<T>(operation: () => Promise<T>): Promise<T> {
  try { return await operation(); } catch (error) {
    const code = (error as { code?: string })?.code;
    throw new ResultStorageError(`PostgreSQL result operation failed${code && /^[A-Z0-9]{5}$/.test(code) ? ` (${code})` : ''}; check config/schema. Retry a write with the same note ID and payload; never fall back to files.`);
  }
}
const query = <T extends QueryResultRow = QueryResultRow>(client: PoolClient, sql: string, values?: unknown[]) =>
  database(() => client.query<T>(sql, values));

/** Human administration only. No provider, lease acquisition, report rewrite or model tools. */
export class PostgresResultStore {
  constructor(private readonly pool: Pool) {}

  private async transaction<T>(write: boolean, operation: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await database(() => this.pool.connect());
    try {
      await query(client, write ? 'BEGIN' : 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
      const result = await operation(client);
      await query(client, 'COMMIT');
      return result;
    } catch (error) { await client.query('ROLLBACK').catch(() => undefined); throw error; }
    finally { client.release(); }
  }

  private async context(client: PoolClient, root: string, source: ResultStateSource, write: boolean) {
    let reader = new ResultRecordReader(root);
    let stateReceipt: { backend: 'file' | 'postgres'; lastSeq: number; eventsSha256?: string };
    if (source.backend === 'postgres') {
      const run = (await query(client, `SELECT last_seq FROM nunchi_runs WHERE run_id=$1${write ? ' FOR SHARE' : ''}`, [source.runId])).rows[0];
      if (!run) throw new Error('PostgreSQL run does not exist');
      const rows = (await query(client, 'SELECT payload FROM nunchi_run_events WHERE run_id=$1 ORDER BY seq', [source.runId])).rows;
      const events = rows.map(row => RunEventSchema.parse(row.payload));
      const state = replayRunEvents(events);
      if (state.runId !== source.runId || state.lastSeq !== Number(run.last_seq)) throw new Error('PostgreSQL run event head is inconsistent');
      reader = new ResultRecordReader(root, state);
      // A supplied run ID alone cannot bind unrelated local evidence to a DB run.
      const manifest = state.inputManifest?.fileHashes.find(file => file.path === join(root, 'source_manifest.json'));
      if (!manifest || manifest.sha256 !== reader.reference('source_manifest.json').sha256) throw new Error('PostgreSQL run is not bound to this engagement source manifest');
      stateReceipt = { backend: 'postgres', lastSeq: state.lastSeq, eventsSha256: contentHash(JSON.stringify(events)) };
    } else stateReceipt = { backend: 'file', lastSeq: readResultState(reader).lastSeq };
    const identity = resultIdentity(reader);
    const catalog = (await query(client, 'SELECT catalog_id::text FROM nunchi_review_catalog WHERE singleton')).rows[0];
    if (!catalog) throw new Error('PostgreSQL review catalog missing; run pnpm db:migrate');
    const binding = Binding.parse({ schemaVersion: 1, backend: 'postgres', catalogId: catalog.catalog_id, ...identity });
    const bindingReader = new ResultRecordReader(root), raw = bindingReader.json(REVIEW_NOTES_BACKEND_FILE, true);
    const saved = raw === undefined ? undefined : Binding.parse(raw);
    if (saved && JSON.stringify({ ...saved, initialOperationSha256: undefined }) !== JSON.stringify(binding)) throw new Error('Review note database binding differs; restore the original catalog and run');
    return { reader, identity, binding: saved ?? binding, bindingReader, bound: raw !== undefined, stateReceipt };
  }

  private async history(client: PoolClient, identity: ReviewNoteHistory['identity'], write: boolean) {
    if (write) await query(client, 'INSERT INTO nunchi_review_histories(run_id,source_manifest_sha256) VALUES($1,$2) ON CONFLICT DO NOTHING', [identity.runId, identity.sourceManifestFileSha256]);
    const row = (await query(client, `SELECT source_manifest_sha256,head,entry_count FROM nunchi_review_histories WHERE run_id=$1${write ? ' FOR UPDATE' : ''}`, [identity.runId])).rows[0];
    if (!row) return { history: validateReviewNoteHistory(identity, undefined), exists: false };
    if (row.source_manifest_sha256 !== identity.sourceManifestFileSha256) throw new Error('Review notes belong to a different run or source manifest');
    const entries = (await query(client, 'SELECT sequence,note_id,sha256,body FROM nunchi_review_entries WHERE run_id=$1 ORDER BY sequence', [identity.runId])).rows;
    const history = validateReviewNoteHistory(identity, { schemaVersion: 1, identity, entries: entries.map(entry => entry.body) });
    if (history.entries.length !== row.entry_count || (history.entries.at(-1)?.sha256 ?? 'empty') !== row.head ||
      entries.some((entry, index) => entry.sequence !== history.entries[index]!.sequence || entry.note_id !== history.entries[index]!.note.id || entry.sha256 !== history.entries[index]!.sha256)) {
      throw new Error('PostgreSQL review history head is inconsistent');
    }
    return { history, exists: true };
  }

  private assertLocalPrefix(local: ReviewNoteHistory, stored: ReviewNoteHistory) {
    if (local.entries.some((entry, index) => entry.sha256 !== stored.entries[index]?.sha256)) throw new Error('Local review history is not a database prefix; explicitly import notes or resolve the divergent history');
  }

  async inspect(directory: string, source: ResultStateSource = { backend: 'file' }) {
    return this.read(directory, source, (reader, notes) => auditResultRecords(reader.root, { reader, notes }));
  }

  async reviewStatus(directory: string, assignee?: string, source: ResultStateSource = { backend: 'file' }) {
    return this.read(directory, source, (reader, notes) => readManualReviewStatus(reader.root, assignee, { reader, notes }));
  }

  async responseTemplate(directory: string, assignmentId: string, noteId: string, source: ResultStateSource = { backend: 'file' }) {
    return this.read(directory, source, (reader, notes) => createManualResponseTemplate(reader.root, assignmentId, noteId, { reader, notes }));
  }

  async collect(directory: string, inputPath: string, options: unknown = {}, source: ResultStateSource = { backend: 'file' }) {
    return this.read(directory, source, (reader, notes) => collectReviewSubmissions(reader.root, inputPath, options, { reader, notes }));
  }

  async conflicts(directory: string, mode: 'human' | 'unattended' = 'human', source: ResultStateSource = { backend: 'file' }) {
    return this.read(directory, source, (reader, notes) => readReviewConflicts(reader.root, mode, { reader, notes }));
  }

  private async read<T>(directory: string, source: ResultStateSource, project: (reader: ResultRecordReader, notes: ReviewNoteHistory) => T | Promise<T>) {
    const root = realpathSync(directory);
    return this.transaction(false, async client => {
      const context = await this.context(client, root, source, false);
      const { history, exists } = await this.history(client, context.identity, false);
      if (context.bound && !exists) throw new Error('Bound PostgreSQL review history is missing; retry the original import/write or restore the database');
      this.assertLocalPrefix(readLocalReviewNotes(context.reader), history);
      const result = await project(context.reader, history);
      context.reader.assertUnchanged(); context.bindingReader.assertUnchanged();
      return { ...result, storage: { state: context.stateReceipt, notes: { backend: 'postgres' as const, catalogId: context.binding.catalogId,
        head: history.entries.at(-1)?.sha256 ?? 'empty' }, consistency: 'Database transaction snapshot; local observed files remained unchanged during inspection.' } };
    });
  }

  async append(directory: string, value: unknown, expectedHead: string, source: ResultStateSource = { backend: 'file' }) {
    return this.write(directory, source, { value, expectedHead });
  }

  async appendBatch(directory: string, batch: unknown, expectedHead: string, source: ResultStateSource = { backend: 'file' }) {
    return this.write(directory, source, { batch, expectedHead });
  }

  /** Explicit one-way import. Original timestamps/hashes and local archive bytes survive. */
  async importNotes(directory: string, source: ResultStateSource = { backend: 'file' }) {
    return this.write(directory, source);
  }

  private async write(directory: string, source: ResultStateSource, input?: { value: unknown; expectedHead: string } | { batch: unknown; expectedHead: string }) {
    const root = realpathSync(directory), release = acquireRunLock(join(dirname(root), `.${basename(root)}.agent.lock`));
    try {
      return await this.transaction(true, async client => {
        const context = await this.context(client, root, source, true);
        const local = readLocalReviewNotes(context.reader);
        const operationSha256 = contentHash(JSON.stringify(input ? 'batch' in input
          ? { batch: ManualReviewBatchSchema.parse(input.batch), expectedHead: input.expectedHead }
          : { note: ReviewNoteInputSchema.parse(input.value), expectedHead: input.expectedHead } : { import: local }));
        const present = await query(client, 'SELECT 1 FROM nunchi_review_histories WHERE run_id=$1', [context.identity.runId]);
        if (context.bound && !present.rowCount && context.binding.initialOperationSha256 !== operationSha256) throw new Error('Bound PostgreSQL review history is missing; only the original operation may be retried');
        const { history } = await this.history(client, context.identity, true);
        let next = history, receipt;
        if (input) {
          this.assertLocalPrefix(local, history);
          if ('batch' in input) {
            const prepared = prepareReviewNoteBatch(context.reader, history, input.batch, input.expectedHead);
            next = prepared.history; receipt = prepared.result;
          } else {
            const prepared = prepareReviewNote(context.reader, history, input.value, input.expectedHead);
            receipt = prepared;
            if (prepared.inserted) next = { ...history, entries: [...history.entries, prepared.entry] };
          }
        } else if (!history.entries.length) next = local;
        else this.assertLocalPrefix(local, history);
        const findingRecords = input && next.entries.length > history.entries.length ? JSON.stringify(readStandardFindingRecordReceipts(root)) : undefined;
        context.reader.assertUnchanged(); context.bindingReader.assertUnchanged();
        for (const entry of next.entries.slice(history.entries.length)) await query(client,
          'INSERT INTO nunchi_review_entries(run_id,sequence,note_id,sha256,body) VALUES($1,$2,$3,$4,$5::jsonb)',
          [context.identity.runId, entry.sequence, entry.note.id, entry.sha256, JSON.stringify(entry)]);
        const head = next.entries.at(-1)?.sha256 ?? 'empty';
        if (next.entries.length !== history.entries.length) await query(client,
          'UPDATE nunchi_review_histories SET head=$2,entry_count=$3 WHERE run_id=$1', [context.identity.runId, head, next.entries.length]);
        context.reader.assertUnchanged();
        if (findingRecords !== undefined && findingRecords !== JSON.stringify(readStandardFindingRecordReceipts(root))) throw new Error('Finding records changed during note persistence; retry with current evidence');
        context.bindingReader.assertUnchanged();
        // Persist the route after validation, immediately before committing. A
        // crash/rollback here may leave a pending binding; retry the same operation.
        // File writers must never fork the history after an ambiguous commit.
        if (!context.bound) atomicPrivateWrite(join(root, REVIEW_NOTES_BACKEND_FILE), JSON.stringify({ ...context.binding, initialOperationSha256: operationSha256 }, null, 2) + '\n');
        return { ...(receipt ?? { head, imported: next.entries.length - history.entries.length, entryCount: next.entries.length }),
          backend: 'postgres' as const, catalogId: context.binding.catalogId };
      });
    } finally { release(); }
  }
}
