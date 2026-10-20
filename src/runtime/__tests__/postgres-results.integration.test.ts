import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { cpSync, existsSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import type { Pool } from 'pg';
import { createPostgresPool } from '../workflow/database.js';
import { PostgresResultStore } from '../postgres-results.js';
import { appendReviewNote, appendReviewNoteBatch, REVIEW_NOTES_BACKEND_FILE, REVIEW_NOTES_FILE } from '../review-notes.js';
import { contentHash } from '../result-records.js';
import { createArtifactRef } from '../contracts/result-contract.js';
import { reviewNotesFixture } from './fixtures/review-notes.js';
import { manualReviewFixture, responseFor, feedbackFor } from './fixtures/manual-review.js';
import { createManualResponseTemplate, readManualReviewStatus } from '../manual-review-view.js';
import { readReviewConflicts } from '../review-intake.js';
import { mediationFor, opinionFor, writeIntake } from './fixtures/review-intake.js';

const url = process.env.NUNCHI_RESULTS_TEST_URL ?? process.env.NUNCHI_DATABASE_URL;
const schema = `results_test_${randomUUID().replaceAll('-', '')}`;
let admin: Pool, pool: Pool, store: PostgresResultStore, isolatedUrl: string;
const roots: string[] = [];
const temp = () => { const path = realpathSync(mkdtempSync(join(tmpdir(), 'pg-results-'))); roots.push(path); return path; };
const fixture = () => reviewNotesFixture(temp(), randomUUID());
const files = (root: string) => readdirSync(root, { recursive: true, withFileTypes: true }).filter(entry => entry.isFile())
  .map(entry => join(entry.parentPath, entry.name)).sort().map(path => [path, contentHash(readFileSync(path))]);
const count = async (runId: string) => (await pool.query('SELECT count(*)::int AS n FROM nunchi_review_entries WHERE run_id=$1', [runId])).rows[0].n;

describe.skipIf(!url)('PostgreSQL result administration', () => {
  beforeAll(async () => {
    admin = createPostgresPool({ NUNCHI_DATABASE_URL: url });
    await admin.query(`CREATE SCHEMA ${schema}`);
    const isolated = new URL(url!); isolated.searchParams.set('options', `-c search_path=${schema}`); isolatedUrl = isolated.toString();
    pool = createPostgresPool({ NUNCHI_DATABASE_URL: isolatedUrl }); store = new PostgresResultStore(pool);
    await pool.query(readFileSync(new URL('../workflow/postgres-run-state.sql', import.meta.url), 'utf8'));
    for (let index = 0; index < 2; index++) await pool.query(readFileSync(new URL('../review-notes.sql', import.meta.url), 'utf8'));
  });
  afterAll(async () => { await pool?.end(); if (admin) { await admin.query(`DROP SCHEMA ${schema} CASCADE`); await admin.end(); } });
  afterEach(() => { for (const path of roots.splice(0)) rmSync(path, { recursive: true, force: true }); });

  it('retains idempotent notes, version conflicts and current finding evidence without changing reports', async () => {
    const f = fixture(), report = readFileSync(join(f.root, '03_review_result.json'));
    const first = await store.append(f.root, f.note, 'empty');
    expect(first).toMatchObject({ inserted: true, backend: 'postgres' });
    expect(await store.append(f.root, f.note, 'empty')).toMatchObject({ inserted: false, head: first.head });
    await expect(store.append(f.root, { ...f.note, id: 'D2' }, 'empty')).rejects.toThrow('version conflict');
    await expect(store.append(f.root, { ...f.note, author: 'another reviewer' }, first.head)).rejects.toThrow('ID collision');
    await expect(store.append(f.root, { ...f.note, id: 'D2', references: f.note.references.slice(0, 1) }, first.head)).rejects.toThrow('current finding version');
    writeFileSync(join(f.root, '03_review_result.json'), '{"reviewedFindings":[],"revision":1}');
    expect((await store.inspect(f.root)).notes.disputes[0]!.status).toBe('stale');
    await store.append(f.root, { id: 'R1', kind: 'resolution', disputeId: 'D1', author: 'human', outcome: 'resolved',
      rationale: 'Human reviewer revisited the changed artifact and preserved the uncertainty.', references: f.references() }, first.head);
    const before = files(f.root), audit = await store.inspect(f.root);
    expect(files(f.root)).toEqual(before);
    expect(audit.notes).toMatchObject({ entryCount: 2, openCount: 0 });
    expect(audit.notes.disputes[0]).toMatchObject({ status: 'resolved', historicalStaleReferences: ['03_review_result.json'] });
    expect(existsSync(join(f.root, REVIEW_NOTES_FILE))).toBe(false);
    expect(audit.findings.canonicalRecords).toBe(1);
    // Only the test's explicit revision changed the review artifact.
    expect(report.toString()).toBe('{"reviewedFindings":[]}');
    expect(readFileSync(join(f.root, '03_review_result.json'), 'utf8')).toBe('{"reviewedFindings":[],"revision":1}');
    expect(() => appendReviewNote(f.root, f.note, 'empty')).toThrow('bound to PostgreSQL');
  });

  it('imports an exact file history once and rejects divergent or silently selected histories', async () => {
    const f = fixture(), first = appendReviewNote(f.root, f.note, 'empty');
    const bytes = readFileSync(join(f.root, REVIEW_NOTES_FILE));
    await expect(store.inspect(f.root)).rejects.toThrow('explicitly import');
    await expect(store.append(f.root, { ...f.note, id: 'D2' }, first.head)).rejects.toThrow('explicitly import');
    expect(await store.importNotes(f.root)).toMatchObject({ head: first.head, imported: 1 });
    expect(await store.importNotes(f.root)).toMatchObject({ head: first.head, imported: 0 });
    await store.append(f.root, { ...f.note, id: 'D2' }, first.head);
    expect(readFileSync(join(f.root, REVIEW_NOTES_FILE))).toEqual(bytes);
    expect((await store.inspect(f.root)).notes.entryCount).toBe(2);
    const binding = readFileSync(join(f.root, REVIEW_NOTES_BACKEND_FILE));
    rmSync(join(f.root, REVIEW_NOTES_BACKEND_FILE)); // Deliberately simulate a second file writer ignoring the route.
    appendReviewNote(f.root, { ...f.note, id: 'D3' }, first.head);
    writeFileSync(join(f.root, REVIEW_NOTES_BACKEND_FILE), binding);
    await expect(store.inspect(f.root)).rejects.toThrow('not a database prefix');
  });

  it('serializes independent database writers with CAS and keeps both earlier entries', async () => {
    const f = fixture(), first = await store.append(f.root, f.note, 'empty');
    const copy = join(temp(), 'run'); cpSync(f.root, copy, { recursive: true });
    const results = await Promise.allSettled([
      store.append(f.root, { ...f.note, id: 'D2' }, first.head), store.append(copy, { ...f.note, id: 'D3' }, first.head),
    ]);
    expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1);
    const rejected = results.find(result => result.status === 'rejected') as PromiseRejectedResult;
    expect(String(rejected.reason)).toContain('version conflict');
    expect(await count(f.state.read().runId)).toBe(2);
    expect((await store.inspect(f.root)).notes.disputes[0]!.id).toBe('D1');
  });

  it('keeps one read-only database snapshot when another writer commits during inspection', async () => {
    const f = fixture(), first = await store.append(f.root, f.note, 'empty');
    const copy = join(temp(), 'run'); cpSync(f.root, copy, { recursive: true });
    let committed = false;
    const observer = new PostgresResultStore({ connect: async () => {
      const client = await pool.connect();
      return new Proxy(client, { get(target, property) {
        if (property === 'query') return async (sql: string, values?: unknown[]) => {
          if (!committed && sql.startsWith('SELECT sequence,note_id')) {
            committed = true; await store.append(copy, { ...f.note, id: 'D2' }, first.head);
          }
          return client.query(sql, values);
        };
        const value = Reflect.get(target, property); return typeof value === 'function' ? value.bind(target) : value;
      } });
    } } as Pool);
    const before = files(f.root), snapshot = await observer.inspect(f.root);
    expect(committed).toBe(true); expect(files(f.root)).toEqual(before);
    expect(snapshot.notes).toMatchObject({ head: first.head, entryCount: 1 });
    expect((await store.inspect(f.root)).notes.entryCount).toBe(2);
  });

  it('rolls back failed persistence and redacts database details before binding the result store', async () => {
    const f = fixture();
    await pool.query("CREATE FUNCTION reject_note() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'credential-do-not-print'; END $$");
    await pool.query('CREATE TRIGGER reject_note BEFORE INSERT ON nunchi_review_entries FOR EACH ROW EXECUTE FUNCTION reject_note()');
    try {
      let error: unknown; try { await store.append(f.root, f.note, 'empty'); } catch (caught) { error = caught; }
      expect(String(error)).toContain('PostgreSQL result operation failed'); expect(String(error)).not.toContain('credential-do-not-print');
      expect(await count(f.state.read().runId)).toBe(0);
      expect(existsSync(join(f.root, REVIEW_NOTES_BACKEND_FILE))).toBe(false);
      expect((await store.inspect(f.root)).notes.entryCount).toBe(0);
    } finally { await pool.query('DROP TRIGGER reject_note ON nunchi_review_entries'); await pool.query('DROP FUNCTION reject_note()'); }
    expect(await store.append(f.root, f.note, 'empty')).toMatchObject({ inserted: true });
    expect(await count(f.state.read().runId)).toBe(1);
  });

  it('rejects a newly added finding version during persistence and allows a fresh-evidence retry', async () => {
    const f = fixture();
    let added = false;
    const changing = new PostgresResultStore({ connect: async () => {
      const client = await pool.connect();
      return new Proxy(client, { get(target, property) {
        if (property === 'query') return async (sql: string, values?: unknown[]) => {
          const result = await client.query(sql, values);
          if (!added && sql.startsWith('INSERT INTO nunchi_review_entries')) {
            added = true;
            const original = f.note.references.find(ref => ref.path.startsWith('standard-findings/'))!;
            const record = JSON.parse(readFileSync(join(f.root, original.path), 'utf8'));
            record.remediation = 'Later human-authored fixture clarification.';
            writeFileSync(join(f.root, 'standard-findings', 'a'.repeat(64) + '.json'), JSON.stringify(record));
          }
          return result;
        };
        const value = Reflect.get(target, property); return typeof value === 'function' ? value.bind(target) : value;
      } });
    } } as Pool);
    await expect(changing.append(f.root, f.note, 'empty')).rejects.toThrow('Finding records changed');
    expect(await count(f.state.read().runId)).toBe(0);
    expect(existsSync(join(f.root, REVIEW_NOTES_BACKEND_FILE))).toBe(false);
    expect(await store.append(f.root, { ...f.note, references: f.references() }, 'empty')).toMatchObject({ inserted: true });
  });

  it('recovers a pending binding after rollback immediately before commit', async () => {
    const f = fixture();
    const interrupted = new PostgresResultStore({ connect: async () => {
      const client = await pool.connect();
      return new Proxy(client, { get(target, property) {
        if (property === 'query') return async (sql: string, values?: unknown[]) => {
          if (sql === 'COMMIT') throw new Error('simulated failure before commit');
          return client.query(sql, values);
        };
        const value = Reflect.get(target, property); return typeof value === 'function' ? value.bind(target) : value;
      } });
    } } as Pool);
    await expect(interrupted.append(f.root, f.note, 'empty')).rejects.toThrow('PostgreSQL result operation failed');
    expect(await count(f.state.read().runId)).toBe(0);
    expect(existsSync(join(f.root, REVIEW_NOTES_BACKEND_FILE))).toBe(true);
    expect(() => appendReviewNote(f.root, f.note, 'empty')).toThrow('bound to PostgreSQL');
    await expect(store.inspect(f.root)).rejects.toThrow('history is missing');
    await expect(store.append(f.root, { ...f.note, id: 'D2' }, 'empty')).rejects.toThrow('original operation');
    expect(await store.append(f.root, f.note, 'empty')).toMatchObject({ inserted: true });
  });

  it('recovers a committed write whose acknowledgment was lost without a duplicate', async () => {
    const f = fixture();
    const lost = new PostgresResultStore({ connect: async () => {
      const client = await pool.connect();
      return new Proxy(client, { get(target, property) {
        if (property === 'query') return async (sql: string, values?: unknown[]) => {
          const result = await client.query(sql, values);
          if (sql === 'COMMIT') throw new Error('lost response containing credential-do-not-print');
          return result;
        };
        const value = Reflect.get(target, property); return typeof value === 'function' ? value.bind(target) : value;
      } });
    } } as Pool);
    await expect(lost.append(f.root, f.note, 'empty')).rejects.toThrow('PostgreSQL result operation failed');
    expect(await store.append(f.root, f.note, 'empty')).toMatchObject({ inserted: false });
    expect(await count(f.state.read().runId)).toBe(1);
  });

  it('rejects the wrong catalog, changed run manifest and corrupted database head', async () => {
    const f = fixture(); await store.append(f.root, f.note, 'empty');
    const path = join(f.root, REVIEW_NOTES_BACKEND_FILE), bytes = readFileSync(path);
    writeFileSync(path, JSON.stringify({ ...JSON.parse(bytes.toString()), catalogId: randomUUID() }));
    await expect(store.inspect(f.root)).rejects.toThrow('binding differs');
    writeFileSync(path, bytes);
    const manifest = join(f.root, 'source_manifest.json'), original = readFileSync(manifest);
    writeFileSync(manifest, '{"source_files":[]}'); await expect(store.inspect(f.root)).rejects.toThrow('binding differs');
    writeFileSync(manifest, original);
    await pool.query("UPDATE nunchi_review_histories SET head='empty' WHERE run_id=$1", [f.state.read().runId]);
    await expect(store.inspect(f.root)).rejects.toThrow('head is inconsistent');
  });

  it('audits PostgreSQL-only events read-only and binds the requested run to the exact local manifest', async () => {
    const f = manualReviewFixture(temp(), randomUUID());
    const manifest = createArtifactRef({ engagementDir: f.root, name: 'source_manifest.json', phase: 'input', role: 'host', attempt: '1' });
    f.state.append({ type: 'input.recorded', eventId: randomUUID(), input: { inputRevision: 0, contextEpoch: 'a'.repeat(64), manifest,
      allowedReadFiles: [manifest.path], fileHashes: [{ path: manifest.path, sha256: manifest.sha256, bytes: manifest.bytes }] } });
    const state = f.state.read(), events = readFileSync(join(f.root, 'run-events.jsonl'), 'utf8').trim().split('\n').map(line => JSON.parse(line));
    await pool.query('INSERT INTO nunchi_runs(run_id,contract_id,contract_version,domain,mission,status,last_seq,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',
      [state.runId, state.contractId, state.contractVersion, state.domain, state.mission, state.status, state.lastSeq, JSON.stringify(state)]);
    for (const event of events) await pool.query('INSERT INTO nunchi_run_events(run_id,seq,event_id,fencing_token,event_type,payload) VALUES($1,$2,$3,0,$4,$5)',
      [event.runId, event.seq, event.eventId, event.type, JSON.stringify(event)]);
    rmSync(join(f.root, 'run-events.jsonl')); rmSync(join(f.root, 'run-state.json'), { force: true });
    const source = { backend: 'postgres' as const, runId: state.runId }, before = files(f.root);
    const audit = await store.inspect(f.root, source);
    expect(files(f.root)).toEqual(before);
    expect(audit.storage.state).toMatchObject({ backend: 'postgres', lastSeq: 2, eventsSha256: expect.stringMatching(/^[a-f0-9]{64}$/) });
    expect(audit.coverage.beforeUncoveredFiles).toBeNull();
    expect((await pool.query('SELECT * FROM nunchi_review_histories WHERE run_id=$1', [state.runId])).rowCount).toBe(0);
    expect((await pool.query('SELECT * FROM nunchi_run_leases WHERE run_id=$1', [state.runId])).rowCount).toBe(0);
    await expect(store.inspect(f.root, { backend: 'postgres', runId: 'missing' })).rejects.toThrow('does not exist');
    const another = fixture(); await expect(store.inspect(another.root, source)).rejects.toThrow('not bound');
    const saved = await store.append(f.root, f.note, 'empty', source);
    expect((await store.inspect(f.root, source)).notes.entryCount).toBe(1);
    const batch = await store.appendBatch(f.root, f.batch, saved.head, source);
    const beforeProjection = files(f.root);
    expect((await store.reviewStatus(f.root, 'reader-a', source)).selected.assignmentCount).toBe(1);
    expect((await store.responseTemplate(f.root, 'DOC-0001', 'PG-REPLY', source)).expectedHead).toBe(batch.head);
    expect(files(f.root)).toEqual(beforeProjection);
    expect(await count(state.runId)).toBe(3);
    expect((await pool.query('SELECT * FROM nunchi_run_leases WHERE run_id=$1', [state.runId])).rowCount).toBe(0);
    expect((await pool.query('SELECT last_seq FROM nunchi_runs WHERE run_id=$1', [state.runId])).rows[0].last_seq).toBe('2');
  });

  it('uses configured database connection and backend from the actual administration CLI', () => {
    const f = manualReviewFixture(temp(), randomUUID()), config = join(f.base, 'config.json'), input = join(f.base, 'note.json');
    writeFileSync(config, JSON.stringify({ version: 1, database: { connectionStringEnv: 'RESULTS_FIXTURE_DATABASE' }, results: { backend: 'postgres' } }));
    writeFileSync(input, JSON.stringify(f.note));
    const run = (...args: string[]) => spawnSync(process.execPath, ['--import', 'tsx', resolve(import.meta.dirname, '../../../scripts/results-admin.ts'), ...args], {
      encoding: 'utf8', env: { ...process.env, NUNCHI_DATABASE_URL: undefined, DATABASE_URL: undefined, RESULTS_FIXTURE_DATABASE: isolatedUrl },
    });
    const note = run('note', `--engagement=${f.root}`, `--config=${config}`, `--input=${input}`, '--expected-head=empty');
    expect(note.status, note.stderr).toBe(0); expect(JSON.parse(note.stdout).backend).toBe('postgres');
    const audit = run('inspect', `--engagement=${f.root}`, `--config=${config}`);
    expect(audit.status, audit.stderr).toBe(2); expect(JSON.parse(audit.stdout).notes.entryCount).toBe(1);
    expect(audit.stdout).not.toContain(isolatedUrl);
    const batchInput = join(f.base, 'batch.json'); writeFileSync(batchInput, JSON.stringify(f.batch));
    const batch = run('note-batch', `--engagement=${f.root}`, `--config=${config}`, `--input=${batchInput}`, `--expected-head=${JSON.parse(note.stdout).head}`);
    expect(batch.status, batch.stderr).toBe(0); expect(JSON.parse(batch.stdout).insertedCount).toBe(2);
    const after = run('inspect', `--engagement=${f.root}`, `--config=${config}`);
    expect(after.status).toBe(2); expect(JSON.parse(after.stdout).notes.manualReviews.assignmentCount).toBe(2);
    const beforeRead = files(f.root);
    const status = run('review-status', `--engagement=${f.root}`, `--config=${config}`, '--assignee=reader-a');
    expect(status.status, status.stderr).toBe(0);
    expect(JSON.parse(status.stdout)).toMatchObject({ global: { assignmentCount: 2 }, selected: { assignmentCount: 1 }, storage: { notes: { backend: 'postgres' } } });
    const template = run('review-response-template', `--engagement=${f.root}`, `--config=${config}`, '--assignment=DOC-0001', '--note-id=CLI-DRAFT');
    expect(template.status, template.stderr).toBe(0);
    expect(JSON.parse(template.stdout)).toMatchObject({ expectedHead: JSON.parse(batch.stdout).head,
      note: { results: [{ status: 'not-reviewed' }, { status: 'not-reviewed' }] }, storage: { notes: { backend: 'postgres' } } });
    expect(template.stdout).not.toContain(isolatedUrl); expect(files(f.root)).toEqual(beforeRead);
    const head = JSON.parse(batch.stdout).head;
    const intake = writeIntake(f.root, join(f.base, 'intake'), head, [opinionFor(f.input.files[0]!, 'OPINION', 'support'), '{']);
    const collected = run('review-collect', `--engagement=${f.root}`, `--config=${config}`, `--input=${intake.input}`, '--mode=unattended', '--concurrency=2');
    expect(collected.status, collected.stderr).toBe(2);
    expect(JSON.parse(collected.stdout)).toMatchObject({ persisted: false, processingComplete: true, counts: { validated: 1, invalid: 1 }, storage: { notes: { backend: 'postgres' } } });
    expect(collected.stdout).not.toContain(isolatedUrl);
    const opinion = run('note', `--engagement=${f.root}`, `--config=${config}`, `--input=${join(intake.directory, 'submission-0.json')}`, `--expected-head=${head}`);
    expect(opinion.status, opinion.stderr).toBe(0);
    const conflicts = run('review-conflicts', `--engagement=${f.root}`, `--config=${config}`, '--mode=unattended');
    expect(conflicts.status, conflicts.stderr).toBe(2);
    expect(JSON.parse(conflicts.stdout)).toMatchObject({ openCount: 1, decisionRouting: 'deferred', storage: { notes: { backend: 'postgres' } } });
    const missingId = run('inspect', `--engagement=${f.root}`, `--config=${config}`, '--state-backend=postgres');
    expect(missingId.status).toBe(1); expect(missingId.stderr).toContain('--run-id is required');
  });

  it('stores manual assignment batches and version-bound replies in the same PostgreSQL history', async () => {
    const f = manualReviewFixture(temp(), randomUUID());
    const first = await store.appendBatch(f.root, f.batch, 'empty');
    expect(first).toMatchObject({ insertedCount: 2 });
    const contract = (await store.inspect(f.root)).notes.manualReviews.assignments[0]!.history[0]!;
    const response = await store.append(f.root, responseFor(contract), first.head);
    const replied = (await store.inspect(f.root)).notes.manualReviews.assignments[0]!.history.at(-1)!;
    const accepted = await store.append(f.root, feedbackFor(contract, replied, 'accept'), response.head);
    const before = files(f.root), audit = await store.inspect(f.root);
    expect(files(f.root)).toEqual(before);
    expect(audit.notes.manualReviews).toMatchObject({ assignmentCount: 2, openCount: 1, allAccepted: false });
    expect(audit.notes.manualReviews.assignments[0]!.status).toBe('accepted');
    expect(audit.coverage.finalRecordedComplete).toBeNull();
    expect(await store.appendBatch(f.root, f.batch, 'empty')).toMatchObject({ head: accepted.head, insertedCount: 0 });
    await expect(store.appendBatch(f.root, { schemaVersion: 1, assignments: [f.batch.assignments[0], { ...f.batch.assignments[1], id: 'DOC-new' }] }, 'empty')).rejects.toThrow('version conflict');
    expect(await count(f.state.read().runId)).toBe(4);
  });

  it('rolls back the entire manual assignment batch when a later insert fails', async () => {
    const f = manualReviewFixture(temp(), randomUUID());
    await pool.query("CREATE FUNCTION reject_batch_second() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.note_id='DOC-0002' THEN RAISE EXCEPTION 'private batch storage detail'; END IF; RETURN NEW; END $$");
    await pool.query('CREATE TRIGGER reject_batch_second BEFORE INSERT ON nunchi_review_entries FOR EACH ROW EXECUTE FUNCTION reject_batch_second()');
    try {
      await expect(store.appendBatch(f.root, f.batch, 'empty')).rejects.toThrow('PostgreSQL result operation failed');
      expect(await count(f.state.read().runId)).toBe(0);
      expect(existsSync(join(f.root, REVIEW_NOTES_BACKEND_FILE))).toBe(false);
    } finally { await pool.query('DROP TRIGGER reject_batch_second ON nunchi_review_entries'); await pool.query('DROP FUNCTION reject_batch_second()'); }
    expect(await store.appendBatch(f.root, f.batch, 'empty')).toMatchObject({ insertedCount: 2 });
    expect(await count(f.state.read().runId)).toBe(2);
  });

  it('imports mixed dispute and manual review history without rewriting any earlier hashes', async () => {
    const f = manualReviewFixture(temp(), randomUUID());
    const dispute = appendReviewNote(f.root, f.note, 'empty');
    const batch = appendReviewNoteBatch(f.root, f.batch, dispute.head);
    const reply = appendReviewNote(f.root, responseFor(batch.entries[0]!), batch.head);
    const bytes = readFileSync(join(f.root, REVIEW_NOTES_FILE));
    expect(await store.importNotes(f.root)).toMatchObject({ imported: 4, head: reply.head });
    const audit = await store.inspect(f.root);
    expect(audit.notes.disputes[0]!.id).toBe('D1');
    expect(audit.notes.manualReviews.assignments[0]!.latestResponse?.sha256).toBe(reply.entry.sha256);
    expect(readFileSync(join(f.root, REVIEW_NOTES_FILE))).toEqual(bytes);
  });

  it('projects identical manual views after explicit import without writing notes or state', async () => {
    const f = manualReviewFixture(temp(), randomUUID());
    appendReviewNoteBatch(f.root, f.batch, 'empty');
    const { inspectedAt: _fileTime, references: _fileRefs, ...fileView } = readManualReviewStatus(f.root);
    const { generatedAt: _fileGenerated, ...fileTemplate } = createManualResponseTemplate(f.root, 'DOC-0001', 'DRAFT');
    await expect(store.reviewStatus(f.root)).rejects.toThrow('explicitly import');
    await store.importNotes(f.root);
    const before = files(f.root);
    const { inspectedAt: _dbTime, references: _dbRefs, storage: statusStorage, ...dbView } = await store.reviewStatus(f.root);
    const { generatedAt: _dbGenerated, storage: templateStorage, ...dbTemplate } = await store.responseTemplate(f.root, 'DOC-0001', 'DRAFT');
    expect(dbView).toEqual(fileView); expect(dbTemplate).toEqual(fileTemplate);
    expect(statusStorage.notes).toMatchObject({ backend: 'postgres', head: fileView.head });
    expect(templateStorage.notes.head).toBe(fileTemplate.expectedHead);
    expect(files(f.root)).toEqual(before); expect(await count(f.state.read().runId)).toBe(2);
    expect(() => readManualReviewStatus(f.root)).toThrow('bound to PostgreSQL');
    expect(() => createManualResponseTemplate(f.root, 'DOC-0001', 'DRAFT')).toThrow('bound to PostgreSQL');
  });

  it('exports a consistent response snapshot and rejects it after another writer answers', async () => {
    const f = manualReviewFixture(temp(), randomUUID());
    const first = await store.appendBatch(f.root, f.batch, 'empty');
    const contract = (await store.inspect(f.root)).notes.manualReviews.assignments[0]!.history[0]!;
    const copy = join(temp(), 'run'); cpSync(f.root, copy, { recursive: true });
    let committed = false;
    const observer = new PostgresResultStore({ connect: async () => {
      const client = await pool.connect();
      return new Proxy(client, { get(target, property) {
        if (property === 'query') return async (sql: string, values?: unknown[]) => {
          if (!committed && sql.startsWith('SELECT sequence,note_id')) {
            committed = true; await store.append(copy, responseFor(contract), first.head);
          }
          return client.query(sql, values);
        };
        const value = Reflect.get(target, property); return typeof value === 'function' ? value.bind(target) : value;
      } });
    } } as Pool);
    const before = files(f.root), packet = await observer.responseTemplate(f.root, 'DOC-0001', 'STALE-DRAFT');
    expect(committed).toBe(true); expect(packet.expectedHead).toBe(first.head);
    expect(files(f.root)).toEqual(before); expect(await count(f.state.read().runId)).toBe(3);
    await expect(store.append(f.root, packet.note, packet.expectedHead)).rejects.toThrow('version conflict');
    await expect(store.responseTemplate(f.root, 'DOC-0001', 'FRESH-DRAFT')).rejects.toThrow('no unanswered request');
    expect((await store.reviewStatus(f.root)).assignments[0]!.status).toBe('response-received');
  });

  it('preserves opinion and mediation history across explicit database import and unattended intake', async () => {
    const f = manualReviewFixture(temp(), randomUUID());
    const a = appendReviewNote(f.root, opinionFor(f.input.files[0]!, 'A', 'support'), 'empty');
    const b = appendReviewNote(f.root, opinionFor(f.input.files[0]!, 'B', 'oppose'), a.head);
    const fileView = readReviewConflicts(f.root), archive = readFileSync(join(f.root, REVIEW_NOTES_FILE));
    await store.importNotes(f.root);
    const { storage: _storage, ...dbView } = await store.conflicts(f.root);
    expect(dbView).toEqual(fileView);
    const intake = writeIntake(f.root, join(f.base, 'inputs'), b.head, [opinionFor(f.input.files[0]!, 'C', 'uncertain'), '{']);
    const before = files(f.root), collected = await store.collect(f.root, intake.input, { mode: 'unattended', concurrency: 2 });
    expect(collected).toMatchObject({ counts: { validated: 1, invalid: 1 }, storedMediation: { openCount: 1 }, persisted: false });
    expect(collected.pendingOpinions[0]!.opinions).toHaveLength(3);
    expect(files(f.root)).toEqual(before); expect(await count(f.state.read().runId)).toBe(2);
    await expect(store.append(f.root, mediationFor([a.entry], 'adopt'), b.head)).rejects.toThrow('every current opinion');
    expect(await count(f.state.read().runId)).toBe(2);
    const decision = mediationFor([b.entry, a.entry], 'adopt');
    const accepted = await store.append(f.root, decision, b.head);
    expect(await store.append(f.root, decision, b.head)).toMatchObject({ inserted: false, head: accepted.head });
    expect((await store.conflicts(f.root, 'unattended')).groups[0]).toMatchObject({ status: 'adopted', conflictingPositions: true });
    expect(readFileSync(join(f.root, REVIEW_NOTES_FILE))).toEqual(archive);
    expect(await count(f.state.read().runId)).toBe(3);
  });

  it('collects against one database snapshot and refuses a mediation missing a concurrently saved opinion', async () => {
    const f = manualReviewFixture(temp(), randomUUID());
    const first = await store.append(f.root, opinionFor(f.input.files[0]!, 'A', 'support'), 'empty');
    const a = (await store.conflicts(f.root)).groups[0]!.opinions[0]!;
    const intake = writeIntake(f.root, join(f.base, 'inputs'), first.head, [opinionFor(f.input.files[0]!, 'C', 'support')]);
    const copy = join(temp(), 'run'); cpSync(f.root, copy, { recursive: true });
    let committed = false;
    const observer = new PostgresResultStore({ connect: async () => {
      const client = await pool.connect();
      return new Proxy(client, { get(target, property) {
        if (property === 'query') return async (sql: string, values?: unknown[]) => {
          if (!committed && sql.startsWith('SELECT sequence,note_id')) {
            committed = true; await store.append(copy, opinionFor(f.input.files[0]!, 'B', 'oppose'), first.head);
          }
          return client.query(sql, values);
        };
        const value = Reflect.get(target, property); return typeof value === 'function' ? value.bind(target) : value;
      } });
    } } as Pool);
    const before = files(f.root), collected = await observer.collect(f.root, intake.input, { mode: 'unattended' });
    expect(collected.head).toBe(first.head); expect(collected.counts.validated).toBe(1);
    expect(collected.pendingOpinions[0]!.opinions).toHaveLength(2); expect(files(f.root)).toEqual(before);
    const current = await store.conflicts(f.root);
    expect(current.groups[0]!.opinions).toHaveLength(2); expect(current.head).not.toBe(first.head);
    await expect(store.append(f.root, mediationFor([a], 'adopt'), current.head)).rejects.toThrow('every current opinion');
    await expect(store.append(f.root, collected.submissions[0]!.note, collected.head)).rejects.toThrow('version conflict');
    expect(await count(f.state.read().runId)).toBe(2);
  });

  it('does not create a database history or binding when only collecting unregistered opinions', async () => {
    const f = manualReviewFixture(temp(), randomUUID());
    const intake = writeIntake(f.root, join(f.base, 'inputs'), 'empty', [opinionFor(f.input.files[0]!, 'A', 'support')]);
    const before = files(f.root), result = await store.collect(f.root, intake.input, { mode: 'unattended' });
    expect(result).toMatchObject({ head: 'empty', processingComplete: true, persisted: false, requiresAction: true });
    expect(files(f.root)).toEqual(before);
    expect((await pool.query('SELECT * FROM nunchi_review_histories WHERE run_id=$1', [f.state.read().runId])).rowCount).toBe(0);
    expect(existsSync(join(f.root, REVIEW_NOTES_BACKEND_FILE))).toBe(false);
  });
});
