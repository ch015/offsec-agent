import { realpathSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { z } from 'zod';
import { canonicalV2Findings } from './v2-review-resolution.js';
import { readStandardFindingRecordReceipts } from './finding-contract.js';
import { acquireRunLock } from './workflow/run-lock.js';
import { atomicPrivateWrite } from './workflow/storage-files.js';
import { contentHash, resultIdentity, ResultRecordReader } from './result-records.js';
import { ManualReviewBatchSchema, ReviewNoteInputSchema } from './review-note-schema.js';
import { projectManualReviews, summarizeManualReviews } from './manual-review.js';
import { projectReviewMediation, summarizeReviewMediation } from './review-mediation.js';
export { ReviewNoteInputSchema, type ReviewNoteInput } from './review-note-schema.js';

export const REVIEW_NOTES_FILE = 'review-notes/history.json';
export const REVIEW_NOTES_BACKEND_FILE = 'review-notes/backend.json';
const Identity = z.object({ runId: z.string().min(1), sourceManifestFileSha256: z.string().regex(/^[a-f0-9]{64}$/) }).strict();
const Entry = z.object({ sequence: z.number().int().positive(), at: z.iso.datetime(),
  previous: z.string(), sha256: z.string().regex(/^[a-f0-9]{64}$/), note: ReviewNoteInputSchema }).strict();
const History = z.object({ schemaVersion: z.literal(1), identity: Identity, entries: z.array(Entry) }).strict();
export type ReviewNoteHistory = z.infer<typeof History>;
const entryHash = (identity: ReviewNoteHistory['identity'], entry: Omit<ReviewNoteHistory['entries'][number], 'sha256'>) => contentHash(JSON.stringify({ identity, ...entry }));

export function validateReviewNoteHistory(identity: ReviewNoteHistory['identity'], raw: unknown): ReviewNoteHistory {
  const history = raw === undefined ? History.parse({ schemaVersion: 1, identity, entries: [] }) : History.parse(raw);
  if (JSON.stringify(history.identity) !== JSON.stringify(identity)) throw new Error('Review notes belong to a different run or source manifest');
  const ids = new Set<string>(), disputes = new Set<string>();
  let previous = 'empty';
  for (const entry of history.entries) {
    const { sha256, ...payload } = entry;
    if (entry.sequence !== ids.size + 1 || ids.has(entry.note.id) || entry.previous !== previous || entryHash(identity, payload) !== sha256) throw new Error('Review note history is inconsistent');
    if (entry.note.kind === 'resolution' && !disputes.has(entry.note.disputeId)) throw new Error('Review resolution has no preceding dispute');
    if (entry.note.kind === 'dispute') disputes.add(entry.note.id);
    ids.add(entry.note.id); previous = sha256;
  }
  projectManualReviews(history.entries);
  projectReviewMediation(history.entries);
  return history;
}

export function readLocalReviewNotes(reader: ResultRecordReader): ReviewNoteHistory {
  return validateReviewNoteHistory(resultIdentity(reader), reader.json(REVIEW_NOTES_FILE, true));
}

export function readReviewNotes(reader: ResultRecordReader): ReviewNoteHistory {
  if (reader.json(REVIEW_NOTES_BACKEND_FILE, true) !== undefined) throw new Error('Review notes are bound to PostgreSQL; use the configured database, not the file backend');
  return readLocalReviewNotes(reader);
}

/** Shared validation for both persistence adapters; never modifies artifacts. */
export function prepareReviewNote(reader: ResultRecordReader, history: ReviewNoteHistory, value: unknown, expectedHead: string) {
  history = validateReviewNoteHistory(resultIdentity(reader), history);
  const note = ReviewNoteInputSchema.parse(value);
  const existing = history.entries.find(entry => entry.note.id === note.id);
  if (existing) {
    if (JSON.stringify(existing.note) !== JSON.stringify(note)) throw new Error('Review note ID collision: use a new note ID and preserve the prior entry');
    reader.assertUnchanged();
    return { head: history.entries.at(-1)!.sha256, inserted: false, entry: existing };
  }
  const head = history.entries.at(-1)?.sha256 ?? 'empty';
  if (head !== expectedHead) throw new Error('Review note version conflict; inspect the latest head before appending');
  if (new Set(note.references.map(ref => ref.path)).size !== note.references.length) throw new Error('Duplicate review note references');
  for (const ref of note.references) {
    if (ref.path.startsWith('review-notes/')) throw new Error('Review notes must cite source artifacts, not their own mutable history');
    reader.verify(ref);
  }
  let findingIds: string[] = [];
  if (note.kind === 'dispute') {
    const canonical = canonicalV2Findings(reader.root);
    if (new Set(note.findingIds).size !== note.findingIds.length || note.findingIds.some(id => !canonical.has(id))) throw new Error('Unknown or duplicate finding in review dispute');
    findingIds = note.findingIds;
  } else if (note.kind === 'resolution') {
    const dispute = history.entries.find(entry => entry.note.kind === 'dispute' && entry.note.id === note.disputeId)?.note;
    if (dispute?.kind !== 'dispute') throw new Error('Review resolution has no preceding dispute');
    findingIds = dispute.findingIds;
  }
  const records = findingIds.length ? readStandardFindingRecordReceipts(reader.root).filter(record => findingIds.includes(record.findingId)) : [];
  if (findingIds.some(id => !records.some(record => record.findingId === id))) throw new Error('Disputed finding no longer exists');
  for (const record of records) {
    const path = `standard-findings/${record.recordName}`;
    if (!note.references.some(ref => ref.path === path && ref.sha256 === record.sha256)) throw new Error(`Review note must bind the current finding version: ${path}`);
    reader.verify({ path, sha256: record.sha256 });
  }
  const payload = { sequence: history.entries.length + 1, at: new Date().toISOString(), previous: head, note };
  const entry = { ...payload, sha256: entryHash(history.identity, payload) };
  projectManualReviews([...history.entries, entry]);
  projectReviewMediation([...history.entries, entry]);
  reader.assertUnchanged();
  return { head: entry.sha256, inserted: true, entry };
}

/** Human-authored annotations only. They never rewrite findings or publish a report. */
export function appendReviewNote(root: string, value: unknown, expectedHead: string) {
  return writeReviewNotes(root, (reader, history) => {
    const result = prepareReviewNote(reader, history, value, expectedHead);
    return { result, history: result.inserted ? { ...history, entries: [...history.entries, result.entry] } : history };
  });
}

/** All assignments become visible together; retrying an already saved batch is a no-op. */
export function prepareReviewNoteBatch(reader: ResultRecordReader, history: ReviewNoteHistory, value: unknown, expectedHead: string) {
  const { assignments } = ManualReviewBatchSchema.parse(value);
  if (new Set(assignments.map(note => note.id)).size !== assignments.length) throw new Error('Duplicate assignment IDs in review batch');
  const currentHead = history.entries.at(-1)?.sha256 ?? 'empty';
  const hasNew = assignments.some(note => !history.entries.some(entry => entry.note.id === note.id));
  if (hasNew && currentHead !== expectedHead) throw new Error('Review note version conflict; inspect the latest head before appending');
  let next = history;
  const receipts = assignments.map(note => {
    const result = prepareReviewNote(reader, next, note, next.entries.at(-1)?.sha256 ?? 'empty');
    if (result.inserted) next = { ...next, entries: [...next.entries, result.entry] };
    return result;
  });
  return { history: next, result: { head: next.entries.at(-1)!.sha256,
    insertedCount: receipts.filter(result => result.inserted).length, entries: receipts.map(result => result.entry) } };
}

export function appendReviewNoteBatch(root: string, value: unknown, expectedHead: string) {
  return writeReviewNotes(root, (reader, history) => prepareReviewNoteBatch(reader, history, value, expectedHead));
}

function writeReviewNotes<T>(root: string, prepare: (reader: ResultRecordReader, history: ReviewNoteHistory) => { result: T; history: ReviewNoteHistory }): T {
  root = realpathSync(root);
  const release = acquireRunLock(join(dirname(root), `.${basename(root)}.agent.lock`));
  try {
    const reader = new ResultRecordReader(root), history = readReviewNotes(reader);
    const prepared = prepare(reader, history);
    reader.assertUnchanged();
    if (prepared.history.entries.length !== history.entries.length) atomicPrivateWrite(join(root, REVIEW_NOTES_FILE), JSON.stringify(prepared.history, null, 2) + '\n');
    return prepared.result;
  } finally { release(); }
}

export function summarizeReviewNotes(reader: ResultRecordReader, supplied?: ReviewNoteHistory) {
  const history = supplied ? validateReviewNoteHistory(resultIdentity(reader), supplied) : readReviewNotes(reader);
  const stale = new Map(history.entries.map(entry => [entry.note.id, entry.note.references.filter(ref => {
    try { reader.verify(ref); return false; } catch { return true; }
  }).map(ref => ref.path)]));
  const disputes = history.entries.filter(entry => entry.note.kind === 'dispute').map(entry => {
    const resolutions = history.entries.filter(other => other.note.kind === 'resolution' && other.note.disputeId === entry.note.id);
    const latest = resolutions.at(-1);
    const historicalStaleReferences = stale.get(entry.note.id) ?? [];
    const staleReferences = latest ? stale.get(latest.note.id) ?? [] : historicalStaleReferences;
    return { id: entry.note.id, findingIds: entry.note.kind === 'dispute' ? entry.note.findingIds : [],
      status: staleReferences.length ? 'stale' : latest?.note.kind === 'resolution' ? latest.note.outcome : 'open',
      staleReferences, historicalStaleReferences, latestResolution: latest?.note.id ?? null, history: [entry, ...resolutions] };
  });
  return { head: history.entries.at(-1)?.sha256 ?? 'empty', entryCount: history.entries.length, disputes,
    manualReviews: summarizeManualReviews(history.entries, stale),
    mediation: summarizeReviewMediation(history.entries, stale),
    openCount: disputes.filter(dispute => dispute.status !== 'resolved').length,
    notice: 'Human-authored review notes; resolution does not alter canonical findings, scope completeness or published decisions.' };
}
