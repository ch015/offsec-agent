import { constants, realpathSync } from 'node:fs';
import { open } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { z } from 'zod';
import { contentHash, ResultRecordReader, resultIdentity, StoredReferenceSchema, validateResultPath } from './result-records.js';
import { prepareReviewNote, readReviewNotes, summarizeReviewNotes, validateReviewNoteHistory, type ReviewNoteHistory } from './review-notes.js';
import { ReviewNoteInputSchema, type ReviewNoteInput } from './review-note-schema.js';
import { reviewSubjectKey } from './review-mediation.js';
import { managedPath } from './workflow/storage-files.js';

const Mode = z.enum(['human', 'unattended']);
export const ReviewCollectionOptionsSchema = z.object({ mode: Mode.default('human'), concurrency: z.number().int().min(1).max(16).default(4) }).strict();
export const ReviewSubmissionManifestSchema = z.object({ schemaVersion: z.literal(1),
  identity: z.object({ runId: z.string().min(1), sourceManifestFileSha256: z.string().regex(/^[a-f0-9]{64}$/) }).strict(),
  expectedHead: z.union([z.literal('empty'), z.string().regex(/^[a-f0-9]{64}$/)]),
  submissions: z.array(StoredReferenceSchema).min(1).max(128),
}).strict();
type Context = { reader: ResultRecordReader; notes: ReviewNoteHistory };
type SubmittedNote = Extract<ReviewNoteInput, { kind: 'review-response' | 'review-opinion' }>;
type Submission = { index: number; source: z.infer<typeof StoredReferenceSchema>; observedSha256: string | null; bytes: number | null;
  state: 'validated' | 'already-recorded' | 'duplicate' | 'invalid'; note: SubmittedNote | null; duplicateOf?: number;
  issues: Array<{ code: string; message: string }> };
const MAX_FILE_BYTES = 1024 * 1024;
const parseJson = (bytes: Uint8Array): unknown => JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));

function context(directory: string, supplied?: Context) {
  const root = realpathSync(directory), reader = supplied?.reader ?? new ResultRecordReader(root);
  if (reader.root !== root) throw new Error('Review intake reader belongs to a different engagement');
  const identity = resultIdentity(reader), notes = supplied ? validateReviewNoteHistory(identity, supplied.notes) : readReviewNotes(reader);
  return { reader, identity, notes };
}

/** Bounded concurrent I/O. Validation/hashing remains ordinary in-process code. */
async function parallel<T, R>(values: readonly T[], concurrency: number, operation: (value: T, index: number) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(values.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, values.length) }, async () => {
    for (;;) { const index = next++; if (index >= values.length) return; results[index] = await operation(values[index]!, index); }
  }));
  return results;
}

async function readInput(root: string, path: string) {
  validateResultPath(path);
  const full = managedPath(root, join(root, path));
  const handle = await open(full, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > MAX_FILE_BYTES) throw new Error('Input must be a regular file no larger than 1 MiB');
    // A bounded buffer also limits a file that grows after stat().
    const buffer = Buffer.alloc(MAX_FILE_BYTES + 1); let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
      if (!bytesRead) break; offset += bytesRead;
    }
    if (offset > MAX_FILE_BYTES) throw new Error('Input exceeds 1 MiB');
    managedPath(root, full);
    return buffer.subarray(0, offset);
  } finally { await handle.close(); }
}

const invalidate = (row: Submission, code: string, message: string) => { row.state = 'invalid'; row.issues.push({ code, message }); };

/** Read-only batch intake. Never appends notes, prompts, dispatches or chooses a verdict. */
export async function collectReviewSubmissions(directory: string, manifestPath: string, options: unknown = {}, supplied?: Context) {
  const settings = ReviewCollectionOptionsSchema.parse(options), { reader, identity, notes } = context(directory, supplied);
  const absolute = resolve(manifestPath), inputRoot = realpathSync(dirname(absolute));
  const inputName = absolute.slice(dirname(absolute).length + 1);
  const manifestBytes = await readInput(inputRoot, inputName);
  const manifest = ReviewSubmissionManifestSchema.parse(parseJson(manifestBytes));
  if (JSON.stringify(manifest.identity) !== JSON.stringify(identity)) throw new Error('Submission manifest belongs to a different run or source manifest');
  if (new Set(manifest.submissions.map(ref => ref.path)).size !== manifest.submissions.length) throw new Error('Duplicate submission paths');
  const head = notes.entries.at(-1)?.sha256 ?? 'empty';
  const rows = await parallel(manifest.submissions, settings.concurrency, async (source, index): Promise<Submission> => {
    const row: Submission = { index, source, observedSha256: null, bytes: null, state: 'validated', note: null, issues: [] };
    try {
      const bytes = await readInput(inputRoot, source.path); row.observedSha256 = contentHash(bytes); row.bytes = bytes.length;
      if (row.observedSha256 !== source.sha256) invalidate(row, 'input-version-mismatch', 'Submission bytes do not match the supplied hash');
      let value: unknown;
      try { value = parseJson(bytes); } catch { invalidate(row, 'invalid-json', 'Submission is not valid UTF-8 JSON'); return row; }
      const parsed = ReviewNoteInputSchema.safeParse(value);
      if (!parsed.success) {
        invalidate(row, 'invalid-schema', parsed.error.issues.map(issue => `${issue.path.join('.')}: ${issue.code}`).join('; ')); return row;
      }
      if (parsed.data.kind !== 'review-response' && parsed.data.kind !== 'review-opinion') {
        invalidate(row, 'unsupported-kind', 'Intake accepts review-response and review-opinion only; mediation uses explicit note submission'); return row;
      }
      row.note = parsed.data;
    } catch { invalidate(row, 'input-unreadable', 'Cannot safely read this submission as a regular file of at most 1 MiB'); }
    return row;
  });
  // Never choose the first of conflicting submissions based on input order.
  const ids = new Map<string, Submission[]>();
  for (const row of rows) if (row.note) ids.set(row.note.id, [...(ids.get(row.note.id) ?? []), row]);
  for (const group of ids.values()) if (group.length > 1) {
    if (new Set(group.map(row => JSON.stringify(row.note))).size > 1) {
      for (const row of group) invalidate(row, 'id-collision', 'Different payloads use the same note ID; all versions remain in the intake result');
    } else {
      const first = group.find(row => row.state !== 'invalid');
      if (first) for (const row of group) if (row !== first && row.state !== 'invalid') { row.state = 'duplicate'; row.duplicateOf = first.index; }
    }
  }
  // Validate every independent input against the same stored contract snapshot.
  // No fabricated entry hashes or unsaved history are exposed as persisted data.
  for (const row of rows) if (row.note && row.state === 'validated') {
    try {
      const result = prepareReviewNote(reader, notes, row.note, manifest.expectedHead);
      if (!result.inserted) row.state = 'already-recorded';
    } catch (error) { invalidate(row, 'record-validation', error instanceof Error ? error.message : 'Record validation failed'); }
  }
  const responses = new Map<string, Submission[]>();
  for (const row of rows) if (row.state === 'validated' && row.note?.kind === 'review-response') {
    const key = JSON.stringify([row.note.assignment, row.note.replyTo]); responses.set(key, [...(responses.get(key) ?? []), row]);
  }
  for (const group of responses.values()) if (group.length > 1) for (const row of group) invalidate(row, 'competing-responses', 'Multiple new responses answer the same request; none is selected automatically');
  // Keep each receipt even when an input disappeared or changed during collection.
  await parallel(rows, settings.concurrency, async row => {
    if (row.observedSha256) {
      try { if (contentHash(await readInput(inputRoot, row.source.path)) !== row.observedSha256) invalidate(row, 'input-changed', 'Submission changed during collection'); }
      catch { invalidate(row, 'input-changed', 'Submission became unavailable during collection'); }
    }
  });
  for (const row of rows) if (row.state === 'duplicate' && rows[row.duplicateOf!]!.state === 'invalid') invalidate(row, 'duplicate-invalid', 'The referenced duplicate failed validation');
  const summary = summarizeReviewNotes(reader, notes);
  const pending = new Map<string, { key: string; subject: Extract<SubmittedNote, { kind: 'review-opinion' }>['subject'];
    opinions: Array<{ origin: 'stored' | 'submission'; id: string; author: string; position: string; rationale: string; references: SubmittedNote['references'] }> }>();
  for (const row of rows) if (row.state === 'validated' && row.note?.kind === 'review-opinion') {
    const note = row.note, key = reviewSubjectKey(note.subject);
    const group = pending.get(key) ?? { key, subject: note.subject, opinions: (summary.mediation.groups.find(group => group.key === key)?.opinions ?? [])
      .map(entry => ({ origin: 'stored' as const, id: entry.note.id, author: entry.note.author, position: entry.note.position, rationale: entry.note.rationale, references: entry.note.references })) };
    group.opinions.push({ origin: 'submission', id: note.id, author: note.author, position: note.position, rationale: note.rationale, references: note.references }); pending.set(key, group);
  }
  if (contentHash(await readInput(inputRoot, inputName)) !== contentHash(manifestBytes)) throw new Error('Submission manifest changed during collection');
  reader.assertUnchanged();
  return { schemaVersion: 1 as const, identity, head, expectedHead: manifest.expectedHead, headMatches: head === manifest.expectedHead,
    mode: settings.mode, decisionRouting: settings.mode === 'human' ? 'human-review' : 'deferred', concurrency: settings.concurrency,
    inputSha256: contentHash(manifestBytes), collectedAt: new Date().toISOString(), processingComplete: true,
    persisted: false, submissions: rows,
    counts: Object.fromEntries(['validated', 'already-recorded', 'duplicate', 'invalid'].map(state => [state, rows.filter(row => row.state === state).length])),
    storedMediation: summary.mediation,
    storedManualReviews: summary.manualReviews, storedDisputes: summary.disputes,
    pendingOpinions: [...pending.values()].map(group => ({ ...group, status: 'unresolved' as const,
      conflictingPositions: new Set(group.opinions.map(opinion => opinion.position)).size > 1 })),
    requiresAction: head !== manifest.expectedHead || rows.some(row => ['invalid', 'validated'].includes(row.state)) || summary.mediation.openCount > 0 || summary.manualReviews.openCount > 0 || summary.openCount > 0,
    notice: 'Offline intake only. Originals remain at their supplied paths; receipts bind their bytes. Validated does not mean saved, accepted, read or true. Unattended mode never adjudicates or dispatches work.',
  };
}

export function readReviewConflicts(directory: string, mode: 'human' | 'unattended' = 'human', supplied?: Context) {
  Mode.parse(mode);
  const { reader, identity, notes } = context(directory, supplied), summary = summarizeReviewNotes(reader, notes);
  reader.assertUnchanged();
  return { schemaVersion: 1 as const, identity, head: summary.head, mode,
    decisionRouting: mode === 'human' ? 'human-review' : 'deferred', ...summary.mediation,
    pending: summary.mediation.groups.filter(group => group.status !== 'adopted').map(group => ({
      key: group.key, subject: group.subject, status: group.status, conflictingPositions: group.conflictingPositions,
      opinions: group.opinions.map(entry => ({ id: entry.note.id, sha256: entry.sha256 })),
    })),
  };
}
