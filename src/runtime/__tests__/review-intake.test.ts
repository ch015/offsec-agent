import { mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import * as fsPromises from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';
import { collectReviewSubmissions, readReviewConflicts } from '../review-intake.js';
import { appendReviewNote, appendReviewNoteBatch, readReviewNotes, REVIEW_NOTES_FILE } from '../review-notes.js';
import { contentHash, ResultRecordReader } from '../result-records.js';
import { auditResultRecords } from '../result-audit.js';
import { entryRef, manualReviewFixture, responseFor } from './fixtures/manual-review.js';
import { mediationFor, opinionFor, writeIntake } from './fixtures/review-intake.js';

vi.mock('node:fs/promises', async importOriginal => {
  const actual = await importOriginal<typeof import('node:fs/promises')>();
  return { ...actual, open: vi.fn(actual.open) };
});
const actualOpen = (await vi.importActual<typeof import('node:fs/promises')>('node:fs/promises')).open;
const roots: string[] = [];
afterEach(() => { vi.mocked(fsPromises.open).mockImplementation(actualOpen); for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function fixture() {
  const base = realpathSync(mkdtempSync(join(tmpdir(), 'review-intake-'))); roots.push(base);
  return manualReviewFixture(base);
}
const snapshot = (root: string) => readdirSync(root, { recursive: true, withFileTypes: true }).filter(entry => entry.isFile())
  .map(entry => join(entry.parentPath, entry.name)).sort().map(path => [path, contentHash(readFileSync(path))]);

it('preserves both sides and requires an explicit current human decision instead of majority voting', () => {
  const f = fixture(), artifact = f.input.files[0]!, before = f.references().map(ref => [ref.path, readFileSync(join(f.root, ref.path))] as const);
  const a = appendReviewNote(f.root, opinionFor(artifact, 'A', 'support'), 'empty');
  const b = appendReviewNote(f.root, opinionFor(artifact, 'B', 'support'), a.head);
  const c = appendReviewNote(f.root, opinionFor(artifact, 'C', 'oppose'), b.head);
  const waiting = readReviewConflicts(f.root, 'unattended');
  expect(waiting).toMatchObject({ openCount: 1, conflictingGroupCount: 1, decisionRouting: 'deferred' });
  expect(waiting.groups[0]).toMatchObject({ status: 'awaiting-mediation', selectedOpinion: null });
  expect(waiting.groups[0]!.opinions).toHaveLength(3);
  const incomplete = mediationFor([a.entry, b.entry], 'adopt');
  expect(() => appendReviewNote(f.root, incomplete, c.head)).toThrow('every current opinion');
  const adopted = appendReviewNote(f.root, mediationFor([c.entry, a.entry, b.entry], 'adopt'), c.head);
  expect(readReviewConflicts(f.root).groups[0]).toMatchObject({ status: 'adopted', selectedOpinion: entryRef(c.entry), conflictingPositions: true });
  const newOpinion = appendReviewNote(f.root, opinionFor(artifact, 'D', 'support'), adopted.head);
  expect(readReviewConflicts(f.root).groups[0]).toMatchObject({ status: 'awaiting-mediation', decisionCurrent: false, selectedOpinion: null });
  expect(() => appendReviewNote(f.root, { ...mediationFor([a.entry, b.entry, c.entry], 'adopt'), id: 'OLD' }, newOpinion.head)).toThrow('every current opinion');
  const all = [a.entry, b.entry, c.entry, newOpinion.entry];
  const deferred = appendReviewNote(f.root, mediationFor(all, 'defer', 'DEFER'), newOpinion.head);
  appendReviewNote(f.root, mediationFor(all, 'needs-information', 'NEEDS'), deferred.head);
  expect(readReviewConflicts(f.root).groups[0]).toMatchObject({ status: 'needs-information', selectedOpinion: null });
  expect(readReviewConflicts(f.root).groups[0]!.mediations).toHaveLength(3);
  const audit = auditResultRecords(f.root);
  expect(audit.issues.map(issue => issue.code)).toContain('manual-mediation-open'); expect(audit.coverage.finalRecordedComplete).toBeNull();
  for (const [path, bytes] of before) expect(readFileSync(join(f.root, path))).toEqual(bytes);
});

it('does not turn matching or uncertain opinions into adopted decisions', () => {
  const f = fixture(), a = appendReviewNote(f.root, opinionFor(f.input.files[0]!, 'A', 'uncertain'), 'empty');
  expect(readReviewConflicts(f.root).groups[0]).toMatchObject({ conflictingPositions: false, status: 'awaiting-mediation' });
  expect(() => appendReviewNote(f.root, mediationFor([a.entry], 'adopt'), a.head)).toThrow('uncertain opinion');
  expect(() => appendReviewNote(f.root, { ...mediationFor([a.entry], 'defer'), selectedOpinion: entryRef(a.entry) }, a.head)).toThrow('must not select');
  const b = appendReviewNote(f.root, opinionFor(f.input.files[0]!, 'B', 'uncertain'), a.head);
  const wrongHash = mediationFor([a.entry, b.entry], 'defer'); wrongHash.opinions[0]!.sha256 = 'a'.repeat(64);
  expect(() => appendReviewNote(f.root, wrongHash, b.head)).toThrow('every current opinion');
  expect(readReviewConflicts(f.root).openCount).toBe(1);
});

it('invalidates changed decision evidence and keeps original opinion versions when a human revisits them', () => {
  const f = fixture(), artifact = f.input.files[0]!, support = f.input.files[1]!;
  const a = appendReviewNote(f.root, { ...opinionFor(artifact, 'A', 'support'), references: [artifact, support] }, 'empty');
  expect(() => appendReviewNote(f.root, { ...mediationFor([a.entry], 'adopt'), references: [artifact] }, a.head)).toThrow('all opinion evidence');
  const decision = appendReviewNote(f.root, mediationFor([a.entry], 'adopt'), a.head);
  writeFileSync(join(f.root, support.path), 'A changed supporting document revision.');
  expect(readReviewConflicts(f.root).groups[0]).toMatchObject({ status: 'stale', selectedOpinion: null });
  const fresh = new ResultRecordReader(f.root).reference(support.path);
  const refreshed = appendReviewNote(f.root, { ...mediationFor([a.entry], 'adopt', 'REFRESHED'), references: [artifact, fresh] }, decision.head);
  expect(readReviewConflicts(f.root).groups[0]).toMatchObject({ status: 'adopted', historicalStaleReferences: [support.path], staleReferences: [] });
  expect(readReviewConflicts(f.root).groups[0]!.opinions[0]).toEqual(a.entry);
  writeFileSync(join(f.root, artifact.path), 'The subject itself now has a new version.');
  expect(readReviewConflicts(f.root).groups[0]!.status).toBe('stale');
  expect(() => appendReviewNote(f.root, { ...mediationFor([a.entry], 'adopt', 'WRONG-VERSION'), references: [new ResultRecordReader(f.root).reference(artifact.path), fresh] }, refreshed.head)).toThrow('exact subject version');
});

it('isolates malformed inputs and preserves both colliding payloads in unattended collection', async () => {
  const f = fixture(), first = appendReviewNoteBatch(f.root, f.batch, 'empty');
  const intake = writeIntake(f.root, join(f.base, 'inputs'), first.head, [
    responseFor(first.entries[0]!), '{', opinionFor(f.input.files[0]!, 'SAME', 'support'), opinionFor(f.input.files[0]!, 'SAME', 'oppose'),
    opinionFor(f.input.files[0]!, 'VALID', 'uncertain'),
  ]);
  const before = snapshot(f.base), result = await collectReviewSubmissions(f.root, intake.input, { mode: 'unattended', concurrency: 2 });
  expect(snapshot(f.base)).toEqual(before);
  expect(result).toMatchObject({ processingComplete: true, persisted: false, decisionRouting: 'deferred', requiresAction: true, counts: { validated: 2, invalid: 3 } });
  expect(result.submissions.map(row => row.index)).toEqual([0, 1, 2, 3, 4]);
  expect(result.submissions[1]!.issues[0]!.code).toBe('invalid-json');
  expect(result.storedManualReviews).toMatchObject({ assignmentCount: 2, openCount: 2 });
  expect(result.submissions.slice(2, 4).map(row => row.note?.kind === 'review-opinion' && row.note.position)).toEqual(['support', 'oppose']);
  expect(result.submissions.slice(2, 4).every(row => row.issues.some(issue => issue.code === 'id-collision'))).toBe(true);
  expect(result.pendingOpinions[0]).toMatchObject({ status: 'unresolved', conflictingPositions: false });
});

it('deduplicates identical copies but never picks a competing response by input order', async () => {
  const f = fixture(), first = appendReviewNoteBatch(f.root, f.batch, 'empty'), response = responseFor(first.entries[0]!);
  const opinion = opinionFor(f.input.files[0]!, 'A', 'support');
  const intake = writeIntake(f.root, join(f.base, 'inputs'), first.head, [response, { ...response, id: 'OTHER' }, opinion, opinion]);
  const result = await collectReviewSubmissions(f.root, intake.input);
  expect(result.counts).toMatchObject({ invalid: 2, validated: 1, duplicate: 1 });
  expect(result.submissions[0]!.issues.some(issue => issue.code === 'competing-responses')).toBe(true);
  expect(result.submissions[1]!.issues.some(issue => issue.code === 'competing-responses')).toBe(true);
  expect(result.submissions[3]).toMatchObject({ state: 'duplicate', duplicateOf: 2 });
  const invalid = { ...opinion, id: 'BAD', references: [{ ...opinion.references[0], sha256: 'a'.repeat(64) }] };
  const duplicates = writeIntake(f.root, join(f.base, 'invalid'), first.head, [invalid, invalid]);
  expect((await collectReviewSubmissions(f.root, duplicates.input)).counts.invalid).toBe(2);
});

it('requires the correct run, current head and latest assignment request while retaining every receipt', async () => {
  const f = fixture(), first = appendReviewNoteBatch(f.root, f.batch, 'empty'), note = responseFor(first.entries[0]!);
  const saved = appendReviewNote(f.root, note, first.head);
  const intake = writeIntake(f.root, join(f.base, 'inputs'), saved.head, [note, { ...note, id: 'LATE' }]);
  const result = await collectReviewSubmissions(f.root, intake.input);
  expect(result.counts).toMatchObject({ 'already-recorded': 1, invalid: 1 });
  expect(result.submissions[1]!.issues[0]!.message).toContain('latest unanswered request');
  const old = writeIntake(f.root, join(f.base, 'old'), 'empty', [opinionFor(f.input.files[0]!, 'NEW', 'support')]);
  expect((await collectReviewSubmissions(f.root, old.input))).toMatchObject({ headMatches: false, counts: { invalid: 1 } });
  writeFileSync(intake.input, JSON.stringify({ ...intake.manifest, identity: { ...intake.manifest.identity, runId: 'wrong-run' } }));
  await expect(collectReviewSubmissions(f.root, intake.input)).rejects.toThrow('different run');
});

it('keeps new opinions unresolved even when they match a saved human decision', async () => {
  const f = fixture(), a = appendReviewNote(f.root, opinionFor(f.input.files[0]!, 'A', 'support'), 'empty');
  const decision = appendReviewNote(f.root, mediationFor([a.entry], 'adopt'), a.head);
  const intake = writeIntake(f.root, join(f.base, 'inputs'), decision.head, [opinionFor(f.input.files[0]!, 'B', 'support')]);
  const human = await collectReviewSubmissions(f.root, intake.input, { mode: 'human' });
  const unattended = await collectReviewSubmissions(f.root, intake.input, { mode: 'unattended' });
  expect(unattended.pendingOpinions).toEqual(human.pendingOpinions);
  expect(unattended.pendingOpinions[0]).toMatchObject({ status: 'unresolved', conflictingPositions: false });
  expect(unattended.pendingOpinions[0]!.opinions.map(opinion => opinion.origin)).toEqual(['stored', 'submission']);
  expect(readReviewConflicts(f.root).groups[0]!.opinions).toHaveLength(1);
});

it('returns no pending action for an exact recorded retry and rejects lossy UTF-8 decoding', async () => {
  const f = fixture(), opinion = opinionFor(f.input.files[0]!, 'A', 'support');
  const first = appendReviewNote(f.root, opinion, 'empty');
  const adopted = appendReviewNote(f.root, mediationFor([first.entry], 'adopt'), first.head);
  const intake = writeIntake(f.root, join(f.base, 'inputs'), adopted.head, [opinion]);
  expect(await collectReviewSubmissions(f.root, intake.input, { mode: 'unattended' })).toMatchObject({ requiresAction: false,
    counts: { 'already-recorded': 1 }, pendingOpinions: [] });
  const bytes = Buffer.concat([Buffer.from(JSON.stringify(opinion).replace(/}$/, ',"extra":"')), Buffer.from([0xff]), Buffer.from('"}')]);
  const ref = intake.manifest.submissions[0]!; writeFileSync(join(intake.directory, ref.path), bytes);
  ref.sha256 = contentHash(bytes); writeFileSync(intake.input, JSON.stringify(intake.manifest));
  const invalid = await collectReviewSubmissions(f.root, intake.input);
  expect(invalid.submissions[0]!.issues[0]!.code).toBe('invalid-json'); expect(invalid.requiresAction).toBe(true);
});

it('bounds concurrent file reads and returns stable order despite asynchronous completion', async () => {
  const f = fixture(), intake = writeIntake(f.root, join(f.base, 'inputs'), 'empty', Array.from({ length: 7 }, (_, i) => opinionFor(f.input.files[0]!, `OP-${i}`, 'support')));
  let active = 0, maximum = 0;
  vi.mocked(fsPromises.open).mockImplementation(async (...args) => {
    const handle = await actualOpen(...args), counted = String(args[0]).includes('submission-');
    if (counted) { active++; maximum = Math.max(maximum, active); }
    return new Proxy(handle, { get(target, property) {
      if (property === 'read') return async (...readArgs: Parameters<typeof handle.read>) => {
        await new Promise(resolve => setTimeout(resolve, 2)); return handle.read(...readArgs);
      };
      if (property === 'close') return async () => { try { await handle.close(); } finally { if (counted) active--; } };
      const value = Reflect.get(target, property); return typeof value === 'function' ? value.bind(target) : value;
    } });
  });
  const result = await collectReviewSubmissions(f.root, intake.input, { concurrency: 3 });
  expect(maximum).toBeGreaterThan(1); expect(maximum).toBeLessThanOrEqual(3); expect(active).toBe(0);
  expect(result.submissions.map(row => row.note?.id)).toEqual(Array.from({ length: 7 }, (_, i) => `OP-${i}`));
});

it('rejects unsafe paths, mismatched bytes, excessive input and mutations without saving any record', async () => {
  const f = fixture(), note = opinionFor(f.input.files[0]!, 'A', 'support');
  const intake = writeIntake(f.root, join(f.base, 'inputs'), 'empty', [note, note, note, note]);
  writeFileSync(join(intake.directory, intake.manifest.submissions[0]!.path), '{}');
  const link = join(intake.directory, intake.manifest.submissions[1]!.path); rmSync(link); symlinkSync(join(f.root, f.input.files[0]!.path), link);
  writeFileSync(join(intake.directory, intake.manifest.submissions[2]!.path), 'x'.repeat(1024 * 1024 + 1));
  intake.manifest.submissions[3]!.path = '../outside.json'; writeFileSync(intake.input, JSON.stringify(intake.manifest));
  const result = await collectReviewSubmissions(f.root, intake.input);
  expect(result.counts.invalid).toBe(4); expect(result.submissions[0]!.issues[0]!.code).toBe('input-version-mismatch');
  expect(readReviewNotes(new ResultRecordReader(f.root)).entries).toHaveLength(0);
  await expect(collectReviewSubmissions(f.root, intake.input, { concurrency: 17 })).rejects.toThrow();
  await expect(collectReviewSubmissions(f.root, intake.input, { mode: 'automatic-adoption' })).rejects.toThrow();
});

it('detects submissions changing after their first read and rejects mediated history with missing opinions', async () => {
  const f = fixture(), a = appendReviewNote(f.root, opinionFor(f.input.files[0]!, 'A', 'support'), 'empty');
  const intake = writeIntake(f.root, join(f.base, 'inputs'), a.head, [opinionFor(f.input.files[0]!, 'B', 'oppose')]);
  let changed = false;
  vi.mocked(fsPromises.open).mockImplementation(async (...args) => {
    const handle = await actualOpen(...args);
    return new Proxy(handle, { get(target, property) {
      if (property === 'close') return async () => { await handle.close(); if (!changed && String(args[0]).includes('submission-')) {
        changed = true; writeFileSync(String(args[0]), '{}');
      } };
      const value = Reflect.get(target, property); return typeof value === 'function' ? value.bind(target) : value;
    } });
  });
  const result = await collectReviewSubmissions(f.root, intake.input);
  expect(result.submissions[0]!.issues.some(issue => issue.code === 'input-changed')).toBe(true);
  expect(result.pendingOpinions).toHaveLength(0);
  vi.mocked(fsPromises.open).mockImplementation(actualOpen);
  appendReviewNote(f.root, mediationFor([a.entry], 'adopt'), a.head);
  const path = join(f.root, REVIEW_NOTES_FILE), history = JSON.parse(readFileSync(path, 'utf8'));
  const last = history.entries.at(-1); last.note.opinions[0].sha256 = 'a'.repeat(64);
  const { sha256: _ignored, ...payload } = last; last.sha256 = contentHash(JSON.stringify({ identity: history.identity, ...payload }));
  writeFileSync(path, JSON.stringify(history));
  expect(() => readReviewConflicts(f.root)).toThrow('every current opinion');
});
