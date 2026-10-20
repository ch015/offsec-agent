import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { afterEach, describe, expect, it } from 'vitest';
import { planManualReview } from '../manual-review.js';
import { appendReviewNote, appendReviewNoteBatch, readReviewNotes, REVIEW_NOTES_FILE, summarizeReviewNotes } from '../review-notes.js';
import { contentHash, ResultRecordReader, resultIdentity } from '../result-records.js';
import { manualReviewFixture, entryRef, feedbackFor, responseFor } from './fixtures/manual-review.js';
import { auditResultRecords, renderResultAudit } from '../result-audit.js';

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function fixture() {
  const base = realpathSync(mkdtempSync(join(tmpdir(), 'manual-review-'))); roots.push(base);
  return manualReviewFixture(base);
}
const summary = (root: string) => summarizeReviewNotes(new ResultRecordReader(root)).manualReviews;

describe('human review contracts', () => {
  it('reads the original dispute serialization without changing its stored hash', () => {
    const f = fixture(), reader = new ResultRecordReader(f.root), identity = resultIdentity(reader);
    const note = { id: 'LEGACY', author: 'original reviewer', references: f.references(),
      rationale: 'Preserve the original interpretation and source evidence for later human review.', kind: 'dispute',
      findingIds: [f.finding.id], assertions: ['The original reviewer recorded one possible interpretation.', 'Another interpretation remains open in this fixture record.'] };
    const payload = { sequence: 1, at: '2026-10-13T00:00:00.000Z', previous: 'empty', note };
    const sha256 = contentHash(JSON.stringify({ identity, ...payload }));
    const bytes = JSON.stringify({ schemaVersion: 1, identity, entries: [{ ...payload, sha256 }] });
    mkdirSync(join(f.root, 'review-notes'), { recursive: true, mode: 0o700 });
    writeFileSync(join(f.root, REVIEW_NOTES_FILE), bytes);
    expect(readReviewNotes(new ResultRecordReader(f.root)).entries[0]!.sha256).toBe(sha256);
    expect(readFileSync(join(f.root, REVIEW_NOTES_FILE), 'utf8')).toBe(bytes);
    expect(appendReviewNoteBatch(f.root, f.batch, sha256).insertedCount).toBe(2);
    expect(readReviewNotes(new ResultRecordReader(f.root)).entries[0]!.sha256).toBe(sha256);
  });

  it('partitions only the supplied files deterministically without omitting a remainder', () => {
    const f = fixture(), plan = planManualReview({ ...f.input, files: [...f.input.files].reverse() });
    expect(plan).toEqual(f.batch);
    expect(plan.assignments.map(row => [row.id, row.assignee, row.references.length])).toEqual([['DOC-0001', 'reader-a', 2], ['DOC-0002', 'reader-b', 1]]);
    expect(plan.assignments.flatMap(row => row.references)).toEqual(f.input.files);
    expect(() => planManualReview({ ...f.input, files: [f.input.files[0], f.input.files[0]] })).toThrow('Duplicate files');
    expect(() => planManualReview({ ...f.input, assignees: ['reader-a', 'reader-a'] })).toThrow('Duplicate assignee');
    expect(() => planManualReview({ ...f.input, files: [{ path: '../private', sha256: 'a'.repeat(64) }] })).toThrow('relative artifact');
    expect(() => planManualReview({ ...f.input, files: [{ path: 'review-notes/history.json', sha256: 'a'.repeat(64) }] })).toThrow('mutable history');
    expect(() => planManualReview({ ...f.input, maxFilesPerAssignment: 1, files: Array.from({ length: 501 }, (_, index) => ({ path: `${index}.txt`, sha256: 'a'.repeat(64) })) })).toThrow('exceeds 500');
  });

  it('registers every assignment atomically and preserves idempotency and CAS for mixed batches', () => {
    const f = fixture();
    const broken = structuredClone(f.batch); broken.assignments[1]!.references[0]!.sha256 = 'b'.repeat(64);
    expect(() => appendReviewNoteBatch(f.root, broken, 'empty')).toThrow('version changed');
    expect(readReviewNotes(new ResultRecordReader(f.root)).entries).toHaveLength(0);
    const first = appendReviewNoteBatch(f.root, f.batch, 'empty');
    expect(first.insertedCount).toBe(2);
    const bytes = readFileSync(join(f.root, REVIEW_NOTES_FILE));
    expect(appendReviewNoteBatch(f.root, f.batch, 'empty')).toMatchObject({ insertedCount: 0, head: first.head });
    expect(readFileSync(join(f.root, REVIEW_NOTES_FILE))).toEqual(bytes);
    const mixed = { schemaVersion: 1, assignments: [f.batch.assignments[0], { ...f.batch.assignments[1], id: 'DOC-new' }] };
    expect(() => appendReviewNoteBatch(f.root, mixed, 'empty')).toThrow('version conflict');
    expect(() => appendReviewNoteBatch(f.root, { schemaVersion: 1, assignments: [f.batch.assignments[0], f.batch.assignments[0]] }, first.head)).toThrow('Duplicate assignment');
    expect(() => appendReviewNoteBatch(f.root, { schemaVersion: 1, assignments: [{ ...f.batch.assignments[0], instructions: 'Changed instructions must not replace a stored contract.' }] }, first.head)).toThrow('ID collision');
    expect(summary(f.root)).toMatchObject({ assignmentCount: 2, openCount: 2, allAccepted: false });
  });

  it('requires a latest-request response and explicit human acceptance without changing canonical coverage', () => {
    const f = fixture(), canonicalBefore = f.references().map(ref => [ref.path, readFileSync(join(f.root, ref.path))]);
    const first = appendReviewNoteBatch(f.root, f.batch, 'empty'), contract = first.entries[0]!;
    const replied = appendReviewNote(f.root, responseFor(contract), first.head);
    expect(summary(f.root).assignments[0]!.status).toBe('response-received');
    const feedback = appendReviewNote(f.root, feedbackFor(contract, replied.entry, 'request-changes'), replied.head);
    expect(summary(f.root).assignments[0]).toMatchObject({ status: 'changes-requested', latestResponse: entryRef(replied.entry) });
    expect(() => appendReviewNote(f.root, responseFor(contract, 'REPLY-2'), feedback.head)).toThrow('latest unanswered request');
    const revised = appendReviewNote(f.root, responseFor(contract, 'REPLY-2', feedback.entry), feedback.head);
    expect(() => appendReviewNote(f.root, feedbackFor(contract, replied.entry, 'accept', 'OLD-ACCEPT'), revised.head)).toThrow('latest response');
    const accepted = appendReviewNote(f.root, feedbackFor(contract, revised.entry, 'accept', 'ACCEPT-2'), revised.head);
    const current = summary(f.root);
    expect(current).toMatchObject({ openCount: 1, allAccepted: false });
    expect(current.assignments[0]).toMatchObject({ status: 'accepted', history: expect.any(Array) });
    expect(current.assignments[0]!.history).toHaveLength(5);
    expect(current.assignments[1]!.files[0]!.reportedStatus).toBeNull();
    expect(() => appendReviewNote(f.root, responseFor(contract, 'UNREQUESTED'), accepted.head)).toThrow('latest unanswered request');
    const audit = auditResultRecords(f.root);
    expect(audit.issues.map(issue => issue.code)).toContain('manual-reviews-open');
    expect(audit.coverage.finalRecordedComplete).toBeNull();
    expect(renderResultAudit(audit)).toContain('미회신');
    const second = first.entries[1]!;
    const secondReply = appendReviewNote(f.root, responseFor(second, 'SECOND-REPLY'), accepted.head);
    appendReviewNote(f.root, feedbackFor(second, secondReply.entry, 'accept', 'SECOND-ACCEPT'), secondReply.head);
    const final = auditResultRecords(f.root);
    expect(final.notes.manualReviews).toMatchObject({ allAccepted: true, openCount: 0 });
    expect(final.coverage.finalRecordedComplete).toBeNull();
    for (const [path, bytes] of canonicalBefore) expect(readFileSync(join(f.root, path as string))).toEqual(bytes);
  });

  it('rejects wrong author labels, foreign versions, duplicate paths and incomplete acceptance', () => {
    const f = fixture(), first = appendReviewNoteBatch(f.root, f.batch, 'empty'), contract = first.entries[0]!;
    const note = responseFor(contract);
    expect(() => appendReviewNote(f.root, { ...note, author: 'reader-b' }, first.head)).toThrow('assigned label');
    expect(() => appendReviewNote(f.root, { ...note, assignment: { ...note.assignment, sha256: 'a'.repeat(64) } }, first.head)).toThrow('different version');
    expect(() => appendReviewNote(f.root, { ...note, results: [note.results[0], note.results[0]] }, first.head)).toThrow('exactly once');
    expect(() => appendReviewNote(f.root, { ...note, results: note.results.slice(1) }, first.head)).toThrow('exactly once');
    expect(() => appendReviewNote(f.root, { ...note, references: note.references.slice(1) }, first.head)).toThrow('every assigned file');
    const response = appendReviewNote(f.root, { ...note, results: note.results.map(row => ({ ...row, status: 'needs-information' })) }, first.head);
    expect(() => appendReviewNote(f.root, feedbackFor(contract, response.entry, 'accept'), response.head)).toThrow('cannot accept');
    expect(() => appendReviewNote(f.root, { ...feedbackFor(contract, response.entry, 'request-changes'), author: 'reader-a' }, response.head)).toThrow('assigning label');
    expect(summary(f.root).assignments[0]!.files.every(file => file.reportedStatus === 'needs-information')).toBe(true);
  });

  it('marks accepted contracts stale after evidence changes and preserves an explicit cancellation', () => {
    const f = fixture(), first = appendReviewNoteBatch(f.root, f.batch, 'empty'), contract = first.entries[0]!;
    const response = appendReviewNote(f.root, responseFor(contract), first.head);
    const accepted = appendReviewNote(f.root, feedbackFor(contract, response.entry, 'accept'), response.head);
    writeFileSync(join(f.root, f.input.files[0]!.path), 'A new editorial revision.\n');
    expect(summary(f.root).assignments[0]).toMatchObject({ status: 'stale', declaredStatus: 'accepted' });
    const cancelled = appendReviewNote(f.root, { kind: 'review-feedback', id: 'CANCEL', author: 'coordinator', assignment: entryRef(contract), action: 'cancel',
      rationale: 'The prior document contract was explicitly retired after an editorial revision.',
      references: [new ResultRecordReader(f.root).reference(f.input.files[0]!.path)] }, accepted.head);
    expect(summary(f.root).assignments[0]).toMatchObject({ status: 'cancelled', staleReferences: [f.input.files[0]!.path] });
    expect(summary(f.root).allAccepted).toBe(false);
    expect(() => appendReviewNote(f.root, responseFor(contract, 'LATE'), cancelled.head)).toThrow();
  });

  it('validates contract relationships on history load even when an invalid reply has a recomputed hash', () => {
    const f = fixture(), first = appendReviewNoteBatch(f.root, f.batch, 'empty'), contract = first.entries[0]!;
    appendReviewNote(f.root, responseFor(contract), first.head);
    const path = join(f.root, REVIEW_NOTES_FILE), history = JSON.parse(readFileSync(path, 'utf8'));
    const entry = history.entries.at(-1); entry.note.author = 'unassigned label';
    const { sha256: _hash, ...payload } = entry;
    entry.sha256 = contentHash(JSON.stringify({ identity: history.identity, ...payload }));
    writeFileSync(path, JSON.stringify(history));
    expect(() => readReviewNotes(new ResultRecordReader(f.root))).toThrow('assigned label');
  });

  it('binds acceptance to supplemental response evidence and reopens it only through explicit feedback', () => {
    const f = fixture(), first = appendReviewNoteBatch(f.root, f.batch, 'empty'), contract = first.entries[0]!;
    const path = 'review-material/supporting.txt'; writeFileSync(join(f.root, path), 'Supporting editorial context.\n');
    const initial = responseFor(contract), references = [...initial.references, new ResultRecordReader(f.root).reference(path)];
    const response = appendReviewNote(f.root, { ...initial, references }, first.head);
    expect(() => appendReviewNote(f.root, feedbackFor(contract, response.entry, 'accept'), response.head)).toThrow('all evidence');
    const accepted = appendReviewNote(f.root, { ...feedbackFor(contract, response.entry, 'accept'), references }, response.head);
    writeFileSync(join(f.root, path), 'Changed supporting editorial context.\n');
    expect(summary(f.root).assignments[0]).toMatchObject({ status: 'stale', staleReferences: [path] });
    const change = appendReviewNote(f.root, feedbackFor(contract, response.entry, 'request-changes', 'REOPEN'), accepted.head);
    const freshRefs = [...initial.references, new ResultRecordReader(f.root).reference(path)];
    const fresh = appendReviewNote(f.root, { ...responseFor(contract, 'FRESH', change.entry), references: freshRefs }, change.head);
    appendReviewNote(f.root, { ...feedbackFor(contract, fresh.entry, 'accept', 'FRESH-ACCEPT'), references: freshRefs }, fresh.head);
    expect(summary(f.root).assignments[0]).toMatchObject({ status: 'accepted', staleReferences: [] });
    expect(summary(f.root).assignments[0]!.history).toHaveLength(6);
  });
});
