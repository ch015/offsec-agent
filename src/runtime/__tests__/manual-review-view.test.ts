import { mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';
import { createManualResponseTemplate, readManualReviewStatus, renderManualReviewStatus } from '../manual-review-view.js';
import { appendReviewNote, appendReviewNoteBatch } from '../review-notes.js';
import { contentHash, ResultRecordReader } from '../result-records.js';
import { entryRef, feedbackFor, manualReviewFixture, responseFor } from './fixtures/manual-review.js';

const roots: string[] = [];
afterEach(() => { vi.restoreAllMocks(); for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function fixture() {
  const base = realpathSync(mkdtempSync(join(tmpdir(), 'manual-view-'))); roots.push(base);
  return manualReviewFixture(base);
}
const bytes = (root: string) => readdirSync(root, { recursive: true, withFileTypes: true }).filter(entry => entry.isFile())
  .map(entry => join(entry.parentPath, entry.name)).sort().map(path => [path, contentHash(readFileSync(path))]);

it('keeps overlapping assignments and global pending work visible under assignee filters', () => {
  const f = fixture(), first = appendReviewNoteBatch(f.root, f.batch, 'empty'), contract = first.entries[0]!;
  const extra = appendReviewNote(f.root, { ...f.batch.assignments[0], id: 'SECOND-READER', assignee: 'reader-b' }, first.head);
  const response = appendReviewNote(f.root, responseFor(contract), extra.head);
  appendReviewNote(f.root, feedbackFor(contract, response.entry, 'accept'), response.head);
  const before = bytes(f.root), view = readManualReviewStatus(f.root, 'reader-a');
  expect(bytes(f.root)).toEqual(before);
  expect(view.global).toMatchObject({ assignmentCount: 3, fileCount: 3, fileVersionCount: 3, fileObligationCount: 5, openCount: 2, allAccepted: false });
  expect(view.selected).toMatchObject({ assignmentCount: 1, fileCount: 2, fileObligationCount: 2, openCount: 0, allAccepted: true });
  const all = readManualReviewStatus(f.root);
  expect(all.byFile[0]).toMatchObject({ openCount: 1, allAccepted: false });
  expect(all.byFile[0]!.assignments.map(task => task.status)).toEqual(['accepted', 'awaiting-response']);
  expect(readManualReviewStatus(f.root, 'unknown').selected).toMatchObject({ assignmentCount: 0, allAccepted: null });
  expect(readManualReviewStatus(f.root, 'unknown').global.openCount).toBe(2);
  expect(renderManualReviewStatus(view)).toContain('미종결 2건');
});

it('separates changed file versions and cancellation from accepted work', () => {
  const f = fixture();
  expect(readManualReviewStatus(f.root).global).toMatchObject({ assignmentCount: 0, allAccepted: null });
  const first = appendReviewNoteBatch(f.root, f.batch, 'empty'), contract = first.entries[0]!;
  const path = f.input.files[0]!.path;
  writeFileSync(join(f.root, path), 'A later document revision for human review.\n');
  expect(readManualReviewStatus(f.root).assignments[0]).toMatchObject({ status: 'stale', staleReferences: [path] });
  const fresh = new ResultRecordReader(f.root).reference(path);
  const cancelled = appendReviewNote(f.root, { id: 'CANCEL', kind: 'review-feedback', author: 'coordinator',
    assignment: entryRef(contract), action: 'cancel', references: [fresh], rationale: 'Retire the old document contract after the supplied section changed.' }, first.head);
  appendReviewNote(f.root, { ...f.batch.assignments[0], id: 'NEW-VERSION', references: [fresh] }, cancelled.head);
  const view = readManualReviewStatus(f.root);
  expect(view.global).toMatchObject({ fileCount: 3, fileVersionCount: 4, fileObligationCount: 4, openCount: 2, allAccepted: false, counts: { cancelled: 1 } });
  expect(view.byFile.filter(file => file.path === path)).toHaveLength(2);
  expect(view.assignments[0]).toMatchObject({ status: 'cancelled', staleReferences: [path] });
});

it('exports an unreviewed latest-request template without inheriting prior completed claims', () => {
  const f = fixture(), first = appendReviewNoteBatch(f.root, f.batch, 'empty'), contract = first.entries[0]!;
  const reply = appendReviewNote(f.root, responseFor(contract), first.head);
  const feedback = appendReviewNote(f.root, feedbackFor(contract, reply.entry, 'request-changes'), reply.head);
  const before = bytes(f.root), packet = createManualResponseTemplate(f.root, contract.note.id, 'NEW-REPLY');
  expect(bytes(f.root)).toEqual(before);
  expect(packet).toMatchObject({ expectedHead: feedback.head, request: feedback.entry, previousResponse: reply.entry,
    note: { author: 'reader-a', assignment: entryRef(contract), replyTo: entryRef(feedback.entry), results: [
      { status: 'not-reviewed' }, { status: 'not-reviewed' },
    ] } });
  const view = readManualReviewStatus(f.root);
  expect(view.assignments[0]).toMatchObject({ status: 'changes-requested', awaitingCurrentResponse: true });
  expect(view.byFile[0]!.assignments[0]).toMatchObject({ status: 'changes-requested', reportedStatus: 'completed', awaitingCurrentResponse: true });
  expect(view.global.awaitingCurrentResponseCount).toBe(2);
  // Explicitly recording the untouched draft can only report unreviewed work.
  const saved = appendReviewNote(f.root, packet.note, packet.expectedHead);
  expect(() => appendReviewNote(f.root, feedbackFor(contract, saved.entry, 'accept', 'INVALID-ACCEPT'), saved.head)).toThrow('cannot accept');
});

it('rejects stale templates at submission and templates for unknown or already answered requests', () => {
  const f = fixture(), first = appendReviewNoteBatch(f.root, f.batch, 'empty'), contract = first.entries[0]!;
  expect(() => createManualResponseTemplate(f.root, 'MISSING', 'R')).toThrow('Unknown');
  expect(() => createManualResponseTemplate(f.root, contract.note.id, contract.note.id)).toThrow('already exists');
  const packet = createManualResponseTemplate(f.root, contract.note.id, 'DRAFT');
  const unrelated = appendReviewNote(f.root, { ...f.batch.assignments[1], id: 'EXTRA' }, first.head);
  expect(() => appendReviewNote(f.root, packet.note, packet.expectedHead)).toThrow('version conflict');
  const reply = appendReviewNote(f.root, responseFor(contract), unrelated.head);
  expect(() => createManualResponseTemplate(f.root, contract.note.id, 'OTHER')).toThrow('no unanswered request');
  const feedback = appendReviewNote(f.root, feedbackFor(contract, reply.entry, 'request-changes'), reply.head);
  // Replacing expectedHead alone cannot make an old request current.
  expect(() => appendReviewNote(f.root, packet.note, feedback.head)).toThrow('latest unanswered request');
  const newer = createManualResponseTemplate(f.root, contract.note.id, 'DRAFT');
  expect(newer.note.kind === 'review-response' && newer.note.replyTo).toEqual(entryRef(feedback.entry));
  const answered = appendReviewNote(f.root, responseFor(contract, 'FINAL', feedback.entry), feedback.head);
  appendReviewNote(f.root, feedbackFor(contract, answered.entry, 'accept', 'ACCEPT'), answered.head);
  expect(() => createManualResponseTemplate(f.root, contract.note.id, 'AFTER')).toThrow('no unanswered request');
});

it('requires current contract and request evidence but permits correcting a stale prior response', () => {
  const f = fixture(), first = appendReviewNoteBatch(f.root, f.batch, 'empty'), contract = first.entries[0]!;
  const path = 'review-material/support.txt'; writeFileSync(join(f.root, path), 'Original supporting editorial context.');
  const support = new ResultRecordReader(f.root).reference(path), note = responseFor(contract);
  const reply = appendReviewNote(f.root, { ...note, references: [...note.references, support] }, first.head);
  const feedback = appendReviewNote(f.root, feedbackFor(contract, reply.entry, 'request-changes'), reply.head);
  writeFileSync(join(f.root, path), 'Revised supporting editorial context.');
  const packet = createManualResponseTemplate(f.root, contract.note.id, 'CORRECTED');
  expect(packet.expectedHead).toBe(feedback.head);
  expect(packet.note.references).not.toContainEqual(support);
  expect(packet.previousResponse).toEqual(reply.entry);
  writeFileSync(join(f.root, f.input.files[0]!.path), 'Changed contract evidence.');
  expect(() => createManualResponseTemplate(f.root, contract.note.id, 'AFTER-CHANGE')).toThrow('version changed');
});

it('refuses templates with changed supplemental request evidence and detects concurrent file mutation', () => {
  const f = fixture(), first = appendReviewNoteBatch(f.root, f.batch, 'empty'), contract = first.entries[0]!;
  const reply = appendReviewNote(f.root, responseFor(contract), first.head);
  const path = 'review-material/request.txt'; writeFileSync(join(f.root, path), 'Supporting context for this change request.');
  const feedback = feedbackFor(contract, reply.entry, 'request-changes');
  appendReviewNote(f.root, { ...feedback, references: [...feedback.references, new ResultRecordReader(f.root).reference(path)] }, reply.head);
  writeFileSync(join(f.root, path), 'Changed context for this change request.');
  expect(() => createManualResponseTemplate(f.root, contract.note.id, 'AFTER-CHANGE')).toThrow('version changed');
  const original = ResultRecordReader.prototype.assertUnchanged;
  vi.spyOn(ResultRecordReader.prototype, 'assertUnchanged').mockImplementation(function (this: ResultRecordReader) {
    writeFileSync(join(f.root, f.input.files[1]!.path), 'Mutation while inspecting the current view.');
    return original.call(this);
  });
  expect(() => readManualReviewStatus(f.root)).toThrow('changed during inspection');
});

it('keeps changed current-request evidence visible after a later reply and acceptance', () => {
  const f = fixture(), first = appendReviewNoteBatch(f.root, f.batch, 'empty'), contract = first.entries[0]!;
  const reply = appendReviewNote(f.root, responseFor(contract), first.head);
  const path = 'review-material/request.txt'; writeFileSync(join(f.root, path), 'Original context for the current request.');
  const feedback = feedbackFor(contract, reply.entry, 'request-changes');
  const requested = appendReviewNote(f.root, { ...feedback, references: [...feedback.references, new ResultRecordReader(f.root).reference(path)] }, reply.head);
  const revised = appendReviewNote(f.root, responseFor(contract, 'REVISED', requested.entry), requested.head);
  const accepted = appendReviewNote(f.root, feedbackFor(contract, revised.entry, 'accept', 'ACCEPT'), revised.head);
  writeFileSync(join(f.root, path), 'Changed context for the same request.');
  expect(readManualReviewStatus(f.root).assignments[0]).toMatchObject({ status: 'stale', declaredStatus: 'accepted', staleReferences: [path] });
  // A human can explicitly open a new request using current references.
  const reopened = appendReviewNote(f.root, { ...feedbackFor(contract, revised.entry, 'request-changes', 'REOPEN'),
    references: [...feedback.references, new ResultRecordReader(f.root).reference(path)] }, accepted.head);
  const packet = createManualResponseTemplate(f.root, contract.note.id, 'FRESH');
  expect(packet.expectedHead).toBe(reopened.head);
  expect(readManualReviewStatus(f.root).assignments[0]).toMatchObject({ status: 'changes-requested', staleReferences: [] });
});

it('renders author labels and reasons as literal Markdown without hiding needs-information replies', () => {
  const f = fixture(), assignee = '<b>reader</b>|[click](https://example.invalid)\n# heading';
  const contract = appendReviewNote(f.root, { ...f.batch.assignments[0], assignee }, 'empty');
  const note = responseFor(contract.entry);
  appendReviewNote(f.root, { ...note, results: note.results.map(result => ({ ...result, status: 'needs-information',
    reason: 'Missing reference | <b>markup</b> [link](https://example.invalid).' })) }, contract.head);
  const view = readManualReviewStatus(f.root), markdown = renderManualReviewStatus(view);
  expect(view.byFile[0]!.assignments[0]).toMatchObject({ reportedStatus: 'needs-information', status: 'response-received' });
  expect(markdown).not.toContain('<b>'); expect(markdown).not.toContain('[click](');
  expect(markdown).toContain('&#124;'); expect(markdown).toContain('needs&#45;information');
});
