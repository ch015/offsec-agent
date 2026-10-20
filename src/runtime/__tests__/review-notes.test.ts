import { mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { reviewNotesFixture } from './fixtures/review-notes.js';
import { acquireRunLock } from '../workflow/run-lock.js';
import { ResultRecordReader } from '../result-records.js';
import { appendReviewNote, readReviewNotes, REVIEW_NOTES_FILE, summarizeReviewNotes, type ReviewNoteInput } from '../review-notes.js';

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function fixture() {
  const base = realpathSync(mkdtempSync(join(tmpdir(), 'review-notes-'))); roots.push(base);
  return reviewNotesFixture(base);
}

describe('human review annotations', () => {
  it('retains an idempotent history and never changes canonical artifacts', () => {
    const f = fixture(), before = readFileSync(join(f.root, '03_review_result.json'));
    const first = appendReviewNote(f.root, f.note, 'empty');
    expect(first.inserted).toBe(true);
    const saved = readFileSync(join(f.root, REVIEW_NOTES_FILE));
    expect(appendReviewNote(f.root, f.note, 'empty')).toMatchObject({ inserted: false, head: first.head });
    expect(readFileSync(join(f.root, REVIEW_NOTES_FILE))).toEqual(saved);
    const resolution: ReviewNoteInput = { id: 'R1', kind: 'resolution', disputeId: 'D1', author: 'fixture human reviewer', outcome: 'resolved',
      rationale: 'Human review confirmed that uncertainty remains explicit in the canonical record.', references: f.references() };
    const final = appendReviewNote(f.root, resolution, first.head);
    expect(summarizeReviewNotes(new ResultRecordReader(f.root))).toMatchObject({ head: final.head, entryCount: 2, openCount: 0 });
    expect(readFileSync(join(f.root, '03_review_result.json'))).toEqual(before);
  });
  it('rejects stale writes and same-ID different content without losing the original note', () => {
    const f = fixture(); appendReviewNote(f.root, f.note, 'empty');
    const before = readFileSync(join(f.root, REVIEW_NOTES_FILE));
    expect(() => appendReviewNote(f.root, { ...f.note, id: 'D2' }, 'empty')).toThrow('version conflict');
    expect(() => appendReviewNote(f.root, { ...f.note, rationale: 'A different rationale must remain a separate historical record.' }, 'empty')).toThrow('ID collision');
    expect(readFileSync(join(f.root, REVIEW_NOTES_FILE))).toEqual(before);
  });
  it('marks changed references stale and retains them when a fresh human resolution is added', () => {
    const f = fixture(), first = appendReviewNote(f.root, f.note, 'empty');
    writeFileSync(join(f.root, '03_review_result.json'), JSON.stringify({ reviewedFindings: [], revision: 1 }));
    expect(summarizeReviewNotes(new ResultRecordReader(f.root)).disputes[0]).toMatchObject({ status: 'stale' });
    appendReviewNote(f.root, { id: 'R1', kind: 'resolution', disputeId: 'D1', author: 'fixture reviewer', outcome: 'resolved',
      rationale: 'The human reviewer explicitly revisited the changed review artifact.', references: f.references() }, first.head);
    const summary = summarizeReviewNotes(new ResultRecordReader(f.root));
    expect(summary.disputes[0]).toMatchObject({ status: 'resolved', historicalStaleReferences: ['03_review_result.json'] });
    expect(summary.disputes[0]!.history).toHaveLength(2);
  });
  it('requires the current finding version and rejects forged or escaping references', () => {
    const f = fixture();
    expect(() => appendReviewNote(f.root, { ...f.note, references: f.note.references.slice(0, 1) }, 'empty')).toThrow('current finding version');
    expect(() => appendReviewNote(f.root, { ...f.note, references: [{ path: '../source/app.ts', sha256: 'a'.repeat(64) }] }, 'empty')).toThrow('relative artifact path');
    expect(() => appendReviewNote(f.root, { ...f.note, references: f.note.references.map(ref => ({ ...ref, sha256: 'a'.repeat(64) })) }, 'empty')).toThrow('version changed');
    expect(() => appendReviewNote(f.root, { ...f.note, findingIds: ['F-000000000000'] }, 'empty')).toThrow('Unknown');
  });
  it('rejects a resolution without a dispute and respects the existing run lock', () => {
    const f = fixture();
    expect(() => appendReviewNote(f.root, { id: 'R1', kind: 'resolution', disputeId: 'missing', author: 'reviewer', outcome: 'unresolved',
      rationale: 'Evidence remains insufficient for a supported resolution.', references: f.references() }, 'empty')).toThrow('preceding dispute');
    const release = acquireRunLock(join(f.base, '.run.agent.lock'));
    try { expect(() => appendReviewNote(f.root, f.note, 'empty')).toThrow(); } finally { release(); }
    expect(appendReviewNote(f.root, f.note, 'empty').inserted).toBe(true);
  });
  it('detects history tampering and copied notes from a different run context', () => {
    const f = fixture(); appendReviewNote(f.root, f.note, 'empty');
    const path = join(f.root, REVIEW_NOTES_FILE), original = readFileSync(path), value = JSON.parse(original.toString());
    value.entries[0].note.author = 'different author'; writeFileSync(path, JSON.stringify(value));
    expect(() => readReviewNotes(new ResultRecordReader(f.root))).toThrow('inconsistent');
    writeFileSync(path, original);
    writeFileSync(join(f.root, 'source_manifest.json'), '{"source_files":["other.ts"]}');
    expect(() => readReviewNotes(new ResultRecordReader(f.root))).toThrow('different run or source manifest');
  });
  it('detects a concurrent change even when the inspected file was initially absent', () => {
    const f = fixture(), reader = new ResultRecordReader(f.root);
    expect(reader.read('new.json', true)).toBeUndefined();
    writeFileSync(join(f.root, 'new.json'), '{}');
    expect(() => reader.assertUnchanged()).toThrow('changed during inspection');
  });
  it('does not hide a broken symlink as an absent optional artifact', () => {
    const f = fixture(); symlinkSync(join(f.base, 'missing.json'), join(f.root, 'optional.json'));
    expect(() => new ResultRecordReader(f.root).read('optional.json', true)).toThrow('symlink');
  });
});
