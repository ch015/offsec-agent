import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { reviewNotesFixture } from './review-notes.js';
import { ResultRecordReader } from '../../result-records.js';
import { planManualReview } from '../../manual-review.js';
import type { ReviewNoteHistory, ReviewNoteInput } from '../../review-notes.js';

export function manualReviewFixture(base: string, runId?: string) {
  const f = reviewNotesFixture(base, runId);
  mkdirSync(join(f.root, 'review-material'));
  const reader = new ResultRecordReader(f.root);
  const files = ['a', 'b', 'c'].map(name => {
    const path = `review-material/${name}.txt`;
    writeFileSync(join(f.root, path), `Fixture editorial section ${name}.\n`);
    return reader.reference(path);
  });
  const input = { idPrefix: 'DOC', author: 'coordinator', assignees: ['reader-a', 'reader-b'], maxFilesPerAssignment: 2, files,
    instructions: 'Check the supplied document sections for editorial consistency and report missing information.',
    rationale: 'Track human review of these explicitly selected document sections.' };
  return { ...f, input, batch: planManualReview(input) };
}

type Entry = ReviewNoteHistory['entries'][number];
export const entryRef = (entry: Entry) => ({ id: entry.note.id, sha256: entry.sha256 });
export function responseFor(contract: Entry, id = 'REPLY-1', request = contract): Extract<ReviewNoteInput, { kind: 'review-response' }> {
  if (contract.note.kind !== 'review-assignment') throw new Error('Expected assignment fixture');
  return { id, kind: 'review-response', author: contract.note.assignee, assignment: entryRef(contract), replyTo: entryRef(request),
    rationale: 'The assigned reader recorded the editorial review of every requested section.', references: contract.note.references,
    results: contract.note.references.map(ref => ({ path: ref.path, status: 'completed', reason: 'The human reader reports the section was checked for editorial consistency.' })) };
}
export function feedbackFor(contract: Entry, response: Entry, action: 'accept' | 'request-changes', id = 'FEEDBACK-1'): Extract<ReviewNoteInput, { kind: 'review-feedback' }> {
  return { id, kind: 'review-feedback', author: contract.note.author, assignment: entryRef(contract), response: entryRef(response), action,
    rationale: 'The coordinator explicitly reviewed the response against the assigned document sections.', references: contract.note.references };
}
