import { z } from 'zod';
import { StoredReferenceSchema, validateResultPath } from './result-records.js';
import { ManualReviewAssignmentSchema, ManualReviewBatchSchema, ReviewAuthor, ReviewNoteText, type ReviewNoteInput } from './review-note-schema.js';
import type { ReviewNoteHistory } from './review-notes.js';

export const ManualReviewPlanInputSchema = z.object({
  idPrefix: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/), author: ReviewAuthor,
  assignees: z.array(ReviewAuthor).min(1).max(100), maxFilesPerAssignment: z.number().int().min(1).max(50),
  files: z.array(StoredReferenceSchema).min(1).max(10000), instructions: ReviewNoteText, rationale: ReviewNoteText,
}).strict();

/** Pure draft generation over explicitly supplied file references. No discovery or dispatch. */
export function planManualReview(value: unknown) {
  const input = ManualReviewPlanInputSchema.parse(value);
  if (new Set(input.files.map(file => file.path)).size !== input.files.length) throw new Error('Duplicate files in manual review plan');
  if (new Set(input.assignees).size !== input.assignees.length) throw new Error('Duplicate assignee labels in manual review plan');
  for (const file of input.files) {
    validateResultPath(file.path);
    if (file.path.startsWith('review-notes/')) throw new Error('Manual review plan must not cite its own mutable history');
  }
  if (Math.ceil(input.files.length / input.maxFilesPerAssignment) > 500) throw new Error('Manual review plan exceeds 500 assignments; increase the file limit or explicitly divide the input');
  const files = [...input.files].sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  const assignments: z.input<typeof ManualReviewAssignmentSchema>[] = [];
  for (let offset = 0; offset < files.length; offset += input.maxFilesPerAssignment) {
    const index = assignments.length;
    assignments.push({ id: `${input.idPrefix}-${String(index + 1).padStart(4, '0')}`, kind: 'review-assignment',
      author: input.author, assignee: input.assignees[index % input.assignees.length]!,
      references: files.slice(offset, offset + input.maxFilesPerAssignment), instructions: input.instructions, rationale: input.rationale });
  }
  return ManualReviewBatchSchema.parse({ schemaVersion: 1, assignments });
}

type Entry = ReviewNoteHistory['entries'][number];
type Assignment = Extract<ReviewNoteInput, { kind: 'review-assignment' }>;
type Response = Extract<ReviewNoteInput, { kind: 'review-response' }>;
type AssignmentEntry = Entry & { note: Assignment };
type ResponseEntry = Entry & { note: Response };
type AssignmentProjection = { contract: AssignmentEntry; request: Entry; response?: ResponseEntry; latest: Entry;
  status: 'awaiting-response' | 'response-received' | 'changes-requested' | 'accepted' | 'cancelled'; history: Entry[] };
const reference = (entry: Entry) => ({ id: entry.note.id, sha256: entry.sha256 });
const matches = (ref: { id: string; sha256: string }, entry?: Entry) => !!entry && ref.id === entry.note.id && ref.sha256 === entry.sha256;

/** Fold human annotation events only; this projection never runs work or changes mission state. */
export function projectManualReviews(entries: readonly Entry[]): AssignmentProjection[] {
  const assignments = new Map<string, AssignmentProjection>();
  for (const entry of entries) {
    const note = entry.note;
    if (note.kind === 'review-assignment') {
      if (new Set(note.references.map(ref => ref.path)).size !== note.references.length) throw new Error('Duplicate files in manual review assignment');
      assignments.set(note.id, { contract: entry as AssignmentEntry, request: entry, latest: entry, status: 'awaiting-response', history: [entry] });
    } else if (note.kind === 'review-response' || note.kind === 'review-feedback') {
      const task = assignments.get(note.assignment.id);
      if (!task || !matches(note.assignment, task.contract)) throw new Error('Manual review assignment reference is missing or has a different version');
      if (task.status === 'cancelled') throw new Error('Cancelled manual review assignment cannot receive new replies or feedback');
      const cancelled = note.kind === 'review-feedback' && note.action === 'cancel';
      if (!cancelled) for (const file of task.contract.note.references) {
        if (!note.references.some(ref => ref.path === file.path && ref.sha256 === file.sha256)) throw new Error('Manual review reply must bind every assigned file version');
      }
      if (note.kind === 'review-response') {
        if (note.author !== task.contract.note.assignee) throw new Error('Manual review response author must match the assigned label');
        if (!['awaiting-response', 'changes-requested'].includes(task.status) || !matches(note.replyTo, task.request)) throw new Error('Manual review response must answer the latest unanswered request');
        const paths = new Set(task.contract.note.references.map(file => file.path));
        if (note.results.length !== paths.size || new Set(note.results.map(result => result.path)).size !== paths.size || note.results.some(result => !paths.has(result.path))) throw new Error('Manual review response must account for every assigned file exactly once');
        task.response = entry as ResponseEntry; task.status = 'response-received';
      } else {
        if (note.author !== task.contract.note.author) throw new Error('Manual review feedback author must match the assigning label');
        if (note.action === 'cancel') {
          if (note.response) throw new Error('Cancellation targets the assignment and must omit a response reference');
          task.status = 'cancelled';
        } else {
          if (!note.response || !matches(note.response, task.response) || !(task.status === 'response-received' || (task.status === 'accepted' && note.action === 'request-changes'))) throw new Error('Manual review feedback must target the latest response without skipping pending work');
          if (note.action === 'accept') {
            if (task.response!.note.results.some(result => result.status !== 'completed')) throw new Error('Manual review cannot accept unreviewed or needs-information files');
            if (task.response!.note.references.some(file => !note.references.some(ref => ref.path === file.path && ref.sha256 === file.sha256))) throw new Error('Manual review acceptance must bind all evidence in the latest response');
            task.status = 'accepted';
          } else { task.status = 'changes-requested'; task.request = entry; }
        }
      }
      task.latest = entry; task.history.push(entry);
    }
  }
  return [...assignments.values()];
}

export function summarizeManualReviews(entries: readonly Entry[], stale: ReadonlyMap<string, string[]>) {
  const assignments = projectManualReviews(entries).map(task => {
    const staleReferences = [...new Set([...(stale.get(task.contract.note.id) ?? []), ...(stale.get(task.request.note.id) ?? []),
      ...(task.response ? stale.get(task.response.note.id) ?? [] : []), ...(stale.get(task.latest.note.id) ?? [])])];
    const status = staleReferences.length && task.status !== 'cancelled' ? 'stale' : task.status;
    return { id: task.contract.note.id, author: task.contract.note.author, assignee: task.contract.note.assignee,
      instructions: task.contract.note.instructions, status, declaredStatus: task.status,
      contract: reference(task.contract), latestRequest: reference(task.request), latestResponse: task.response ? reference(task.response) : null,
      staleReferences, files: task.contract.note.references.map(file => {
        const result = task.response?.note.results.find(result => result.path === file.path);
        return { ...file, reportedStatus: result?.status ?? null, reason: result?.reason ?? null };
      }), history: task.history };
  });
  const counts = Object.fromEntries(['awaiting-response', 'response-received', 'changes-requested', 'accepted', 'cancelled', 'stale']
    .map(status => [status, assignments.filter(task => task.status === status).length]));
  return { assignmentCount: assignments.length, counts, assignments,
    openCount: assignments.filter(task => !['accepted', 'cancelled'].includes(task.status)).length,
    allAccepted: assignments.length ? assignments.every(task => task.status === 'accepted') : null,
    notice: 'Human-entered labels and acknowledgments, not authenticated identities or proof of source reading, coverage or finding validity.' };
}
