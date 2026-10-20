import { realpathSync } from 'node:fs';
import { ResultRecordReader, resultIdentity } from './result-records.js';
import { projectManualReviews } from './manual-review.js';
import { ReviewAuthor, ReviewNoteId, ReviewNoteInputSchema } from './review-note-schema.js';
import { readReviewNotes, summarizeReviewNotes, validateReviewNoteHistory, type ReviewNoteHistory } from './review-notes.js';

type Context = { reader: ResultRecordReader; notes: ReviewNoteHistory };
type Assignment = ReturnType<typeof summarizeReviewNotes>['manualReviews']['assignments'][number];
const pendingResponse = (task: Pick<Assignment, 'declaredStatus'>) => ['awaiting-response', 'changes-requested'].includes(task.declaredStatus);
const open = (task: Pick<Assignment, 'status'>) => !['accepted', 'cancelled'].includes(task.status);
const notice = 'Registered human review assignments only. Unregistered files and mission coverage are not assessed. Labels are not authenticated identities; reported completion is not proof of reading or finding validity.';

function context(directory: string, supplied?: Context) {
  const root = realpathSync(directory), reader = supplied?.reader ?? new ResultRecordReader(root);
  if (reader.root !== root) throw new Error('Manual review reader belongs to a different engagement');
  const identity = resultIdentity(reader);
  const notes = supplied ? validateReviewNoteHistory(identity, supplied.notes) : readReviewNotes(reader);
  return { reader, identity, notes };
}

function totals(assignments: readonly Assignment[]) {
  const files = assignments.flatMap(task => task.files);
  return {
    assignmentCount: assignments.length,
    counts: Object.fromEntries(['awaiting-response', 'response-received', 'changes-requested', 'accepted', 'cancelled', 'stale']
      .map(status => [status, assignments.filter(task => task.status === status).length])),
    openCount: assignments.filter(open).length,
    awaitingCurrentResponseCount: assignments.filter(pendingResponse).length,
    allAccepted: assignments.length ? assignments.every(task => task.status === 'accepted') : null,
    fileCount: new Set(files.map(file => file.path)).size,
    fileVersionCount: new Set(files.map(file => JSON.stringify([file.path, file.sha256]))).size,
    fileObligationCount: files.length,
  };
}

/** Read-only projection of the existing annotation ledger, not a new task queue. */
export function readManualReviewStatus(directory: string, assignee?: string, supplied?: Context) {
  const { reader, identity, notes } = context(directory, supplied);
  const selectedAssignee = assignee === undefined ? null : ReviewAuthor.parse(assignee);
  const summary = summarizeReviewNotes(reader, notes);
  const all = summary.manualReviews.assignments;
  const selected = selectedAssignee === null ? all : all.filter(task => task.assignee === selectedAssignee);
  const fileGroups = new Map<string, { path: string; sha256: string; assignments: Array<{
    id: string; assignee: string; status: Assignment['status']; declaredStatus: Assignment['declaredStatus'];
    awaitingCurrentResponse: boolean; reportedStatus: Assignment['files'][number]['reportedStatus']; reason: string | null;
  }> }>();
  for (const task of selected) for (const file of task.files) {
    const key = JSON.stringify([file.path, file.sha256]);
    const group = fileGroups.get(key) ?? { path: file.path, sha256: file.sha256, assignments: [] };
    group.assignments.push({ id: task.id, assignee: task.assignee, status: task.status, declaredStatus: task.declaredStatus,
      awaitingCurrentResponse: pendingResponse(task), reportedStatus: file.reportedStatus, reason: file.reason });
    fileGroups.set(key, group);
  }
  const result = {
    schemaVersion: 1 as const, identity, head: summary.head, inspectedAt: new Date().toISOString(),
    scope: { kind: 'registered-manual-assignments' as const, assignee: selectedAssignee },
    global: totals(all), selected: totals(selected),
    byAssignee: [...new Set(selected.map(task => task.assignee))].sort().map(label => ({
      assignee: label, ...totals(selected.filter(task => task.assignee === label)),
    })),
    byFile: [...fileGroups.values()].sort((a, b) => a.path.localeCompare(b.path) || a.sha256.localeCompare(b.sha256)).map(group => ({
      ...group, openCount: group.assignments.filter(open).length,
      allAccepted: group.assignments.every(task => task.status === 'accepted'),
    })),
    assignments: selected.map(({ history, ...task }) => ({ ...task, historyEntryCount: history.length, awaitingCurrentResponse: pendingResponse(task) })),
    references: reader.references(), notice,
  };
  reader.assertUnchanged();
  return result;
}

/** An editable packet. Exporting it does not append a note or claim completed work. */
export function createManualResponseTemplate(directory: string, assignmentId: string, noteId: string, supplied?: Context) {
  const { reader, identity, notes } = context(directory, supplied);
  ReviewNoteId.parse(assignmentId); ReviewNoteId.parse(noteId);
  if (notes.entries.some(entry => entry.note.id === noteId)) throw new Error('Response note ID already exists; choose a new note ID');
  const task = projectManualReviews(notes.entries).find(task => task.contract.note.id === assignmentId);
  if (!task) throw new Error('Unknown manual review assignment');
  if (!['awaiting-response', 'changes-requested'].includes(task.status)) throw new Error('Manual review has no unanswered request');
  // A changed prior response may be corrected. The contract and the current
  // request, however, must still refer to current evidence before exporting.
  for (const ref of [...task.contract.note.references, ...task.request.note.references]) reader.verify(ref);
  const note = ReviewNoteInputSchema.parse({
    id: noteId, kind: 'review-response', author: task.contract.note.assignee,
    assignment: { id: assignmentId, sha256: task.contract.sha256 },
    replyTo: { id: task.request.note.id, sha256: task.request.sha256 },
    rationale: 'Draft only: replace this text with the human reviewer’s account before recording a response.',
    references: task.contract.note.references.map(ref => ({ ...ref })),
    results: task.contract.note.references.map(ref => ({ path: ref.path, status: 'not-reviewed',
      reason: 'Not reviewed: this draft does not record a completed human review.' })),
  });
  const result = { schemaVersion: 1 as const, kind: 'manual-review-response-template' as const, identity,
    expectedHead: notes.entries.at(-1)?.sha256 ?? 'empty', generatedAt: new Date().toISOString(),
    instructions: task.contract.note.instructions, request: task.request, previousResponse: task.response ?? null, note,
    notice: 'Edit note and explicitly submit it with expectedHead. This packet is not a saved response. Previous replies are historical context; every new file result starts as not-reviewed.',
  };
  reader.assertUnchanged();
  return result;
}

// Encode untrusted text as literal Markdown, including table delimiters and HTML.
const md = (value: unknown) => String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/[\\`*_{}\[\]()#+.!|~-]/g, character => `&#${character.charCodeAt(0)};`).replace(/\r?\n/g, '<br>');

export function renderManualReviewStatus(view: ReturnType<typeof readManualReviewStatus>): string {
  const lines = ['# 수동 검토 현황', '', `Run: ${md(view.identity.runId)}`, `Head: ${md(view.head)}`, '',
    `범위: 등록된 계약 / 담당자 필터: ${md(view.scope.assignee ?? '전체')}`,
    `전체: ${view.global.assignmentCount}건, 미종결 ${view.global.openCount}건, 전체 수락 ${view.global.allAccepted ?? '확인 불가'}`,
    `선택: ${view.selected.assignmentCount}건, 미종결 ${view.selected.openCount}건, 현재 요청 미회신 ${view.selected.awaitingCurrentResponseCount}건`,
    `선택 파일: ${view.selected.fileCount}개 경로, ${view.selected.fileVersionCount}개 버전, ${view.selected.fileObligationCount}개 배정`, '',
    '미등록 파일 및 진단 coverage는 이 현황의 평가 범위가 아닙니다. 과거 회신의 completed는 현재 작업 수락과 다릅니다.', '',
    '## 담당자별', '', '| 담당자 | 계약 | 미종결 | 현재 요청 미회신 | 전체 수락 |', '| --- | ---: | ---: | ---: | --- |'];
  for (const row of view.byAssignee) lines.push(`| ${md(row.assignee)} | ${row.assignmentCount} | ${row.openCount} | ${row.awaitingCurrentResponseCount} | ${row.allAccepted} |`);
  lines.push('', '## 파일 버전별', '', '| 파일 | SHA-256 | 계약 / 담당자 | 현재 상태 | 마지막 회신 | 사유 |', '| --- | --- | --- | --- | --- | --- |');
  for (const file of view.byFile) for (const task of file.assignments) lines.push(`| ${md(file.path)} | ${file.sha256} | ${md(task.id)} / ${md(task.assignee)} | ${md(task.status)}${task.awaitingCurrentResponse ? ' (현재 요청 미회신)' : ''} | ${md(task.reportedStatus ?? '미회신')} | ${md(task.reason ?? '')} |`);
  lines.push('', '## 변경된 근거', '');
  for (const task of view.assignments) if (task.staleReferences.length) lines.push(`- ${md(task.id)}: ${task.staleReferences.map(md).join(', ')}`);
  lines.push('', md(view.notice), '');
  return lines.join('\n');
}
