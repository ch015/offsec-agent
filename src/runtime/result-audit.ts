import { realpathSync } from 'node:fs';
import { join, relative } from 'node:path';
import { z } from 'zod';
import { verifyRunArtifactRef, type ArtifactRef } from './contracts/result-contract.js';
import { assertEvaluationProjection } from './evaluation-projection.js';
import { readStandardFindingRecordReceipts } from './finding-contract.js';
import { canonicalV2Findings, resolveV2Review } from './v2-review-resolution.js';
import { ReviewRequestSchema, FollowupAnswersSchema } from './planning/review-coordinator.js';
import { ResultRecordReader, readResultState, resultIdentity } from './result-records.js';
import { summarizeReviewNotes, type ReviewNoteHistory } from './review-notes.js';
import { loadSourceSnapshot } from './source-snapshot.js';

const Coverage = z.object({ complete: z.boolean(), uncoveredFiles: z.array(z.string()),
  securityControlCoverage: z.object({ counts: z.record(z.string(), z.number().int().nonnegative()) }).passthrough().optional(),
}).passthrough();
const Requests = z.object({ additionalEvidenceRequests: z.array(ReviewRequestSchema).default([]) }).passthrough();

/** Read-only accounting over existing results; never launches review or changes decisions. */
export function auditResultRecords(directory: string, context?: { reader: ResultRecordReader; notes: ReviewNoteHistory }) {
  const root = realpathSync(directory), reader = context?.reader ?? new ResultRecordReader(root);
  if (reader.root !== root) throw new Error('Audit reader belongs to a different engagement');
  const state = readResultState(reader), identity = resultIdentity(reader);
  const issues: Array<{ code: string; detail: string }> = [];
  const issue = (code: string, error: unknown) => issues.push({ code, detail: error instanceof Error ? error.message : String(error) });
  let snapshotVerified = false;
  try {
    reader.read('00_source_snapshot.json');
    const { snapshot } = loadSourceSnapshot(root);
    for (const file of snapshot.files) reader.verify({ path: `source-snapshot/${file.path}`, sha256: file.sha256 });
    snapshotVerified = true;
  } catch (error) { issue('source-snapshot-integrity', error); }
  const refs = [...Object.values(state.attempts).filter(attempt => attempt.status === 'completed' && !attempt.superseded).flatMap(attempt => attempt.artifacts ?? []),
    ...(state.revisions ?? []).flatMap(revision => revision.artifacts), ...(state.analysisCheckpoint?.artifacts ?? []),
    ...(state.completionCoverage ? [state.completionCoverage] : []), ...(state.publication ? [state.publication.artifact] : [])];
  const byPath = new Map(refs.map(ref => [relative(root, ref.path), ref]));
  function verify(path: string, explicit?: ArtifactRef) {
    const ref = explicit ?? byPath.get(path);
    if (!ref) { issue('unsealed-artifact', path); return false; }
    try {
      reader.verify({ path, sha256: ref.sha256 });
      verifyRunArtifactRef(ref, root);
      return true;
    } catch (error) { issue('artifact-integrity', error); return false; }
  }
  const originalRaw = reader.json('00_analysis_coverage.json', true), finalRaw = reader.json('00_completion_coverage.json', true);
  const original = originalRaw === undefined ? null : Coverage.parse(originalRaw);
  const completion = finalRaw === undefined ? null : Coverage.parse(finalRaw);
  if (original) verify('00_analysis_coverage.json'); else issue('analysis-coverage-unavailable', 'No original coverage artifact');
  if (completion) verify('00_completion_coverage.json', state.completionCoverage); else issue('completion-coverage-unavailable', 'No finalized coverage artifact');
  const beforeFiles = [...new Set(original?.uncoveredFiles ?? [])].sort(), afterFiles = [...new Set(completion?.uncoveredFiles ?? [])].sort();
  // A resolved answer addresses its exact question; it never removes a file or
  // decrements an unresolved control count by inference.
  const rounds: Array<{ revision: number; requestPath: string; answerPath: string; requests: Array<{
    id: string; question: string; findingIds: string[]; files: string[]; answerStatus: 'resolved' | 'deferred' | 'unanswered' | 'unverified'; reason: string;
  }> }> = [];
  const revision = state.analysisRevision ?? 0;
  const at = (index: number, name: string) => index === revision ? name : `revisions/${index}/${name}`;
  for (let index = 0; index <= revision; index++) {
    const requestPath = at(index, '03_review_result.json'), raw = reader.json(requestPath, true);
    if (raw === undefined) continue;
    const requests = Requests.parse(raw).additionalEvidenceRequests;
    if (!requests.length) continue;
    const requestVerified = verify(requestPath);
    const answerPath = index < revision ? at(index + 1, '02_followup_answers.json') : '02_followup_answers.json';
    // The current review's requests have no subsequent completed revision.
    const answersRaw = index < revision ? reader.json(answerPath, true) : undefined;
    const answers = answersRaw === undefined ? [] : FollowupAnswersSchema.parse(answersRaw).answers;
    const answersVerified = answersRaw !== undefined && verify(answerPath);
    if (new Set(requests.map(request => request.id)).size !== requests.length || new Set(answers.map(answer => answer.id)).size !== answers.length
      || answers.some(answer => !requests.some(request => request.id === answer.id))) issue('followup-identities', `Duplicate or unexpected question/answer in revision ${index}`);
    rounds.push({ revision: index, requestPath, answerPath, requests: requests.map(request => {
      const answer = answers.find(row => row.id === request.id);
      let sourceValid = snapshotVerified;
      if (answer) for (const ref of answer.evidence) {
        try {
          if (!request.files.includes(ref.path) || ref.lineEnd < ref.lineStart) throw new Error('Evidence outside the requested scope');
          const lines = reader.read(`source-snapshot/${ref.path}`)!.toString('utf8').split(/\r?\n/);
          if (ref.lineEnd > lines.length || !lines.slice(ref.lineStart - 1, ref.lineEnd).join('\n').includes(ref.quote)) throw new Error('Follow-up quotation differs from snapshot');
        } catch (error) { sourceValid = false; issue('followup-evidence', error); }
      }
      if (answer?.status === 'resolved' && !answer.evidence.length) { sourceValid = false; issue('followup-evidence', `Resolved answer has no evidence: ${request.id}`); }
      return { id: request.id, question: request.question, findingIds: request.findingIds, files: request.files,
        answerStatus: !answer ? 'unanswered' : !requestVerified || !answersVerified || !sourceValid ? 'unverified' : answer.status,
        reason: answer?.reason ?? 'No answer in the subsequent revision' };
    }) });
  }
  const records = readStandardFindingRecordReceipts(root);
  for (const record of records) reader.read(`standard-findings/${record.recordName}`);
  reader.read('standard-findings.jsonl', true);
  const canonical = canonicalV2Findings(root);
  let dispositions: null | Record<string, number> = null, independentCauses: number | null = null;
  const reviewRaw = reader.json('03_review_result.json', true);
  if (reviewRaw !== undefined) {
    verify('03_review_result.json');
    try {
      const review = resolveV2Review(root, reviewRaw);
      dispositions = Object.fromEntries(['CONFIRMED', 'FOLDED_INTO', 'FALSE_POSITIVE', 'BACKLOG'].map(status => [status, review.dispositions.filter(row => row.finalStatus === status).length]));
      independentCauses = review.vulnerabilityInventory.independentVulnerabilityCount;
      const classification = reader.json('04_evaluation_classification.yaml', true);
      if (classification !== undefined) {
        reader.read('03_evaluation_input.json', true); reader.read('.recovery/evaluation-projection.json', true);
        assertEvaluationProjection(root);
        const parsed = z.object({ candidates: z.array(z.object({ id: z.string(), final_status: z.string() }).passthrough()) }).passthrough().parse(classification);
        const expected = new Map(review.dispositions.map(row => [row.id, row.finalStatus]));
        if (parsed.candidates.length !== expected.size || new Set(parsed.candidates.map(row => row.id)).size !== expected.size
          || parsed.candidates.some(row => expected.get(row.id) !== row.final_status)) issue('classification-disagrees', 'Classification IDs/statuses differ from canonical reviewed decisions');
      } else issue('classification-unavailable', 'No classification artifact');
    } catch (error) { issue('review-projection', error); }
  } else issue('review-unavailable', 'No completed review artifact');
  let publicationVerified = false;
  if (state.publication) {
    const path = relative(root, state.publication.artifact.path);
    publicationVerified = verify(path, state.publication.artifact);
    // publication.sourceManifestSha256 is the manifest's logical inventory
    // hash, not the SHA-256 of the serialized JSON file.
    const manifest = z.object({ hash: z.string() }).passthrough().parse(reader.json('source_manifest.json'));
    const sealedManifest = state.inputManifest?.fileHashes.find(file => relative(root, file.path) === 'source_manifest.json');
    if (state.publication.sourceManifestSha256 !== manifest.hash || !sealedManifest || sealedManifest.sha256 !== identity.sourceManifestFileSha256) {
      publicationVerified = false; issue('publication-source-changed', 'Published source manifest differs from the sealed inventory or has no file receipt');
    }
    if (publicationVerified) {
      const report = reader.read(path)!.toString('utf8');
      const missing = [...canonical.keys()].filter(id => !report.includes(id));
      if (missing.length) { publicationVerified = false; issue('report-ids-missing', missing.join(', ')); }
    }
  } else issue('publication-unavailable', 'No publication receipt');
  const notes = summarizeReviewNotes(reader, context?.notes);
  if (notes.openCount) issue('manual-disputes-open', `${notes.openCount} open, unresolved or stale human review disputes`);
  if (notes.manualReviews.openCount) issue('manual-reviews-open', `${notes.manualReviews.openCount} human review assignments awaiting response, acceptance or fresh evidence`);
  if (notes.mediation.openCount) issue('manual-mediation-open', `${notes.mediation.openCount} opinion groups awaiting human mediation or current evidence`);
  if (JSON.stringify(records) !== JSON.stringify(readStandardFindingRecordReceipts(root))) throw new Error('Finding records changed during inspection; retry');
  reader.assertUnchanged();
  return { schemaVersion: 1, identity, inspectedAt: new Date().toISOString(), runState: state.status, analysisRevision: revision,
    coverage: { originalComplete: original?.complete ?? null, finalRecordedComplete: completion?.complete ?? null,
      beforeUncoveredFiles: original ? beforeFiles : null, afterUncoveredFiles: completion ? afterFiles : null,
      removedFromRecordedList: original && completion ? beforeFiles.filter(path => !afterFiles.includes(path)) : null,
      addedToRecordedList: original && completion ? afterFiles.filter(path => !beforeFiles.includes(path)) : null,
      originalUnresolvedChecks: original?.securityControlCoverage?.counts.unresolved ?? null,
      finalRecordedUnresolvedChecks: completion?.securityControlCoverage?.counts.unresolved ?? null,
      notice: 'Recorded state comparison only. A resolved follow-up answer does not prove full-file coverage or resolve other security checks.' },
    followups: rounds, findings: { canonicalRecords: canonical.size, dispositions, independentCauses },
    publicationVerified, notes, issues, references: reader.references(),
    limitation: 'Artifact consistency and human annotations only; not independent vulnerability verification or a completeness/accuracy guarantee.' };
}

export function renderResultAudit(audit: ReturnType<typeof auditResultRecords>): string {
  const safe = (value: unknown) => String(value).replace(/[&<>]/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[character]!)
    .replace(/([\\`*_{}\[\]()#+.!|~\-])/g, '\\$1').replace(/\r?\n/g, ' ');
  const rows = ['# 결과 기록 감사', '', `Run: ${safe(audit.identity.runId)}`, '',
    `기록된 최종 범위 완료: ${audit.coverage.finalRecordedComplete ?? '미기록'}`, `발행 바이트 검증: ${audit.publicationVerified}`,
    `Finding 기록: ${audit.findings.canonicalRecords}; 독립 원인: ${audit.findings.independentCauses ?? '미확정'}`,
    `열린 수동 이견: ${audit.notes.openCount}`, '', safe(audit.coverage.notice), '', '## 상태 대조', '',
    `미확인 파일: ${audit.coverage.beforeUncoveredFiles?.length ?? '미기록'} → ${audit.coverage.afterUncoveredFiles?.length ?? '미기록'}`,
    `미확인 검사: ${audit.coverage.originalUnresolvedChecks ?? '미기록'} → ${audit.coverage.finalRecordedUnresolvedChecks ?? '미기록'}`, '',
    '## 보완 답변 이력', '',
    ...audit.followups.flatMap(round => round.requests.map(request => `- revision ${round.revision} / ${safe(request.id)}: ${request.answerStatus} — ${safe(request.reason)}`)), '',
    '## 수동 이견', '', ...audit.notes.disputes.map(dispute => `- ${safe(dispute.id)}: ${dispute.status}; ${dispute.findingIds.map(safe).join(', ')}`), '',
    '## 의견 중재', '', safe(audit.notes.mediation.notice), '',
    ...audit.notes.mediation.groups.map(group => `- ${safe(group.subject.artifact.path)} / ${safe(group.subject.topic)}: ${group.status}; 상충 표기 ${group.conflictingPositions}; 의견 ${group.opinions.length}개`), '',
    '## 수동 검토 작업', '', safe(audit.notes.manualReviews.notice), '',
    `등록 ${audit.notes.manualReviews.assignmentCount}; 미종결 ${audit.notes.manualReviews.openCount}; 모든 작업의 명시적 수락: ${audit.notes.manualReviews.allAccepted ?? '미등록'}`, '',
    ...audit.notes.manualReviews.assignments.flatMap(task => [
      `- ${safe(task.id)} / ${safe(task.assignee)}: ${task.status}; 파일 ${task.files.length}; 회신 ${safe(task.latestResponse?.id ?? '미수신')}`,
      ...task.files.map(file => `  - ${safe(file.path)}: ${file.reportedStatus ?? '미회신'}${file.reason ? ` — ${safe(file.reason)}` : ''}`),
    ]), '',
    '## 검사 결과', '', ...audit.issues.map(issue => `- ${safe(issue.code)}: ${safe(issue.detail)}`), '', safe(audit.limitation), ''];
  return rows.join('\n');
}
