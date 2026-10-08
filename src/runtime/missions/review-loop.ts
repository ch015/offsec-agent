import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { reviewRequests, validateFollowupAnswers } from '../planning/review-coordinator.js';
import type { MissionRuntime } from '../workflow/mission-runtime.js';
import { atomicPrivateWrite, readManagedFile } from '../workflow/storage-files.js';
import type { ProviderRuntimeEvent } from '../providers/provider-runtime.js';
import type { PhaseExecution } from './assessment-types.js';
import { beginAnalysisRevision } from './analysis-revision.js';

const Progress = z.object({
  schemaVersion: z.literal(1), rounds: z.number().int().nonnegative(), seen: z.array(z.string().regex(/^[a-f0-9]{64}$/)),
  checkpointHash: z.string().optional(),
  deferred: z.array(z.object({ id: z.string(), reason: z.string() })),
  pending: z.object({ revision: z.number().int().nonnegative(), reviewAttempt: z.string(),
    findingHashes: z.array(z.object({ findingId: z.string(), sha256: z.string() })),
    fingerprints: z.array(z.string().regex(/^[a-f0-9]{64}$/)),
  }).optional(),
});

export function hasPendingReview(root: string): boolean {
  const path = join(root, '.recovery', 'review-coordination.json');
  return existsSync(path) && !!Progress.parse(JSON.parse(readManagedFile(root, path).toString())).pending;
}

/** Persist the next question before invalidating a review, so a crash cannot
 * repeat the full review or lose a completed scoped follow-up. */
export async function coordinateReview(input: {
  root: string; target: string; files: readonly string[]; flowIds: readonly string[]; runtime: MissionRuntime;
  initialInputs: Record<string, unknown>; analysisCoveragePath: string;
  findings(): Array<{ findingId: string; path: string; sha256: string }>;
  allowRead(paths: string[]): void; refreshReadSet(): void;
  log(event: Record<string, unknown>): void;
  execute(options: { id: string; round?: string; inputs?: Record<string, unknown>; priorArtifactPaths?: readonly string[] }): Promise<PhaseExecution>;
}) {
  const path = join(input.root, '.recovery', 'review-coordination.json');
  const checkpointHash = (await input.runtime.read()).analysisCheckpoint?.artifacts.find(artifact => artifact.name === '00_analysis_coverage.json')?.sha256;
  let state = Progress.parse(existsSync(path) ? JSON.parse(readManagedFile(input.root, path).toString()) : { schemaVersion: 1, rounds: 0, seen: [], deferred: [], checkpointHash });
  if (!state.pending && state.checkpointHash !== checkpointHash) state = Progress.parse({ schemaVersion: 1, rounds: 0, seen: [], deferred: [], checkpointHash });
  const save = () => atomicPrivateWrite(path, JSON.stringify(state) + '\n');
  const defer = (requests: Array<{ id: string; reason: string }>) => {
    for (const request of requests) if (!state.deferred.some(known => known.id === request.id && known.reason === request.reason)) state.deferred.push(request);
  };
  let review = state.pending ? undefined : await input.execute({ id: 'review', inputs: input.initialInputs });
  input.refreshReadSet();
  while (true) {
    const current = await input.runtime.read();
    const sourceDirectory = state.pending && (current.analysisRevision ?? 0) > state.pending.revision
      ? join(input.root, 'revisions', String(state.pending.revision)) : input.root;
    // A pending request is validated again against its original sealed review.
    const selected = reviewRequests(sourceDirectory, input.files, input.findings().map(f => f.findingId), input.flowIds,
      new Set(state.pending ? state.seen.filter(hash => !state.pending!.fingerprints.includes(hash)) : state.seen));
    defer(selected.deferred);
    if (!selected.selected.length) { save(); break; }
    if (!state.pending && state.rounds >= 3) {
      defer(selected.selected.map(request => ({ id: request.id, reason: 'Review revision limit reached; retained for further assessment' }))); save(); break;
    }
    if (!state.pending) {
      const prior = Object.entries(current.attempts).findLast(([, attempt]) => attempt.phase === 'review' && !attempt.superseded && attempt.status === 'completed');
      if (!prior) throw new Error('Completed review receipt missing');
      state.pending = { revision: current.analysisRevision ?? 0, reviewAttempt: prior[0],
        findingHashes: input.findings().map(({ findingId, sha256 }) => ({ findingId, sha256 })), fingerprints: selected.selected.map(request => request.fingerprint) };
      state.seen.push(...state.pending.fingerprints); save();
    }
    const pending = state.pending;
    if (JSON.stringify(pending.fingerprints) !== JSON.stringify(selected.selected.map(request => request.fingerprint))) throw new Error('Pending review questions differ from their sealed review');
    if ((current.analysisRevision ?? 0) === pending.revision) {
      await beginAnalysisRevision(input.runtime, input.root, 'Reviewer requested scoped evidence', [], true);
    } else if ((current.analysisRevision ?? 0) !== pending.revision + 1) throw new Error('Pending review revision is stale');
    const previousReview = join(input.root, 'revisions', String(pending.revision), '03_review_result.json');
    const original = (await input.runtime.read()).attempts[pending.reviewAttempt];
    if (!original) throw new Error('Previous review attempt is missing');
    const previousEvents = ((original.result as any)?.recoveryOutcome?.events ?? []) as ProviderRuntimeEvent[];
    input.allowRead([previousReview]);
    input.log({ event: 'ReviewEvidenceRequested', requests: selected.selected.map(({ id, files, question }) => ({ id, files, question })) });
    const followup = await input.execute({ id: 'analyze', round: `review-request-${pending.fingerprints[0]!.slice(0, 16)}`,
      inputs: { reviewRequests: selected.selected.map(({ fingerprint: _fingerprint, ...request }) => request),
        instruction: 'Investigate only these missing evidence questions. Write 02_followup_answers.json and include it in artifacts. Do not restart repository analysis. Existing findings remain unreviewed claims until Reviewer decides.' } });
    const answers = validateFollowupAnswers(input.root, input.target, selected.selected);
    defer(answers.answers.filter(answer => answer.status === 'deferred').map(({ id, reason }) => ({ id, reason })));
    input.refreshReadSet();
    const unchangedIds = pending.findingHashes.filter(prior => input.findings().some(now => now.findingId === prior.findingId && now.sha256 === prior.sha256)
      && !selected.selected.some(request => request.findingIds.includes(prior.findingId))).map(prior => prior.findingId);
    review = await input.execute({ id: 'review', inputs: { previousReview, followupAnswers: join(input.root, '02_followup_answers.json'),
      independentCounting: input.initialInputs.independentCounting,
      flowIds: input.flowIds, flowPlan: input.initialInputs.flowPlan,
      findingRecords: input.findings(), analysisCoverage: input.analysisCoveragePath, reviewReuse: { ids: unchangedIds, events: previousEvents },
      instruction: 'Revisit requested/changed findings and flows. Preserve previous dispositions for unchanged IDs; their verified original-source receipts are carried by the host. Return the complete review projection. Repeated questions without new evidence are deferred.' },
      priorArtifactPaths: followup.result.artifacts.map(name => join(input.root, name)) });
    state.rounds++; delete state.pending; save();
  }
  if (!review) throw new Error('Review coordination ended without a completed review');
  return { review, rounds: state.rounds, deferred: state.deferred };
}
