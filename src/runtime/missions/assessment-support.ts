import { existsSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { basename, resolve } from 'node:path';
import { createArtifactRef, verifyRunArtifactRef } from '../contracts/result-contract.js';
import { assertStandardFindingsRepresented } from '../finding-contract.js';
import type { MissionRuntime } from '../workflow/mission-runtime.js';
const reportGate = createRequire(import.meta.url)('../../../domains/offsec/hooks/report-gate-hook.js') as {
  runGate(options: { filePath: string; env: Record<string, string>; content: string }): { activated: boolean; noArtifacts?: boolean; result?: { ok: boolean; errors?: unknown[] } };
};

export async function recordOffsecPublication(input: {
  runtime: MissionRuntime;
  engagementDir: string;
  runId: string;
  contractId: string;
  finalArtifact: string;
  sourceManifestSha256: string;
}): Promise<string> {
  const finalReport = resolve(input.engagementDir, input.finalArtifact);
  const snapshot = await input.runtime.read();
  if (snapshot.publication) {
    verifyRunArtifactRef(snapshot.publication.artifact, input.engagementDir);
    if (snapshot.publication.sourceManifestSha256 !== input.sourceManifestSha256) {
      throw new Error('OffSec publication source manifest hash가 일치하지 않는다');
    }
    if (snapshot.status === 'running') {
      await input.runtime.append({ type: 'run.completed', eventId: `${input.runId}:completed` });
    }
    return snapshot.publication.artifact.path;
  }
  if (!existsSync(finalReport)) throw new Error(`계약된 최종 OffSec report가 없다: ${finalReport}`);
  const publicationArtifact = createArtifactRef({
    engagementDir: input.engagementDir,
    name: input.finalArtifact,
    phase: 'publication',
    role: 'host',
    attempt: '1',
  });
  verifyRunArtifactRef(publicationArtifact, input.engagementDir);
  const artifactReceipts = input.runtime.artifactStore
    ? [await input.runtime.artifactStore.put({
        uri: `artifact://runs/${createHash('sha256').update(input.runId).digest('hex').slice(0, 32)}/${publicationArtifact.sha256}`,
        content: readFileSync(finalReport),
        mediaType: publicationArtifact.mediaType,
        producer: 'publication/host/1',
      })]
    : [];
  await input.runtime.append({
    type: 'publication.completed',
    eventId: `${input.runId}:publication-completed`,
    artifact: publicationArtifact,
    sourceManifestSha256: input.sourceManifestSha256,
  }, {
    artifactReceipts,
    outbox: [{
      id: `${input.runId}:publication-completed`,
      idempotencyKey: `${input.runId}:publication-completed`,
      topic: 'run.publication.completed',
      payload: { runId: input.runId, artifactSha256: publicationArtifact.sha256 },
    }],
  });
  await input.runtime.append({ type: 'run.completed', eventId: `${input.runId}:completed` }, {
    outbox: [{
      id: `${input.runId}:run-completed`,
      idempotencyKey: `${input.runId}:run-completed`,
      topic: 'run.completed',
      payload: { runId: input.runId, contractId: input.contractId, finalReport },
    }],
  });
  return finalReport;
}

export function makeEngagementId(target: string, now: Date): string {
  const timestamp = now.toISOString().replace(/[-:.]/g, '');
  return `${basename(target)}_${timestamp}`;
}

export function resolveRunBudget(
  requested: number | undefined,
  contractMaximum: number | null,
): number | undefined {
  if (contractMaximum !== null && (!Number.isFinite(contractMaximum) || contractMaximum <= 0)) {
    throw new Error(`contract 예산 상한이 잘못됐다: ${contractMaximum}`);
  }
  if (requested === undefined) return contractMaximum ?? undefined;
  if (!Number.isFinite(requested) || requested <= 0) {
    throw new Error(`요청 예산은 유한한 양수여야 한다: ${requested}`);
  }
  return contractMaximum === null ? requested : Math.min(requested, contractMaximum);
}

export function validateSourcePublicationCandidate(input: {
  engagementDir: string;
  candidate: string;
  requirePocBinding: boolean;
  allowEmptyCandidates: boolean;
}): void {
  assertStandardFindingsRepresented(input.engagementDir, input.candidate);
  const outcome = reportGate.runGate({
    filePath: input.candidate,
    env: {
      AGENT_ENGAGEMENT_DIR: input.engagementDir,
      CH015_REPORT_GATE: process.env.CH015_REPORT_GATE ?? 'on',
      CH015_REQUIRE_POC_BINDING: input.requirePocBinding ? 'on' : 'off',
      CH015_ALLOW_EMPTY_CANDIDATES: input.allowEmptyCandidates ? 'on' : 'off',
    },
    content: readFileSync(input.candidate, 'utf8'),
  });
  if (!outcome.activated || outcome.noArtifacts || outcome.result?.ok !== true) {
    throw new Error(`호스트 report gate가 최종 보고서 발행을 거부했다: ${JSON.stringify(outcome)}`);
  }
}
