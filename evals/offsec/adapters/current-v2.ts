import { readStandardFindings } from '../../../src/runtime/finding-contract.js';
import {
  NormalizedBenchmarkFindingSchema,
  type BenchmarkRunRecord,
  type NormalizedBenchmarkFinding,
} from '../../../src/runtime/offsec-benchmark.js';

/**
 * OffSec v2 산출물 정규화 어댑터.
 *
 * v1(current.ts)과 달리 v2 계약(offsec-contract.v2.json)은 선형 6-phase 파이프라인이며
 * pentest/redteam/feedback/verifier/objection 시스템이 없다. 따라서 phase 순위는
 * recon -> plan -> analyze -> review -> evaluate -> report 만 인식한다.
 *
 * standard-findings 원장(readStandardFindings)은 v1과 공유하되, 동일 finding id에 대해
 * 가장 나중(높은 순위) phase의 레코드를 lineage 대표로 채택하는 로직만 v2 phase에 맞춘다.
 */
export function normalizeCurrentV2OffsecFindings(input: {
  engagementDir: string;
  run: BenchmarkRunRecord;
}): NormalizedBenchmarkFinding[] {
  const phaseOrder = new Map([
    ['recon', 1], ['plan', 2], ['analyze', 3], ['review', 4], ['evaluate', 5], ['report', 6],
  ]);
  const latest = new Map<string, ReturnType<typeof readStandardFindings>[number]>();
  for (const finding of readStandardFindings(input.engagementDir)) {
    const lineageKey = finding.id;
    const prior = latest.get(lineageKey);
    const rank = (value: typeof finding): number =>
      (phaseOrder.get(value.phase) ?? 0) * 1_000 + roundNumber(value.round);
    if (!prior || rank(finding) >= rank(prior)) latest.set(lineageKey, finding);
  }
  return [...latest.values()].sort((left, right) => left.id.localeCompare(right.id)).map((finding) =>
    NormalizedBenchmarkFindingSchema.parse({
      schemaVersion: '1.0.0',
      runId: input.run.runId,
      runSha256: input.run.runSha256,
      caseId: input.run.caseId,
      arm: input.run.arm,
      findingId: finding.id,
      title: finding.title,
      verdict: finding.verdict,
      severity: finding.severity,
      cwes: finding.standards.filter((value) => /^CWE-\d+$/.test(value)),
      evidence: finding.evidence.map((evidence) => ({ ...evidence, origin: 'reported' as const })),
      ...(finding.runtimeEvidence ? {
        runtimeProof: {
          scenarioId: finding.runtimeEvidence.scenarioId,
          receiptIds: [
            finding.runtimeEvidence.receiptId,
            ...(finding.runtimeEvidence.relatedReceiptIds ?? []),
          ],
        },
      } : {}),
    }));
}

function roundNumber(round: string | null): number {
  if (!round) return 0;
  const numeric = Number.parseInt(round, 10);
  if (Number.isFinite(numeric)) return numeric;
  return ({ '1st': 1, '2nd': 2, '3rd': 3 } as Record<string, number>)[round] ?? 0;
}
