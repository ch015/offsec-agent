import { readStandardFindings } from '../../../src/runtime/finding-contract.js';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalV2Findings, resolveV2Review } from '../../../src/runtime/v2-review-resolution.js';
import { assertEvaluationProjection } from '../../../src/runtime/evaluation-projection.js';
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
 * countingSchemaVersion 1 결과는 봉인된 최종 검토의 독립 원인당 한 예측으로 정규화한다.
 * 원인 분류가 없는 과거 자료는 기존 ID/phase 기준을 유지한다. 두 집계 기준을 같은
 * 독립 취약점 성능으로 해석해서는 안 된다.
 */
export function normalizeCurrentV2OffsecFindings(input: {
  engagementDir: string;
  run: BenchmarkRunRecord;
}): NormalizedBenchmarkFinding[] {
  const reviewPath = join(input.engagementDir, '03_review_result.json');
  if (existsSync(reviewPath) && JSON.parse(readFileSync(reviewPath, 'utf8')).countingSchemaVersion === 1) {
    // New runs expose one packet per reviewed cause. An observation or a
    // superseded assertion is not another positive prediction. Independent
    // adjudicators still decide whether the claimed cause is actually valid.
    assertEvaluationProjection(input.engagementDir);
    const resolved = resolveV2Review(input.engagementDir), canonical = canonicalV2Findings(input.engagementDir);
    return resolved.vulnerabilityInventory.causes.map(cause => {
      const members = [...cause.findingIds,...cause.corroboratingFindingIds].map(id => canonical.get(id)!);
      return NormalizedBenchmarkFindingSchema.parse({schemaVersion:'1.0.0',runId:input.run.runId,runSha256:input.run.runSha256,
        caseId:input.run.caseId,arm:input.run.arm,findingId:cause.causeId,title:cause.rootCause.slice(0,512),
        verdict:'supported',severity:cause.severity,cwes:[...new Set(members.flatMap(f=>f.standards).filter(s=>/^CWE-\d+$/.test(s)))],
        evidence:cause.evidence.map(ref=>({...ref,origin:'reported'})),
      });
    });
  }
  // Historical normalization remains readable; it is record-based, not a
  // retrospectively invented count of independent security defects.
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
