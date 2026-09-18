import { readStandardFindings } from '../../../src/runtime/finding-contract.js';
import {
  NormalizedBenchmarkFindingSchema,
  type BenchmarkRunRecord,
  type NormalizedBenchmarkFinding,
} from '../../../src/runtime/offsec-benchmark.js';

export function normalizeCurrentOffsecFindings(input: {
  engagementDir: string;
  run: BenchmarkRunRecord;
}): NormalizedBenchmarkFinding[] {
  const phaseOrder = new Map([
    ['va', 1], ['verify', 2], ['va-feedback', 3], ['verify-feedback', 4],
    ['pentest', 5], ['pentest-verify', 6], ['pentest-feedback', 7], ['pentest-verify-feedback', 8],
    ['redteam', 9], ['redteam-verify', 10], ['report', 11],
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
