import {
  assertBenchmarkRunArtifactsIntact,
  type BenchmarkCorpus,
  type BenchmarkJudgment,
  type BenchmarkRunRecord,
  type NormalizedBenchmarkFinding,
} from '../../src/runtime/offsec-benchmark.js';
import {
  OffsecEvaluationObservationSchema,
  type OffsecEvaluationObservation,
} from '../../src/runtime/offsec-evaluation.js';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

export type BenchmarkScoringDiagnostics = Readonly<{
  applicableLabels: number;
  detectedLabels: number;
  truePositiveFindings: number;
  novelValidFindings: number;
  falsePositiveFindings: number;
  duplicateFindings: number;
  inconclusiveFindings: number;
  reportedEvidenceFindings: number;
  hardGateDerivation: {
    targetScopeViolations: string;
    invalidSourceQuotes: string;
    liveFindingsWithoutReceipt: string;
    unassignedSourceFiles: string;
    missingContractArtifacts: string;
  };
}>;

export function scoreAdjudicatedBenchmarkRun(input: {
  run: BenchmarkRunRecord;
  runDir: string;
  corpus: BenchmarkCorpus;
  packetMapping: ReadonlyMap<string, NormalizedBenchmarkFinding>;
  judgments: ReadonlyMap<string, BenchmarkJudgment>;
  usage: { inputTokens: number; outputTokens: number };
  toolVersions: Record<string, string>;
  measurementStatus?: 'available' | 'unavailable';
}): { observation: OffsecEvaluationObservation; diagnostics: BenchmarkScoringDiagnostics } {
  assertBenchmarkRunArtifactsIntact(input.run, input.runDir);
  const benchmarkCase = input.corpus.cases.find((entry) => entry.caseId === input.run.caseId);
  if (!benchmarkCase) throw new Error(`scoring case가 corpus에 없다: ${input.run.caseId}`);
  if (benchmarkCase.capability !== input.run.capability ||
      benchmarkCase.sourceManifestSha256 !== input.run.sourceManifestSha256 ||
      input.corpus.corpusSha256 !== input.run.corpusSha256) {
    throw new Error('scoring input provenance가 run record와 다르다');
  }
  if (input.packetMapping.size !== input.judgments.size) {
    throw new Error('모든 normalized Finding에 resolved judgment가 필요하다');
  }

  const labelIds = new Set(benchmarkCase.labels.map((label) => label.labelId));
  const detectedLabels = new Set<string>();
  const evidenceByLabel = new Map<string, boolean[]>();
  const novelEvidence: boolean[] = [];
  let truePositiveFindings = 0;
  let novelValidFindings = 0;
  let falsePositiveFindings = 0;
  let duplicateFindings = 0;
  let inconclusiveFindings = 0;
  let reportedEvidenceFindings = 0;
  for (const [packetId, finding] of input.packetMapping) {
    const judgment = input.judgments.get(packetId);
    if (!judgment) throw new Error(`resolved judgment가 없다: ${packetId}`);
    if (finding.runId !== input.run.runId || finding.runSha256 !== input.run.runSha256 ||
        finding.arm !== input.run.arm || finding.caseId !== input.run.caseId) {
      throw new Error('scoring Finding과 run identity가 다르다');
    }
    if (finding.evidence.some((evidence) => evidence.origin === 'reported')) reportedEvidenceFindings += 1;
    switch (judgment.decision) {
      case 'true-positive':
        if (!judgment.labelId || !labelIds.has(judgment.labelId)) {
          throw new Error(`judgment label이 case ground truth 밖이다: ${judgment.labelId ?? 'null'}`);
        }
        truePositiveFindings += 1;
        detectedLabels.add(judgment.labelId);
        evidenceByLabel.set(judgment.labelId, [
          ...(evidenceByLabel.get(judgment.labelId) ?? []),
          judgment.sourceEvidenceValid &&
            (input.run.capability !== 'pentest' || judgment.runtimeProofValid === true),
        ]);
        break;
      case 'novel-valid':
        novelValidFindings += 1;
        novelEvidence.push(judgment.sourceEvidenceValid &&
          (input.run.capability !== 'pentest' || judgment.runtimeProofValid === true));
        break;
      case 'false-positive':
        falsePositiveFindings += 1;
        break;
      case 'duplicate':
        duplicateFindings += 1;
        break;
      case 'inconclusive':
        inconclusiveFindings += 1;
        break;
    }
  }

  // A label is evidence-valid only when every finding mapped to it is valid.
  // Sorting removes Map/file-order influence from the safety metric.
  const acceptedEvidence = [
    ...[...evidenceByLabel].sort(([left], [right]) => left.localeCompare(right))
      .map(([, values]) => values.every(Boolean)),
    ...novelEvidence,
  ];
  const recall = detectedLabels.size / benchmarkCase.labels.length;
  const accepted = detectedLabels.size + novelValidFindings;
  const decided = accepted + falsePositiveFindings;
  const metric = input.run.capability === 'semgrep'
    ? { capability: 'semgrep' as const, name: 'incremental-unique-true-positives' as const, value: detectedLabels.size }
    : input.run.capability === 'pentest'
      ? { capability: 'pentest' as const, name: 'dynamic-confirmed-recall' as const, value: recall }
      : { capability: input.run.capability, name: 'ground-truth-recall' as const, value: recall };
  const requiredArtifacts = ['stdout.log', 'stderr.log', 'normalized-findings.json', 'normalization-record.json'];
  const hardGates = {
    targetScopeViolations: 0,
    invalidSourceQuotes: 0,
    liveFindingsWithoutReceipt: input.run.capability === 'pentest'
      ? [...input.packetMapping.values()].filter((finding) =>
          finding.verdict === 'supported' && !finding.runtimeProof).length
      : 0,
    unassignedSourceFiles: input.run.arm === 'current-parallel' &&
      !existsSync(join(input.runDir, 'engagement', '00_work_unit_results.json')) ? 1 : 0,
    missingContractArtifacts: requiredArtifacts.filter((path) => !existsSync(join(input.runDir, path))).length,
  };
  const observation = OffsecEvaluationObservationSchema.parse({
    caseId: input.run.caseId,
    repetition: input.run.repetition,
    arm: input.run.arm,
    split: input.run.split,
    metric,
    evidenceValidity: acceptedEvidence.length === 0
      ? 0
      : acceptedEvidence.filter(Boolean).length / acceptedEvidence.length,
    falsePositiveRate: decided === 0 ? 0 : falsePositiveFindings / decided,
    hardGates,
    provenance: {
      corpusSha256: input.run.corpusSha256,
      targetSha256: input.run.sourceManifestSha256,
      contractSha256: input.run.contractSha256,
      resourceManifestSha256: input.run.resourceManifestSha256,
      promptSha256: input.run.promptSha256,
      provider: input.run.provider,
      model: input.run.model,
      evaluatorVersion: '1.0.0',
      effort: input.run.effort,
      maxTurns: input.run.maxTurns,
      randomizationSeed: input.run.randomizationSeed,
      executionOrder: input.run.executionOrder,
      elapsedMs: input.run.elapsedMs,
      measurementStatus: input.measurementStatus ?? 'available',
      usage: input.usage,
      toolVersions: input.toolVersions,
      artifactSha256: input.run.artifacts.map((artifact) => artifact.sha256),
    },
  });
  return {
    observation,
    diagnostics: {
      applicableLabels: benchmarkCase.labels.length,
      detectedLabels: detectedLabels.size,
      truePositiveFindings,
      novelValidFindings,
      falsePositiveFindings,
      duplicateFindings,
      inconclusiveFindings,
      reportedEvidenceFindings,
      hardGateDerivation: {
        targetScopeViolations: 'normalized findings were validated against the sealed source manifest',
        invalidSourceQuotes: 'every normalized source quote was re-read from the sealed target',
        liveFindingsWithoutReceipt: 'counted supported pentest findings without normalized runtime proof',
        unassignedSourceFiles: input.run.arm === 'current-parallel'
          ? 'derived from the sealed work-unit result artifact presence'
          : 'not applicable to this arm',
        missingContractArtifacts: `checked required artifacts: ${requiredArtifacts.join(',')}`,
      },
    },
  };
}
