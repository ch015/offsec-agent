import { z } from 'zod';

const Sha256Schema = z.string().regex(/^[a-f0-9]{64}$/);

export const OffsecEvaluationArmSchema = z.enum([
  'ch015',
  'current-sequential',
  'current-parallel',
  'legacy-read-only',
  'adaptive-unverified',
  'adaptive-verified',
]);

export const OffsecCapabilitySchema = z.enum([
  'semgrep',
  'large-repository',
  'pentest',
  'redteam-iac',
]);

const PrimaryMetricSchema = z.discriminatedUnion('capability', [
  z.object({
    capability: z.literal('semgrep'),
    name: z.literal('incremental-unique-true-positives'),
    value: z.number().nonnegative(),
  }).strict(),
  z.object({
    capability: z.literal('large-repository'),
    name: z.literal('ground-truth-recall'),
    value: z.number().min(0).max(1),
  }).strict(),
  z.object({
    capability: z.literal('pentest'),
    name: z.literal('dynamic-confirmed-recall'),
    value: z.number().min(0).max(1),
  }).strict(),
  z.object({
    capability: z.literal('redteam-iac'),
    name: z.literal('ground-truth-recall'),
    value: z.number().min(0).max(1),
  }).strict(),
]);

const HardGatesSchema = z.object({
  targetScopeViolations: z.number().int().nonnegative(),
  invalidSourceQuotes: z.number().int().nonnegative(),
  liveFindingsWithoutReceipt: z.number().int().nonnegative(),
  unassignedSourceFiles: z.number().int().nonnegative(),
  missingContractArtifacts: z.number().int().nonnegative(),
}).strict();

export const LiveDastMetricsSchema = z.object({
  applicableCoverage: z.number().min(0).max(1),
  confirmedRecall: z.number().min(0).max(1),
  confirmedPrecision: z.number().min(0).max(1),
  unsafeRequestRejection: z.number().min(0).max(1),
  receiptCompleteness: z.number().min(0).max(1),
  reproducibility: z.number().min(0).max(1),
  inconclusiveRate: z.number().min(0).max(1),
}).strict();

export const OffsecEvaluationObservationSchema = z.object({
  caseId: z.string().regex(/^[a-z0-9][a-z0-9._-]*$/),
  repetition: z.number().int().positive(),
  arm: OffsecEvaluationArmSchema,
  split: z.enum(['validation', 'holdout']),
  metric: PrimaryMetricSchema,
  evidenceValidity: z.number().min(0).max(1),
  falsePositiveRate: z.number().min(0).max(1),
  liveDastMetrics: LiveDastMetricsSchema.optional(),
  hardGates: HardGatesSchema,
  provenance: z.object({
    corpusSha256: Sha256Schema,
    targetSha256: Sha256Schema,
    contractSha256: Sha256Schema,
    resourceManifestSha256: Sha256Schema,
    promptSha256: Sha256Schema,
    provider: z.string().min(1),
    model: z.string().min(1),
    evaluatorVersion: z.string().min(1),
    effort: z.string().min(1),
    maxTurns: z.number().int().positive(),
    randomizationSeed: z.number().int().nonnegative(),
    executionOrder: z.number().int().nonnegative(),
    elapsedMs: z.number().nonnegative(),
    measurementStatus: z.enum(['available', 'unavailable']).default('available'),
    usage: z.object({
      inputTokens: z.number().int().nonnegative(),
      outputTokens: z.number().int().nonnegative(),
    }).strict(),
    toolVersions: z.record(z.string(), z.string().min(1)),
    artifactSha256: z.array(Sha256Schema),
  }).strict(),
}).strict();

export const OffsecEvaluationPolicySchema = z.object({
  minimumEligibleCases: z.number().int().min(2),
  minimumPairedRepetitionsPerCase: z.number().int().positive(),
  bootstrapSamples: z.number().int().min(1_000).max(100_000),
  bootstrapSeed: z.number().int().nonnegative(),
  familyAlpha: z.number().gt(0).lt(0.5),
  declaredClaims: z.array(OffsecCapabilitySchema).min(1),
  margins: z.record(OffsecCapabilitySchema, z.object({
    evidenceValidity: z.number().min(0).max(1),
    falsePositiveRate: z.number().min(0).max(1),
  }).strict()),
}).strict();

export type OffsecEvaluationObservation = z.infer<typeof OffsecEvaluationObservationSchema>;
export type OffsecCapability = z.infer<typeof OffsecCapabilitySchema>;
export type OffsecEvaluationArm = z.infer<typeof OffsecEvaluationArmSchema>;
export type OffsecClaim = 'superior' | 'non-inferior' | 'inferior' | 'inconclusive';

export type ConfidenceInterval = Readonly<{
  mean: number;
  lower: number;
  upper: number;
}>;

export type OffsecComparison = Readonly<{
  capability: OffsecCapability;
  baseline: OffsecEvaluationArm;
  candidate: OffsecEvaluationArm;
  eligibleCases: number;
  pairedRepetitions: number;
  claim: OffsecClaim;
  reason: string;
  primaryDifference: ConfidenceInterval;
  evidenceValidityDifference: ConfidenceInterval;
  falsePositiveRateDifference: ConfidenceInterval;
}>;

type Policy = z.infer<typeof OffsecEvaluationPolicySchema>;
type CaseDifference = Readonly<{
  primary: number;
  evidence: number;
  falsePositive: number;
  repetitions: number;
}>;

export function compareOffsecArms(input: {
  observations: readonly unknown[];
  capability: OffsecCapability;
  baseline: OffsecEvaluationArm;
  candidate: OffsecEvaluationArm;
  policy: unknown;
  split?: 'validation' | 'holdout';
}): OffsecComparison {
  const policy = OffsecEvaluationPolicySchema.parse(input.policy);
  if (!policy.declaredClaims.includes(input.capability)) {
    throw new Error(`OffSec evaluation claim이 사전 등록되지 않았다: ${input.capability}`);
  }
  if (input.baseline === input.candidate) throw new Error('OffSec evaluation 비교 arm이 같다');

  const observations = input.observations
    .map((value) => OffsecEvaluationObservationSchema.parse(value))
    .filter((value) =>
      value.metric.capability === input.capability && value.split === (input.split ?? 'validation'));
  assertUniqueObservations(observations);
  assertProvenanceConsistency(observations);

  const paired = pairedObservationSet(
    observations, input.baseline, input.candidate, policy.minimumPairedRepetitionsPerCase,
  );
  const candidateGateFailure = paired.find((value) => value.arm === input.candidate && !hardGatesPass(value));
  const baselineGateFailure = paired.find((value) => value.arm === input.baseline && !hardGatesPass(value));
  const differences = pairedCaseDifferences(
    observations,
    input.baseline,
    input.candidate,
    policy.minimumPairedRepetitionsPerCase,
  );
  const intervals = intervalsFor(differences, policy, input.capability);

  if (baselineGateFailure) {
    return result(input, differences, intervals, 'inconclusive', `baseline hard gate 실패: ${baselineGateFailure.caseId}`);
  }
  if (candidateGateFailure) {
    return result(input, differences, intervals, 'inferior', `candidate hard gate 실패: ${candidateGateFailure.caseId}`);
  }
  if (differences.length < policy.minimumEligibleCases) {
    return result(
      input,
      differences,
      intervals,
      'inconclusive',
      `eligible case 부족: ${differences.length} < ${policy.minimumEligibleCases}`,
    );
  }

  const margin = policy.margins[input.capability];
  const evidenceNonInferior = intervals.evidence.lower >= -margin.evidenceValidity;
  const falsePositiveNonInferior = intervals.falsePositive.upper <= margin.falsePositiveRate;
  if (evidenceNonInferior && falsePositiveNonInferior && intervals.primary.lower > 0) {
    return result(input, differences, intervals, 'superior', 'primary CI와 non-inferiority gate 통과');
  }
  if (
    intervals.evidence.upper < -margin.evidenceValidity
    || intervals.falsePositive.lower > margin.falsePositiveRate
    || intervals.primary.upper < 0
  ) {
    return result(input, differences, intervals, 'inferior', '사전 등록된 성능 또는 안전성 gate 열화');
  }
  if (evidenceNonInferior && falsePositiveNonInferior) {
    return result(input, differences, intervals, 'non-inferior', '안전성 non-inferiority만 입증');
  }
  return result(input, differences, intervals, 'inconclusive', '신뢰구간이 방향성 판단을 지지하지 않음');
}

function pairedCaseDifferences(
  observations: readonly OffsecEvaluationObservation[],
  baseline: OffsecEvaluationArm,
  candidate: OffsecEvaluationArm,
  minimumRepetitions: number,
): CaseDifference[] {
  const caseIds = new Set(observations.map((value) => value.caseId));
  const differences: CaseDifference[] = [];
  for (const caseId of [...caseIds].sort()) {
    const baselineByRepetition = byRepetition(observations, caseId, baseline);
    const candidateByRepetition = byRepetition(observations, caseId, candidate);
    const repetitions = [...baselineByRepetition.keys()]
      .filter((value) => candidateByRepetition.has(value))
      .sort((left, right) => left - right);
    if (repetitions.length < minimumRepetitions) continue;
    differences.push({
      primary: average(repetitions.map((value) =>
        candidateByRepetition.get(value)!.metric.value - baselineByRepetition.get(value)!.metric.value)),
      evidence: average(repetitions.map((value) =>
        candidateByRepetition.get(value)!.evidenceValidity - baselineByRepetition.get(value)!.evidenceValidity)),
      falsePositive: average(repetitions.map((value) =>
        candidateByRepetition.get(value)!.falsePositiveRate - baselineByRepetition.get(value)!.falsePositiveRate)),
      repetitions: repetitions.length,
    });
  }
  return differences;
}

function pairedObservationSet(
  observations: readonly OffsecEvaluationObservation[],
  baseline: OffsecEvaluationArm,
  candidate: OffsecEvaluationArm,
  minimumRepetitions: number,
): OffsecEvaluationObservation[] {
  return [...new Set(observations.map((value) => value.caseId))].flatMap((caseId) => {
    const baselineByRepetition = byRepetition(observations, caseId, baseline);
    const candidateByRepetition = byRepetition(observations, caseId, candidate);
    const repetitions = [...baselineByRepetition.keys()].filter((value) => candidateByRepetition.has(value));
    if (repetitions.length < minimumRepetitions) return [];
    return repetitions.flatMap((repetition) => [
      baselineByRepetition.get(repetition)!, candidateByRepetition.get(repetition)!,
    ]);
  });
}

function intervalsFor(differences: readonly CaseDifference[], policy: Policy, capability: OffsecCapability) {
  // The evaluator emits at most three pairwise contrasts per declared capability.
  const correctedAlpha = policy.familyAlpha / (policy.declaredClaims.length * 3);
  const seedOffset = policy.declaredClaims.indexOf(capability) + 1;
  return {
    primary: clusteredBootstrap(differences.map((value) => value.primary), policy, correctedAlpha, seedOffset),
    evidence: clusteredBootstrap(differences.map((value) => value.evidence), policy, correctedAlpha, seedOffset + 17),
    falsePositive: clusteredBootstrap(
      differences.map((value) => value.falsePositive), policy, correctedAlpha, seedOffset + 31,
    ),
  };
}

function clusteredBootstrap(
  values: readonly number[],
  policy: Policy,
  alpha: number,
  seedOffset: number,
): ConfidenceInterval {
  if (values.length === 0) return { mean: 0, lower: 0, upper: 0 };
  const random = xorshift32((policy.bootstrapSeed + seedOffset) >>> 0);
  const samples: number[] = [];
  for (let index = 0; index < policy.bootstrapSamples; index += 1) {
    const selected: number[] = [];
    for (let draw = 0; draw < values.length; draw += 1) {
      selected.push(values[Math.floor(random() * values.length)]!);
    }
    samples.push(average(selected));
  }
  samples.sort((left, right) => left - right);
  return {
    mean: average(values),
    lower: percentile(samples, alpha / 2),
    upper: percentile(samples, 1 - alpha / 2),
  };
}

function result(
  input: { capability: OffsecCapability; baseline: OffsecEvaluationArm; candidate: OffsecEvaluationArm },
  differences: readonly CaseDifference[],
  intervals: ReturnType<typeof intervalsFor>,
  claim: OffsecClaim,
  reason: string,
): OffsecComparison {
  return {
    capability: input.capability,
    baseline: input.baseline,
    candidate: input.candidate,
    eligibleCases: differences.length,
    pairedRepetitions: differences.reduce((sum, value) => sum + value.repetitions, 0),
    claim,
    reason,
    primaryDifference: intervals.primary,
    evidenceValidityDifference: intervals.evidence,
    falsePositiveRateDifference: intervals.falsePositive,
  };
}

function byRepetition(
  observations: readonly OffsecEvaluationObservation[],
  caseId: string,
  arm: OffsecEvaluationArm,
): Map<number, OffsecEvaluationObservation> {
  return new Map(observations
    .filter((value) => value.caseId === caseId && value.arm === arm)
    .map((value) => [value.repetition, value]));
}

function assertUniqueObservations(observations: readonly OffsecEvaluationObservation[]): void {
  const identities = new Set<string>();
  for (const value of observations) {
    const identity = `${value.caseId}:${value.repetition}:${value.arm}:${value.metric.capability}`;
    if (!identities.add(identity)) throw new Error(`OffSec evaluation observation이 중복됐다: ${identity}`);
  }
}

function assertProvenanceConsistency(observations: readonly OffsecEvaluationObservation[]): void {
  const byCase = new Map<string, OffsecEvaluationObservation[]>();
  const byCaseRepetition = new Map<string, OffsecEvaluationObservation[]>();
  for (const value of observations) {
    byCase.set(value.caseId, [...(byCase.get(value.caseId) ?? []), value]);
    const key = `${value.caseId}:${value.repetition}`;
    byCaseRepetition.set(key, [...(byCaseRepetition.get(key) ?? []), value]);
  }
  for (const [caseId, values] of byCase) {
    const corpus = new Set(values.map((value) => value.provenance.corpusSha256));
    const target = new Set(values.map((value) => value.provenance.targetSha256));
    if (corpus.size !== 1 || target.size !== 1) {
      throw new Error(`OffSec evaluation case provenance가 반복 사이에 다르다: ${caseId}`);
    }
  }
  for (const [key, values] of byCaseRepetition) {
    const comparable = values.map((value) => value.provenance);
    const fields = [
      'corpusSha256', 'targetSha256', 'promptSha256', 'provider', 'model',
      'evaluatorVersion', 'effort', 'maxTurns', 'randomizationSeed', 'measurementStatus',
    ] as const;
    const mismatched: string[] = fields.filter((field) =>
      new Set(comparable.map((value) => value[field])).size !== 1);
    if (mismatched.length > 0) {
      throw new Error(`OffSec evaluation paired provenance가 다르다: ${key} (${mismatched.join(', ')})`);
    }
  }
}

function hardGatesPass(value: OffsecEvaluationObservation): boolean {
  return Object.values(value.hardGates).every((count) => count === 0);
}

function average(values: readonly number[]): number {
  return values.length === 0 ? 0 : values.reduce((sum, value) => sum + value, 0) / values.length;
}

function percentile(values: readonly number[], point: number): number {
  return values[Math.min(values.length - 1, Math.max(0, Math.floor(point * values.length)))]!;
}

function xorshift32(seed: number): () => number {
  let state = seed === 0 ? 0x9e3779b9 : seed;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 0x1_0000_0000;
  };
}
