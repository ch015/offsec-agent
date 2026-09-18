import { z } from 'zod';

import {
  compareOffsecArms,
  LiveDastMetricsSchema,
  OffsecEvaluationObservationSchema,
  type OffsecComparison,
} from './offsec-evaluation.js';

export const LIVE_DAST_ARMS = ['legacy-read-only', 'adaptive-unverified', 'adaptive-verified'] as const;
export const LIVE_DAST_METRICS = [
  'applicableCoverage',
  'confirmedRecall',
  'confirmedPrecision',
  'unsafeRequestRejection',
  'receiptCompleteness',
  'reproducibility',
  'inconclusiveRate',
] as const;

export type LiveDastEvaluationResult = Readonly<{
  status: 'not_run' | 'evaluated';
  claim: 'inconclusive';
  reason: string;
  observationCount: number;
  arms: typeof LIVE_DAST_ARMS;
  metrics: typeof LIVE_DAST_METRICS;
  averages: Partial<Record<(typeof LIVE_DAST_ARMS)[number], z.infer<typeof LiveDastMetricsSchema>>>;
  comparisons: OffsecComparison[];
}>;

export function evaluateLiveDastObservations(input: {
  observations: readonly unknown[];
  policy: unknown;
  split?: 'validation' | 'holdout';
}): LiveDastEvaluationResult {
  const split = input.split ?? 'validation';
  const observations = input.observations
    .map((value) => OffsecEvaluationObservationSchema.parse(value))
    .filter((value) =>
      value.split === split &&
      value.metric.capability === 'pentest' &&
      LIVE_DAST_ARMS.includes(value.arm as (typeof LIVE_DAST_ARMS)[number]) &&
      value.liveDastMetrics !== undefined);
  if (observations.length === 0) {
    return {
      status: 'not_run',
      claim: 'inconclusive',
      reason: '검증된 Live DAST observation이 없다',
      observationCount: 0,
      arms: LIVE_DAST_ARMS,
      metrics: LIVE_DAST_METRICS,
      averages: {},
      comparisons: [],
    };
  }
  const averages: LiveDastEvaluationResult['averages'] = {};
  for (const arm of LIVE_DAST_ARMS) {
    const selected = observations.filter((value) => value.arm === arm).map((value) => value.liveDastMetrics!);
    if (selected.length === 0) continue;
    averages[arm] = Object.fromEntries(LIVE_DAST_METRICS.map((metric) => [
      metric,
      selected.reduce((sum, value) => sum + value[metric], 0) / selected.length,
    ])) as z.infer<typeof LiveDastMetricsSchema>;
  }
  const comparisons = [
    compareOffsecArms({
      observations,
      capability: 'pentest',
      baseline: 'legacy-read-only',
      candidate: 'adaptive-unverified',
      policy: input.policy,
      split,
    }),
    compareOffsecArms({
      observations,
      capability: 'pentest',
      baseline: 'adaptive-unverified',
      candidate: 'adaptive-verified',
      policy: input.policy,
      split,
    }),
    compareOffsecArms({
      observations,
      capability: 'pentest',
      baseline: 'legacy-read-only',
      candidate: 'adaptive-verified',
      policy: input.policy,
      split,
    }),
  ];
  return {
    status: 'evaluated',
    claim: 'inconclusive',
    reason: '다차원 관측값을 기록했지만 사전 등록된 차원별 paired CI가 없어 우세를 주장하지 않는다',
    observationCount: observations.length,
    arms: LIVE_DAST_ARMS,
    metrics: LIVE_DAST_METRICS,
    averages,
    comparisons,
  };
}
