import { AsyncLocalStorage } from 'node:async_hooks';
export interface PhaseMetrics {
  runId: string;
  domain: string;
  phase: string;
  agent: string;
  attempt: number;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  totalTokens: number;
  estimatedContextUsagePercent: number;
  duration: number;
  validationPassed: boolean;
  qualityIssueCount: number;
  costUsd: number;
}

const DEFAULT_CONTEXT_WINDOW = 200_000;

export function buildPhaseMetrics(input: {
  runId: string;
  domain: string;
  phase: string;
  agent: string;
  attempt: number;
  usage: { inputTokens?: number; outputTokens?: number; cacheReadInputTokens?: number };
  contextWindow?: number;
  startTime: number;
  validationPassed: boolean;
  qualityIssueCount: number;
  costUsd: number;
}): PhaseMetrics {
  const inputTokens = input.usage.inputTokens ?? 0;
  const outputTokens = input.usage.outputTokens ?? 0;
  const cacheReadTokens = input.usage.cacheReadInputTokens ?? 0;
  const totalTokens = inputTokens + outputTokens + cacheReadTokens;
  const contextWindow = input.contextWindow ?? DEFAULT_CONTEXT_WINDOW;
  const estimatedContextUsagePercent = contextWindow > 0
    ? Math.round((totalTokens / contextWindow) * 10_000) / 100
    : 0;

  return {
    runId: input.runId,
    domain: input.domain,
    phase: input.phase,
    agent: input.agent,
    attempt: input.attempt,
    inputTokens,
    outputTokens,
    cacheReadTokens,
    totalTokens,
    estimatedContextUsagePercent,
    duration: Date.now() - input.startTime,
    validationPassed: input.validationPassed,
    qualityIssueCount: input.qualityIssueCount,
    costUsd: input.costUsd,
  };
}

export type PhaseMetricsSink = (metrics: PhaseMetrics) => void;
const scopedMetrics = new AsyncLocalStorage<{ sink: PhaseMetricsSink | null }>();
/** Keep embedded calls and concurrent applications from sharing logging configuration. */
export function withPhaseMetrics<T>(sink: PhaseMetricsSink | null, run: () => T): T {
  return scopedMetrics.run({ sink }, run);
}
export function emitPhaseMetrics(metrics: PhaseMetrics): void {
  const scope = scopedMetrics.getStore();
  if (scope) scope.sink?.(metrics);
  else process.stderr.write(`${JSON.stringify(metrics)}\n`);
}
