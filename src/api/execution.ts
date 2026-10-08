import { SessionExecutionError } from '../runtime/session-types.js';
import { mkdirSync, realpathSync, existsSync } from 'node:fs';
import { basename, dirname, isAbsolute, join } from 'node:path';
import { runSession, type SessionSpec } from '../runtime/session-runner.js';
import { withPhaseMetrics, type PhaseMetricsSink } from '../runtime/workflow/phase-metrics.js';

export type SessionRunner = typeof runSession;
export type AgentExecutionOptions = { signal?: AbortSignal };
export type AgentSessionOptions = {
  apiKey?: string;
  sessionRunner?: SessionRunner;
  onProgress?: SessionSpec['onProgress'];
  onLedger?: SessionSpec['onLedger'];
  onStderr?: SessionSpec['onStderr'];
  onMetrics?: PhaseMetricsSink;
};
export function assertSessionConfigured(options: AgentSessionOptions): void {
  if (!options.sessionRunner && !options.apiKey?.trim()) throw new Error('Provide apiKey or sessionRunner when embedding the agent');
}
export function absolutePath(path: string, label: string): string {
  if (!isAbsolute(path)) throw new Error(`${label} must be an absolute path`);
  return path;
}
export function sessionFor(options: AgentSessionOptions, execution: AgentExecutionOptions): SessionRunner {
  const runner = options.sessionRunner ?? runSession;
  return async spec => {
    const signals = [execution.signal, spec.abortController?.signal].filter((s): s is AbortSignal => !!s);
    const signal = signals.length ? AbortSignal.any(signals) : undefined;
    signal?.throwIfAborted();
    const controller = new AbortController();
    const cancel = () => controller.abort(signal?.reason);
    signal?.addEventListener('abort', cancel, { once: true });
    try {
      const result = await runner({ ...spec,
        ...(options.apiKey !== undefined ? { apiKey: options.apiKey, authMode: 'api_key' as const } : {}),
        abortController: controller,
        onStderr: options.onStderr ?? spec.onStderr,
        onProgress: event => { spec.onProgress?.(event); options.onProgress?.(event); },
        onLedger: row => { spec.onLedger?.(row); options.onLedger?.(row); },
      });
      if (signal?.aborted) throw new SessionExecutionError(result, signal.reason);
      return result;
    } finally { signal?.removeEventListener('abort', cancel); }
  };
}
/** Session configuration and metrics are scoped to this API invocation. The mission owns its lock. */
export async function executeInDirectory<T>(directory: string, options: AgentSessionOptions,
  execution: AgentExecutionOptions, run: (directory: string) => Promise<T>): Promise<T> {
  execution.signal?.throwIfAborted();
  absolutePath(directory, 'engagementDir');
  mkdirSync(dirname(directory), { recursive: true });
  const canonical = existsSync(directory) ? realpathSync(directory) : join(realpathSync(dirname(directory)), basename(directory));
  try {
    const result = await withPhaseMetrics(options.onMetrics ?? null, () => run(canonical));
    execution.signal?.throwIfAborted();
    return result;
  } catch (error) {
    execution.signal?.throwIfAborted();
    throw error;
  }
}
