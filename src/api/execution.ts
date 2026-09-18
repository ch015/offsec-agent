import { openSync, closeSync, writeFileSync, unlinkSync, mkdirSync, realpathSync, existsSync } from 'node:fs';
import { basename, dirname, isAbsolute, join } from 'node:path';
import { runSession, type SessionSpec } from '../runtime/session.js';
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
        onProgress: options.onProgress ?? spec.onProgress,
        onLedger: row => { spec.onLedger?.(row); options.onLedger?.(row); },
      });
      signal?.throwIfAborted();
      return result;
    } finally { signal?.removeEventListener('abort', cancel); }
  };
}
/** A sibling lock works before the mission creates its empty output directory. */
export async function executeInDirectory<T>(directory: string, options: AgentSessionOptions,
  execution: AgentExecutionOptions, run: (directory: string) => Promise<T>): Promise<T> {
  execution.signal?.throwIfAborted();
  absolutePath(directory, 'engagementDir');
  mkdirSync(dirname(directory), { recursive: true });
  const canonical = existsSync(directory) ? realpathSync(directory) : join(realpathSync(dirname(directory)), basename(directory));
  const lock = join(dirname(canonical), `.${basename(canonical)}.agent.lock`);
  let fd: number;
  try { fd = openSync(lock, 'wx', 0o600); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new Error('Agent run is already active for this engagementDir'); throw error; }
  try {
    writeFileSync(fd, JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() }));
    const result = await withPhaseMetrics(options.onMetrics ?? null, () => run(canonical));
    execution.signal?.throwIfAborted();
    return result;
  } catch (error) {
    execution.signal?.throwIfAborted();
    throw error;
  } finally { try { closeSync(fd); } finally { unlinkSync(lock); } }
}
