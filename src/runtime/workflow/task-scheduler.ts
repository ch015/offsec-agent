import { processAdmissionController, type AdmissionController } from './admission-controller.js';

export class WorkUnitTimeoutError extends Error {}
export class TerminationUnknownError extends Error {}
export class AdmissionDeferredError extends Error {}

export type ScheduledResult<TUnit, TValue> = Readonly<{
  unit: TUnit; status: 'fulfilled' | 'rejected'; value?: TValue; reason?: unknown;
}>;
export type SchedulerEvent = {
  event: string; unitKey?: string; attempt?: number; state?: string;
  active: number; target: number; queued: number; reason?: string; retryAt?: number;
};
export type TaskControls = {
  progress(): void;
  pressure(reason: string, retryAfterMs?: number): void;
};

/** Only transport/overload and explicit validation failures can be retried. */
export function retryDisposition(error: unknown): { retryable: boolean; pressure: boolean; delayMs?: number } {
  const chain: any[] = []; let current: any = error;
  while (current && chain.length < 8 && !chain.includes(current)) { chain.push(current); current = current.cause; }
  const status = chain.map(item => item.status ?? item.statusCode).find(value => [429, 503, 529].includes(value));
  const reason = chain.map(item => String(item.message ?? item)).join(' ');
  const pressure = !!status || /\b(429|503|529|ENOMEM|EMFILE|ENFILE|EAGAIN)\b|rate.?limit|overload/i.test(reason);
  const rawRetry = chain.map(item => item.retryAfterMs).find(value => Number.isFinite(value) && value >= 0);
  const seconds = chain.map(item => item.headers?.get?.('retry-after') ?? item.headers?.['retry-after']).find(value => value !== undefined);
  const delayMs = rawRetry ?? (seconds !== undefined ? (/^\d+(\.\d+)?$/.test(String(seconds))
    ? Number(seconds) * 1000 : Math.max(0, Date.parse(String(seconds)) - Date.now())) : undefined);
  const forbidden = /permission|policy refusal|not authorized|invalid.api.key|\b(401|403)\b/i.test(reason);
  return { pressure, retryable: !forbidden && (pressure || /ECONNRESET|ETIMEDOUT|ECONNREFUSED|EHOSTUNREACH|socket|network|stream.*(?:disconnect|fail)|went to sleep mid-response/i.test(reason)
    || chain.some(item => item.retryable === true || item.constructor?.name === 'PhaseResultFailure')),
    ...(Number.isFinite(delayMs) ? { delayMs } : {}) };
}

/** One continuous ready queue. A cancellation retains capacity until worker settlement. */
export async function executeTaskQueue<TUnit extends { unitKey: string }, TValue>(input: {
  units: readonly TUnit[];
  maxConcurrency?: number;
  dynamic?: boolean;
  initialConcurrency?: number;
  controlIntervalMs?: number;
  unitTimeoutMs?: number;
  /** Lack of observed provider progress; independent of an optional wall-time cap. */
  unitIdleTimeoutMs?: number;
  cancellationGraceMs?: number;
  maximumAttempts?: number;
  retryBaseMs?: number;
  shouldRetry?: (error: unknown) => boolean;
  resourceCapacity?: () => number;
  admissionController?: AdmissionController;
  dependencies?: (unit: TUnit) => readonly string[];
  signal?: AbortSignal;
  onEvent?: (event: SchedulerEvent) => void;
  worker(unit: TUnit, attempt: number, controller: AbortController, controls: TaskControls): Promise<TValue>;
}): Promise<ScheduledResult<TUnit, TValue>[]> {
  for (const [name, value] of Object.entries({ maxConcurrency: input.maxConcurrency, initialConcurrency: input.initialConcurrency,
    controlIntervalMs: input.controlIntervalMs, unitTimeoutMs: input.unitTimeoutMs, unitIdleTimeoutMs: input.unitIdleTimeoutMs, cancellationGraceMs: input.cancellationGraceMs,
    maximumAttempts: input.maximumAttempts, retryBaseMs: input.retryBaseMs })) {
    if (value !== undefined && (!Number.isSafeInteger(value) || value < 1)) throw new Error(`${name} must be a positive safe integer`);
  }
  if (new Set(input.units.map(unit => unit.unitKey)).size !== input.units.length) throw new Error('duplicate work unitKey');
  const dependencies = new Map(input.units.map(unit => [unit.unitKey, input.dependencies?.(unit) ?? []]));
  const visited = new Set<string>(), visiting = new Set<string>();
  const visit = (key: string) => {
    if (visiting.has(key)) throw new Error(`Cyclic task dependency: ${key}`);
    if (visited.has(key)) return;
    if (!dependencies.has(key)) throw new Error(`Unknown task dependency: ${key}`);
    visiting.add(key); for (const dependency of dependencies.get(key)!) visit(dependency);
    visiting.delete(key); visited.add(key);
  };
  for (const key of dependencies.keys()) visit(key);
  if (!input.units.length) return [];
  input.signal?.throwIfAborted();
  const sharedAdmission = input.admissionController ?? (input.resourceCapacity ? undefined : processAdmissionController);
  const resourceCapacity = input.resourceCapacity ?? (() => sharedAdmission!.available());
  const capacity = () => Math.max(0, Math.floor(resourceCapacity()));
  const ceiling = input.maxConcurrency ?? input.units.length;
  const dynamic = input.dynamic !== false;
  let target = Math.min(ceiling, input.initialConcurrency ?? (dynamic ? 1 : ceiling));
  let active = 0, progress = false, pauseUntil = 0, lastControl = Date.now(), stopped: unknown;
  const queue = input.units.map((unit, index) => ({ unit, index, attempt: 1, readyAt: 0 }));
  const results = new Array<ScheduledResult<TUnit, TValue>>(queue.length);
  const resultIndex = new Map(input.units.map((unit, index) => [unit.unitKey, index]));
  const prerequisiteResults = (unit: TUnit) => dependencies.get(unit.unitKey)!.map(key => results[resultIndex.get(key)!]);
  const controllers = new Set<AbortController>();
  const pending = new Set<Promise<void>>();
  let wake: (() => void) | undefined;
  const emit = (event: string, extra: Partial<SchedulerEvent> = {}) => input.onEvent?.({ event, active, target, queued: queue.length, ...extra });
  const pressure = (reason: string, retryAfterMs = 1000) => {
    sharedAdmission?.pressure(retryAfterMs);
    pauseUntil = Math.max(pauseUntil, Date.now() + retryAfterMs);
    target = Math.max(1, Math.floor(target / 2)); progress = false;
    emit('SchedulerBackoff', { reason, retryAt: pauseUntil }); wake?.();
  };
  const stop = (reason: unknown) => {
    stopped ??= reason;
    for (const controller of controllers) if (!controller.signal.aborted) controller.abort(reason);
    wake?.();
  };
  const abort = () => stop(input.signal?.reason ?? new AdmissionDeferredError('Run cancelled'));
  input.signal?.addEventListener('abort', abort, { once: true });
  const start = (item: typeof queue[number]) => {
    if (sharedAdmission && !sharedAdmission.reserve()) { queue.unshift(item); return false; }
    const controller = new AbortController(); controllers.add(controller); active++;
    try { emit('TaskAttemptState', { unitKey: item.unit.unitKey, attempt: item.attempt, state: 'starting' }); }
    catch (error) { controllers.delete(controller); active--; sharedAdmission?.release(); throw error; }
    let timeout: ReturnType<typeof setTimeout> | undefined, idle: ReturnType<typeof setTimeout> | undefined, grace: ReturnType<typeof setTimeout> | undefined;
    let cancelled: unknown;
    let unknownTermination: ((error: unknown) => void) | undefined;
    const cancel = () => {
      if (idle) clearTimeout(idle);
      cancelled = controller.signal.reason ?? new AdmissionDeferredError('Cancelled');
      emit('TaskAttemptState', { unitKey: item.unit.unitKey, attempt: item.attempt, state: 'cancelling', reason: String(cancelled) });
      grace = setTimeout(() => {
        const reason = new TerminationUnknownError(`Worker termination unconfirmed: ${item.unit.unitKey}`);
        emit('TaskAttemptState', { unitKey: item.unit.unitKey, attempt: item.attempt, state: 'termination-unknown', reason: reason.message });
        stop(reason); unknownTermination?.(reason);
      }, input.cancellationGraceMs ?? 30_000);
    };
    controller.signal.addEventListener('abort', cancel, { once: true });
    if (input.unitTimeoutMs) timeout = setTimeout(() => controller.abort(new WorkUnitTimeoutError(`unit ${item.unit.unitKey} timeout: ${input.unitTimeoutMs}ms`)), input.unitTimeoutMs);
    let workerSettled = false;
    const refreshIdle = () => {
      if (idle) clearTimeout(idle);
      if (input.unitIdleTimeoutMs) idle = setTimeout(() => controller.abort(new WorkUnitTimeoutError(`unit ${item.unit.unitKey} idle timeout: ${input.unitIdleTimeoutMs}ms without provider progress`)), input.unitIdleTimeoutMs);
    };
    const observedProgress = () => {
      if (controller.signal.aborted || workerSettled) return;
      refreshIdle();
      progress = true; wake?.();
    };
    refreshIdle();
    const worker = Promise.resolve().then(() => {
      emit('TaskAttemptState', { unitKey: item.unit.unitKey, attempt: item.attempt, state: 'running' });
      return input.worker(item.unit, item.attempt, controller, { progress: observedProgress, pressure });
    });
    // This settlement is the local lifetime boundary, even when the coordinator has stopped.
    const settled = worker.finally(() => {
      workerSettled = true;
      if (timeout) clearTimeout(timeout); if (idle) clearTimeout(idle); if (grace) clearTimeout(grace);
      controllers.delete(controller); active--;
      sharedAdmission?.release();
      emit('TaskAttemptState', { unitKey: item.unit.unitKey, attempt: item.attempt, state: 'terminated' });
    });
    let task!: Promise<void>;
    task = (async () => {
      try {
        const value = await Promise.race([settled, new Promise<never>((_, reject) => { unknownTermination = reject; })]);
        if (cancelled) throw cancelled;
        results[item.index] = { unit: item.unit, status: 'fulfilled', value }; progress = true;
        emit('TaskSatisfied', { unitKey: item.unit.unitKey, attempt: item.attempt, state: 'satisfied' });
      } catch (reason) {
        const disposition = retryDisposition(reason);
        if (disposition.pressure) pressure(String(reason), disposition.delayMs ?? (input.retryBaseMs ?? 1000) * 2 ** (item.attempt - 1));
        const retryable = input.shouldRetry?.(reason) ?? disposition.retryable;
        if (!stopped && !cancelled && retryable && item.attempt < (input.maximumAttempts ?? 3)) {
          const readyAt = Date.now() + (disposition.delayMs ?? (input.retryBaseMs ?? 1000) * 2 ** (item.attempt - 1));
          queue.push({ ...item, attempt: item.attempt + 1, readyAt });
          emit('TaskRetryScheduled', { unitKey: item.unit.unitKey, attempt: item.attempt + 1, state: 'retry-wait', retryAt: readyAt, reason: String(reason) });
        } else { results[item.index] = { unit: item.unit, status: 'rejected', reason };
          if (!(reason instanceof TerminationUnknownError)) emit('TaskDeferred', { unitKey: item.unit.unitKey, attempt: item.attempt, state: 'deferred', reason: String(reason) }); }
      } finally {
        if (timeout) clearTimeout(timeout); if (idle) clearTimeout(idle); if (grace) clearTimeout(grace);
        controller.signal.removeEventListener('abort', cancel);
        pending.delete(task); wake?.();
      }
    })();
    pending.add(task);
    return true;
  };
  for (const item of queue) emit('TaskPlanned', { unitKey: item.unit.unitKey, attempt: item.attempt, state: 'ready' });
  try {
    while (queue.length || pending.size) {
      const now = Date.now(), interval = input.controlIntervalMs ?? 5000;
      if (dynamic && progress && now - lastControl >= interval && now >= pauseUntil && !stopped) {
        const next = Math.max(1, Math.min(ceiling, active + queue.length, capacity() + active, target + Math.max(1, Math.floor(target / 4))));
        if (next !== target) { target = next; emit('SchedulerConcurrencyChanged', { reason: 'Observed progress and available resources' }); }
        progress = false; lastControl = now;
      }
      let availableStarts = capacity();
      for (let index = queue.length - 1; index >= 0; index--) {
        const item = queue[index]!;
        const failed = prerequisiteResults(item.unit).find(result => result?.status === 'rejected');
        if (!failed) continue;
        const reason = new AdmissionDeferredError(`Prerequisite task incomplete: ${failed.unit.unitKey}`);
        results[item.index] = { unit: item.unit, status: 'rejected', reason };
        queue.splice(index, 1);
        emit('TaskDeferred', { unitKey: item.unit.unitKey, state: 'deferred', reason: reason.message });
      }
      while (!stopped && Date.now() >= pauseUntil && active < target && availableStarts > 0) {
        const index = queue.findIndex(item => item.readyAt <= Date.now() && prerequisiteResults(item.unit).every(result => result?.status === 'fulfilled'));
        if (index < 0) break;
        if (!start(queue.splice(index, 1)[0]!)) break;
        availableStarts--;
      }
      if (stopped) {
        for (const item of queue.splice(0)) results[item.index] = { unit: item.unit, status: 'rejected', reason: stopped };
      } else if (queue.length && capacity() === 0 && Date.now() >= pauseUntil && (!sharedAdmission ||
        (sharedAdmission.snapshot().occupied === 0 && Date.now() >= sharedAdmission.snapshot().pauseUntil))) {
        pressure('Local resources unavailable', Math.max(interval, 1000));
      }
      if (pending.size || queue.length) {
        await new Promise<void>(resolve => {
          const timer = setTimeout(() => { wake = undefined; resolve(); }, Math.min(interval, 1000));
          wake = () => { clearTimeout(timer); wake = undefined; resolve(); };
        });
      }
    }
  } finally { input.signal?.removeEventListener('abort', abort); }
  return results;
}
