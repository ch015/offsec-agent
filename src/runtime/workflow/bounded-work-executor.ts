import { executeTaskQueue, type ScheduledResult } from './task-scheduler.js';
export { WorkUnitTimeoutError } from './task-scheduler.js';
export type BoundedWorkResult<TUnit, TValue> = ScheduledResult<TUnit, TValue>;

type WorkInput<TUnit, TValue> = {
  units: readonly TUnit[];
  maxConcurrency: number;
  maximumWorkUnits: number;
  retryRejectedOnce?: boolean;
  unitTimeoutMs?: number;
  shouldRetryRejection?: (reason: unknown) => boolean;
  worker: (unit: TUnit, attempt: 1 | 2, controller: AbortController) => Promise<TValue>;
};

export async function executeBoundedWork<TUnit extends { unitKey: string }, TValue>(input: WorkInput<TUnit, TValue>): Promise<BoundedWorkResult<TUnit, TValue>[]> {
  if (input.units.length > input.maximumWorkUnits) throw new Error(`sealed work unit 상한을 초과했다: ${input.units.length}/${input.maximumWorkUnits}`);
  return executePagedWork(input);
}

/** Compatibility entrypoint: page size is no longer an execution barrier. */
export async function executePagedWork<TUnit extends { unitKey: string }, TValue>(input: WorkInput<TUnit, TValue>): Promise<BoundedWorkResult<TUnit, TValue>[]> {
  if (!Number.isSafeInteger(input.maximumWorkUnits) || input.maximumWorkUnits < 1) throw new Error('invalid scheduling window');
  return executeTaskQueue({ ...input, dynamic: false,
    maximumAttempts: input.retryRejectedOnce ? 2 : 1,
    shouldRetry: input.shouldRetryRejection ?? (() => true),
    worker: (unit, attempt, controller) => input.worker(unit, attempt as 1 | 2, controller),
  });
}
