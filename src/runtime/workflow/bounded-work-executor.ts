export class WorkUnitTimeoutError extends Error {}

export type BoundedWorkResult<TUnit, TValue> = Readonly<{
  unit: TUnit;
  status: 'fulfilled' | 'rejected';
  value?: TValue;
  reason?: unknown;
}>;

export async function executeBoundedWork<TUnit extends { unitKey: string }, TValue>(input: {
  units: readonly TUnit[];
  maxConcurrency: number;
  maximumWorkUnits: number;
  retryRejectedOnce?: boolean;
  /** #14: unit당 최대 실행 시간 (ms). 초과 시 rejected로 처리. 기본 무제한. */
  unitTimeoutMs?: number;
  /** P0: 실패 원인이 재시도 적격인지 판별. false이면 해당 unit은 재시도하지 않는다. */
  shouldRetryRejection?: (reason: unknown) => boolean;
  worker: (unit: TUnit, attempt: 1 | 2, controller: AbortController) => Promise<TValue>;
}): Promise<BoundedWorkResult<TUnit, TValue>[]> {
  if (!Number.isInteger(input.maxConcurrency) || input.maxConcurrency < 1) {
    throw new Error('bounded work maxConcurrency가 잘못됐다');
  }
  if (!Number.isInteger(input.maximumWorkUnits) || input.maximumWorkUnits < 1) {
    throw new Error('bounded work maximumWorkUnits가 잘못됐다');
  }
  if (input.units.length > input.maximumWorkUnits) {
    throw new Error(`sealed work unit 상한을 초과했다: ${input.units.length}/${input.maximumWorkUnits}`);
  }
  if (new Set(input.units.map((unit) => unit.unitKey)).size !== input.units.length) {
    throw new Error('bounded work unitKey가 중복됐다');
  }

  const results = new Array<BoundedWorkResult<TUnit, TValue>>(input.units.length);
  const timeoutMs = input.unitTimeoutMs;

  const runWithTimeout = async (unit: TUnit, attempt: 1 | 2): Promise<TValue> => {
    const controller = new AbortController();
    if (!timeoutMs) return input.worker(unit, attempt, controller);
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        input.worker(unit, attempt, controller),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => {
            const error = new WorkUnitTimeoutError(`unit ${unit.unitKey} timeout 초과: ${timeoutMs}ms`);
            reject(error);
            controller.abort(error);
          }, timeoutMs);
        }),
      ]);
    } finally { if (timer) clearTimeout(timer); }
  };

  let cursor = 0;
  const run = async (): Promise<void> => {
    while (true) {
      const index = cursor;
      cursor += 1;
      const unit = input.units[index];
      if (!unit) return;
      try {
        results[index] = { unit, status: 'fulfilled', value: await runWithTimeout(unit, 1) };
      } catch (reason) {
        results[index] = { unit, status: 'rejected', reason };
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(input.maxConcurrency, input.units.length) }, run));
  if (input.retryRejectedOnce) {
    for (let index = 0; index < results.length; index += 1) {
      const result = results[index];
      if (result?.status !== 'rejected') continue;
      // A timed-out worker may still be winding down. Never overlap it with a retry.
      if (result.reason instanceof WorkUnitTimeoutError) continue;
      if (input.shouldRetryRejection && !input.shouldRetryRejection(result.reason)) continue;
      try {
        results[index] = { unit: result.unit, status: 'fulfilled', value: await runWithTimeout(result.unit, 2) };
      } catch (reason) {
        results[index] = { unit: result.unit, status: 'rejected', reason };
      }
    }
  }
  return results;
}

/** Bound each scheduling window without truncating the sealed analysis scope. */
export async function executePagedWork<TUnit extends { unitKey: string }, TValue>(
  input: Parameters<typeof executeBoundedWork<TUnit, TValue>>[0],
): Promise<BoundedWorkResult<TUnit, TValue>[]> {
  if (!Number.isInteger(input.maximumWorkUnits) || input.maximumWorkUnits < 1) throw new Error('invalid scheduling window');
  if (new Set(input.units.map(unit => unit.unitKey)).size !== input.units.length) throw new Error('duplicate work unitKey');
  const results: BoundedWorkResult<TUnit, TValue>[] = [];
  for (let start = 0; start < input.units.length; start += input.maximumWorkUnits) {
    results.push(...await executeBoundedWork({ ...input, units: input.units.slice(start, start + input.maximumWorkUnits) }));
  }
  return results;
}
