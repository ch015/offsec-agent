import { afterEach, describe, expect, it, vi } from 'vitest';
import { executeBoundedWork, WorkUnitTimeoutError } from '../workflow/bounded-work-executor.js';
afterEach(() => vi.useRealTimers());
describe('bounded work cancellation', () => {
  it('aborts an overdue worker and does not start an overlapping retry', async () => {
    vi.useFakeTimers();
    let observed: AbortSignal | undefined;
    const worker = vi.fn((_unit, _attempt, controller: AbortController) => {
      observed = controller.signal;
      return new Promise<never>((_resolve, reject) => controller.signal.addEventListener('abort', () => reject(controller.signal.reason), { once: true }));
    });
    const pending = executeBoundedWork({ units: [{ unitKey: 'test' }], maximumWorkUnits: 1, maxConcurrency: 1,
      unitTimeoutMs: 100, retryRejectedOnce: true, worker });
    await vi.advanceTimersByTimeAsync(100);
    const results = await pending;
    expect(observed?.aborted).toBe(true);
    expect(results[0]?.reason).toBeInstanceOf(WorkUnitTimeoutError);
    expect(worker).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });
  it('clears its timeout after a successful worker', async () => {
    vi.useFakeTimers();
    const results = await executeBoundedWork({ units: [{ unitKey: 'test' }], maximumWorkUnits: 1, maxConcurrency: 1,
      unitTimeoutMs: 100, worker: async () => 'done' });
    expect(results[0]?.value).toBe('done');
    expect(vi.getTimerCount()).toBe(0);
  });
});
