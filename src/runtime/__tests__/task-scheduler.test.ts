import { afterEach, describe, expect, it, vi } from 'vitest';
import { executeTaskQueue, retryDisposition, TerminationUnknownError, WorkUnitTimeoutError, type SchedulerEvent } from '../workflow/task-scheduler.js';
import { AdmissionController } from '../workflow/admission-controller.js';

afterEach(() => vi.useRealTimers());
const units = (n: number) => Array.from({ length: n }, (_, i) => ({ unitKey: `u-${i}` }));
const delay = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms));

describe('continuous adaptive scheduling', () => {
  it('grows beyond 16 using progress and headroom, without a product ceiling', async () => {
    vi.useFakeTimers(); let active = 0, peak = 0;
    const pending = executeTaskQueue({ resourceCapacity: () => 100, units: units(48), controlIntervalMs: 1,
      worker: async (_, __, ___, controls) => { peak = Math.max(peak, ++active); controls.progress(); await delay(200); active--; return true; } });
    await vi.runAllTimersAsync();
    expect((await pending).every(result => result.status === 'fulfilled')).toBe(true);
    expect(peak).toBeGreaterThan(16);
  });
  it('starts tasks beyond 128 while a first task is still running', async () => {
    vi.useFakeTimers(); const started: string[] = []; let slowFinished = false, beyondStarted = false;
    const pending = executeTaskQueue({ resourceCapacity: () => 100, units: units(260), maxConcurrency: 3, dynamic: false,
      worker: async unit => {
        started.push(unit.unitKey);
        if (unit.unitKey === 'u-200') beyondStarted = !slowFinished;
        await delay(unit.unitKey === 'u-0' ? 1000 : 1);
        if (unit.unitKey === 'u-0') slowFinished = true;
      } });
    await vi.runAllTimersAsync(); await pending;
    expect(beyondStarted).toBe(true); expect(new Set(started).size).toBe(260);
  });
  it('retains occupancy until cancellation actually settles and rejects late success', async () => {
    vi.useFakeTimers(); let active = 0, peak = 0, calls = 0;
    const pending = executeTaskQueue({ resourceCapacity: () => 100, units: units(6), maxConcurrency: 2, dynamic: false, unitTimeoutMs: 10,
      cancellationGraceMs: 500, shouldRetry: () => true,
      worker: async () => { calls++; peak = Math.max(peak, ++active); await delay(100); active--; return 'late'; } });
    await vi.runAllTimersAsync(); const results = await pending;
    expect(peak).toBe(2); expect(calls).toBe(6);
    expect(results.every(result => result.reason instanceof WorkUnitTimeoutError)).toBe(true);
  });
  it.each([false, true])('extends idle deadlines with observed progress while honoring an explicit wall cap (%s)', async wallCap => {
    vi.useFakeTimers();
    const pending = executeTaskQueue({ resourceCapacity: () => 10, units: units(1), unitIdleTimeoutMs: 10, ...(wallCap ? { unitTimeoutMs: 25 } : {}),
      worker: async (_, __, ___, controls) => { for (let index = 0; index < 8; index++) { await delay(5); controls.progress(); } return 'done'; } });
    await vi.runAllTimersAsync(); const result = (await pending)[0]!;
    if (wallCap) expect(result.reason).toBeInstanceOf(WorkUnitTimeoutError);
    else expect(result).toMatchObject({ status: 'fulfilled', value: 'done' });
  });
  it('cancels after provider progress stops and rejects its late result', async () => {
    vi.useFakeTimers(); let cancelled = false;
    const pending = executeTaskQueue({ resourceCapacity: () => 10, units: units(1), unitIdleTimeoutMs: 10,
      worker: async (_, __, controller, controls) => { controls.progress(); await delay(30); cancelled = controller.signal.aborted; return 'late'; } });
    await vi.runAllTimersAsync(); const result = (await pending)[0]!;
    expect(cancelled).toBe(true); expect(result.reason).toBeInstanceOf(WorkUnitTimeoutError);
    expect(String(result.reason)).toContain('idle timeout');
  });
  it('stops admission when termination is unknown, preserving the occupied attempt', async () => {
    vi.useFakeTimers(); const events: SchedulerEvent[] = []; let finish!: () => void;
    const worker = vi.fn(() => new Promise<void>(resolve => { finish = resolve; }));
    const pending = executeTaskQueue({ resourceCapacity: () => 100, units: units(3), maxConcurrency: 1, unitTimeoutMs: 10, cancellationGraceMs: 20,
      onEvent: event => events.push(event), worker });
    await vi.advanceTimersByTimeAsync(40); const results = await pending;
    expect(worker).toHaveBeenCalledTimes(1);
    expect(results.every(result => result.reason instanceof TerminationUnknownError)).toBe(true);
    expect(events.find(event => event.state === 'termination-unknown')?.active).toBe(1);
    finish(); await vi.runAllTimersAsync();
    expect(events.at(-1)?.state).toBe('terminated');
  });
  it('honors Retry-After and retries under the same scheduler', async () => {
    vi.useFakeTimers(); const starts: number[] = []; const events: SchedulerEvent[] = [];
    const pending = executeTaskQueue({ resourceCapacity: () => 100, units: units(2), maxConcurrency: 1, retryBaseMs: 1,
      onEvent: event => events.push(event), worker: async (unit, attempt) => {
        starts.push(Date.now());
        if (unit.unitKey === 'u-0' && attempt === 1) throw Object.assign(new Error('overloaded'), { status: 429, retryAfterMs: 100 });
      } });
    await vi.runAllTimersAsync(); const results = await pending;
    expect(starts[1]! - starts[0]!).toBeGreaterThanOrEqual(100);
    expect(results.every(result => result.status === 'fulfilled')).toBe(true);
    expect(events.some(event => event.event === 'SchedulerBackoff')).toBe(true);
  });
  it('does not retry permission or refusal errors', async () => {
    const worker = vi.fn(async () => { throw new Error('403 permission denied'); });
    await executeTaskQueue({ resourceCapacity: () => 100, units: units(1), worker }); expect(worker).toHaveBeenCalledTimes(1);
  });
});

it('runs bridges only after all prerequisites succeed and defers failed dependency chains', async () => {
  const order: string[] = [];
  const input = [{ unitKey: 'bridge', deps: ['a', 'b'] }, { unitKey: 'a', deps: [] }, { unitKey: 'b', deps: [] }, { unitKey: 'independent', deps: [] }];
  const result = await executeTaskQueue({ units: input, resourceCapacity: () => 10, dynamic: false, maxConcurrency: 4,
    dependencies: unit => unit.deps, worker: async unit => { await delay(1); order.push(unit.unitKey); } });
  expect(order.indexOf('bridge')).toBeGreaterThan(order.indexOf('a')); expect(order.indexOf('bridge')).toBeGreaterThan(order.indexOf('b'));
  expect(result.every(row => row.status === 'fulfilled')).toBe(true);
  const blocked = await executeTaskQueue({ units: input, resourceCapacity: () => 10, dependencies: unit => unit.deps,
    worker: async unit => { if (unit.unitKey === 'a') throw new Error('403'); } });
  expect(blocked[0]!.status).toBe('rejected'); expect(String(blocked[0]!.reason)).toContain('Prerequisite');
  await expect(executeTaskQueue({ units: input, dependencies: () => ['bridge'], worker: async () => true })).rejects.toThrow('Cyclic');
});

it('shares physical occupancy and provider cooldown across simultaneous runs', async () => {
  vi.useFakeTimers(); const admission = new AdmissionController(() => 2); let active = 0, peak = 0;
  const starts: number[] = [];
  const run = (pressured: boolean) => executeTaskQueue({ units: units(6), admissionController: admission, dynamic: false, maxConcurrency: 6, controlIntervalMs: 1,
    worker: async (_, attempt, __, controls) => {
      starts.push(Date.now()); peak = Math.max(peak, ++active);
      if (pressured && starts.length === 1) controls.pressure('503', 50);
      await delay(10); active--; return attempt;
    } });
  const first = run(true), second = run(false); const beginning = Date.now();
  await vi.runAllTimersAsync(); await Promise.all([first, second]);
  expect(peak).toBeLessThanOrEqual(2); expect(starts.slice(2).every(at => at - beginning >= 50)).toBe(true);
  expect(admission.snapshot().occupied).toBe(0);
});

it.each([429, 503, 529, 'ENOMEM', 'EMFILE', 'EAGAIN'])('backs off boundedly on %s pressure', reason => {
  expect(retryDisposition(new Error(String(reason)))).toMatchObject({ retryable: true, pressure: true });
});

it('reduces admission during resource pressure and resumes when headroom recovers', async () => {
  vi.useFakeTimers(); let available = 0; const events: SchedulerEvent[] = [], starts: number[] = [];
  const pending = executeTaskQueue({ units: units(3), resourceCapacity: () => available, controlIntervalMs: 1,
    onEvent: event => events.push(event), worker: async () => { starts.push(Date.now()); } });
  await vi.advanceTimersByTimeAsync(50); expect(starts).toHaveLength(0);
  available = 4; await vi.runAllTimersAsync(); expect((await pending).every(result => result.status === 'fulfilled')).toBe(true);
  expect(events.some(event => event.reason === 'Local resources unavailable')).toBe(true);
});
