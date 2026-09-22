import { describe, expect, it } from 'vitest';
import { BudgetedRuntime } from '../providers/budgeted-runtime.js';
import { ProviderRuntimeFailure, type ProviderPhaseRequest, type ProviderPhaseOutcome, type ProviderRuntime } from '../providers/provider-runtime.js';
const request = (phase = 'analyze'): ProviderPhaseRequest => ({ contractId: 'test', contractVersion: '2.0.0', domain: 'offsec', mission: 'assessment', phase, role: 'analyzer', runId: 'budget', attempt: '1', target: '/tmp', engagementDir: '/tmp', prompt: '', requiredCapabilities: [], maxBudgetUsd: 10 });
const outcome = (costUsd: number): ProviderPhaseOutcome => ({ provider: 'fixture', texts: [], events: [], usage: { provider: 'fixture', costUsd, accountingComplete: true }, raw: {} });
describe('mission budget reservations', () => {
  it('keeps review and publication funds available after discovery uses its allowance', async () => {
    const allocations: number[] = [];
    const provider: ProviderRuntime = { name: 'fixture', capabilities: new Set(), async runPhase(req) {
      allocations.push(req.maxBudgetUsd!); return outcome(req.maxBudgetUsd!);
    } };
    const runtime = new BudgetedRuntime(provider, 10, () => 1, req => ({ analyze: 3, review: 1, evaluate: 0.5 }[req.phase] ?? 0));
    await runtime.runPhase(request());
    await expect(runtime.runPhase(request())).rejects.toThrow('exhausted');
    await runtime.runPhase(request('review'));
    await runtime.runPhase(request('evaluate'));
    await runtime.runPhase(request('report'));
    expect(allocations).toEqual([7, 2, 0.5, 0.5]);
  });
  it('does not give concurrent sessions the same unspent budget and reuses only settled remainder', async () => {
    const pending: Array<{ allocation: number; resolve: (value: ProviderPhaseOutcome) => void }> = [];
    const provider: ProviderRuntime = { name: 'fixture', capabilities: new Set(), runPhase: req => new Promise(resolve => pending.push({ allocation: req.maxBudgetUsd!, resolve })) };
    const runtime = new BudgetedRuntime(provider, 10, req => req.phase === 'analyze' ? 2 : 1);
    const first = runtime.runPhase(request()), second = runtime.runPhase(request());
    expect(pending.map(p => p.allocation)).toEqual([5, 5]);
    await expect(runtime.runPhase(request())).rejects.toThrow('reserved');
    pending[0]!.resolve(outcome(4)); await first;
    const third = runtime.runPhase(request()); expect(pending[2]!.allocation).toBe(1);
    pending[1]!.resolve(outcome(3)); pending[2]!.resolve(outcome(1)); await Promise.all([second, third]);
    const report = runtime.runPhase(request('report')); expect(pending[3]!.allocation).toBe(2);
    pending[3]!.resolve(outcome(2)); await report;
    await expect(runtime.runPhase(request())).rejects.toThrow('exhausted');
  });
  it('retains unaccounted reservations instead of refunding failed calls for unlimited retries', async () => {
    let calls = 0;
    const provider: ProviderRuntime = { name: 'fixture', capabilities: new Set(), async runPhase() {
      calls++; throw new ProviderRuntimeFailure('lost usage', { provider: 'fixture', costUsd: 0, accountingComplete: false });
    } };
    const runtime = new BudgetedRuntime(provider, 5, () => 1);
    await expect(runtime.runPhase(request())).rejects.toThrow('lost usage');
    await expect(runtime.runPhase(request())).rejects.toThrow('exhausted'); expect(calls).toBe(1);
  });
  it('accounts provider-reported failure charges before allowing another call', async () => {
    const allocations: number[] = [];
    const provider: ProviderRuntime = { name: 'fixture', capabilities: new Set(), async runPhase(req) {
      allocations.push(req.maxBudgetUsd!);
      if (allocations.length === 1) throw new ProviderRuntimeFailure('charged failure', { provider: 'fixture', costUsd: 4, accountingComplete: true });
      return outcome(1);
    } };
    const runtime = new BudgetedRuntime(provider, 5, () => 1);
    await expect(runtime.runPhase(request())).rejects.toThrow('charged failure'); await runtime.runPhase(request());
    expect(allocations).toEqual([5, 1]);
  });
  it('preserves stricter host limits and blocks later calls after provider overspend', async () => {
    const provider: ProviderRuntime = { name: 'fixture', capabilities: new Set(), async runPhase(req) {
      expect(req.maxBudgetUsd).toBe(2); return outcome(6);
    } };
    const runtime = new BudgetedRuntime(provider, 5, () => 1);
    await runtime.runPhase({ ...request(), maxBudgetUsd: 2 });
    await expect(runtime.runPhase(request())).rejects.toThrow('exhausted');
  });
  it('persists a reservation before the provider and settles known charges before returning', async () => {
    const order: string[] = [];
    const runtime = new BudgetedRuntime({ name: 'fixture', capabilities: new Set(), async runPhase(req) {
      order.push('provider'); expect(req.maxBudgetUsd).toBeCloseTo(3.2); return outcome(1);
    } }, 10, () => 1, () => 0, { spentUsd: 6.8,
      async reserve(_request, amount) { order.push('reserve'); expect(amount).toBeCloseTo(3.2); },
      async settle(_request, charge, complete) { order.push('settle'); expect(charge).toBe(1); expect(complete).toBe(true); },
    });
    await runtime.runPhase(request()); expect(order).toEqual(['reserve', 'provider', 'settle']);
  });
  it('does not invoke the provider if its reservation cannot be persisted', async () => {
    let calls = 0;
    const runtime = new BudgetedRuntime({ name: 'fixture', capabilities: new Set(), async runPhase() { calls++; return outcome(0); } },
      10, () => 1, () => 0, { spentUsd: 0, async reserve() { throw new Error('disk unavailable'); }, async settle() { throw new Error('unexpected settle'); } });
    await expect(runtime.runPhase(request())).rejects.toThrow('disk unavailable'); expect(calls).toBe(0);
  });

});
