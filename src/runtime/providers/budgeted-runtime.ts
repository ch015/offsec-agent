import { ProviderRuntimeFailure, type ProviderRuntime, type ProviderPhaseRequest, type ProviderPhaseOutcome } from './provider-runtime.js';

/** One mission's concurrent sessions reserve disjoint portions of its budget. */
export class BudgetedRuntime<TOptions, TRaw> implements ProviderRuntime<TOptions, TRaw> {
  readonly name;
  readonly capabilities;
  private spent = 0;
  private reserved = 0;
  private active = 0;
  constructor(private readonly runtime: ProviderRuntime<TOptions, TRaw>, private readonly limit: number,
    private readonly concurrency: (request: ProviderPhaseRequest<TOptions>) => number) {
    if (!Number.isFinite(limit) || limit <= 0) throw new Error('invalid mission budget');
    this.name = runtime.name; this.capabilities = runtime.capabilities;
  }
  async runPhase(request: ProviderPhaseRequest<TOptions>): Promise<ProviderPhaseOutcome<TRaw>> {
    const available = this.limit - this.spent - this.reserved;
    const slots = Math.max(1, this.concurrency(request) - this.active);
    const allocation = Math.min(available / slots, request.maxBudgetUsd ?? available);
    if (!(allocation > 0)) throw new Error('mission budget is exhausted or reserved by active sessions');
    this.active++; this.reserved += allocation;
    // Missing usage must never release possibly-spent money for another retry.
    let charged = allocation;
    const account = (usage: { costUsd?: number; accountingComplete?: boolean } | undefined) => {
      if (usage?.accountingComplete !== false && typeof usage?.costUsd === 'number'
        && Number.isFinite(usage.costUsd) && usage.costUsd >= 0) charged = usage.costUsd;
    };
    try {
      const outcome = await this.runtime.runPhase({ ...request, maxBudgetUsd: allocation });
      account(outcome.usage); return outcome;
    } catch (error) {
      if (error instanceof ProviderRuntimeFailure) account(error.usage);
      throw error;
    } finally {
      this.active--; this.reserved -= allocation; this.spent += charged;
      if (this.active === 0) this.reserved = 0;
    }
  }
}
