import { ProviderRuntimeFailure, type ProviderRuntime, type ProviderPhaseRequest, type ProviderPhaseOutcome } from './provider-runtime.js';

export class MissionBudgetExhaustedError extends Error {}

export type BudgetAccounting<TOptions> = {
  spentUsd: number;
  reserve(request: ProviderPhaseRequest<TOptions>, amountUsd: number): Promise<void>;
  settle(request: ProviderPhaseRequest<TOptions>, chargedUsd: number, accountingComplete: boolean): Promise<void>;
};

/** One mission's concurrent sessions reserve disjoint portions of its budget. */
export class BudgetedRuntime<TOptions, TRaw> implements ProviderRuntime<TOptions, TRaw> {
  readonly name;
  readonly capabilities;
  private spent = 0;
  private reserved = 0;
  private active = 0;
  constructor(private readonly runtime: ProviderRuntime<TOptions, TRaw>, private readonly limit: number,
    private readonly concurrency: (request: ProviderPhaseRequest<TOptions>) => number,
    private readonly reserveForLater: (request: ProviderPhaseRequest<TOptions>) => number = () => 0,
    private readonly accounting?: BudgetAccounting<TOptions>) {
    if (!Number.isFinite(limit) || limit <= 0) throw new Error('invalid mission budget');
    this.spent = accounting?.spentUsd ?? 0;
    if (!Number.isFinite(this.spent) || this.spent < 0) throw new Error('invalid recovered mission spend');
    this.name = runtime.name; this.capabilities = runtime.capabilities;
  }
  async runPhase(request: ProviderPhaseRequest<TOptions>): Promise<ProviderPhaseOutcome<TRaw>> {
    const futureReserve = this.reserveForLater(request);
    if (!Number.isFinite(futureReserve) || futureReserve < 0 || futureReserve >= this.limit) throw new Error('invalid future phase budget reserve');
    const available = this.limit - this.spent - this.reserved - futureReserve;
    const slots = Math.max(1, this.concurrency(request) - this.active);
    const allocation = Math.min(available / slots, request.maxBudgetUsd ?? available);
    if (!(allocation > 0)) throw new MissionBudgetExhaustedError('mission budget is exhausted or reserved by active sessions');
    this.active++; this.reserved += allocation;
    // Missing usage must never release possibly-spent money for another retry.
    let charged = allocation, accountingComplete = false, invoked = false;
    const account = (usage: { costUsd?: number; accountingComplete?: boolean } | undefined) => {
      if (usage?.accountingComplete !== false && typeof usage?.costUsd === 'number'
        && Number.isFinite(usage.costUsd) && usage.costUsd >= 0) { charged = usage.costUsd; accountingComplete = true; }
    };
    try {
      // Persist the reservation before a provider can spend money. A crash after this
      // point keeps the full allocation charged until a durable settlement exists.
      if (this.accounting) await this.accounting.reserve(request, allocation);
      invoked = true;
      const outcome = await this.runtime.runPhase({ ...request, maxBudgetUsd: allocation });
      account(outcome.usage); return outcome;
    } catch (error) {
      if (error instanceof ProviderRuntimeFailure) account(error.usage);
      throw error;
    } finally {
      // An uncertain reservation write is conservative too; never recycle it locally.
      this.active--; this.reserved -= allocation; this.spent += charged;
      if (this.active === 0) this.reserved = 0;
      if (invoked) await this.accounting?.settle(request, charged, accountingComplete);
    }
  }
}
