import { resolveRunBudget } from './assessment-support.js';
import type { BudgetAccounting } from '../providers/budgeted-runtime.js';
import type { MissionRuntime } from '../workflow/mission-runtime.js';
import type { RunSnapshot } from '../workflow/state-store.js';

/** Include calls whose provider result never reached attempt.received. */
export function committedBudget(snapshot: Readonly<RunSnapshot>): number {
  let committed = 0;
  const keys = new Set([...Object.keys(snapshot.attempts), ...Object.keys(snapshot.budgetReservations ?? {})]);
  for (const key of keys) {
    const attempt = snapshot.attempts[key], reservation = snapshot.budgetReservations?.[key];
    if (reservation) committed += Math.max(attempt?.usage?.costUsd ?? 0, reservation.chargedUsd ?? reservation.amountUsd);
    else if (attempt?.usage?.accountingComplete === false || attempt?.status === 'started') {
      // Legacy calls have no durable allocation. A missing receipt is not zero spend.
      if (snapshot.maxBudgetUsd !== undefined) return Math.max(snapshot.maxBudgetUsd, snapshot.totalCostUsd);
    } else committed += attempt?.usage?.costUsd ?? 0;
  }
  return Math.max(committed, snapshot.totalCostUsd);
}

export function budgetAccounting<TOptions>(runtime: MissionRuntime, snapshot: Readonly<RunSnapshot>): BudgetAccounting<TOptions> {
  return {
    spentUsd: committedBudget(snapshot),
    async reserve(request, amountUsd) {
      await runtime.append({ type: 'budget.reserved', eventId: `${request.runId}:${request.attempt}:budget-reserved`,
        attemptKey: request.attempt, amountUsd });
    },
    async settle(request, chargedUsd, accountingComplete) {
      await runtime.append({ type: 'budget.settled', eventId: `${request.runId}:${request.attempt}:budget-settled`,
        attemptKey: request.attempt, chargedUsd, accountingComplete });
    },
  };
}

/** Preserve uncertain legacy allocations before interrupted attempts become failed. */
export async function recoverLegacyBudget(runtime: MissionRuntime, snapshot: Readonly<RunSnapshot>): Promise<void> {
  if (snapshot.maxBudgetUsd === undefined) return;
  const uncertain = Object.entries(snapshot.attempts).find(([key, attempt]) => !snapshot.budgetReservations?.[key]
    && (attempt.status === 'started' || attempt.usage?.accountingComplete === false));
  if (!uncertain) return;
  const [attemptKey, attempt] = uncertain;
  const otherCommitted = Object.entries(snapshot.attempts).filter(([key]) => key !== attemptKey).reduce((total, [key, value]) => {
    const reservation = snapshot.budgetReservations?.[key];
    return total + Math.max(value.usage?.costUsd ?? 0, reservation?.chargedUsd ?? reservation?.amountUsd ?? 0);
  }, 0);
  const amountUsd = Math.max(attempt.usage?.costUsd ?? 0, snapshot.maxBudgetUsd - otherCommitted);
  if (amountUsd <= 0) return; // Other durable charges already exhaust the original limit.
  await runtime.append({ type: 'budget.reserved', eventId: `${snapshot.runId}:${attemptKey}:legacy-budget-reserved`,
    attemptKey, amountUsd, recovered: true });
}

/** Only budget settings may change on resume; sealed source inputs stay unchanged. */
export type ResumeBudgetOptions = { maxBudgetUsd?: number; noCostGuard?: boolean };

export async function increaseResumeBudget(runtime: MissionRuntime, options: ResumeBudgetOptions,
  contractMaximum: number | null): Promise<Readonly<RunSnapshot>> {
  const snapshot = await runtime.read();
  if (options.noCostGuard !== true && options.maxBudgetUsd === undefined) return snapshot;
  const next = options.noCostGuard ? undefined : resolveRunBudget(options.maxBudgetUsd, contractMaximum);
  if (next === snapshot.maxBudgetUsd) return snapshot;
  if (next !== undefined && (snapshot.maxBudgetUsd === undefined || next < snapshot.maxBudgetUsd)) {
    throw new Error('resume budget must increase the current limit; use noCostGuard to remove it');
  }
  return runtime.append({ type: 'run.budget-increased',
    eventId: `${snapshot.runId}:budget-increased:${snapshot.lastSeq + 1}`,
    previousMaxBudgetUsd: snapshot.maxBudgetUsd ?? null, maxBudgetUsd: next ?? null });
}
