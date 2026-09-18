/**
 * M12: Phase transition policy — codified transition conditions.
 *
 * Provides a pre-flight query API for mission orchestrators (assess.ts, feedback.ts, etc.)
 * to check whether a transition is allowed before calling engine.ts executePhase().
 *
 * Runtime enforcement remains in engine.ts via assertWorkflowPrerequisites (contract-level)
 * and the existing budget check. This module adds domain-specific guards on top for
 * orchestration-level decisions (e.g., feedback iteration caps, budget pre-checks).
 *
 * evaluateTransition() intentionally mirrors the prerequisite check so orchestrators
 * get a single consolidated answer without calling engine.ts and catching throws.
 *
 * This does NOT change phase order, concurrency, or work-unit cap.
 */
import type { DomainAdapter, PhaseTransitionState, TransitionDecision } from '../domains/domain-adapter.js';
import type { WorkflowContract, WorkflowPhase } from '../contracts/workflow-contract.js';

/**
 * A named transition rule — one entry per allowed phase edge.
 *
 * @planned Future extension: explicit per-edge policies can be registered here
 * for advanced orchestration scenarios (e.g., conditional pentest gating based on
 * finding severity thresholds). Currently unused — domain adapters implement
 * canTransition() directly instead. Retained as a stable type contract.
 */
export interface TransitionPolicy {
  readonly from: string;
  readonly to: string;
  readonly condition: (state: PhaseTransitionState) => TransitionDecision;
}

/**
 * Pre-flight query: evaluate whether a transition from `from` to `to` is allowed.
 *
 * This is a read-only decision function for orchestrators. It does NOT throw.
 * Runtime enforcement in engine.ts uses assertWorkflowPrerequisites (which throws).
 * Both check the same contract prerequisites, so their answers are consistent.
 *
 * Checks (in order):
 * 1. Contract prerequisite: `to` phase's required phases must be in completedPhases.
 * 2. Domain adapter canTransition guard (if implemented).
 *
 * Returns a consolidated TransitionDecision.
 */
export function evaluateTransition(
  contract: WorkflowContract,
  adapter: DomainAdapter,
  from: string,
  to: string,
  state: PhaseTransitionState,
): TransitionDecision {
  // 1. Find the target phase in contract
  const toPhase = contract.phases.find((p) => p.id === to);
  if (!toPhase) {
    return { allowed: false, reason: `알 수 없는 target phase: ${to}` };
  }

  // 2. Check contract prerequisites
  const missingPrereqs = toPhase.requires.filter((req) => !state.completedPhases.has(req));
  if (missingPrereqs.length > 0) {
    return {
      allowed: false,
      reason: `${to} 선행 계약 미충족: ${missingPrereqs.join(', ')}`,
    };
  }

  // 3. Domain-specific guard
  if (adapter.canTransition) {
    const domainDecision = adapter.canTransition(from, to, state);
    if (!domainDecision.allowed) return domainDecision;
  }

  return { allowed: true };
}

/**
 * Build a PhaseTransitionState from a RunSnapshot-like input.
 */
export function buildPhaseTransitionState(input: {
  completedPhases: ReadonlySet<string> | readonly string[];
  runStatus: 'running' | 'awaiting-input' | 'completed' | 'blocked';
  totalCostUsd: number;
  maxBudgetUsd?: number;
  attempts: Readonly<Record<string, { phase: string; status: string }>>;
}): PhaseTransitionState {
  const completedPhases = input.completedPhases instanceof Set
    ? input.completedPhases as ReadonlySet<string>
    : new Set(input.completedPhases);

  // Count completed attempts per phase
  const completedAttemptsByPhase: Record<string, number> = {};
  for (const attempt of Object.values(input.attempts)) {
    if (attempt.status === 'completed') {
      completedAttemptsByPhase[attempt.phase] = (completedAttemptsByPhase[attempt.phase] ?? 0) + 1;
    }
  }

  return {
    completedPhases,
    runStatus: input.runStatus,
    totalCostUsd: input.totalCostUsd,
    maxBudgetUsd: input.maxBudgetUsd,
    completedAttemptsByPhase,
  };
}

/**
 * Given the current state and a contract, compute the set of phases that are
 * eligible to transition to from `currentPhase`.
 */
export function availableTransitions(
  contract: WorkflowContract,
  adapter: DomainAdapter,
  currentPhase: string,
  state: PhaseTransitionState,
): Array<{ phase: string; decision: TransitionDecision }> {
  return contract.phases
    .filter((p) => p.id !== currentPhase)
    .map((p) => ({
      phase: p.id,
      decision: evaluateTransition(contract, adapter, currentPhase, p.id, state),
    }));
}
