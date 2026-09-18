/**
 * M9: canTransition — offsec domain adapter transition guard tests.
 */
import { describe, expect, it } from 'vitest';

import type { PhaseTransitionState } from '../domains/domain-adapter.js';
import { OffsecDomainAdapter } from '../domains/offsec.js';

function makeState(overrides: Partial<PhaseTransitionState> = {}): PhaseTransitionState {
  return {
    completedPhases: new Set<string>(),
    runStatus: 'running',
    totalCostUsd: 0,
    completedAttemptsByPhase: {},
    ...overrides,
  };
}

describe('OffsecDomainAdapter.canTransition', () => {
  const adapter = new OffsecDomainAdapter();

  it('allows va → verify when no constraints', () => {
    const state = makeState({ completedPhases: new Set(['va']) });
    const decision = adapter.canTransition!('va', 'verify', state);
    expect(decision.allowed).toBe(true);
  });

  it('blocks transition when budget is exhausted', () => {
    const state = makeState({
      completedPhases: new Set(['va']),
      totalCostUsd: 10,
      maxBudgetUsd: 10,
    });
    const decision = adapter.canTransition!('va', 'verify', state);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain('예산 소진');
  });

  it('blocks va-feedback when iteration limit reached', () => {
    const state = makeState({
      completedPhases: new Set(['va', 'verify']),
      completedAttemptsByPhase: { 'va-feedback': 2 },
    });
    const decision = adapter.canTransition!('verify', 'va-feedback', state);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain('va-feedback 반복 상한 초과');
  });

  it('allows va-feedback when under iteration limit', () => {
    const state = makeState({
      completedPhases: new Set(['va', 'verify']),
      completedAttemptsByPhase: { 'va-feedback': 1 },
    });
    const decision = adapter.canTransition!('verify', 'va-feedback', state);
    expect(decision.allowed).toBe(true);
  });

  it('blocks verify-feedback when iteration limit reached', () => {
    const state = makeState({
      completedPhases: new Set(['va', 'verify', 'va-feedback']),
      completedAttemptsByPhase: { 'verify-feedback': 2 },
    });
    const decision = adapter.canTransition!('va-feedback', 'verify-feedback', state);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain('verify-feedback 반복 상한 초과');
  });

  it('blocks pentest-feedback when iteration limit reached', () => {
    const state = makeState({
      completedPhases: new Set(['va', 'verify', 'pentest-plan', 'pentest-discovery', 'pentest', 'pentest-verify']),
      completedAttemptsByPhase: { 'pentest-feedback': 2 },
    });
    const decision = adapter.canTransition!('pentest-verify', 'pentest-feedback', state);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain('pentest-feedback 반복 상한 초과');
  });

  it('blocks pentest-verify-feedback when iteration limit reached', () => {
    const state = makeState({
      completedPhases: new Set(['va', 'verify', 'pentest-plan', 'pentest-discovery', 'pentest', 'pentest-verify', 'pentest-feedback']),
      completedAttemptsByPhase: { 'pentest-verify-feedback': 2 },
    });
    const decision = adapter.canTransition!('pentest-feedback', 'pentest-verify-feedback', state);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain('pentest-verify-feedback 반복 상한 초과');
  });

  it('blocks converge when verify not completed', () => {
    const state = makeState({ completedPhases: new Set(['va']) });
    const decision = adapter.canTransition!('va', 'converge', state);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain('converge는 verify 완료 후에만');
  });

  it('allows converge when verify is completed', () => {
    const state = makeState({ completedPhases: new Set(['va', 'verify']) });
    const decision = adapter.canTransition!('verify', 'converge', state);
    expect(decision.allowed).toBe(true);
  });
});
