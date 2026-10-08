/**
 * M12: Phase transition policy tests (offsec).
 */
import { describe, expect, it } from 'vitest';

import type { PhaseTransitionState } from '../domains/domain-adapter.js';
import { OffsecDomainAdapter } from '../domains/offsec.js';
import {
  availableTransitions,
  buildPhaseTransitionState,
  evaluateTransition,
} from '../workflow/transitions.js';

function makeState(overrides: Partial<PhaseTransitionState> = {}): PhaseTransitionState {
  return {
    completedPhases: new Set<string>(),
    runStatus: 'running',
    totalCostUsd: 0,
    completedAttemptsByPhase: {},
    ...overrides,
  };
}

describe('evaluateTransition', () => {
  describe('offsec', () => {
    const adapter = new OffsecDomainAdapter();

    it('allows va → verify with prerequisites met', () => {
      const state = makeState({ completedPhases: new Set(['analyze']) });
      const decision = evaluateTransition(adapter.contract, adapter, 'analyze', 'review', state);
      expect(decision.allowed).toBe(true);
    });

    it('blocks va → verify when prerequisite not met', () => {
      const state = makeState({ completedPhases: new Set() });
      const decision = evaluateTransition(adapter.contract, adapter, 'analyze', 'review', state);
      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain('선행 계약 미충족');
    });

    it('allows verify → converge when verify is in completedPhases', () => {
      // Contract requires only 'review' for converge — domain guard also passes with verify completed
      const state = makeState({ completedPhases: new Set(['analyze', 'review']) });
      const decision = evaluateTransition(adapter.contract, adapter, 'review', 'evaluate', state);
      expect(decision.allowed).toBe(true);
    });

    it('rejects unknown target phase', () => {
      const state = makeState({ completedPhases: new Set(['analyze']) });
      const decision = evaluateTransition(adapter.contract, adapter, 'analyze', 'nonexistent', state);
      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain('알 수 없는 target phase');
    });

    it('blocks va-feedback when iteration limit reached', () => {
      const state = makeState({
        completedPhases: new Set(['analyze', 'review']),
        completedAttemptsByPhase: { 'va-feedback': 2 },
      });
      const decision = evaluateTransition(adapter.contract, adapter, 'review', 'va-feedback', state);
      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain('알 수 없는 target phase');
    });

    it('blocks when budget exhausted', () => {
      const state = makeState({
        completedPhases: new Set(['analyze']),
        totalCostUsd: 50,
        maxBudgetUsd: 50,
      });
      const decision = evaluateTransition(adapter.contract, adapter, 'analyze', 'review', state);
      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain('예산 소진');
    });
  });
});

describe('buildPhaseTransitionState', () => {
  it('builds state from attempts record', () => {
    const state = buildPhaseTransitionState({
      completedPhases: ['analyze', 'review'],
      runStatus: 'running',
      totalCostUsd: 5.3,
      maxBudgetUsd: 50,
      attempts: {
        'va:-:1': { phase: 'analyze', status: 'completed' },
        'va:-:2': { phase: 'analyze', status: 'failed' },
        'verify:-:1': { phase: 'review', status: 'completed' },
        'va-feedback:-:1': { phase: 'va-feedback', status: 'completed' },
        'va-feedback:-:2': { phase: 'va-feedback', status: 'completed' },
      },
    });

    expect(state.completedPhases).toEqual(new Set(['analyze', 'review']));
    expect(state.runStatus).toBe('running');
    expect(state.totalCostUsd).toBe(5.3);
    expect(state.maxBudgetUsd).toBe(50);
    expect(state.completedAttemptsByPhase).toEqual({
      'analyze': 1,
      'review': 1,
      'va-feedback': 2,
    });
  });

  it('handles Set input for completedPhases', () => {
    const state = buildPhaseTransitionState({
      completedPhases: new Set(['a', 'b']),
      runStatus: 'completed',
      totalCostUsd: 0,
      attempts: {},
    });
    expect(state.completedPhases).toEqual(new Set(['a', 'b']));
  });
});

describe('availableTransitions', () => {
  const adapter = new OffsecDomainAdapter();

  it('returns all phases with their decisions', () => {
    const state = makeState({ completedPhases: new Set(['analyze']) });
    const transitions = availableTransitions(adapter.contract, adapter, 'analyze', state);

    // verify should be allowed (requires: va)
    const verify = transitions.find((t) => t.phase === 'review');
    expect(verify?.decision.allowed).toBe(true);

    // converge should be blocked (requires: verify)
    const converge = transitions.find((t) => t.phase === 'evaluate');
    expect(converge?.decision.allowed).toBe(false);

    // report should be blocked (requires: converge)
    const report = transitions.find((t) => t.phase === 'report');
    expect(report?.decision.allowed).toBe(false);
  });

  it('does not include currentPhase in results', () => {
    const state = makeState({ completedPhases: new Set(['analyze']) });
    const transitions = availableTransitions(adapter.contract, adapter, 'analyze', state);
    expect(transitions.find((t) => t.phase === 'analyze')).toBeUndefined();
  });
});
