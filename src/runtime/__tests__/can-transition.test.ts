import { describe, expect, it } from 'vitest';
import type { PhaseTransitionState } from '../domains/domain-adapter.js';
import { OffsecDomainAdapter } from '../domains/offsec.js';
const state = (overrides: Partial<PhaseTransitionState> = {}): PhaseTransitionState => ({
  completedPhases: new Set(), runStatus: 'running', totalCostUsd: 0, completedAttemptsByPhase: {}, ...overrides,
});
describe('single OffSec phase transitions', () => {
  const adapter = new OffsecDomainAdapter();
  it('allows analysis to independent review and retains explicit budget enforcement', () => {
    expect(adapter.canTransition('analyze', 'review', state({ completedPhases: new Set(['analyze']) })).allowed).toBe(true);
    expect(adapter.canTransition('analyze', 'review', state({ totalCostUsd: 10, maxBudgetUsd: 10 })).reason).toContain('예산 소진');
    expect(adapter.canTransition('analyze', 'review', state({ totalCostUsd: 1000 })).allowed).toBe(true);
  });
  it.each(['va', 'verify', 'converge', 'va-feedback', 'verify-feedback', 'pentest', 'pentest-feedback', 'pentest-verify-feedback', 'redteam'])('rejects retired phase %s', phase => {
    expect(adapter.canTransition('analyze', phase, state())).toMatchObject({ allowed: false, reason: expect.stringContaining('Unsupported') });
  });
  it('requires review before evaluation and evaluation before reporting', () => {
    expect(adapter.canTransition('analyze', 'evaluate', state()).allowed).toBe(false);
    expect(adapter.canTransition('review', 'evaluate', state({ completedPhases: new Set(['review']) })).allowed).toBe(true);
    expect(adapter.canTransition('review', 'report', state()).allowed).toBe(false);
    expect(adapter.canTransition('evaluate', 'report', state({ completedPhases: new Set(['evaluate']) })).allowed).toBe(true);
  });
});
