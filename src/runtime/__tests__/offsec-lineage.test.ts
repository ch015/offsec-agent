import { describe, expect, it } from 'vitest';

import { assertOffsecConvergenceReady } from '../domains/offsec.js';
import { loadOffsecContract, type PhaseResult } from '../offsec-contract.js';

function result(phase: string, role: string, objectionCount = 0): PhaseResult {
  return {
    contractVersion: loadOffsecContract().version,
    phase,
    role,
    status: 'complete',
    artifacts: [],
    summary: 'test',
    metrics: { findingCount: 0, objectionCount },
    unresolved: [],
  };
}

describe('OffSec convergence lineage', () => {
  it('rejects stale verification after a newer feedback result', () => {
    expect(() =>
      assertOffsecConvergenceReady(
        [
          { phase: 'verify', result: result('verify', 'verifier') },
          { phase: 'va-feedback', result: result('va-feedback', 'va-auditor') },
        ],
        'VA_ONLY',
      ),
    ).toThrow(/최신 feedback/);
  });

  it('requires configured pentest and redteam phases', () => {
    const verified = [{ phase: 'verify', result: result('verify', 'verifier') }];
    expect(() => assertOffsecConvergenceReady(verified, 'VA_PENTEST')).toThrow(/pentest/);
    expect(() =>
      assertOffsecConvergenceReady(
        [...verified, { phase: 'pentest', result: result('pentest', 'pentester') }],
        'VA_PENTEST_REDTEAM',
      ),
    ).toThrow(/독립 검증/);
    expect(() =>
      assertOffsecConvergenceReady(
        [
          ...verified,
          { phase: 'pentest', result: result('pentest', 'pentester') },
          { phase: 'pentest-verify', result: result('pentest-verify', 'verifier') },
        ],
        'VA_PENTEST_REDTEAM',
      ),
    ).toThrow(/redteam/);
  });

  it('requires pentest feedback to be independently reverified without objections', () => {
    const executions = [
      { phase: 'verify', result: result('verify', 'verifier') },
      { phase: 'pentest', result: result('pentest', 'pentester') },
      { phase: 'pentest-verify', result: result('pentest-verify', 'verifier', 1) },
      { phase: 'pentest-feedback', result: result('pentest-feedback', 'pentester') },
    ];
    expect(() => assertOffsecConvergenceReady(executions, 'VA_PENTEST')).toThrow(/재검증/);
    expect(() => assertOffsecConvergenceReady([
      ...executions,
      { phase: 'pentest-verify-feedback', result: result('pentest-verify-feedback', 'verifier', 1) },
    ], 'VA_PENTEST')).not.toThrow();
    expect(() => assertOffsecConvergenceReady([
      ...executions,
      { phase: 'pentest-verify-feedback', result: result('pentest-verify-feedback', 'verifier') },
    ], 'VA_PENTEST')).not.toThrow();
  });

  it('allows an objection-bearing latest verifier result to proceed', () => {
    expect(() =>
      assertOffsecConvergenceReady(
        [{ phase: 'verify-feedback', result: result('verify-feedback', 'verifier', 1) }],
        'VA_ONLY',
      ),
    ).not.toThrow();
  });
});
