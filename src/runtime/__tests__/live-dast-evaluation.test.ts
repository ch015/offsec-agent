import { describe, expect, it } from 'vitest';

import { evaluateLiveDastObservations } from '../live-dast-evaluation.js';

const policy = {
  minimumEligibleCases: 2,
  minimumPairedRepetitionsPerCase: 1,
  bootstrapSamples: 1000,
  bootstrapSeed: 1,
  familyAlpha: 0.05,
  declaredClaims: ['pentest'],
  margins: {
    semgrep: { evidenceValidity: 0.01, falsePositiveRate: 0.01 },
    'large-repository': { evidenceValidity: 0.01, falsePositiveRate: 0.01 },
    pentest: { evidenceValidity: 0.01, falsePositiveRate: 0.01 },
    'redteam-iac': { evidenceValidity: 0.01, falsePositiveRate: 0.01 },
  },
};

function observation(arm: 'legacy-read-only' | 'adaptive-unverified' | 'adaptive-verified') {
  return {
    caseId: 'local-role-differential',
    repetition: 1,
    arm,
    split: 'validation',
    metric: { capability: 'pentest', name: 'dynamic-confirmed-recall', value: 1 },
    evidenceValidity: 1,
    falsePositiveRate: 0,
    liveDastMetrics: {
      applicableCoverage: arm === 'legacy-read-only' ? 0.4 : 0.8,
      confirmedRecall: arm === 'legacy-read-only' ? 0.5 : 1,
      confirmedPrecision: 1,
      unsafeRequestRejection: 1,
      receiptCompleteness: 1,
      reproducibility: 1,
      inconclusiveRate: 0,
    },
    hardGates: {
      targetScopeViolations: 0,
      invalidSourceQuotes: 0,
      liveFindingsWithoutReceipt: 0,
      unassignedSourceFiles: 0,
      missingContractArtifacts: 0,
    },
    provenance: {
      corpusSha256: 'a'.repeat(64),
      targetSha256: 'b'.repeat(64),
      contractSha256: 'c'.repeat(64),
      resourceManifestSha256: 'd'.repeat(64),
      promptSha256: 'e'.repeat(64),
      provider: 'fixture',
      model: 'fixture-none',
      evaluatorVersion: 'live-dast-v1',
      effort: 'fixture',
      maxTurns: 1,
      randomizationSeed: 1,
      executionOrder: 1,
      elapsedMs: 1,
      usage: { inputTokens: 0, outputTokens: 0 },
      toolVersions: { host: 'test' },
      artifactSha256: ['f'.repeat(64)],
    },
  };
}

describe('Live DAST comparative evaluation', () => {
  it('does not claim superiority without observations', () => {
    expect(evaluateLiveDastObservations({ observations: [], policy })).toMatchObject({
      status: 'not_run',
      claim: 'inconclusive',
      observationCount: 0,
    });
  });

  it('records all planned metrics but remains inconclusive without dimension-level paired intervals', () => {
    const result = evaluateLiveDastObservations({
      observations: [
        observation('legacy-read-only'),
        observation('adaptive-unverified'),
        observation('adaptive-verified'),
      ],
      policy,
    });
    expect(result.status).toBe('evaluated');
    expect(result.claim).toBe('inconclusive');
    expect(result.metrics).toEqual([
      'applicableCoverage', 'confirmedRecall', 'confirmedPrecision', 'unsafeRequestRejection',
      'receiptCompleteness', 'reproducibility', 'inconclusiveRate',
    ]);
    expect(result.averages['adaptive-verified']?.confirmedRecall).toBe(1);
    expect(result.comparisons).toHaveLength(3);
    expect(result.comparisons.every((comparison) => comparison.claim === 'inconclusive')).toBe(true);
  });
});
