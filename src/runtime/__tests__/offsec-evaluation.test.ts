import { describe, expect, it } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { compareOffsecArms } from '../offsec-evaluation.js';
import { claimHoldoutOpening, evaluateObservationSet } from '../../../scripts/eval-offsec.js';
import { benchmarkSha256, benchmarkStableJson } from '../offsec-benchmark.js';

const hash = 'a'.repeat(64);
const policy = {
  minimumEligibleCases: 2,
  minimumPairedRepetitionsPerCase: 2,
  bootstrapSamples: 1_000,
  bootstrapSeed: 17,
  familyAlpha: 0.05,
  declaredClaims: ['large-repository'],
  margins: {
    semgrep: { evidenceValidity: 0.01, falsePositiveRate: 0.01 },
    'large-repository': { evidenceValidity: 0.01, falsePositiveRate: 0.01 },
    pentest: { evidenceValidity: 0.01, falsePositiveRate: 0.01 },
    'redteam-iac': { evidenceValidity: 0.01, falsePositiveRate: 0.01 },
  },
};

function observation(input: {
  caseId: string;
  repetition: number;
  arm: 'ch015' | 'current-parallel';
  recall: number;
  evidence?: number;
  falsePositive?: number;
  scopeViolations?: number;
}) {
  return {
    caseId: input.caseId,
    repetition: input.repetition,
    arm: input.arm,
    split: 'validation',
    metric: { capability: 'large-repository', name: 'ground-truth-recall', value: input.recall },
    evidenceValidity: input.evidence ?? 1,
    falsePositiveRate: input.falsePositive ?? 0,
    hardGates: {
      targetScopeViolations: input.scopeViolations ?? 0,
      invalidSourceQuotes: 0,
      liveFindingsWithoutReceipt: 0,
      unassignedSourceFiles: 0,
      missingContractArtifacts: 0,
    },
    provenance: {
      corpusSha256: hash,
      targetSha256: hash,
      contractSha256: hash,
      resourceManifestSha256: hash,
      promptSha256: hash,
      provider: 'fixture',
      model: 'matched-model',
      evaluatorVersion: '1.0.0',
      effort: 'high',
      maxTurns: 120,
      randomizationSeed: 7,
      executionOrder: input.repetition,
      elapsedMs: 100,
      usage: { inputTokens: 10, outputTokens: 5 },
      toolVersions: { semgrep: '1.157.0' },
      artifactSha256: [hash],
    },
  };
}

function paired(candidateDelta = 0.2) {
  return ['case-aaaaaaaa', 'case-bbbbbbbb'].flatMap((caseId) => [1, 2].flatMap((repetition) => [
    observation({ caseId, repetition, arm: 'ch015', recall: 0.5 }),
    observation({ caseId, repetition, arm: 'current-parallel', recall: 0.5 + candidateDelta }),
  ]));
}

describe('OffSec comparative claim gate', () => {
  it('keeps baseline arms separate in the provider-neutral result', () => {
    const result = evaluateObservationSet({ observations: paired(), policy, split: 'validation' });
    expect(result.status).toBe('evaluated');
    expect(result.claimAuthority).toBe('diagnostic-only');
    expect(result.comparisons.map((comparison) => comparison.baseline)).toEqual([
      'ch015', 'current-sequential',
    ]);
  });

  it('binds one-time holdout opening to corpus and policy outside result paths', () => {
    const stateDir = mkdtempSync(join(tmpdir(), 'nunchi-holdout-state-'));
    const corpusCore = {
      schemaVersion: '1.0.0' as const,
      corpusId: 'corpus-holdout-test',
      split: 'holdout' as const,
      claimAuthority: 'final-holdout' as const,
      cases: ['case-aaaaaaaa', 'case-bbbbbbbb'].map((caseId) => ({
        caseId,
        capability: 'large-repository' as const,
        sourceManifestSha256: hash,
        repositoryPseudonym: `repo-${caseId === 'case-aaaaaaaa' ? '111111111111' : '222222222222'}`,
        vulnerableRevision: '1'.repeat(40),
        labels: [{
          labelId: `GT-${caseId === 'case-aaaaaaaa' ? 'A' : 'B'}`,
          rootCauseId: `RC-${caseId === 'case-aaaaaaaa' ? 'A' : 'B'}`,
          title: caseId,
          cwes: ['CWE-20'],
          modality: 'static' as const,
          anchors: [{ path: 'app.ts', lineStart: 1, lineEnd: 1, quote: 'source' }],
        }],
      })),
    };
    const corpus = { ...corpusCore, corpusSha256: benchmarkSha256(benchmarkStableJson(corpusCore)) };
    const holdout = paired().map((value) => ({
      ...value,
      split: 'holdout' as const,
      provenance: { ...value.provenance, corpusSha256: corpus.corpusSha256 },
    }));
    expect(claimHoldoutOpening({ observations: holdout, policySha256: hash, corpus, stateDir }).bindingSha256)
      .toMatch(/^[a-f0-9]{64}$/);
    expect(() => claimHoldoutOpening({ observations: holdout, policySha256: hash, corpus, stateDir }))
      .toThrow(/이미 개봉/);
    expect(() => claimHoldoutOpening({ observations: [...holdout].reverse(), policySha256: hash, corpus, stateDir }))
      .toThrow(/이미 개봉/);
    const changedObservationSet = holdout.map((value, index) => index === 0
      ? { ...value, metric: { ...value.metric, value: 0.4 } }
      : value);
    expect(() => claimHoldoutOpening({
      observations: changedObservationSet, policySha256: hash, corpus, stateDir,
    })).toThrow(/이미 개봉/);
    expect(() => claimHoldoutOpening({
      observations: holdout.filter((value) => value.caseId === 'case-aaaaaaaa'),
      policySha256: hash,
      corpus,
      stateDir: mkdtempSync(join(tmpdir(), 'nunchi-holdout-subset-')),
    })).toThrow(/전체 case/);
    expect(() => claimHoldoutOpening({
      observations: holdout.map((value) => ({
        ...value, provenance: { ...value.provenance, targetSha256: 'b'.repeat(64) },
      })),
      policySha256: hash,
      corpus,
      stateDir: mkdtempSync(join(tmpdir(), 'nunchi-holdout-target-')),
    })).toThrow(/target/);
  });

  it('rejects observations from a different split', () => {
    expect(() => evaluateObservationSet({ observations: paired(), policy, split: 'holdout' }))
      .toThrow(/split/);
  });
  it('uses case-clustered paired evidence before declaring superiority', () => {
    const result = compareOffsecArms({
      observations: paired(),
      capability: 'large-repository',
      baseline: 'ch015',
      candidate: 'current-parallel',
      policy,
    });
    expect(result).toMatchObject({ claim: 'superior', eligibleCases: 2, pairedRepetitions: 4 });
    expect(result.primaryDifference.lower).toBeGreaterThan(0);
  });

  it('fails the claim when any candidate observation violates a hard gate', () => {
    const values = paired();
    values[1] = observation({
      caseId: 'case-aaaaaaaa', repetition: 1, arm: 'current-parallel', recall: 0.7, scopeViolations: 1,
    });
    expect(compareOffsecArms({
      observations: values,
      capability: 'large-repository',
      baseline: 'ch015',
      candidate: 'current-parallel',
      policy,
    }).claim).toBe('inferior');
  });

  it('applies hard gates only to paired observations and treats an invalid baseline as inconclusive', () => {
    const unpairedFailure = observation({
      caseId: 'case-cccccccc', repetition: 1, arm: 'current-parallel', recall: 0, scopeViolations: 1,
    });
    expect(compareOffsecArms({
      observations: [...paired(), unpairedFailure], capability: 'large-repository',
      baseline: 'ch015', candidate: 'current-parallel', policy,
    }).claim).toBe('superior');
    const invalidBaseline = paired();
    invalidBaseline[0] = observation({
      caseId: 'case-aaaaaaaa', repetition: 1, arm: 'ch015', recall: 0.5, scopeViolations: 1,
    });
    expect(compareOffsecArms({
      observations: invalidBaseline, capability: 'large-repository',
      baseline: 'ch015', candidate: 'current-parallel', policy,
    }).claim).toBe('inconclusive');
  });

  it('reports inconclusive when eligible independent cases are insufficient', () => {
    expect(compareOffsecArms({
      observations: paired().filter((value) => value.caseId === 'case-aaaaaaaa'),
      capability: 'large-repository',
      baseline: 'ch015',
      candidate: 'current-parallel',
      policy,
    }).claim).toBe('inconclusive');
  });

  it('rejects paired arms from different target provenance', () => {
    const values = paired();
    values[1] = {
      ...values[1],
      provenance: { ...values[1]!.provenance, targetSha256: 'b'.repeat(64) },
    };
    expect(() => compareOffsecArms({
      observations: values,
      capability: 'large-repository',
      baseline: 'ch015',
      candidate: 'current-parallel',
      policy,
    })).toThrow(/provenance/);
  });

  it('rejects case target drift across repetitions', () => {
    const values = paired();
    values[3] = {
      ...values[3],
      provenance: { ...values[3]!.provenance, targetSha256: 'b'.repeat(64) },
    };
    expect(() => compareOffsecArms({
      observations: values,
      capability: 'large-repository',
      baseline: 'ch015',
      candidate: 'current-parallel',
      policy,
    })).toThrow(/case provenance/);
  });

  it('rejects paired arms scored by different evaluator versions', () => {
    const values = paired();
    values[1] = {
      ...values[1],
      provenance: { ...values[1]!.provenance, evaluatorVersion: '2.0.0' },
    };
    expect(() => compareOffsecArms({
      observations: values,
      capability: 'large-repository',
      baseline: 'ch015',
      candidate: 'current-parallel',
      policy,
    })).toThrow(/paired provenance.*evaluatorVersion/);
  });

  it('rejects paired arms run with different models', () => {
    const values = paired();
    values[1] = {
      ...values[1],
      provenance: { ...values[1]!.provenance, model: 'different-model' },
    };
    expect(() => compareOffsecArms({
      observations: values,
      capability: 'large-repository',
      baseline: 'ch015',
      candidate: 'current-parallel',
      policy,
    })).toThrow(/paired provenance.*model/);
  });

  it('allows arm-specific tool version provenance for different implementations', () => {
    const values = paired().map((value) => ({
      ...value,
      provenance: {
        ...value.provenance,
        toolVersions: value.arm === 'ch015' ? { 'ch015-plugin': '1.0.0' } : { semgrep: '1.157.0' },
      },
    }));
    expect(compareOffsecArms({
      observations: values,
      capability: 'large-repository',
      baseline: 'ch015',
      candidate: 'current-parallel',
      policy,
    }).claim).toBe('superior');
  });
});
