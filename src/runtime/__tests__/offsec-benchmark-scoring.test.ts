import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  benchmarkSha256,
  benchmarkStableJson,
  type BenchmarkCorpus,
  type BenchmarkJudgment,
  type BenchmarkRunRecord,
  type NormalizedBenchmarkFinding,
} from '../offsec-benchmark.js';
import { scoreAdjudicatedBenchmarkRun } from '../../../evals/offsec/scoring.js';

const hash = 'a'.repeat(64);

function corpus(): BenchmarkCorpus {
  const core = {
    schemaVersion: '1.0.0' as const,
    corpusId: 'corpus-scoring-test',
    split: 'validation' as const,
    claimAuthority: 'pilot-only' as const,
    cases: [{
      caseId: 'case-scoring1',
      capability: 'large-repository' as const,
      sourceManifestSha256: hash,
      repositoryPseudonym: 'repo-111111111111',
      vulnerableRevision: '1'.repeat(40),
      labels: ['ONE', 'TWO'].map((suffix, index) => ({
        labelId: `GT-${suffix}`,
        rootCauseId: `RC-${suffix}`,
        title: suffix,
        cwes: [`CWE-${89 + index}`],
        modality: 'static' as const,
        anchors: [{ path: 'app.ts', lineStart: 1, lineEnd: 1, quote: 'source' }],
      })),
    }],
  };
  return { ...core, corpusSha256: benchmarkSha256(benchmarkStableJson(core)) };
}

function run(value: BenchmarkCorpus): { record: BenchmarkRunRecord; runDir: string } {
  const runDir = mkdtempSync(join(tmpdir(), 'nunchi-scoring-run-'));
  writeFileSync(join(runDir, 'stdout.log'), 'x');
  const core = {
    schemaVersion: '1.0.0' as const,
    runId: 'run-11111111111111111111',
    nonce: '1'.repeat(32),
    caseId: 'case-scoring1',
    repetition: 1,
    arm: 'current-parallel' as const,
    split: 'validation' as const,
    capability: 'large-repository' as const,
    corpusSha256: value.corpusSha256,
    sourceManifestSha256: hash,
    promptSha256: hash,
    contractSha256: hash,
    resourceManifestSha256: hash,
    entrypoint: 'nunchi-assess' as const,
    commandSha256: hash,
    provider: 'anthropic',
    model: 'claude-opus-4-6',
    effort: 'high',
    maxTurns: 120,
    randomizationSeed: 7,
    executionOrder: 0,
    startedAt: '2026-08-06T00:00:00.000Z',
    finishedAt: '2026-08-06T00:01:00.000Z',
    elapsedMs: 60_000,
    exitCode: 0,
    artifacts: [{ path: 'stdout.log', bytes: 1, sha256: benchmarkSha256('x') }],
  };
  return { record: { ...core, runSha256: benchmarkSha256(benchmarkStableJson(core)) }, runDir };
}

function finding(record: BenchmarkRunRecord, findingId: string): NormalizedBenchmarkFinding {
  return {
    schemaVersion: '1.0.0',
    runId: record.runId,
    runSha256: record.runSha256,
    caseId: record.caseId,
    arm: record.arm,
    findingId,
    title: findingId,
    verdict: 'supported',
    severity: 'HIGH',
    cwes: ['CWE-89'],
    evidence: [{ path: 'app.ts', lineStart: 1, lineEnd: 1, quote: 'source', origin: 'reported' }],
  };
}

function judgment(packetId: string, decision: BenchmarkJudgment['decision'], labelId: string | null) {
  return {
    packetId,
    reviewerBlindId: 'reviewer-111111111111',
    authority: 'reviewer' as const,
    decision,
    labelId,
    sourceEvidenceValid: true,
    runtimeProofValid: null,
    rationale: 'The source evidence and root cause were independently checked.',
  } satisfies BenchmarkJudgment;
}

describe('adjudicated benchmark scoring', () => {
  it('deduplicates label recall and excludes duplicate/inconclusive decisions from precision', () => {
    const value = corpus();
    const { record, runDir } = run(value);
    const mapping = new Map([
      ['packet-111111111111111111111111', finding(record, 'F-1')],
      ['packet-222222222222222222222222', finding(record, 'F-2')],
      ['packet-333333333333333333333333', finding(record, 'F-3')],
      ['packet-444444444444444444444444', finding(record, 'F-4')],
    ]);
    const judgments = new Map<string, BenchmarkJudgment>([
      ['packet-111111111111111111111111', judgment('packet-111111111111111111111111', 'true-positive', 'GT-ONE')],
      ['packet-222222222222222222222222', judgment('packet-222222222222222222222222', 'true-positive', 'GT-ONE')],
      ['packet-333333333333333333333333', judgment('packet-333333333333333333333333', 'false-positive', null)],
      ['packet-444444444444444444444444', judgment('packet-444444444444444444444444', 'inconclusive', null)],
    ]);
    const result = scoreAdjudicatedBenchmarkRun({
      run: record,
      runDir,
      corpus: value,
      packetMapping: mapping,
      judgments,
      usage: { inputTokens: 10, outputTokens: 5 },
      toolVersions: { semgrep: 'unavailable' },
    });
    expect(result.observation.metric).toEqual({
      capability: 'large-repository', name: 'ground-truth-recall', value: 0.5,
    });
    expect(result.observation.falsePositiveRate).toBe(0.5);
    expect(result.diagnostics).toMatchObject({
      applicableLabels: 2,
      detectedLabels: 1,
      truePositiveFindings: 2,
      falsePositiveFindings: 1,
      inconclusiveFindings: 1,
    });
  });

  it('rejects a judgment that maps to a label outside the sealed case', () => {
    const value = corpus();
    const { record, runDir } = run(value);
    const packetId = 'packet-111111111111111111111111';
    expect(() => scoreAdjudicatedBenchmarkRun({
      run: record,
      runDir,
      corpus: value,
      packetMapping: new Map([[packetId, finding(record, 'F-1')]]),
      judgments: new Map([[packetId, judgment(packetId, 'true-positive', 'GT-OUTSIDE')]]),
      usage: { inputTokens: 1, outputTokens: 1 },
      toolVersions: {},
    })).toThrow(/ground truth 밖/);
  });

  it('keeps duplicate-label evidence validity independent of mapping order', () => {
    const value = corpus();
    const { record, runDir } = run(value);
    const first = 'packet-111111111111111111111111';
    const second = 'packet-222222222222222222222222';
    const entries = [[first, finding(record, 'F-1')], [second, finding(record, 'F-2')]] as const;
    const judgments = new Map<string, BenchmarkJudgment>([
      [first, judgment(first, 'true-positive', 'GT-ONE')],
      [second, { ...judgment(second, 'true-positive', 'GT-ONE'), sourceEvidenceValid: false }],
    ]);
    const score = (mapping: Map<string, NormalizedBenchmarkFinding>) => scoreAdjudicatedBenchmarkRun({
      run: record, runDir, corpus: value, packetMapping: mapping, judgments,
      usage: { inputTokens: 0, outputTokens: 0 }, toolVersions: { benchmark: 'unavailable' },
    }).observation.evidenceValidity;
    expect(score(new Map(entries))).toBe(score(new Map([...entries].reverse())));
    expect(score(new Map(entries))).toBe(0);
  });
});
