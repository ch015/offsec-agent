import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  assertBenchmarkCorpusIntact,
  assertBenchmarkRunArtifactsIntact,
  assertBenchmarkSourceManifestIntact,
  assertNoBenchmarkLeak,
  benchmarkSha256,
  benchmarkStableJson,
  createBenchmarkSourceManifest,
  createBlindReviewPackets,
  resolveBenchmarkJudgments,
  validateNormalizedBenchmarkFindings,
  type BenchmarkCorpus,
  type BenchmarkRunRecord,
  type NormalizedBenchmarkFinding,
} from '../offsec-benchmark.js';
import {
  collectScoreRecords,
  prepareReviewArtifacts,
  scoreReviewArtifacts,
} from '../../../scripts/adjudicate-offsec-benchmark.js';

function fixture() {
  const target = mkdtempSync(join(tmpdir(), 'nunchi-benchmark-target-'));
  const runDir = mkdtempSync(join(tmpdir(), 'nunchi-benchmark-run-'));
  writeFileSync(join(target, 'app.ts'), ['export function handler(input: string) {', '  return sink(input);', '}'].join('\n'));
  const sourceManifest = createBenchmarkSourceManifest({
    target,
    revision: '1'.repeat(40),
    files: ['app.ts'],
  });
  const corpusCore = {
    schemaVersion: '1.0.0' as const,
    corpusId: 'corpus-pilot',
    split: 'validation' as const,
    claimAuthority: 'pilot-only' as const,
    cases: [{
      caseId: 'case-00000001',
      capability: 'large-repository' as const,
      sourceManifestSha256: sourceManifest.manifestSha256,
      repositoryPseudonym: 'repo-1234567890ab',
      vulnerableRevision: '1'.repeat(40),
      labels: [{
        labelId: 'GT-ONE',
        rootCauseId: 'RC-ONE',
        title: 'Untrusted input reaches a sink',
        cwes: ['CWE-20'],
        modality: 'static' as const,
        anchors: [{ path: 'app.ts', lineStart: 2, lineEnd: 2, quote: 'return sink(input);' }],
      }],
    }],
  };
  const corpus: BenchmarkCorpus = {
    ...corpusCore,
    corpusSha256: benchmarkSha256(benchmarkStableJson(corpusCore)),
  };
  const artifactPath = join(runDir, 'agent-report.md');
  writeFileSync(artifactPath, 'agent output\n');
  const runCore = {
    schemaVersion: '1.0.0' as const,
    runId: 'run-1234567890abcdef1234',
    nonce: '2'.repeat(32),
    caseId: 'case-00000001',
    repetition: 1,
    arm: 'current-parallel' as const,
    split: 'validation' as const,
    capability: 'large-repository' as const,
    corpusSha256: corpus.corpusSha256,
    sourceManifestSha256: sourceManifest.manifestSha256,
    promptSha256: '3'.repeat(64),
    contractSha256: '4'.repeat(64),
    resourceManifestSha256: '5'.repeat(64),
    entrypoint: 'nunchi-assess' as const,
    commandSha256: '6'.repeat(64),
    provider: 'test-provider',
    model: 'test-model',
    effort: 'high',
    maxTurns: 80,
    randomizationSeed: 42,
    executionOrder: 0,
    startedAt: '2026-08-06T00:00:00.000Z',
    finishedAt: '2026-08-06T00:01:00.000Z',
    elapsedMs: 60_000,
    exitCode: 0,
    artifacts: [{ path: 'agent-report.md', bytes: 13, sha256: benchmarkSha256('agent output\n') }],
  };
  const run: BenchmarkRunRecord = {
    ...runCore,
    runSha256: benchmarkSha256(benchmarkStableJson(runCore)),
  };
  const finding: NormalizedBenchmarkFinding = {
    schemaVersion: '1.0.0',
    runId: run.runId,
    runSha256: run.runSha256,
    caseId: run.caseId,
    arm: run.arm,
    findingId: 'F-001',
    title: 'Untrusted input reaches sink',
    verdict: 'supported',
    severity: 'HIGH',
    cwes: ['CWE-20'],
    rootCauseId: 'RC-ONE',
    evidence: [{
      path: 'app.ts', lineStart: 2, lineEnd: 2, quote: 'return sink(input);', origin: 'reported',
    }],
  };
  return { target, runDir, sourceManifest, corpus, run, finding, artifactPath };
}

describe('OffSec benchmark integrity contract', () => {
  it('binds source, corpus, run artifacts and normalized evidence', () => {
    const value = fixture();
    expect(assertBenchmarkSourceManifestIntact(value.sourceManifest, value.target)).toEqual(value.sourceManifest);
    expect(assertBenchmarkCorpusIntact(value.corpus)).toEqual(value.corpus);
    expect(assertBenchmarkRunArtifactsIntact(value.run, value.runDir)).toEqual(value.run);
    expect(validateNormalizedBenchmarkFindings({
      findings: [value.finding],
      run: value.run,
      sourceManifest: value.sourceManifest,
      target: value.target,
    })).toEqual([value.finding]);
  });

  it('rejects fixture substitution, provenance drift and duplicate inflation', () => {
    const value = fixture();
    writeFileSync(value.artifactPath, 'fixture output\n');
    expect(() => assertBenchmarkRunArtifactsIntact(value.run, value.runDir)).toThrow(/artifact/);
    expect(() => validateNormalizedBenchmarkFindings({
      findings: [{ ...value.finding, runId: 'run-aaaaaaaaaaaaaaaaaaaa' }],
      run: value.run,
      sourceManifest: value.sourceManifest,
      target: value.target,
    })).toThrow(/run identity/);
    expect(() => validateNormalizedBenchmarkFindings({
      findings: [value.finding, value.finding],
      run: value.run,
      sourceManifest: value.sourceManifest,
      target: value.target,
    })).toThrow(/중복/);
  });

  it('rejects source changes, path escapes and invalid quotes', () => {
    const value = fixture();
    writeFileSync(join(value.target, 'app.ts'), 'export const changed = true;\n');
    expect(() => assertBenchmarkSourceManifestIntact(value.sourceManifest, value.target)).toThrow(/달라졌다/);

    const fresh = fixture();
    expect(() => validateNormalizedBenchmarkFindings({
      findings: [{ ...fresh.finding, evidence: [{ ...fresh.finding.evidence[0]!, quote: 'not source' }] }],
      run: fresh.run,
      sourceManifest: fresh.sourceManifest,
      target: fresh.target,
    })).toThrow(/quote/);
    expect(() => createBenchmarkSourceManifest({
      target: fresh.target,
      revision: '1'.repeat(40),
      files: ['../outside.ts'],
    })).toThrow(/상대 경로/);
  });

  it('blocks sealed identifiers from the neutral arm task', () => {
    const { corpus } = fixture();
    expect(() => assertNoBenchmarkLeak('Review the supplied source tree.', corpus)).not.toThrow();
    expect(() => assertNoBenchmarkLeak('Find GT-ONE in the source tree.', corpus)).toThrow(/노출/);
    expect(() => assertNoBenchmarkLeak(`Inspect commit ${'1'.repeat(40)}.`, corpus)).toThrow(/노출/);
  });

  it('creates arm-blind packets and requires independent agreement or adjudication', () => {
    const { finding } = fixture();
    const { packets, privateMapping } = createBlindReviewPackets({
      findings: [finding],
      salt: 'a'.repeat(64),
    });
    const packet = packets[0]!;
    expect(packet).not.toHaveProperty('arm');
    expect(packet).not.toHaveProperty('runId');
    expect(packet.evidence[0]).not.toHaveProperty('origin');
    expect(privateMapping.get(packet.packetId)).toEqual(finding);
    const common = {
      packetId: packet.packetId,
      sourceEvidenceValid: true,
      runtimeProofValid: null,
      rationale: 'The source evidence and root cause independently match the sealed label.',
    };
    const agree = [
      { ...common, reviewerBlindId: 'reviewer-111111111111', authority: 'reviewer', decision: 'true-positive', labelId: 'GT-ONE' },
      { ...common, reviewerBlindId: 'reviewer-222222222222', authority: 'reviewer', decision: 'true-positive', labelId: 'GT-ONE' },
    ];
    expect(resolveBenchmarkJudgments([packet.packetId], agree).get(packet.packetId)?.decision).toBe('true-positive');
    expect(() => resolveBenchmarkJudgments([packet.packetId], [
      agree[0], { ...agree[1], sourceEvidenceValid: false },
    ])).toThrow(/adjudicator/);
    const disagree = [agree[0], { ...agree[1], decision: 'false-positive', labelId: null }];
    expect(() => resolveBenchmarkJudgments([packet.packetId], disagree)).toThrow(/adjudicator/);
    expect(resolveBenchmarkJudgments([packet.packetId], [
      ...disagree,
      { ...common, reviewerBlindId: 'reviewer-333333333333', authority: 'adjudicator', decision: 'inconclusive', labelId: null },
    ]).get(packet.packetId)?.decision).toBe('inconclusive');
  });

  it('rejects reports that are outside the attested run directory', () => {
    const value = fixture();
    const outside = mkdtempSync(join(tmpdir(), 'nunchi-benchmark-outside-'));
    writeFileSync(join(outside, 'fixture.md'), readFileSync(value.artifactPath));
    mkdirSync(join(value.runDir, 'nested'));
    const escaped = {
      ...value.run,
      artifacts: [{ path: '../fixture.md', bytes: 13, sha256: benchmarkSha256('agent output\n') }],
    };
    expect(() => assertBenchmarkRunArtifactsIntact(escaped, value.runDir)).toThrow(/상대 경로/);
  });

  it('prepares arm-blind review artifacts from sealed run inputs', () => {
    const value = fixture();
    mkdirSync(join(value.runDir, 'target'));
    writeFileSync(join(value.runDir, 'target', 'app.ts'), readFileSync(join(value.target, 'app.ts')));
    writeFileSync(join(value.runDir, 'run-record.json'), `${JSON.stringify(value.run)}\n`);
    const normalizedPath = join(value.runDir, 'normalized-findings.json');
    writeFileSync(normalizedPath, `${JSON.stringify([value.finding])}\n`);
    const normalizationCore = {
      schemaVersion: '1.0.0',
      runSha256: value.run.runSha256,
      sourceManifestSha256: value.sourceManifest.manifestSha256,
      adapter: 'current-standard-finding-v1',
      normalizedSha256: benchmarkSha256(benchmarkStableJson([value.finding])),
      normalizedFileSha256: benchmarkSha256(readFileSync(normalizedPath)),
    };
    writeFileSync(join(value.runDir, 'normalization-record.json'), `${JSON.stringify({
      ...normalizationCore,
      recordSha256: benchmarkSha256(benchmarkStableJson(normalizationCore)),
    })}\n`);
    const manifestPath = join(value.runDir, 'source-manifest.json');
    writeFileSync(manifestPath, `${JSON.stringify(value.sourceManifest)}\n`);
    const outputDir = join(value.runDir, 'review');
    const prepared = prepareReviewArtifacts({
      runDir: value.runDir,
      sourceManifestPath: manifestPath,
      outputDir,
      salt: 'a'.repeat(64),
    });
    expect(prepared.packetCount).toBe(1);
    const packets = JSON.parse(readFileSync(prepared.packetsPath, 'utf8')) as unknown[];
    expect(packets[0]).not.toHaveProperty('arm');
    expect(packets[0]).not.toHaveProperty('origin');

    const packetId = (packets[0] as { packetId: string }).packetId;
    const judgmentsPath = join(value.runDir, 'judgments.json');
    const common = {
      packetId, authority: 'reviewer', decision: 'true-positive', labelId: 'GT-ONE',
      sourceEvidenceValid: true, runtimeProofValid: null,
      rationale: 'The sealed source evidence independently matches the ground-truth label.',
    };
    writeFileSync(judgmentsPath, `${JSON.stringify([
      { ...common, reviewerBlindId: 'reviewer-111111111111' },
      { ...common, reviewerBlindId: 'reviewer-222222222222' },
    ])}\n`);
    const corpusPath = join(value.runDir, 'corpus.json');
    writeFileSync(corpusPath, `${JSON.stringify(value.corpus)}\n`);
    const scorePath = join(value.runDir, 'score.json');
    const score = scoreReviewArtifacts({
      runDir: value.runDir, corpusPath, sourceManifestPath: manifestPath,
      mappingPath: prepared.mappingPath, judgmentsPath, outputPath: scorePath,
    });
    expect(score.observation.metric.value).toBe(1);

    const campaignPath = join(value.runDir, 'campaign.json');
    writeFileSync(campaignPath, `${JSON.stringify({
      planned: [{ caseId: value.run.caseId, repetition: value.run.repetition, arm: value.run.arm }],
      completed: [{ identity: `${value.run.caseId}:${value.run.repetition}:${value.run.arm}`, record: value.run }],
    })}\n`);
    const observationsPath = join(value.runDir, 'observations.jsonl');
    expect(collectScoreRecords({ campaignPath, scorePaths: [scorePath], outputPath: observationsPath }))
      .toMatchObject({ observationCount: 1 });
    expect(JSON.parse(readFileSync(observationsPath, 'utf8').trim())).toMatchObject({ caseId: value.run.caseId });
  });
});
