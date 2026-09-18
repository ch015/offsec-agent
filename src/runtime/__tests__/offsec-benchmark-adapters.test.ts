import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { normalizeCh015MarkdownFindings } from '../../../evals/offsec/adapters/ch015.js';
import { normalizeCurrentOffsecFindings } from '../../../evals/offsec/adapters/current.js';
import {
  benchmarkSha256,
  benchmarkStableJson,
  createBenchmarkSourceManifest,
  type BenchmarkRunRecord,
} from '../offsec-benchmark.js';
import { submitStandardFinding } from '../finding-contract.js';

function run(arm: 'ch015' | 'current-parallel', sourceManifestSha256: string): BenchmarkRunRecord {
  const core = {
    schemaVersion: '1.0.0' as const,
    runId: arm === 'ch015' ? 'run-11111111111111111111' : 'run-22222222222222222222',
    nonce: 'a'.repeat(32),
    caseId: 'case-00000001',
    repetition: 1,
    arm,
    split: 'validation' as const,
    capability: 'large-repository' as const,
    corpusSha256: 'b'.repeat(64),
    sourceManifestSha256,
    promptSha256: 'c'.repeat(64),
    contractSha256: 'd'.repeat(64),
    resourceManifestSha256: 'e'.repeat(64),
    entrypoint: arm === 'ch015' ? 'claude-plugin' as const : 'nunchi-assess' as const,
    commandSha256: 'f'.repeat(64),
    provider: 'anthropic',
    model: 'test-model',
    effort: 'high',
    maxTurns: 80,
    randomizationSeed: 7,
    executionOrder: 0,
    startedAt: '2026-08-06T00:00:00.000Z',
    finishedAt: '2026-08-06T00:01:00.000Z',
    elapsedMs: 60_000,
    exitCode: 0,
    artifacts: [{ path: 'report.md', bytes: 1, sha256: '0'.repeat(64) }],
  };
  return { ...core, runSha256: benchmarkSha256(benchmarkStableJson(core)) };
}

describe('OffSec benchmark adapters', () => {
  it('normalizes CH015 headings without granting adapter-resolved evidence model authority', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-ch015-adapter-target-'));
    writeFileSync(join(target, 'app.ts'), ['export function handler(input: string) {', '  return sink(input);', '}'].join('\n'));
    const sourceManifest = createBenchmarkSourceManifest({ target, revision: '1'.repeat(40), files: ['app.ts'] });
    const reportPath = join(mkdtempSync(join(tmpdir(), 'nunchi-ch015-adapter-report-')), 'report.md');
    writeFileSync(reportPath, [
      '### F-001 [HIGH] Untrusted input reaches sink',
      '- **CWE**: CWE-20',
      '- **File**: `app.ts:2`',
    ].join('\n'));
    const findings = normalizeCh015MarkdownFindings({
      reportPath,
      target,
      sourceManifest,
      run: run('ch015', sourceManifest.manifestSha256),
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence[0]).toMatchObject({
      path: 'app.ts', lineStart: 2, quote: '  return sink(input);', origin: 'adapter-resolved',
    });
    expect(findings[0]?.cwes).toEqual(['CWE-20']);
  });

  it('normalizes only host-accepted current standard Findings', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-current-adapter-target-'));
    const engagementDir = mkdtempSync(join(tmpdir(), 'nunchi-current-adapter-engagement-'));
    const source = join(target, 'app.ts');
    writeFileSync(source, ['export function handler(input: string) {', '  return sink(input);', '}'].join('\n'));
    const sourceManifest = createBenchmarkSourceManifest({ target, revision: '1'.repeat(40), files: ['app.ts'] });
    submitStandardFinding({
      target,
      engagementDir,
      phase: 'va',
      role: 'va-auditor',
      finding: {
        title: 'Untrusted input reaches sink',
        verdict: 'supported',
        severity: 'HIGH',
        evidenceClass: 'data-flow',
        reachability: 'confirmed',
        preconditions: ['attacker controls input'],
        severityRationale: 'The confirmed data flow crosses a sensitive trust boundary.',
        confidence: 0.9,
        impact: 'Sensitive operation receives untrusted input.',
        remediation: 'Validate input before the sink.',
        standards: ['CWE-20'],
        unresolved: [],
        evidence: [{ path: source, lineStart: 2, lineEnd: 2, quote: 'return sink(input);' }],
      },
    });
    const findings = normalizeCurrentOffsecFindings({
      engagementDir,
      run: run('current-parallel', sourceManifest.manifestSha256),
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence[0]?.origin).toBe('reported');
    expect(findings[0]?.cwes).toEqual(['CWE-20']);
  });

  it('does not turn narrative headings or out-of-scope locations into findings/evidence', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-ch015-adapter-scope-'));
    writeFileSync(join(target, 'app.ts'), 'export const ok = true;\n');
    const sourceManifest = createBenchmarkSourceManifest({ target, revision: '1'.repeat(40), files: ['app.ts'] });
    const directory = mkdtempSync(join(tmpdir(), 'nunchi-ch015-adapter-scope-report-'));
    const reportPath = join(directory, 'report.md');
    writeFileSync(reportPath, [
      '### Architecture Summary',
      'No finding here.',
      '### F-002 [MEDIUM] Unsupported location',
      '- **File**: `../outside.ts:1`',
    ].join('\n'));
    const findings = normalizeCh015MarkdownFindings({
      reportPath,
      target,
      sourceManifest,
      run: run('ch015', sourceManifest.manifestSha256),
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.findingId).toBe('F-002');
    expect(findings[0]?.evidence).toEqual([]);
    expect(findings[0]?.verdict).toBe('abstain');
  });

  it('does not promote excluded CH015 findings merely because they retain source citations', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-ch015-adapter-excluded-'));
    writeFileSync(join(target, 'app.ts'), 'export const ok = true;\n');
    const sourceManifest = createBenchmarkSourceManifest({ target, revision: '1'.repeat(40), files: ['app.ts'] });
    const reportPath = join(mkdtempSync(join(tmpdir(), 'nunchi-ch015-excluded-report-')), 'report.md');
    writeFileSync(reportPath, '### F-003 [HIGH] Rejected candidate\nStatus: FALSE_POSITIVE\n`app.ts:1`\n');
    const findings = normalizeCh015MarkdownFindings({
      reportPath, target, sourceManifest, run: run('ch015', sourceManifest.manifestSha256),
    });
    expect(findings[0]).toMatchObject({ findingId: 'F-003', verdict: 'abstain' });
  });

  it('does not treat finding-title vocabulary as an explicit excluded status', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-ch015-adapter-status-'));
    writeFileSync(join(target, 'app.ts'), 'export const algorithm = input;\n');
    const sourceManifest = createBenchmarkSourceManifest({ target, revision: '1'.repeat(40), files: ['app.ts'] });
    const reportPath = join(mkdtempSync(join(tmpdir(), 'nunchi-ch015-status-report-')), 'report.md');
    writeFileSync(reportPath, '### F-004 [HIGH] Unsupported JWT algorithm accepted\n`app.ts:1`\n');
    const findings = normalizeCh015MarkdownFindings({
      reportPath, target, sourceManifest, run: run('ch015', sourceManifest.manifestSha256),
    });
    expect(findings[0]).toMatchObject({ findingId: 'F-004', verdict: 'supported' });
  });

  it('preserves distinct current findings that cite the same source line', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-current-adapter-lineage-'));
    const engagementDir = mkdtempSync(join(tmpdir(), 'nunchi-current-adapter-lineage-engagement-'));
    const source = join(target, 'app.ts');
    writeFileSync(source, 'export const result = sink(input);\n');
    const sourceManifest = createBenchmarkSourceManifest({ target, revision: '1'.repeat(40), files: ['app.ts'] });
    for (const [title, standard] of [
      ['Authorization bypass', 'CWE-862'],
      ['Command injection', 'CWE-78'],
    ] as const) {
      submitStandardFinding({
        target, engagementDir, phase: 'va', role: 'va-auditor',
        finding: {
          title, verdict: 'supported', severity: 'HIGH', evidenceClass: 'data-flow',
          reachability: 'confirmed', preconditions: ['attacker input'],
          severityRationale: 'The shared sink line demonstrates a distinct security consequence.',
          confidence: 0.9, impact: title, remediation: 'Validate and authorize the operation.',
          standards: [standard], unresolved: [],
          evidence: [{ path: source, lineStart: 1, lineEnd: 1, quote: 'export const result = sink(input);' }],
        },
      });
    }
    const findings = normalizeCurrentOffsecFindings({
      engagementDir, run: run('current-parallel', sourceManifest.manifestSha256),
    });
    expect(findings.map((finding) => finding.title).sort()).toEqual(['Authorization bypass', 'Command injection']);
  });
});
