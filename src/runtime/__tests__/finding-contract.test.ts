import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';

import { describe, expect, it } from 'vitest';

import {
  assertStandardFindingsRepresented,
  countStandardFindings,
  readStandardFindings,
  submitStandardFinding,
} from '../finding-contract.js';
import { createAdaptiveLiveTestBroker, createLiveTestBroker } from '../live-test-broker.js';
import { LiveScenarioJournal } from '../live-scenario-journal.js';
import { sealAuthInteractionSelection } from '../live-auth-session.js';
import type { LiveScenario, LiveTestProfile } from '../live-test-contract.js';

const execFileAsync = promisify(execFile);

function fixture() {
  const target = mkdtempSync(join(tmpdir(), 'nunchi-finding-target-'));
  const engagementDir = mkdtempSync(join(tmpdir(), 'nunchi-finding-engagement-'));
  const source = join(target, 'app.ts');
  writeFileSync(source, ['export function handler(input: string) {', '  return sink(input);', '}'].join('\n'));
  return { target, engagementDir, source };
}

function supportedFinding(source: string) {
  return {
    title: 'Untrusted input reaches sink',
    verdict: 'supported' as const,
    severity: 'HIGH' as const,
    evidenceClass: 'data-flow' as const,
    reachability: 'confirmed' as const,
    preconditions: ['attacker-controlled input reaches the handler'],
    severityRationale: 'The confirmed input-to-sink path crosses a sensitive trust boundary.',
    confidence: 0.9,
    impact: 'Untrusted input can reach a sensitive sink.',
    remediation: 'Validate input before the sink.',
    standards: ['CWE-20'],
    unresolved: [],
    evidence: [{ path: source, lineStart: 2, lineEnd: 2, quote: 'return sink(input);' }],
  };
}

describe('standard Finding contract', () => {
  it('accepts only source-backed evidence and stores a normalized append-only record', () => {
    const { target, engagementDir, source } = fixture();
    const finding = submitStandardFinding({
      target,
      engagementDir,
      phase: 'va',
      role: 'va-auditor',
      finding: supportedFinding(source),
    });
    expect(finding.id).toMatch(/^F-\d{12}$/);
    expect(finding.evidence[0]?.path).toBe('app.ts');
    expect(readStandardFindings(engagementDir)).toEqual([finding]);
    expect(countStandardFindings(engagementDir, 'va', 'va-auditor')).toBe(1);
    const report = join(engagementDir, 'report.md');
    writeFileSync(report, 'empty report\n');
    expect(() => assertStandardFindingsRepresented(engagementDir, report)).toThrow(/소비하지 않았다/);
    writeFileSync(report, `finding ${finding.id}\n`);
    expect(assertStandardFindingsRepresented(engagementDir, report)).toBe(1);
  });

  it('rejects a quote that does not occur in the declared line range', () => {
    const { target, engagementDir, source } = fixture();
    expect(() =>
      submitStandardFinding({
        target,
        engagementDir,
        phase: 'va',
        role: 'va-auditor',
        finding: {
          ...supportedFinding(source),
          evidence: [{ path: source, lineStart: 1, lineEnd: 1, quote: 'sink(input)' }],
        },
      }),
    ).toThrow(/quote/);
    expect(readStandardFindings(engagementDir)).toEqual([]);
  });

  it('restricts work-unit Finding evidence to host-owned source files', () => {
    const { target, engagementDir, source } = fixture();
    const owned = join(target, 'owned.ts');
    writeFileSync(owned, 'export const owned = true;\n');
    expect(() => submitStandardFinding({
      target,
      engagementDir,
      phase: 'va',
      role: 'va-auditor',
      evidenceAllowedFiles: [owned],
      finding: supportedFinding(source),
    })).toThrow(/owned source/);
  });







  it('rejects symlink evidence that escapes the assessment target', () => {
    const { target, engagementDir } = fixture();
    const outside = join(mkdtempSync(join(tmpdir(), 'nunchi-finding-outside-')), 'secret.ts');
    writeFileSync(outside, 'const secret = true;');
    const linked = join(target, 'linked.ts');
    symlinkSync(outside, linked);
    expect(() =>
      submitStandardFinding({
        target,
        engagementDir,
        phase: 'va',
        role: 'va-auditor',
        finding: {
          ...supportedFinding(linked),
          evidence: [{ path: linked, lineStart: 1, lineEnd: 1, quote: 'secret' }],
        },
      }),
    ).toThrow(/target 밖/);
  });

  it('rejects duplicate submissions and unexplained abstention', () => {
    const { target, engagementDir, source } = fixture();
    const input = {
      target,
      engagementDir,
      phase: 'verify',
      role: 'verifier',
      finding: supportedFinding(source),
    };
    submitStandardFinding(input);
    // #10: upsert로 변경 — 동일 ID 재제출 시 덮어쓰기 (에러 없음)
    expect(() => submitStandardFinding(input)).not.toThrow();
    expect(() =>
      submitStandardFinding({
        ...input,
        finding: {
          ...supportedFinding(source),
          title: 'Unresolved behavior',
          verdict: 'abstain',
          unresolved: [],
        },
      }),
    ).toThrow(/unresolved/);

    expect(() =>
      submitStandardFinding({
        ...input,
        finding: {
          ...supportedFinding(source),
          title: 'Rejected candidate without counter-evidence',
          verdict: 'unsupported',
          evidence: [],
        },
      }),
    ).toThrow(/evidence/);
  });

  it('rejects high-severity confidence based only on an exact but irrelevant quote', () => {
    const { target, engagementDir, source } = fixture();
    expect(() =>
      submitStandardFinding({
        target,
        engagementDir,
        phase: 'va',
        role: 'va-auditor',
        finding: {
          ...supportedFinding(source),
          evidenceClass: 'documentation',
          reachability: 'unconfirmed',
          preconditions: [],
          severityRationale: 'critical',
          confidence: 0.99,
        },
      }),
    ).toThrow(/도달 가능한 비문서 증거/);
  });

  it('commits one valid record under concurrent duplicate submissions', async () => {
    const { target, engagementDir } = fixture();
    const source = join(target, 'concurrent.ts');
    writeFileSync(source, 'export const value = 1;\n');
    const worker = join(import.meta.dirname, 'fixtures', 'finding-submit-worker.ts');
    const outcomes = await Promise.all(
      Array.from({ length: 6 }, () =>
        execFileAsync(process.execPath, ['--import', 'tsx', worker, target, engagementDir, source]),
      ),
    );
    expect(outcomes.filter((outcome) => outcome.stdout === 'accepted')).toHaveLength(6);
    expect(readStandardFindings(engagementDir)).toHaveLength(1);
  }, 20_000);
});
