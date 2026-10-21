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
  readStandardFindingRecordReceipts,
  readStandardFindings,
  submitStandardFinding,
  submitStandardFindingWithNotices,
  anchoredRevisions,
  revisableFindings,
} from '../finding-contract.js';
import { createAdaptiveLiveTestBroker, createLiveTestBroker } from '../live-test/live-test-broker.js';
import { LiveScenarioJournal } from '../live-test/live-scenario-journal.js';
import { sealAuthInteractionSelection } from '../live-test/live-auth-session.js';
import type { LiveScenario, LiveTestProfile } from '../live-test/live-test-contract.js';

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

  it('writes records atomically and tolerates only a leftover staging file from an interrupted write', () => {
    const { target, engagementDir, source } = fixture();
    const submit = (severity: 'HIGH' | 'MEDIUM') => submitStandardFinding({
      target, engagementDir, phase: 'va', role: 'va-auditor', finding: { ...supportedFinding(source), severity },
    });
    submit('HIGH');
    submit('MEDIUM'); // upsert of the same identity replaces the record in place
    const recordsDir = join(engagementDir, 'standard-findings');
    const [record] = readdirSync(recordsDir);
    expect(readdirSync(recordsDir)).toEqual([record]);
    expect(readStandardFindingRecordReceipts(engagementDir)).toHaveLength(1);
    expect(readStandardFindings(engagementDir).map(finding => finding.severity)).toEqual(['MEDIUM']);
    writeFileSync(join(recordsDir, `${record}.123e4567-e89b-12d3-a456-426614174000.tmp`), '{"torn":');
    expect(readStandardFindingRecordReceipts(engagementDir)).toHaveLength(1);
    writeFileSync(join(recordsDir, 'notes.txt'), 'foreign');
    expect(() => readStandardFindingRecordReceipts(engagementDir)).toThrow(/비계약 파일/);
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

describe('stable Finding identity (fp1)', () => {
  const lines = ['export function handler(input: string) {', '  return sink(input);', '}'];
  function submitAt(source: string[], overrides: Record<string, unknown> = {}, extra: Partial<Parameters<typeof submitStandardFinding>[0]> = {}) {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-identity-target-'));
    const engagementDir = (extra.engagementDir as string | undefined) ?? mkdtempSync(join(tmpdir(), 'nunchi-identity-run-'));
    writeFileSync(join(target, 'app.ts'), source.join('\n'));
    const at = source.findIndex(line => line.includes('return sink(input)')) + 1;
    const finding = { ...supportedFinding(join(target, 'app.ts')), evidence: [{ path: join(target, 'app.ts'), lineStart: at, lineEnd: at, quote: source[at - 1]!.trim() }], ...overrides };
    return { engagementDir, ...submitStandardFindingWithNotices({ target, phase: 'analyze', role: 'analyzer', round: 'unit-a', ...extra, engagementDir, finding: finding as never }) };
  }

  it('keeps the ID when the cited line moves, the range end grows or the title spelling changes', () => {
    const base = submitAt(lines).finding;
    expect(base.id).toMatch(/^F-\d{12}$/);
    expect(base.fingerprint).toMatchObject({ scheme: 'fp1', path: 'app.ts', ordinal: 1, weakness: 'CWE-20' });
    expect(submitAt(['// moved', '', '', ...lines]).finding.id).toBe(base.id);
    expect(submitAt(lines, { title: '  untrusted INPUT reaches   sink. ' }).finding.id).toBe(base.id);
    const target = mkdtempSync(join(tmpdir(), 'nunchi-identity-target-'));
    writeFileSync(join(target, 'app.ts'), lines.join('\n'));
    const longer = submitStandardFinding({ target, engagementDir: mkdtempSync(join(tmpdir(), 'nunchi-identity-run-')), phase: 'analyze', role: 'analyzer',
      finding: { ...supportedFinding(join(target, 'app.ts')), evidence: [{ path: join(target, 'app.ts'), lineStart: 2, lineEnd: 3, quote: '  return sink(input);\n}' }] } });
    expect(longer.id).toBe(base.id);
  });

  it('keeps distinct claims that share a quote and tells repeated statements apart', () => {
    const first = submitAt(lines);
    const second = submitAt(lines, { title: 'Missing output encoding at the same sink' }, { engagementDir: first.engagementDir });
    expect(second.finding.id).not.toBe(first.finding.id);
    expect(readStandardFindings(first.engagementDir)).toHaveLength(2);
    expect(second.notices.possibleDuplicates).toEqual([{ id: first.finding.id, title: first.finding.title }]);
    const repeated = [...lines, 'export function other(input: string) {', '  return sink(input);', '}'];
    const target = mkdtempSync(join(tmpdir(), 'nunchi-identity-target-'));
    writeFileSync(join(target, 'app.ts'), repeated.join('\n'));
    const ids = [2, 5].map(line => submitStandardFinding({ target, engagementDir: mkdtempSync(join(tmpdir(), 'nunchi-identity-run-')), phase: 'analyze', role: 'analyzer',
      finding: { ...supportedFinding(join(target, 'app.ts')), evidence: [{ path: join(target, 'app.ts'), lineStart: line, lineEnd: line, quote: 'return sink(input);' }] } }));
    expect(ids.map(finding => finding.fingerprint?.ordinal)).toEqual([1, 2]);
    expect(ids[0]!.id).not.toBe(ids[1]!.id);
  });

  it('continues a retitled claim only through a host-allowed revises ID and archives the replaced bytes', () => {
    const original = submitAt(lines);
    expect(() => submitAt(lines, { title: 'Reworded claim', revises: original.finding.id }, { engagementDir: original.engagementDir }))
      .toThrow(/revises/);
    const revised = submitAt(lines, { title: 'Reworded claim', revises: original.finding.id },
      { engagementDir: original.engagementDir, revisableIds: revisableFindings(anchoredRevisions([original.finding])) });
    expect(revised.finding.id).toBe(original.finding.id);
    expect(revised.notices.replaced?.title).toBe(original.finding.title);
    expect(readStandardFindings(original.engagementDir).map(finding => finding.title)).toEqual(['Reworded claim']);
    const record = readStandardFindingRecordReceipts(original.engagementDir)[0]!.recordName;
    expect(readdirSync(join(original.engagementDir, '.recovery', 'finding-history', record))).toHaveLength(1);
    // Without revises a rewritten title is a different claim.
    expect(submitAt(lines, { title: 'Another wording' }).finding.id).not.toBe(original.finding.id);
    // revises cannot move the claim to another primary statement and overwrite it there.
    expect(() => submitAt(lines, { title: 'Elsewhere', revises: original.finding.id,
      evidence: [{ path: 'app.ts', lineStart: 1, lineEnd: 1, quote: 'export function handler(input: string) {' }] },
    { engagementDir: original.engagementDir, revisableIds: revisableFindings(anchoredRevisions([original.finding])) })).toThrow(/주 근거/);
  });

  it('derives the same identity from CRLF sources and quotes that start with blank lines', () => {
    const base = submitAt(lines).finding;
    const target = mkdtempSync(join(tmpdir(), 'nunchi-identity-target-'));
    writeFileSync(join(target, 'app.ts'), ['', ...lines].join('\r\n'));
    const crlf = submitStandardFinding({ target, engagementDir: mkdtempSync(join(tmpdir(), 'nunchi-identity-run-')), phase: 'analyze', role: 'analyzer',
      finding: { ...supportedFinding(join(target, 'app.ts')), evidence: [{ path: join(target, 'app.ts'), lineStart: 2, lineEnd: 3, quote: 'export function handler(input: string) {\n  return sink(input);' }] } });
    const blankFirst = submitStandardFinding({ target, engagementDir: mkdtempSync(join(tmpdir(), 'nunchi-identity-run-')), phase: 'analyze', role: 'analyzer',
      finding: { ...supportedFinding(join(target, 'app.ts')), evidence: [{ path: join(target, 'app.ts'), lineStart: 1, lineEnd: 2, quote: '\nexport function handler(input: string) {' }] } });
    expect(crlf.fingerprint?.anchor).toBe(blankFirst.fingerprint?.anchor);
    expect(crlf.id).toBe(blankFirst.id);
    expect(crlf.id).not.toBe(base.id); // a different primary statement
  });

  it('ignores an unreadable sibling record during the advisory duplicate scan', () => {
    const first = submitAt(lines);
    writeFileSync(join(first.engagementDir, 'standard-findings', `${'f'.repeat(64)}.json`), 'null');
    expect(() => submitAt(lines, { title: 'Second claim' }, { engagementDir: first.engagementDir })).not.toThrow();
  });

  it('rejects tampered identity on read and still reads records written before 2.2.0', () => {
    const { engagementDir, finding } = submitAt(lines);
    const record = join(engagementDir, 'standard-findings', readStandardFindingRecordReceipts(engagementDir)[0]!.recordName);
    writeFileSync(record, JSON.stringify({ ...finding, title: 'Changed after acceptance' }));
    expect(() => readStandardFindingRecordReceipts(engagementDir)).toThrow(/identity/);
    writeFileSync(record, JSON.stringify({ ...finding, fingerprint: { ...finding.fingerprint!, ordinal: 9 } }));
    expect(() => readStandardFindingRecordReceipts(engagementDir)).toThrow(/fingerprint/);
    const { fingerprint: _fingerprint, ...withoutFingerprint } = finding;
    writeFileSync(record, JSON.stringify(withoutFingerprint));
    expect(() => readStandardFindingRecordReceipts(engagementDir)).toThrow(/fingerprint가 없다/);
    writeFileSync(record, JSON.stringify({ ...withoutFingerprint, id: 'F-000000000001', contractVersion: '2.1.0' }));
    expect(readStandardFindingRecordReceipts(engagementDir)[0]!.findingId).toBe('F-000000000001');
  });
});
