import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';

import { describe, expect, it } from 'vitest';

import {
  assertPentestRuntimeEvidenceIntact,
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

  it('requires an untampered same-scenario host receipt for live-confirmed pentest findings', async () => {
    const { target, engagementDir, source } = fixture();
    const planPath = join(engagementDir, '05_pentest_plan.json');
    writeFileSync(planPath, `${JSON.stringify({
      schemaVersion: '1.0.0',
      scenarios: [{
        scenarioId: 'SC-1', path: 'health', method: 'GET', safety: 'ready', preconditions: [],
        successCriteria: '200', failureCriteria: 'non-200',
      }, {
        scenarioId: 'SC-2', path: 'health?control=1', method: 'GET', safety: 'ready', preconditions: [],
        successCriteria: '200', failureCriteria: 'non-200',
      }],
    })}\n`);
    const planSha256 = createHash('sha256').update(readFileSync(planPath)).digest('hex');
    const broker = createLiveTestBroker({
      engagementDir,
      allowedBaseUrl: 'https://test.example/app/',
      planPath,
      planSha256,
      fetchImpl: async () => new Response('ok', { status: 200, headers: { 'content-type': 'text/plain' } }),
    });
    const receipt = await broker.probe({ scenarioId: 'SC-1' });
    const controlReceipt = await broker.probe({ scenarioId: 'SC-2' });
    const base = {
      ...supportedFinding(source),
      evidenceClass: 'runtime' as const,
      runtimeEvidence: {
        scenarioId: 'SC-1', receiptId: receipt.receiptId,
        relatedReceiptIds: [controlReceipt.receiptId],
        oracle: 'The primary and negative-control requests reach the expected handler.',
        reproducibility: 'differential' as const,
        observedImpact: 'The safe probe reached the expected handler.', inferredImpact: 'No state change tested.',
      },
    };
    expect(() => submitStandardFinding({
      target, engagementDir, phase: 'pentest', role: 'pentester', finding: base,
    })).not.toThrow();
    expect(assertPentestRuntimeEvidenceIntact(engagementDir, planSha256)).toBe(1);
    expect(() => assertPentestRuntimeEvidenceIntact(engagementDir, '0'.repeat(64)))
      .toThrow(/plan binding/);
    expect(() => submitStandardFinding({
      target,
      engagementDir,
      phase: 'pentest',
      role: 'pentester',
      finding: {
        ...base,
        title: 'Duplicate primary receipt',
        runtimeEvidence: { ...base.runtimeEvidence, relatedReceiptIds: [receipt.receiptId] },
      },
    })).toThrow(/primary receipt/);
    expect(() => submitStandardFinding({
      target,
      engagementDir: mkdtempSync(join(tmpdir(), 'nunchi-foreign-receipt-')),
      phase: 'pentest',
      role: 'pentester',
      finding: { ...base, title: 'Foreign receipt' },
    })).toThrow(/receipt/);
  });

  it('rejects confirmed pentester findings outside live execution phases', () => {
    const { target, engagementDir, source } = fixture();
    expect(() => submitStandardFinding({
      target,
      engagementDir,
      phase: 'pentest-discovery',
      role: 'pentester',
      finding: supportedFinding(source),
    })).toThrow(/live 실행 단계 밖/);

    submitStandardFinding({
      target,
      engagementDir,
      phase: 'va',
      role: 'va-auditor',
      finding: supportedFinding(source),
    });
    const recordsDir = join(engagementDir, 'standard-findings');
    const recordPath = join(recordsDir, readdirSync(recordsDir)[0]!);
    const record = JSON.parse(readFileSync(recordPath, 'utf8')) as Record<string, unknown>;
    writeFileSync(recordPath, `${JSON.stringify({ ...record, phase: 'pentest-plan', role: 'pentester' })}\n`);
    expect(() => assertPentestRuntimeEvidenceIntact(engagementDir, '0'.repeat(64)))
      .toThrow(/live 실행 단계 밖/);
  });

  it('rejects live-confirmed publication when required cleanup failed', async () => {
    const { target, engagementDir, source } = fixture();
    const profile: LiveTestProfile = {
      schemaVersion: '1.0.0',
      environment: 'test',
      authorization: {
        nonProduction: true,
        approvedBy: 'security-owner',
        approvedAt: '2026-08-05T00:00:00.000Z',
      },
      targetBaseUrl: 'https://test.example/app/',
      actors: [{ actorId: 'anonymous', role: 'anonymous', authKind: 'none' }],
      policy: {
        allowedMethods: ['POST', 'DELETE'],
        maximumRiskClass: 'reversible-state-change',
        allowedRequestHeaders: ['content-type'],
        maxRequests: 2,
        maxResponseBytes: 4096,
        timeoutMs: 5000,
        maxStateChanges: 1,
        maxDurationMs: 60_000,
      },
    };
    const profileSha256 = '6'.repeat(64);
    const planSha256 = '7'.repeat(64);
    const selection = sealAuthInteractionSelection({
      engagementDir,
      runId: 'run-failed-cleanup',
      mode: 'remote-handoff',
      profileSha256,
    });
    const journal = new LiveScenarioJournal({ engagementDir, profile, profileSha256 });
    const scenario: LiveScenario = {
      schemaVersion: '2.0.0',
      scenarioId: 'SC-FAILED-CLEANUP',
      actorId: 'anonymous',
      sourceAnchors: [{ path: 'app.ts', lineStart: 2, lineEnd: 2 }],
      standardIds: ['WSTG-BUSL-09'],
      request: { method: 'POST', path: 'items/test-owned' },
      riskClass: 'reversible-state-change',
      preconditions: ['test-owned item'],
      oracle: { kind: 'state', description: 'The item is created.' },
      negativeControl: { required: true, description: 'A safe item remains unchanged.' },
      cleanupRequired: true,
      cleanup: {
        request: { method: 'DELETE', path: 'items/test-owned' },
        oracle: 'The item is absent.',
      },
      safety: 'ready',
    };
    expect(journal.propose(scenario, 'reversible state test').decision).toBe('approved');
    const receipt = await createAdaptiveLiveTestBroker({
      engagementDir,
      profile,
      profileSha256,
      planSha256,
      selection,
      journal,
      fetchImpl: async (_url, init) => new Response(
        init?.method === 'DELETE' ? 'cleanup failed' : 'created',
        { status: init?.method === 'DELETE' ? 500 : 201 },
      ),
    }).exchange({ scenarioId: scenario.scenarioId });
    expect(receipt.cleanup.status).toBe('failed');
    expect(() => submitStandardFinding({
      target,
      engagementDir,
      phase: 'pentest',
      role: 'pentester',
      finding: {
        ...supportedFinding(source),
        evidenceClass: 'runtime',
        runtimeEvidence: {
          scenarioId: scenario.scenarioId,
          receiptId: receipt.receiptId,
          observedImpact: 'The state change request completed.',
          inferredImpact: 'Impact is withheld because cleanup failed.',
        },
      },
    })).toThrow(/cleanup/);
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
