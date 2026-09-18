import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  assertPentestRuntimeEvidenceIntact,
  submitStandardFinding,
} from '../finding-contract.js';
import { sealAuthInteractionSelection, sealHostSecretSession } from '../live-auth-session.js';
import { createAdaptiveLiveTestBroker } from '../live-test-broker.js';
import { LiveScenarioJournal } from '../live-scenario-journal.js';
import type { LiveScenario, LiveTestProfile } from '../live-test-contract.js';

describe('live Finding evidence contract', () => {
  it('requires feedback findings to bind differential and negative-control receipts', async () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-live-finding-target-'));
    const engagementDir = mkdtempSync(join(tmpdir(), 'nunchi-live-finding-engagement-'));
    const source = join(target, 'app.ts');
    writeFileSync(source, 'export const handler = (input: string) => sink(input);\n');
    const profile: LiveTestProfile = {
      schemaVersion: '1.0.0',
      environment: 'test',
      authorization: {
        nonProduction: true,
        approvedBy: 'security-owner',
        approvedAt: '2026-08-06T00:00:00.000Z',
      },
      targetBaseUrl: 'https://test.example/app/',
      actors: [
        { actorId: 'subject', role: 'subject', authKind: 'host-secret', secretRef: 'SUBJECT_TOKEN' },
        { actorId: 'control', role: 'control', authKind: 'host-secret', secretRef: 'CONTROL_TOKEN' },
        { actorId: 'anon-a', role: 'anonymous', authKind: 'none' },
        { actorId: 'anon-b', role: 'anonymous-control', authKind: 'none' },
      ],
      policy: {
        allowedMethods: ['GET'],
        maximumRiskClass: 'read-only',
        maxRequests: 10,
        maxResponseBytes: 4096,
        timeoutMs: 5000,
        maxStateChanges: 0,
        maxDurationMs: 60_000,
      },
    };
    const profileSha256 = '8'.repeat(64);
    const planSha256 = '9'.repeat(64);
    const selection = sealAuthInteractionSelection({
      engagementDir,
      runId: 'run-feedback-evidence',
      mode: 'remote-handoff',
      profileSha256,
    });
    const subjectSession = sealHostSecretSession({
      engagementDir,
      selection,
      actorId: 'subject',
      targetOrigin: 'https://test.example',
      material: Buffer.from(JSON.stringify({ headers: { authorization: 'Bearer subject' } })),
    });
    const controlSession = sealHostSecretSession({
      engagementDir,
      selection,
      actorId: 'control',
      targetOrigin: 'https://test.example',
      material: Buffer.from(JSON.stringify({ headers: { authorization: 'Bearer control' } })),
    });
    const journal = new LiveScenarioJournal({ engagementDir, profile, profileSha256 });
    const primary: LiveScenario = {
      schemaVersion: '2.0.0',
      scenarioId: 'SC-SUBJECT',
      actorId: 'subject',
      sourceAnchors: [{ path: 'app.ts', lineStart: 1, lineEnd: 1 }],
      standardIds: ['WSTG-ATHZ-04'],
      request: { method: 'GET', path: 'items/test-owned' },
      riskClass: 'read-only',
      preconditions: ['approved test record'],
      oracle: {
        kind: 'differential',
        description: 'Compare the subject and control actors.',
        compareActorId: 'subject',
        relation: 'different',
        fields: ['body'],
        allowedRequestDelta: 'query-only',
      },
      negativeControl: { required: true, description: 'Control actor request.' },
      cleanupRequired: false,
      safety: 'ready',
    };
    expect(journal.propose(primary, 'subject request').decision).toBe('approved');
    const broker = createAdaptiveLiveTestBroker({
      engagementDir,
      profile,
      profileSha256,
      planSha256,
      selection,
      journal,
      authSessions: new Map([
        ['subject', subjectSession],
        ['control', controlSession],
      ]),
      fetchImpl: async (url) => new Response(String(url).includes('different=1') ? 'different' : 'ok', { status: 200 }),
    });
    const primaryReceipt = await broker.exchange({ scenarioId: primary.scenarioId });
    const sameControl: LiveScenario = {
      ...primary,
      scenarioId: 'SC-CONTROL-SAME',
      actorId: 'subject',
      parentScenarioId: primary.scenarioId,
      parentReceiptId: primaryReceipt.receiptId,
      request: { method: 'GET', path: 'items/test-owned', query: { same: '1' } },
      oracle: { kind: 'status', description: 'Record the control response.' },
      negativeControl: { required: false },
    };
    const differentControl: LiveScenario = {
      ...sameControl,
      scenarioId: 'SC-CONTROL-DIFFERENT',
      request: { method: 'GET', path: 'items/test-owned', query: { different: '1' } },
    };
    expect(journal.propose(sameControl, 'same response control').decision).toBe('approved');
    expect(journal.propose(differentControl, 'different response control').decision).toBe('approved');
    const sameReceipt = await broker.exchange({ scenarioId: sameControl.scenarioId });
    const differentReceipt = await broker.exchange({ scenarioId: differentControl.scenarioId });
    const finding = {
      title: 'Differential authorization result',
      verdict: 'supported' as const,
      severity: 'HIGH' as const,
      evidenceClass: 'runtime' as const,
      reachability: 'confirmed' as const,
      preconditions: ['approved subject and control actors'],
      severityRationale: 'The differential runtime result crosses the authorization boundary.',
      confidence: 0.9,
      impact: 'The subject can reach a control-only result.',
      remediation: 'Enforce authorization before returning the record.',
      standards: ['WSTG-ATHZ-04'],
      unresolved: [],
      evidence: [{ path: source, lineStart: 1, lineEnd: 1, quote: 'export const handler = (input: string) => sink(input);' }],
      runtimeEvidence: {
        scenarioId: primary.scenarioId,
        receiptId: primaryReceipt.receiptId,
        oracle: 'Subject and control responses differ.',
        reproducibility: 'differential' as const,
        observedImpact: 'The approved requests produced a differential observation.',
        inferredImpact: 'Authorization impact requires application-specific interpretation.',
      },
    };
    expect(() => submitStandardFinding({
      target, engagementDir, phase: 'pentest-feedback', role: 'pentester', finding,
    })).toThrow(/negative control/);
    expect(() => submitStandardFinding({
      target,
      engagementDir,
      phase: 'pentest-feedback',
      role: 'pentester',
      finding: {
        ...finding,
        runtimeEvidence: { ...finding.runtimeEvidence, relatedReceiptIds: [sameReceipt.receiptId] },
      },
    })).toThrow(/different response 관계/);
    expect(() => submitStandardFinding({
      target,
      engagementDir,
      phase: 'pentest-feedback',
      role: 'pentester',
      finding: {
        ...finding,
        runtimeEvidence: { ...finding.runtimeEvidence, relatedReceiptIds: [differentReceipt.receiptId] },
      },
    })).not.toThrow();
    expect(assertPentestRuntimeEvidenceIntact(engagementDir, planSha256)).toBe(1);
    const emptyQueryPrimary: LiveScenario = {
      ...primary,
      scenarioId: 'SC-EMPTY-QUERY-PRIMARY',
      request: { method: 'GET', path: 'items/empty-query' },
    };
    expect(journal.propose(emptyQueryPrimary, 'empty query primary').decision).toBe('approved');
    const emptyQueryPrimaryReceipt = await broker.exchange({ scenarioId: emptyQueryPrimary.scenarioId });
    const emptyQueryControl: LiveScenario = {
      ...emptyQueryPrimary,
      scenarioId: 'SC-EMPTY-QUERY-CONTROL',
      parentScenarioId: emptyQueryPrimary.scenarioId,
      parentReceiptId: emptyQueryPrimaryReceipt.receiptId,
      request: { method: 'GET', path: 'items/empty-query', query: {} },
      oracle: { kind: 'status', description: 'Record the empty query control.' },
      negativeControl: { required: false },
    };
    expect(journal.propose(emptyQueryControl, 'empty query control').decision).toBe('approved');
    const emptyQueryControlReceipt = await broker.exchange({ scenarioId: emptyQueryControl.scenarioId });
    expect(() => submitStandardFinding({
      target,
      engagementDir,
      phase: 'pentest-feedback',
      role: 'pentester',
      finding: {
        ...finding,
        title: 'Empty query is not a request delta',
        runtimeEvidence: {
          ...finding.runtimeEvidence,
          scenarioId: emptyQueryPrimary.scenarioId,
          receiptId: emptyQueryPrimaryReceipt.receiptId,
          relatedReceiptIds: [emptyQueryControlReceipt.receiptId],
        },
      },
    })).toThrow(/comparison receipt/);
    const equalPrimary: LiveScenario = {
      ...primary,
      scenarioId: 'SC-EQUAL-SUBJECT',
      request: { method: 'GET', path: 'items/equal' },
      oracle: {
        kind: 'differential',
        description: 'Compare equivalent authorization responses.',
        compareActorId: 'control',
        relation: 'equal',
        fields: ['status', 'body'],
        allowedRequestDelta: 'actor-only',
      },
    };
    expect(journal.propose(equalPrimary, 'equal subject request').decision).toBe('approved');
    const equalPrimaryReceipt = await broker.exchange({ scenarioId: equalPrimary.scenarioId });
    const equalControl: LiveScenario = {
      ...equalPrimary,
      scenarioId: 'SC-EQUAL-CONTROL',
      actorId: 'control',
      parentScenarioId: equalPrimary.scenarioId,
      parentReceiptId: equalPrimaryReceipt.receiptId,
      oracle: { kind: 'status', description: 'Record the equivalent control response.' },
      negativeControl: { required: false },
    };
    expect(journal.propose(equalControl, 'equal control request').decision).toBe('approved');
    const equalControlReceipt = await broker.exchange({ scenarioId: equalControl.scenarioId });
    expect(() => submitStandardFinding({
      target,
      engagementDir,
      phase: 'pentest-feedback',
      role: 'pentester',
      finding: {
        ...finding,
        title: 'Equivalent differential authorization result',
        runtimeEvidence: {
          ...finding.runtimeEvidence,
          scenarioId: equalPrimary.scenarioId,
          receiptId: equalPrimaryReceipt.receiptId,
          relatedReceiptIds: [equalControlReceipt.receiptId],
        },
      },
    })).not.toThrow();
    expect(assertPentestRuntimeEvidenceIntact(engagementDir, planSha256)).toBe(2);
    const anonymousPrimary: LiveScenario = {
      ...equalPrimary,
      scenarioId: 'SC-ANON-SUBJECT',
      actorId: 'anon-a',
      oracle: { ...equalPrimary.oracle, compareActorId: 'anon-b' },
    };
    expect(journal.propose(anonymousPrimary, 'anonymous subject request').decision).toBe('approved');
    const anonymousPrimaryReceipt = await broker.exchange({ scenarioId: anonymousPrimary.scenarioId });
    const anonymousControl: LiveScenario = {
      ...anonymousPrimary,
      scenarioId: 'SC-ANON-CONTROL',
      actorId: 'anon-b',
      parentScenarioId: anonymousPrimary.scenarioId,
      parentReceiptId: anonymousPrimaryReceipt.receiptId,
      oracle: { kind: 'status', description: 'Record the anonymous control response.' },
      negativeControl: { required: false },
    };
    expect(journal.propose(anonymousControl, 'anonymous control request').decision).toBe('approved');
    const anonymousControlReceipt = await broker.exchange({ scenarioId: anonymousControl.scenarioId });
    expect(() => submitStandardFinding({
      target,
      engagementDir,
      phase: 'pentest-feedback',
      role: 'pentester',
      finding: {
        ...finding,
        title: 'Anonymous actor metadata is not auth evidence',
        runtimeEvidence: {
          ...finding.runtimeEvidence,
          scenarioId: anonymousPrimary.scenarioId,
          receiptId: anonymousPrimaryReceipt.receiptId,
          relatedReceiptIds: [anonymousControlReceipt.receiptId],
        },
      },
    })).toThrow(/comparison receipt/);
    expect(() => submitStandardFinding({
      target,
      engagementDir,
      phase: 'pentest-feedback',
      role: 'pentester',
      finding: { ...finding, title: 'Missing runtime evidence', runtimeEvidence: undefined },
    })).toThrow(/runtime evidence/);
  });
});
