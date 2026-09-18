import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it, vi } from 'vitest';

import {
  createAdaptiveLiveTestBroker,
  verifyLiveTestReceipt,
} from '../live-test-broker.js';
import { LiveScenarioJournal } from '../live-scenario-journal.js';
import {
  createOwnerAuthRequest,
  sealAuthInteractionSelection,
  sealOpaqueAuthSession,
} from '../live-auth-session.js';
import type { LiveScenario, LiveTestProfile } from '../live-test-contract.js';

function profile(): LiveTestProfile {
  return {
    schemaVersion: '1.0.0',
    environment: 'test',
    authorization: {
      nonProduction: true,
      approvedBy: 'security-owner',
      approvedAt: '2026-08-05T00:00:00.000Z',
    },
    targetBaseUrl: 'https://test.example/app/',
    actors: [
      { actorId: 'anonymous', role: 'anonymous', authKind: 'none' },
      { actorId: 'owner', role: 'owner', authKind: 'oauth-oidc' },
    ],
    policy: {
      allowedMethods: ['GET', 'HEAD', 'POST'],
      maximumRiskClass: 'read-only',
      allowedRequestHeaders: ['accept', 'content-type'],
      maxRequests: 10,
      maxResponseBytes: 4096,
      timeoutMs: 5000,
      maxStateChanges: 0,
      maxDurationMs: 60_000,
    },
  };
}

function scenario(overrides: Partial<LiveScenario> = {}): LiveScenario {
  return {
    schemaVersion: '2.0.0',
    scenarioId: 'SC-OWNER-1',
    actorId: 'owner',
    sourceAnchors: [{ path: 'src/app.ts', lineStart: 1, lineEnd: 1 }],
    standardIds: ['WSTG-ATHZ-04'],
    request: {
      method: 'POST',
      path: 'api/query',
      headers: { accept: 'application/json' },
      body: { kind: 'json', value: { query: 'test-owned' } },
    },
    riskClass: 'read-only',
    preconditions: ['approved owner actor'],
    oracle: {
      kind: 'differential', description: 'Compare with an unauthenticated baseline.',
      compareActorId: 'anonymous', relation: 'different', fields: ['body'], allowedRequestDelta: 'actor-only',
    },
    negativeControl: { required: true, description: 'Use a test-owned record.' },
    cleanupRequired: false,
    safety: 'ready',
    ...overrides,
  };
}

describe('Adaptive Live DAST scenario journal', () => {
  it('approves only unique in-scope policy-compliant scenarios', () => {
    const engagementDir = mkdtempSync(join(tmpdir(), 'nunchi-live-journal-'));
    const liveProfile = profile();
    const journal = new LiveScenarioJournal({
      engagementDir,
      profile: liveProfile,
      profileSha256: 'a'.repeat(64),
    });
    expect(journal.propose(scenario(), 'source-derived owner route')).toMatchObject({ decision: 'approved' });
    expect(journal.propose(scenario({ scenarioId: 'SC-DUPLICATE' }), 'duplicate request')).toMatchObject({
      decision: 'rejected',
      reason: expect.stringMatching(/fingerprint/),
    });
    expect(journal.propose(scenario({
      scenarioId: 'SC-OUTSIDE',
      request: { method: 'GET', path: 'https://other.example/' },
    }), 'outside target')).toMatchObject({
      decision: 'rejected',
      reason: expect.stringMatching(/범위 밖/),
    });
    expect(journal.verify().map((event) => event.type)).toEqual([
      'proposed', 'approved', 'proposed', 'rejected', 'proposed', 'rejected',
    ]);
  });

  it('rejects unsupported method/header and journal tampering', () => {
    const engagementDir = mkdtempSync(join(tmpdir(), 'nunchi-live-journal-policy-'));
    const liveProfile = profile();
    const journal = new LiveScenarioJournal({
      engagementDir,
      profile: liveProfile,
      profileSha256: '0'.repeat(64),
    });
    expect(journal.propose(scenario({
      scenarioId: 'SC-METHOD',
      request: { method: 'DELETE', path: 'items/test-owned' },
    }), 'unsupported method')).toMatchObject({ decision: 'rejected' });
    expect(journal.propose(scenario({
      scenarioId: 'SC-HEADER',
      request: { method: 'GET', path: 'health', headers: { 'x-unapproved': 'value' } },
    }), 'unsupported header')).toMatchObject({ decision: 'rejected' });
    const lines = readFileSync(journal.path, 'utf8').trimEnd().split('\n');
    const event = JSON.parse(lines[0]!) as Record<string, unknown>;
    event.reason = 'tampered';
    lines[0] = JSON.stringify(event);
    writeFileSync(journal.path, `${lines.join('\n')}\n`);
    expect(() => journal.verify()).toThrow(/hash/);
  });
});

describe('Adaptive Live DAST broker', () => {
  it('injects host-only actor auth, records a redacted receipt and binds journal execution', async () => {
    const engagementDir = mkdtempSync(join(tmpdir(), 'nunchi-live-adaptive-'));
    const liveProfile = profile();
    const profileSha256 = 'b'.repeat(64);
    const planSha256 = 'c'.repeat(64);
    const selection = sealAuthInteractionSelection({
      engagementDir,
      runId: 'run-adaptive',
      mode: 'remote-handoff',
      profileSha256,
    });
    const request = createOwnerAuthRequest({
      engagementDir,
      selection,
      actorId: 'owner',
      authKind: 'oauth-oidc',
      targetOrigin: 'https://test.example',
      startUrl: 'https://test.example/app/login',
      providerOrigin: 'https://idp.example',
      purpose: 'Authenticate the approved owner.',
      postLoginGoal: 'Test owner routes.',
    });
    const session = sealOpaqueAuthSession({
      engagementDir,
      selection,
      request,
      capture: {
        materialKind: 'oauth-token-set',
        material: Buffer.from(JSON.stringify({ access_token: 'server-only-owner-token-value' })),
        publicMetadata: { issuer: 'https://idp.example/' },
      },
    });
    const journal = new LiveScenarioJournal({ engagementDir, profile: liveProfile, profileSha256 });
    expect(journal.propose(scenario(), 'source and runtime route evidence').decision).toBe('approved');
    const observed = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      expect(headers.get('authorization')).toBe('Bearer server-only-owner-token-value');
      expect(Buffer.from(init?.body as Uint8Array).toString('utf8')).toContain('test-owned');
      return new Response('{"token":"abcdefghijklmnopqrstuvwxyz123456","ok":true}', {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });
    const broker = createAdaptiveLiveTestBroker({
      engagementDir,
      profile: liveProfile,
      profileSha256,
      planSha256,
      selection,
      journal,
      authSessions: new Map([['owner', session]]),
      fetchImpl: observed,
    });
    const receipt = await broker.exchange({ scenarioId: 'SC-OWNER-1' });
    expect(receipt.schemaVersion).toBe('2.0.0');
    expect(receipt.actorId).toBe('owner');
    expect(receipt.request.headerNames).toContain('authorization');
    expect(receipt.response.safeExcerpt).toContain('[REDACTED]');
    const serialized = readFileSync(
      join(engagementDir, 'http-probe-receipts', `${receipt.receiptId}.json`),
      'utf8',
    );
    expect(serialized).not.toContain('server-only-owner-token-value');
    expect(verifyLiveTestReceipt({
      engagementDir,
      receiptId: receipt.receiptId,
      scenarioId: receipt.scenarioId,
      planSha256,
    })).toEqual(receipt);
    expect(journal.verify().at(-1)).toMatchObject({
      type: 'executed',
      receiptId: receipt.receiptId,
    });
    expect(observed).toHaveBeenCalledOnce();
  });

  it('opens the circuit after a rate-limit response', async () => {
    const engagementDir = mkdtempSync(join(tmpdir(), 'nunchi-live-circuit-'));
    const liveProfile = profile();
    const profileSha256 = 'd'.repeat(64);
    const selection = sealAuthInteractionSelection({
      engagementDir,
      runId: 'run-circuit',
      mode: 'remote-handoff',
      profileSha256,
    });
    const anonymous = scenario({
      scenarioId: 'SC-RATE-1',
      actorId: 'anonymous',
      request: { method: 'GET', path: 'health' },
    });
    const journal = new LiveScenarioJournal({ engagementDir, profile: liveProfile, profileSha256 });
    expect(journal.propose(anonymous, 'safe health baseline').decision).toBe('approved');
    const broker = createAdaptiveLiveTestBroker({
      engagementDir,
      profile: liveProfile,
      profileSha256,
      planSha256: 'e'.repeat(64),
      selection,
      journal,
      fetchImpl: async () => new Response('limited', { status: 429, headers: { 'content-type': 'text/plain' } }),
    });
    expect((await broker.exchange({ scenarioId: 'SC-RATE-1' })).response.status).toBe(429);
    await expect(broker.exchange({ scenarioId: 'SC-RATE-1' })).rejects.toThrow(/circuit breaker/);
  });

  it('enforces request limits across broker instances and phases', async () => {
    const engagementDir = mkdtempSync(join(tmpdir(), 'nunchi-live-global-limit-'));
    const liveProfile = {
      ...profile(),
      policy: { ...profile().policy, maxRequests: 1 },
    };
    const profileSha256 = 'f'.repeat(64);
    const planSha256 = '1'.repeat(64);
    const selection = sealAuthInteractionSelection({
      engagementDir,
      runId: 'run-global-limit',
      mode: 'remote-handoff',
      profileSha256,
    });
    const journal = new LiveScenarioJournal({ engagementDir, profile: liveProfile, profileSha256 });
    const first = scenario({
      scenarioId: 'SC-LIMIT-1',
      actorId: 'anonymous',
      request: { method: 'GET', path: 'health/first' },
    });
    const second = scenario({
      scenarioId: 'SC-LIMIT-2',
      actorId: 'anonymous',
      request: { method: 'GET', path: 'health/second' },
    });
    expect(journal.propose(first, 'phase one').decision).toBe('approved');
    expect(journal.propose(second, 'phase two').decision).toBe('approved');
    const fetchImpl = vi.fn(async () => new Response('ok', { status: 200 }));
    await createAdaptiveLiveTestBroker({
      engagementDir, profile: liveProfile, profileSha256, planSha256, selection, journal, fetchImpl,
    }).exchange({ scenarioId: first.scenarioId });
    await expect(createAdaptiveLiveTestBroker({
      engagementDir, profile: liveProfile, profileSha256, planSha256, selection, journal, fetchImpl,
    }).exchange({ scenarioId: second.scenarioId })).rejects.toThrow(/request 상한/);
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it('opens the run-wide circuit after three consecutive server errors', async () => {
    const engagementDir = mkdtempSync(join(tmpdir(), 'nunchi-live-server-errors-'));
    const liveProfile = profile();
    const profileSha256 = '2'.repeat(64);
    const planSha256 = '3'.repeat(64);
    const selection = sealAuthInteractionSelection({
      engagementDir,
      runId: 'run-server-errors',
      mode: 'remote-handoff',
      profileSha256,
    });
    const journal = new LiveScenarioJournal({ engagementDir, profile: liveProfile, profileSha256 });
    for (let index = 1; index <= 4; index += 1) {
      expect(journal.propose(scenario({
        scenarioId: `SC-SERVER-${index}`,
        actorId: 'anonymous',
        request: { method: 'GET', path: `health/${index}` },
      }), `server error ${index}`).decision).toBe('approved');
    }
    const fetchImpl = vi.fn(async () => new Response('error', { status: 500 }));
    for (let index = 1; index <= 3; index += 1) {
      await createAdaptiveLiveTestBroker({
        engagementDir, profile: liveProfile, profileSha256, planSha256, selection, journal, fetchImpl,
      }).exchange({ scenarioId: `SC-SERVER-${index}` });
    }
    await expect(createAdaptiveLiveTestBroker({
      engagementDir, profile: liveProfile, profileSha256, planSha256, selection, journal, fetchImpl,
    }).exchange({ scenarioId: 'SC-SERVER-4' })).rejects.toThrow(/circuit breaker/);
    expect(fetchImpl).toHaveBeenCalledTimes(3);
  });

  it('executes reversible cleanup and records whether restoration succeeded', async () => {
    const engagementDir = mkdtempSync(join(tmpdir(), 'nunchi-live-cleanup-'));
    const liveProfile: LiveTestProfile = {
      ...profile(),
      policy: {
        ...profile().policy,
        allowedMethods: ['GET', 'HEAD', 'POST', 'DELETE'],
        maximumRiskClass: 'reversible-state-change',
        maxStateChanges: 1,
      },
    };
    const profileSha256 = '4'.repeat(64);
    const planSha256 = '5'.repeat(64);
    const selection = sealAuthInteractionSelection({
      engagementDir,
      runId: 'run-cleanup',
      mode: 'remote-handoff',
      profileSha256,
    });
    const journal = new LiveScenarioJournal({ engagementDir, profile: liveProfile, profileSha256 });
    const stateful = scenario({
      scenarioId: 'SC-CLEANUP-1',
      actorId: 'anonymous',
      request: { method: 'POST', path: 'items/test-owned', body: { kind: 'json', value: { enabled: true } } },
      riskClass: 'reversible-state-change',
      cleanupRequired: true,
      cleanup: {
        request: { method: 'DELETE', path: 'items/test-owned' },
        oracle: 'The test-owned item no longer exists.',
      },
    });
    expect(journal.propose(stateful, 'test-owned reversible fixture').decision).toBe('approved');
    const fetchImpl = vi.fn(async (_url: string | URL | Request, init?: RequestInit) =>
      init?.method === 'DELETE'
        ? new Response(null, { status: 204 })
        : new Response('', { status: 201 }));
    const receipt = await createAdaptiveLiveTestBroker({
      engagementDir, profile: liveProfile, profileSha256, planSha256, selection, journal, fetchImpl,
    }).exchange({ scenarioId: stateful.scenarioId });
    expect(receipt.cleanup).toMatchObject({ required: true, status: 'succeeded' });
    expect(journal.verify().map((event) => event.type)).toContain('cleanup-succeeded');
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it('blocks state changes before network when the run-wide state budget is exhausted', async () => {
    const engagementDir = mkdtempSync(join(tmpdir(), 'nunchi-live-state-limit-'));
    const liveProfile: LiveTestProfile = {
      ...profile(),
      policy: {
        ...profile().policy,
        allowedMethods: ['POST', 'DELETE'],
        maximumRiskClass: 'reversible-state-change',
        maxStateChanges: 1,
      },
    };
    const profileSha256 = '6'.repeat(64);
    const selection = sealAuthInteractionSelection({
      engagementDir,
      runId: 'run-state-limit',
      mode: 'remote-handoff',
      profileSha256,
    });
    const journal = new LiveScenarioJournal({ engagementDir, profile: liveProfile, profileSha256 });
    const first = scenario({
      scenarioId: 'SC-STATE-FIRST',
      actorId: 'anonymous',
      request: { method: 'POST', path: 'items/first' },
      riskClass: 'reversible-state-change',
      cleanupRequired: true,
      cleanup: {
        request: { method: 'DELETE', path: 'items/first' },
        oracle: 'The test-owned item is absent.',
      },
    });
    const second = scenario({
      ...first,
      scenarioId: 'SC-STATE-SECOND',
      request: { method: 'POST', path: 'items/second' },
      cleanup: {
        request: { method: 'DELETE', path: 'items/second' },
        oracle: 'The second test-owned item is absent.',
      },
    });
    expect(journal.propose(first, 'first state change').decision).toBe('approved');
    expect(journal.propose(second, 'state budget boundary').decision).toBe('approved');
    const fetchImpl = vi.fn(async () => new Response('ok', { status: 200 }));
    await createAdaptiveLiveTestBroker({
      engagementDir,
      profile: liveProfile,
      profileSha256,
      planSha256: '7'.repeat(64),
      selection,
      journal,
      fetchImpl,
    }).exchange({ scenarioId: first.scenarioId });
    await expect(createAdaptiveLiveTestBroker({
      engagementDir,
      profile: liveProfile,
      profileSha256,
      planSha256: '7'.repeat(64),
      selection,
      journal,
      fetchImpl,
    }).exchange({ scenarioId: second.scenarioId })).rejects.toThrow(/state change 상한/);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });
});
