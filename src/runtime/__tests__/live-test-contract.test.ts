import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  assertInteractionModeCompatible,
  LiveScenarioSchema,
  loadLiveTestProfile,
  type LiveTestProfile,
} from '../live-test-contract.js';

function profile(overrides: Partial<LiveTestProfile> = {}): LiveTestProfile {
  return {
    schemaVersion: '1.0.0',
    environment: 'test',
    authorization: {
      nonProduction: true,
      approvedBy: 'security-owner',
      approvedAt: '2026-08-05T00:00:00.000Z',
    },
    targetBaseUrl: 'https://test.example/app/',
    authProviderOrigins: ['https://idp.example/'],
    walletTransportOrigins: ['https://relay.wallet.example/'],
    actors: [
      { actorId: 'anonymous', role: 'anonymous', authKind: 'none' },
      { actorId: 'owner', role: 'owner', authKind: 'oauth-oidc' },
    ],
    policy: {
      allowedMethods: ['GET', 'HEAD', 'POST'],
      maximumRiskClass: 'read-only',
      allowedRequestHeaders: ['accept', 'content-type'],
      maxRequests: 100,
      maxResponseBytes: 1_048_576,
      timeoutMs: 10_000,
      maxStateChanges: 0,
      maxDurationMs: 300_000,
      cleanupRequired: true,
    },
    ...overrides,
  };
}

describe('Live DAST profile contract', () => {
  it('loads an authorized non-production profile and binds its bytes', () => {
    const directory = mkdtempSync(join(tmpdir(), 'nunchi-live-profile-'));
    const path = join(directory, 'profile.json');
    writeFileSync(path, JSON.stringify(profile()));

    const loaded = loadLiveTestProfile(path);
    expect(loaded.profile.targetBaseUrl).toBe('https://test.example/app/');
    expect(loaded.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(() => assertInteractionModeCompatible(loaded.profile, 'remote-handoff')).not.toThrow();
    expect(() => assertInteractionModeCompatible(loaded.profile, 'local-headed-browser')).not.toThrow();
    expect(() => assertInteractionModeCompatible(loaded.profile, 'none')).toThrow(/interactive actor/);
  });

  it('rejects raw secrets, unsafe provider paths, duplicate actors and wallet policy drift', () => {
    const directory = mkdtempSync(join(tmpdir(), 'nunchi-live-profile-invalid-'));
    const path = join(directory, 'profile.json');
    writeFileSync(path, JSON.stringify(profile({
      authProviderOrigins: ['https://idp.example/oauth'],
      actors: [
        { actorId: 'same', role: 'one', authKind: 'none', secretRef: 'env:RAW' },
        { actorId: 'same', role: 'two', authKind: 'none', allowedChainIds: ['eip155:1'] },
      ],
    })));
    expect(() => loadLiveTestProfile(path)).toThrow(/origin|secretRef|중복|wallet/);
  });
});

describe('Live DAST scenario contract', () => {
  it('accepts a bounded adaptive scenario and rejects unsafe body lineage', () => {
    const scenario = {
      schemaVersion: '2.0.0',
      scenarioId: 'SC-authz-1',
      actorId: 'owner',
      sourceAnchors: [{ path: 'src/app.ts', lineStart: 1, lineEnd: 2 }],
      standardIds: ['WSTG-ATHZ-04'],
      request: { method: 'POST', path: 'api/items', body: { kind: 'json', value: { id: 'test' } } },
      riskClass: 'read-only',
      preconditions: ['owner session'],
      oracle: {
        kind: 'differential', description: 'Compare the same resource across test actors.',
        compareActorId: 'anonymous', relation: 'equal', fields: ['status', 'body'], allowedRequestDelta: 'actor-only',
      },
      negativeControl: { required: true, description: 'Use an authorized test-owned resource.' },
      cleanupRequired: false,
      safety: 'ready',
    };
    expect(LiveScenarioSchema.parse(scenario).scenarioId).toBe('SC-authz-1');
    expect(() => LiveScenarioSchema.parse({
      ...scenario,
      oracle: { kind: 'differential', description: 'Missing typed comparator.' },
    })).toThrow(/relation/);
    expect(() => LiveScenarioSchema.parse({
      ...scenario,
      parentReceiptId: 'HTTP-1234567890abcdef1234',
    })).toThrow(/parentScenarioId/);
    expect(() => LiveScenarioSchema.parse({
      ...scenario,
      request: { method: 'GET', path: 'api/items', body: { kind: 'text', value: 'x' } },
    })).toThrow(/GET\/HEAD/);
    expect(() => LiveScenarioSchema.parse({
      ...scenario,
      request: { method: 'GET', path: 'api/items?x=1' },
    })).toThrow(/query 또는 fragment/);
    expect(() => LiveScenarioSchema.parse({
      ...scenario,
      request: { method: 'GET', path: 'api/items#result' },
    })).toThrow(/query 또는 fragment/);
    expect(() => LiveScenarioSchema.parse({
      ...scenario,
      riskClass: 'reversible-state-change',
      cleanupRequired: true,
    })).toThrow(/cleanup/);
    expect(() => LiveScenarioSchema.parse({
      ...scenario,
      riskClass: 'reversible-state-change',
      cleanupRequired: true,
      cleanup: {
        request: { method: 'GET', path: 'api/items', body: { kind: 'text', value: 'x' } },
        oracle: 'The item is absent.',
      },
    })).toThrow(/GET\/HEAD cleanup/);
  });
});
