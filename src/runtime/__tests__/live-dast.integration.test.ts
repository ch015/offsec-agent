import { createServer } from 'node:http';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import {
  createLocalHeadedBrowserAdapter,
  createRemoteHandoffAdapter,
  type AuthInteractionAdapter,
} from '../auth-interaction.js';
import { createAdaptiveLiveTestBroker } from '../live-test-broker.js';
import { LiveScenarioJournal } from '../live-scenario-journal.js';
import {
  createOwnerAuthRequest,
  sealAuthInteractionSelection,
  sealOpaqueAuthSession,
} from '../live-auth-session.js';
import type { AuthInteractionMode, LiveScenario, LiveTestProfile } from '../live-test-contract.js';

let baseUrl = '';
const created = new Set<string>();
const server = createServer((request, response) => {
  const url = new URL(request.url ?? '/', 'http://127.0.0.1');
  const authenticated = request.headers.authorization === 'Bearer owner-fixture-token'
    || request.headers.cookie?.includes('session=owner-fixture-token') === true;
  response.setHeader('content-type', 'application/json');
  if (url.pathname === '/app/role') {
    response.writeHead(authenticated ? 200 : 403).end(JSON.stringify({ role: authenticated ? 'owner' : 'anonymous' }));
    return;
  }
  if (url.pathname === '/app/input') {
    response.writeHead(url.searchParams.get('value') === 'valid' ? 200 : 400).end('{"validated":true}');
    return;
  }
  if (url.pathname === '/app/error') {
    response.writeHead(500).end('{"error":"controlled fixture failure"}');
    return;
  }
  if (url.pathname === '/app/safe') {
    response.writeHead(200).end('{"safe":true}');
    return;
  }
  if (url.pathname === '/app/items/test-owned' && request.method === 'POST') {
    created.add('test-owned');
    response.writeHead(201).end('{"created":true}');
    return;
  }
  if (url.pathname === '/app/items/test-owned' && request.method === 'DELETE') {
    created.delete('test-owned');
    response.writeHead(204).end();
    return;
  }
  response.writeHead(404).end('{"missing":true}');
});

beforeAll(async () => {
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('local fixture address가 없다');
  baseUrl = `http://127.0.0.1:${address.port}/app/`;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

function profile(): LiveTestProfile {
  return {
    schemaVersion: '1.0.0',
    environment: 'test',
    authorization: {
      nonProduction: true,
      approvedBy: 'integration-owner',
      approvedAt: '2026-08-05T00:00:00.000Z',
    },
    targetBaseUrl: baseUrl,
    authProviderOrigins: ['https://idp.example/'],
    actors: [
      { actorId: 'anonymous', role: 'anonymous', authKind: 'none' },
      { actorId: 'owner', role: 'owner', authKind: 'oauth-oidc' },
    ],
    policy: {
      allowedMethods: ['GET', 'POST', 'DELETE'],
      maximumRiskClass: 'reversible-state-change',
      allowedRequestHeaders: ['accept', 'content-type'],
      maxRequests: 7,
      maxResponseBytes: 4096,
      timeoutMs: 5000,
      maxStateChanges: 1,
      maxDurationMs: 60_000,
      cleanupRequired: true,
    },
  };
}

function scenario(
  scenarioId: string,
  actorId: string,
  path: string,
  overrides: Partial<LiveScenario> = {},
): LiveScenario {
  return {
    schemaVersion: '2.0.0',
    scenarioId,
    actorId,
    sourceAnchors: [{ path: 'fixture/app.ts', lineStart: 1, lineEnd: 1 }],
    standardIds: ['WSTG-ATHZ-04'],
    request: { method: 'GET', path },
    riskClass: 'read-only',
    preconditions: ['isolated local fixture'],
    oracle: { kind: 'status', description: 'Compare the bounded fixture status.' },
    negativeControl: { required: true, description: 'Use the look-alike anonymous route.' },
    cleanupRequired: false,
    safety: 'ready',
    ...overrides,
  };
}

async function adapterFor(
  mode: Exclude<AuthInteractionMode, 'none'>,
  engagementDir: string,
  targetOrigin: string,
): Promise<AuthInteractionAdapter> {
  if (mode === 'remote-handoff') {
    return createRemoteHandoffAdapter({
      issue: async () => ({
        userAction: 'Authenticate to the local fixture.',
        authorizationUrl: 'https://idp.example/authorize',
      }),
      capture: async () => ({
        materialKind: 'oauth-token-set',
        material: Buffer.from(JSON.stringify({ access_token: 'owner-fixture-token' })),
        publicMetadata: {
          issuer: 'https://idp.example/',
          redirectUri: `${targetOrigin}/callback`,
          scopes: ['openid'],
        },
      }),
    });
  }
  const page = { goto: vi.fn(async () => undefined), url: () => `${targetOrigin}/dashboard` };
  return createLocalHeadedBrowserAdapter({
    engagementDir,
    launcher: async () => ({
      pages: () => [page],
      newPage: async () => page,
      storageState: async () => ({
        cookies: [{
          name: 'session',
          value: 'owner-fixture-token',
          domain: '127.0.0.1',
          path: '/app/',
          expires: -1,
          httpOnly: true,
          secure: false,
          sameSite: 'Lax' as const,
        }],
        origins: [],
      }),
      close: async () => undefined,
    } as never),
  });
}

describe.each(['remote-handoff', 'local-headed-browser'] as const)(
  'Live DAST local integration (%s)',
  (mode) => {
    it('keeps auth, role, error, cleanup and evidence behavior mode-independent', async () => {
      created.clear();
      const engagementDir = mkdtempSync(join(tmpdir(), `nunchi-live-integration-${mode}-`));
      const liveProfile = profile();
      const profileSha256 = mode === 'remote-handoff' ? '8'.repeat(64) : '9'.repeat(64);
      const planSha256 = 'a'.repeat(64);
      const selection = sealAuthInteractionSelection({
        engagementDir,
        runId: `run-${mode}`,
        mode,
        profileSha256,
      });
      const targetOrigin = new URL(baseUrl).origin;
      const request = createOwnerAuthRequest({
        engagementDir,
        selection,
        actorId: 'owner',
        authKind: 'oauth-oidc',
        targetOrigin,
        startUrl: `${baseUrl}login`,
        providerOrigin: 'https://idp.example',
        requestedScopes: ['openid'],
        purpose: 'Authenticate the local fixture owner.',
        postLoginGoal: 'Exercise role-differential routes.',
      });
      const adapter = await adapterFor(mode, engagementDir, targetOrigin);
      try {
        await adapter.begin(request);
        const session = sealOpaqueAuthSession({
          engagementDir,
          selection,
          request,
          capture: await adapter.capture(request),
        });
        const journal = new LiveScenarioJournal({ engagementDir, profile: liveProfile, profileSha256 });
        const scenarios = [
          scenario('SC-OWNER', 'owner', 'role'),
          scenario('SC-ANONYMOUS', 'anonymous', 'role', {
            request: { method: 'GET', path: 'role', query: { control: 'anonymous' } },
          }),
          scenario('SC-INPUT', 'anonymous', 'input', {
            request: { method: 'GET', path: 'input', query: { value: 'invalid' } },
          }),
          scenario('SC-ERROR', 'anonymous', 'error'),
          scenario('SC-SAFE', 'anonymous', 'safe'),
          scenario('SC-STATE', 'anonymous', 'items/test-owned', {
            request: { method: 'POST', path: 'items/test-owned' },
            riskClass: 'reversible-state-change',
            oracle: { kind: 'state', description: 'The test-owned item is created.' },
            cleanupRequired: true,
            cleanup: {
              request: { method: 'DELETE', path: 'items/test-owned' },
              oracle: 'The test-owned item is removed.',
            },
          }),
        ];
        for (const item of scenarios) {
          expect(journal.propose(item, 'local integration coverage').decision).toBe('approved');
        }
        const broker = createAdaptiveLiveTestBroker({
          engagementDir,
          profile: liveProfile,
          profileSha256,
          planSha256,
          selection,
          journal,
          authSessions: new Map([['owner', session]]),
        });
        const receipts = [];
        for (const item of scenarios) receipts.push(await broker.exchange({ scenarioId: item.scenarioId }));
        expect(receipts.map((receipt) => receipt.response.status)).toEqual([200, 403, 400, 500, 200, 201]);
        expect(receipts.at(-1)?.cleanup.status).toBe('succeeded');
        expect(created.has('test-owned')).toBe(false);
        expect(journal.verify().filter((event) => event.type === 'executed')).toHaveLength(scenarios.length);
        const publicEvidence = [
          readFileSync(journal.path, 'utf8'),
          ...receipts.map((receipt) => readFileSync(
            join(engagementDir, 'http-probe-receipts', `${receipt.receiptId}.json`),
            'utf8',
          )),
          readFileSync(join(engagementDir, 'auth-sessions', `${session.sessionId}.json`), 'utf8'),
        ].join('\n');
        expect(publicEvidence).not.toContain('owner-fixture-token');
        expect(receipts[0]?.response.safeExcerpt).toContain('[UNTRUSTED TARGET DATA]');
      } finally {
        await adapter.close();
      }
    });
  },
);
