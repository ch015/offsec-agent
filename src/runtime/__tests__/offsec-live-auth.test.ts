import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it, vi } from 'vitest';

import {
  assertLocalBrowserCapability,
  awaitOwnerCompletion,
  createLocalHeadedBrowserAdapter,
  createRemoteHandoffAdapter,
} from '../auth-interaction.js';
import {
  createOwnerAuthRequest,
  readAuthInteractionSelection,
  readOpaqueAuthMaterial,
  readOpaqueAuthSession,
  sealAuthInteractionSelection,
  sealOpaqueAuthSession,
} from '../live-auth-session.js';

function engagement(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

describe('OffSec owner authentication state', () => {
  it('seals the initial mode and opaque actor session without exposing material', () => {
    const engagementDir = engagement('nunchi-auth-state-');
    const selection = sealAuthInteractionSelection({
      engagementDir,
      runId: 'run-1',
      mode: 'remote-handoff',
      profileSha256: 'a'.repeat(64),
      now: new Date('2026-08-05T00:00:00.000Z'),
    });
    expect(readAuthInteractionSelection(engagementDir)).toEqual(selection);
    expect(sealAuthInteractionSelection({
      engagementDir,
      runId: 'run-1',
      mode: 'remote-handoff',
      profileSha256: 'a'.repeat(64),
      now: new Date('2026-08-05T00:01:00.000Z'),
    })).toEqual(selection);
    expect(() => sealAuthInteractionSelection({
      engagementDir,
      runId: 'run-1',
      mode: 'local-headed-browser',
      profileSha256: 'a'.repeat(64),
    })).toThrow(/변경할 수 없다/);

    const request = createOwnerAuthRequest({
      engagementDir,
      selection,
      actorId: 'owner',
      authKind: 'oauth-oidc',
      targetOrigin: 'https://test.example',
      startUrl: 'https://test.example/login',
      providerOrigin: 'https://idp.example',
      requestedScopes: ['openid', 'profile'],
      purpose: 'Authenticate the approved test owner.',
      postLoginGoal: 'Review authenticated owner routes.',
      now: new Date('2026-08-05T00:00:00.000Z'),
    });
    const material = Buffer.from('{"access_token":"owner-secret-token"}');
    const session = sealOpaqueAuthSession({
      engagementDir,
      selection,
      request,
      capture: {
        materialKind: 'oauth-token-set',
        material,
        publicMetadata: {
          issuer: 'https://idp.example/',
          clientId: 'public-client',
          scopes: ['openid', 'profile'],
        },
      },
      now: new Date('2026-08-05T00:01:00.000Z'),
    });
    expect(readOpaqueAuthSession({
      engagementDir,
      sessionId: session.sessionId,
      selection,
      actorId: 'owner',
      now: new Date('2026-08-05T00:02:00.000Z'),
    })).toEqual(session);
    expect(readOpaqueAuthMaterial({ engagementDir, session })).toEqual(material);
    const publicRecord = readFileSync(join(engagementDir, 'auth-sessions', `${session.sessionId}.json`), 'utf8');
    expect(publicRecord).not.toContain('owner-secret-token');
    expect(() => readOpaqueAuthSession({
      engagementDir,
      sessionId: session.sessionId,
      actorId: 'other',
      now: new Date('2026-08-05T00:02:00.000Z'),
    })).toThrow(/actor binding/);
  });
});

describe('OffSec authentication interaction adapters', () => {
  it('issues and captures a remote handoff only for the sealed mode', async () => {
    const engagementDir = engagement('nunchi-auth-remote-');
    const selection = sealAuthInteractionSelection({
      engagementDir,
      runId: 'run-remote',
      mode: 'remote-handoff',
      profileSha256: 'b'.repeat(64),
    });
    const request = createOwnerAuthRequest({
      engagementDir,
      selection,
      actorId: 'wallet-owner',
      authKind: 'wallet',
      targetOrigin: 'https://test.example',
      startUrl: 'https://test.example/connect',
      requestedChainIds: ['eip155:11155111'],
      purpose: 'Connect the approved test wallet.',
      postLoginGoal: 'Review wallet-bound authorization.',
    });
    const provider = {
      issue: vi.fn(async () => ({ userAction: 'Scan the test pairing QR.', pairingUri: 'wc:test' })),
      capture: vi.fn(async () => ({
        materialKind: 'wallet-session' as const,
        material: Buffer.from('opaque-wallet-session'),
        publicMetadata: { accountPseudonym: 'wallet-1', chainId: 'eip155:11155111' },
      })),
    };
    const adapter = createRemoteHandoffAdapter(provider);
    expect(await adapter.begin(request)).toMatchObject({
      mode: 'remote-handoff',
      pairingUri: 'wc:test',
      browserOpened: false,
    });
    expect((await adapter.capture(request)).materialKind).toBe('wallet-session');
    await expect(adapter.begin(request)).rejects.toThrow(/이미 발급/);
  });

  it('captures only target-origin storage from a local headed browser', async () => {
    const engagementDir = engagement('nunchi-auth-local-');
    const selection = sealAuthInteractionSelection({
      engagementDir,
      runId: 'run-local',
      mode: 'local-headed-browser',
      profileSha256: 'c'.repeat(64),
    });
    const request = createOwnerAuthRequest({
      engagementDir,
      selection,
      actorId: 'owner',
      authKind: 'passkey',
      targetOrigin: 'https://test.example',
      startUrl: 'https://test.example/login',
      purpose: 'Complete the approved local passkey login.',
      postLoginGoal: 'Review authenticated owner routes.',
    });
    const goto = vi.fn(async () => undefined);
    const close = vi.fn(async () => undefined);
    const page = { goto, url: () => 'https://test.example/dashboard' };
    const adapter = createLocalHeadedBrowserAdapter({
      engagementDir,
      launcher: async () => ({
        pages: () => [page],
        newPage: async () => page,
        storageState: async () => ({
          cookies: [
            { name: 'session', value: 'target-secret', domain: 'test.example', path: '/', expires: -1, httpOnly: true, secure: true, sameSite: 'Lax' as const },
            { name: 'idp', value: 'idp-secret', domain: 'idp.example', path: '/', expires: -1, httpOnly: true, secure: true, sameSite: 'Lax' as const },
          ],
          origins: [
            { origin: 'https://test.example', localStorage: [{ name: 'state', value: 'target' }] },
            { origin: 'https://idp.example', localStorage: [{ name: 'token', value: 'idp-secret' }] },
          ],
        }),
        close,
      } as never),
    });
    expect(await adapter.begin(request)).toMatchObject({
      mode: 'local-headed-browser',
      browserOpened: true,
    });
    expect(goto).toHaveBeenCalledWith('https://test.example/login', { waitUntil: 'domcontentloaded' });
    const capture = await adapter.capture(request);
    const stored = capture.material.toString('utf8');
    expect(stored).toContain('target-secret');
    expect(stored).not.toContain('idp-secret');
    expect(capture.publicMetadata.finalOrigin).toBe('https://test.example');
    await adapter.close();
    expect(close).toHaveBeenCalledOnce();
  });

  it('rejects provider, callback, material and wallet-chain binding mismatches', async () => {
    const engagementDir = engagement('nunchi-auth-binding-');
    const selection = sealAuthInteractionSelection({
      engagementDir,
      runId: 'run-binding',
      mode: 'remote-handoff',
      profileSha256: 'd'.repeat(64),
    });
    const oauthRequest = createOwnerAuthRequest({
      engagementDir,
      selection,
      actorId: 'owner',
      authKind: 'oauth-oidc',
      targetOrigin: 'https://test.example',
      startUrl: 'https://test.example/login',
      providerOrigin: 'https://idp.example',
      requestedScopes: ['openid'],
      purpose: 'Authenticate owner.',
      postLoginGoal: 'Test owner routes.',
    });
    const adapter = createRemoteHandoffAdapter({
      issue: async () => ({
        userAction: 'Authenticate.',
        authorizationUrl: 'https://evil.example/authorize',
      }),
      capture: async () => ({
        materialKind: 'oauth-token-set',
        material: Buffer.from('opaque'),
        publicMetadata: {},
      }),
    });
    await expect(adapter.begin(oauthRequest)).rejects.toThrow(/provider origin/);
    expect(() => sealOpaqueAuthSession({
      engagementDir,
      selection,
      request: oauthRequest,
      capture: {
        materialKind: 'oauth-token-set',
        material: Buffer.from('opaque'),
        publicMetadata: { issuer: 'https://idp.example', redirectUri: 'https://evil.example/callback' },
      },
    })).toThrow(/redirect origin/);
    expect(() => sealOpaqueAuthSession({
      engagementDir,
      selection,
      request: oauthRequest,
      capture: {
        materialKind: 'wallet-session',
        material: Buffer.from('opaque'),
        publicMetadata: {},
      },
    })).toThrow(/material kind/);

    const walletRequest = createOwnerAuthRequest({
      engagementDir,
      selection,
      actorId: 'wallet-owner',
      authKind: 'wallet',
      targetOrigin: 'https://test.example',
      startUrl: 'https://test.example/connect',
      requestedChainIds: ['eip155:11155111'],
      purpose: 'Connect wallet.',
      postLoginGoal: 'Test wallet routes.',
    });
    expect(() => sealOpaqueAuthSession({
      engagementDir,
      selection,
      request: walletRequest,
      capture: {
        materialKind: 'wallet-session',
        material: Buffer.from('opaque'),
        publicMetadata: { chainId: 'eip155:1' },
      },
    })).toThrow(/chain/);
  });

  it('fails local GUI preflight without fallback and rejects expired or cross-mode sessions', async () => {
    expect(() => assertLocalBrowserCapability({}, 'linux')).toThrow(/DISPLAY|WAYLAND_DISPLAY/);
    const engagementDir = engagement('nunchi-auth-expiry-');
    const selection = sealAuthInteractionSelection({
      engagementDir,
      runId: 'run-expiry',
      mode: 'remote-handoff',
      profileSha256: 'e'.repeat(64),
      now: new Date('2026-08-05T00:00:00.000Z'),
    });
    const request = createOwnerAuthRequest({
      engagementDir,
      selection,
      actorId: 'owner',
      authKind: 'oauth-oidc',
      targetOrigin: 'https://test.example',
      startUrl: 'https://test.example/login',
      providerOrigin: 'https://idp.example',
      purpose: 'Authenticate owner.',
      postLoginGoal: 'Test owner routes.',
      ttlMs: 1000,
      now: new Date('2026-08-05T00:00:00.000Z'),
    });
    const capture = {
      materialKind: 'oauth-token-set' as const,
      material: Buffer.from('{"access_token":"opaque-owner-token"}'),
      publicMetadata: { issuer: 'https://idp.example/' },
    };
    expect(() => sealOpaqueAuthSession({
      engagementDir,
      selection,
      request,
      capture,
      now: new Date('2026-08-05T00:00:01.000Z'),
    })).toThrow(/만료/);
    const session = sealOpaqueAuthSession({
      engagementDir,
      selection,
      request,
      capture,
      now: new Date('2026-08-05T00:00:00.500Z'),
    });
    expect(() => readOpaqueAuthSession({
      engagementDir,
      sessionId: session.sessionId,
      selection: { ...selection, mode: 'local-headed-browser' },
      now: new Date('2026-08-05T00:00:00.750Z'),
    })).toThrow(/interaction selection binding/);

    const rejecting = createRemoteHandoffAdapter({
      issue: async () => ({ userAction: 'Authenticate.', authorizationUrl: 'https://idp.example/authorize' }),
      capture: async () => { throw new Error('owner rejected authentication'); },
    });
    await rejecting.begin(request);
    await expect(rejecting.capture(request)).rejects.toThrow(/owner rejected/);
    await expect(awaitOwnerCompletion(
      async () => await new Promise<void>(() => undefined),
      {
        requestId: request.requestId,
        mode: 'remote-handoff',
        userAction: 'Authenticate.',
        browserOpened: false,
        expiresAt: new Date(Date.now() + 10).toISOString(),
      },
    )).rejects.toThrow(/만료/);
  });

  it('captures local SIWE chain metadata without exposing wallet secrets', async () => {
    const engagementDir = engagement('nunchi-auth-local-wallet-');
    const selection = sealAuthInteractionSelection({
      engagementDir,
      runId: 'run-local-wallet',
      mode: 'local-headed-browser',
      profileSha256: 'f'.repeat(64),
    });
    const request = createOwnerAuthRequest({
      engagementDir,
      selection,
      actorId: 'wallet-owner',
      authKind: 'wallet',
      targetOrigin: 'https://test.example',
      startUrl: 'https://test.example/connect',
      requestedChainIds: ['eip155:11155111'],
      purpose: 'Complete testnet SIWE.',
      postLoginGoal: 'Test wallet-bound routes.',
    });
    const page = { goto: async () => undefined, url: () => 'https://test.example/wallet' };
    const adapter = createLocalHeadedBrowserAdapter({
      engagementDir,
      launcher: async () => ({
        pages: () => [page],
        newPage: async () => page,
        storageState: async () => ({
          cookies: [{
            name: 'session', value: 'opaque', domain: 'test.example', path: '/', expires: -1,
            httpOnly: true, secure: true, sameSite: 'Lax' as const,
          }],
          origins: [],
        }),
        close: async () => undefined,
      } as never),
      publicMetadata: async () => ({
        chainId: 'eip155:11155111',
        accountPseudonym: 'wallet-test-1',
      }),
    });
    await adapter.begin(request);
    const session = sealOpaqueAuthSession({
      engagementDir,
      selection,
      request,
      capture: await adapter.capture(request),
    });
    expect(session).toMatchObject({
      materialKind: 'browser-storage-state',
      publicMetadata: { chainId: 'eip155:11155111', accountPseudonym: 'wallet-test-1' },
    });
    await adapter.close();
  });
});
