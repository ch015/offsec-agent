import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';

import type { BrowserContext } from 'playwright-core';

import type { AuthInteractionMode } from './live-test-contract.js';
import type {
  AuthSessionCapture,
  OwnerAuthRequest,
  PublicAuthMetadata,
} from './live-auth-session.js';

export type AuthInteractionChallenge = Readonly<{
  requestId: string;
  mode: Exclude<AuthInteractionMode, 'none'>;
  userAction: string;
  authorizationUrl?: string;
  pairingUri?: string;
  browserOpened: boolean;
  expiresAt: string;
}>;

export interface AuthInteractionAdapter {
  readonly mode: Exclude<AuthInteractionMode, 'none'>;
  begin(request: OwnerAuthRequest): Promise<AuthInteractionChallenge>;
  capture(request: OwnerAuthRequest): Promise<AuthSessionCapture>;
  close(): Promise<void>;
}

export type RemoteHandoffProvider = Readonly<{
  issue(request: OwnerAuthRequest): Promise<{
    userAction: string;
    authorizationUrl?: string;
    pairingUri?: string;
  }>;
  capture(request: OwnerAuthRequest): Promise<AuthSessionCapture>;
  close?(): Promise<void>;
}>;

export function createRemoteHandoffAdapter(provider: RemoteHandoffProvider): AuthInteractionAdapter {
  const issued = new Set<string>();
  return {
    mode: 'remote-handoff',
    async begin(request) {
      assertMode(request, 'remote-handoff');
      if (issued.has(request.requestId)) throw new Error('remote owner auth request가 이미 발급됐다');
      const challenge = await provider.issue(request);
      assertRemoteChallenge(request, challenge);
      issued.add(request.requestId);
      return {
        requestId: request.requestId,
        mode: 'remote-handoff',
        ...challenge,
        browserOpened: false,
        expiresAt: request.expiresAt,
      };
    },
    async capture(request) {
      assertMode(request, 'remote-handoff');
      if (!issued.has(request.requestId)) throw new Error('발급되지 않은 remote owner auth request다');
      return await provider.capture(request);
    },
    async close() {
      await provider.close?.();
    },
  };
}

type BrowserContextLike = Pick<BrowserContext, 'pages' | 'newPage' | 'storageState' | 'close'>;

export type LocalBrowserLauncher = (input: {
  profileDir: string;
  executablePath?: string;
}) => Promise<BrowserContextLike>;

export function createLocalHeadedBrowserAdapter(input: {
  engagementDir: string;
  executablePath?: string;
  launcher?: LocalBrowserLauncher;
  publicMetadata?: (
    request: OwnerAuthRequest,
    context: BrowserContextLike,
  ) => Promise<PublicAuthMetadata>;
}): AuthInteractionAdapter {
  const active = new Map<string, { context: BrowserContextLike; request: OwnerAuthRequest }>();
  const launcher = input.launcher ?? defaultLauncher;
  return {
    mode: 'local-headed-browser',
    async begin(request) {
      assertMode(request, 'local-headed-browser');
      assertLocalBrowserCapability();
      if (active.has(request.requestId)) throw new Error('local owner auth browser가 이미 열려 있다');
      const profileDir = resolve(input.engagementDir, 'auth-browser-profiles', request.actorId, request.requestId);
      mkdirSync(profileDir, { recursive: true, mode: 0o700 });
      const context = await launcher({ profileDir, executablePath: input.executablePath });
      const page = context.pages()[0] ?? await context.newPage();
      await page.goto(request.startUrl, { waitUntil: 'domcontentloaded' });
      active.set(request.requestId, { context, request });
      return {
        requestId: request.requestId,
        mode: 'local-headed-browser',
        userAction: '열린 격리 브라우저에서 승인된 테스트 actor로 로그인한 뒤 완료 신호를 보내세요.',
        browserOpened: true,
        expiresAt: request.expiresAt,
      };
    },
    async capture(request) {
      assertMode(request, 'local-headed-browser');
      const current = active.get(request.requestId);
      if (!current) throw new Error('활성 local owner auth browser가 없다');
      const state = await current.context.storageState();
      const filtered = filterTargetStorageState(state, request.targetOrigin);
      if (filtered.cookies.length === 0 && filtered.origins.length === 0) {
        throw new Error('target origin 인증 session을 관측하지 못했다');
      }
      const pages = current.context.pages();
      const finalUrl = pages[0]?.url();
      const suppliedMetadata = await input.publicMetadata?.(request, current.context) ?? {};
      const publicMetadata: PublicAuthMetadata = {
        ...suppliedMetadata,
        ...(finalUrl ? { finalOrigin: new URL(finalUrl).origin } : {}),
      };
      return {
        materialKind: 'browser-storage-state',
        material: Buffer.from(JSON.stringify(filtered)),
        publicMetadata,
      };
    },
    async close() {
      const contexts = [...active.values()].map(({ context }) => context);
      active.clear();
      await Promise.all(contexts.map(async (context) => await context.close()));
    },
  };
}

export function assertLocalBrowserCapability(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): void {
  if (platform === 'linux' && !env.DISPLAY && !env.WAYLAND_DISPLAY) {
    throw new Error('local-headed-browser에는 DISPLAY 또는 WAYLAND_DISPLAY가 필요하다');
  }
}

export async function awaitOwnerCompletion(
  waitForOwner: (challenge: AuthInteractionChallenge) => Promise<void>,
  challenge: AuthInteractionChallenge,
  now: () => number = Date.now,
): Promise<void> {
  const remaining = Date.parse(challenge.expiresAt) - now();
  if (remaining <= 0) throw new Error('owner authentication request가 만료됐다');
  let timeout: NodeJS.Timeout | undefined;
  try {
    await Promise.race([
      waitForOwner(challenge),
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(() => reject(new Error('owner authentication 완료 대기가 만료됐다')), remaining);
      }),
    ]);
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

async function defaultLauncher(input: {
  profileDir: string;
  executablePath?: string;
}): Promise<BrowserContext> {
  const { chromium } = await import('playwright-core');
  return await chromium.launchPersistentContext(input.profileDir, {
    headless: false,
    ...(input.executablePath ? { executablePath: input.executablePath } : { channel: 'chrome' }),
  });
}

function assertMode(
  request: OwnerAuthRequest,
  expected: Exclude<AuthInteractionMode, 'none'>,
): void {
  if (request.interactionMode !== expected) {
    throw new Error(`owner auth request mode가 adapter와 다르다: ${request.interactionMode} != ${expected}`);
  }
}

function assertRemoteChallenge(
  request: OwnerAuthRequest,
  challenge: Awaited<ReturnType<RemoteHandoffProvider['issue']>>,
): void {
  if (challenge.authorizationUrl) {
    if (!request.providerOrigin) {
      throw new Error('remote authorization URL에는 봉인된 provider origin이 필요하다');
    }
    const authorization = new URL(challenge.authorizationUrl);
    if (authorization.protocol !== 'https:' || authorization.origin !== request.providerOrigin) {
      throw new Error('remote authorization URL이 봉인된 provider origin과 다르다');
    }
  }
  if (challenge.pairingUri && request.authKind !== 'wallet') {
    throw new Error('pairing URI는 wallet owner auth에만 허용된다');
  }
  if (request.authKind === 'wallet' && !challenge.pairingUri) {
    throw new Error('wallet remote handoff에는 pairing URI가 필요하다');
  }
  if (challenge.pairingUri && new URL(challenge.pairingUri).protocol !== 'wc:') {
    throw new Error('wallet pairing URI는 WalletConnect wc scheme이어야 한다');
  }
}

function filterTargetStorageState(
  state: Awaited<ReturnType<BrowserContext['storageState']>>,
  targetOrigin: string,
): Awaited<ReturnType<BrowserContext['storageState']>> {
  const target = new URL(targetOrigin);
  const host = target.hostname.toLowerCase();
  const cookieMatches = (domain: string): boolean => {
    const normalized = domain.replace(/^\./, '').toLowerCase();
    return host === normalized || host.endsWith(`.${normalized}`);
  };
  return {
    cookies: state.cookies.filter((cookie) => cookieMatches(cookie.domain)),
    origins: state.origins.filter((origin) => origin.origin === target.origin),
  };
}
