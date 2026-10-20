import { createHash, randomBytes } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from 'node:fs';
import { join, resolve } from 'node:path';

import { z } from 'zod';

import {
  AuthInteractionModeSchema,
  AuthKindSchema,
  type AuthInteractionMode,
  type AuthKind,
} from './live-test-contract.js';

const SELECTION_FILE = 'auth_interaction_selection.json';
const REQUESTS_DIR = 'owner-auth-requests';
const SESSIONS_DIR = 'auth-sessions';
const PRIVATE_DIR = 'private';

const SelectionCoreSchema = z.object({
  schemaVersion: z.literal('1.0.0'),
  runId: z.string().min(1).max(256),
  mode: AuthInteractionModeSchema,
  profileSha256: z.string().regex(/^[a-f0-9]{64}$/),
  selectedAt: z.string().datetime(),
}).strict();

export const AuthInteractionSelectionSchema = SelectionCoreSchema.extend({
  selectionSha256: z.string().regex(/^[a-f0-9]{64}$/),
}).strict();
export type AuthInteractionSelection = z.infer<typeof AuthInteractionSelectionSchema>;

const OwnerAuthRequestCoreSchema = z.object({
  schemaVersion: z.literal('1.0.0'),
  requestId: z.string().regex(/^AUTH-[a-f0-9]{20}$/),
  runId: z.string().min(1).max(256),
  actorId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/),
  authKind: AuthKindSchema,
  interactionMode: AuthInteractionModeSchema,
  selectionSha256: z.string().regex(/^[a-f0-9]{64}$/),
  targetOrigin: z.string().url(),
  startUrl: z.string().url(),
  providerOrigin: z.string().url().optional(),
  requestedScopes: z.array(z.string().min(1).max(256)).max(64),
  requestedChainIds: z.array(z.string().min(1).max(128)).max(32),
  purpose: z.string().min(1).max(4096),
  postLoginGoal: z.string().min(1).max(4096),
  createdAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
}).strict();

export const OwnerAuthRequestSchema = OwnerAuthRequestCoreSchema.extend({
  requestSha256: z.string().regex(/^[a-f0-9]{64}$/),
}).strict();
export type OwnerAuthRequest = z.infer<typeof OwnerAuthRequestSchema>;

const PublicAuthMetadataSchema = z.object({
  issuer: z.string().url().optional(),
  clientId: z.string().max(256).optional(),
  redirectUri: z.string().url().optional(),
  scopes: z.array(z.string().max(256)).max(64).optional(),
  responseType: z.string().max(128).optional(),
  transactionSha256: z.string().regex(/^[a-f0-9]{64}$/).optional(),
  accountPseudonym: z.string().max(256).optional(),
  chainId: z.string().max(128).optional(),
  walletNamespaces: z.array(z.string().max(128)).max(32).optional(),
  walletMethods: z.array(z.string().max(128)).max(64).optional(),
  finalOrigin: z.string().url().optional(),
}).strict();
export type PublicAuthMetadata = z.infer<typeof PublicAuthMetadataSchema>;

const AuthSessionCoreSchema = z.object({
  schemaVersion: z.literal('1.0.0'),
  sessionId: z.string().regex(/^SESSION-[a-f0-9]{20}$/),
  runId: z.string().min(1).max(256),
  actorId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/),
  authKind: AuthKindSchema,
  interactionMode: z.enum(['remote-handoff', 'local-headed-browser']),
  selectionSha256: z.string().regex(/^[a-f0-9]{64}$/),
  requestId: z.string().regex(/^AUTH-[a-f0-9]{20}$/),
  requestSha256: z.string().regex(/^[a-f0-9]{64}$/),
  targetOrigin: z.string().url(),
  materialKind: z.enum(['oauth-token-set', 'browser-storage-state', 'wallet-session', 'host-secret']),
  materialSha256: z.string().regex(/^[a-f0-9]{64}$/),
  publicMetadata: PublicAuthMetadataSchema,
  createdAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
}).strict();

export const OpaqueAuthSessionSchema = AuthSessionCoreSchema.extend({
  sessionSha256: z.string().regex(/^[a-f0-9]{64}$/),
}).strict();
export type OpaqueAuthSession = z.infer<typeof OpaqueAuthSessionSchema>;

export type AuthSessionCapture = Readonly<{
  materialKind: OpaqueAuthSession['materialKind'];
  material: Buffer;
  publicMetadata: PublicAuthMetadata;
}>;

export function sealAuthInteractionSelection(input: {
  engagementDir: string;
  runId: string;
  mode: AuthInteractionMode;
  profileSha256: string;
  now?: Date;
}): AuthInteractionSelection {
  const directory = resolve(input.engagementDir);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const path = join(directory, SELECTION_FILE);
  const core = SelectionCoreSchema.parse({
    schemaVersion: '1.0.0',
    runId: input.runId,
    mode: input.mode,
    profileSha256: input.profileSha256,
    selectedAt: (input.now ?? new Date()).toISOString(),
  });
  const selection = AuthInteractionSelectionSchema.parse({
    ...core,
    selectionSha256: digest(stableJson(core)),
  });
  if (existsSync(path)) {
    const existing = readAuthInteractionSelection(directory);
    if (
      existing.runId !== selection.runId ||
      existing.mode !== selection.mode ||
      existing.profileSha256 !== selection.profileSha256
    ) {
      throw new Error('auth interaction selection은 같은 run에서 변경할 수 없다');
    }
    return existing;
  }
  writeExclusive(path, selection);
  return selection;
}

export function readAuthInteractionSelection(engagementDir: string): AuthInteractionSelection {
  const path = join(resolve(engagementDir), SELECTION_FILE);
  const selection = AuthInteractionSelectionSchema.parse(JSON.parse(readFileSync(path, 'utf8')));
  const { selectionSha256, ...core } = selection;
  if (digest(stableJson(core)) !== selectionSha256) {
    throw new Error('auth interaction selection hash가 다르다');
  }
  return selection;
}

export function readActorAuthSessions(input: {
  engagementDir: string;
  selection: AuthInteractionSelection;
  now?: Date;
}): Map<string, OpaqueAuthSession> {
  const directory = join(resolve(input.engagementDir), SESSIONS_DIR);
  const sessions = new Map<string, OpaqueAuthSession>();
  if (!existsSync(directory)) return sessions;
  for (const name of readdirSync(directory).filter((entry) => /^SESSION-[a-f0-9]{20}\.json$/.test(entry)).sort()) {
    const sessionId = name.slice(0, -'.json'.length);
    const session = readOpaqueAuthSession({
      engagementDir: input.engagementDir,
      sessionId,
      selection: input.selection,
      now: input.now,
    });
    const previous = sessions.get(session.actorId);
    if (!previous || Date.parse(previous.createdAt) < Date.parse(session.createdAt)) {
      sessions.set(session.actorId, session);
    }
  }
  return sessions;
}

export function createOwnerAuthRequest(input: {
  engagementDir: string;
  selection: AuthInteractionSelection;
  actorId: string;
  authKind: AuthKind;
  targetOrigin: string;
  startUrl: string;
  providerOrigin?: string;
  requestedScopes?: string[];
  requestedChainIds?: string[];
  purpose: string;
  postLoginGoal: string;
  ttlMs?: number;
  now?: Date;
}): OwnerAuthRequest {
  if (input.selection.mode === 'none') throw new Error('none interaction mode는 owner auth를 요청할 수 없다');
  if (input.authKind === 'wallet' && (input.requestedChainIds?.length ?? 0) === 0) {
    throw new Error('wallet owner auth에는 요청 chain이 필요하다');
  }
  const now = input.now ?? new Date();
  const ttlMs = input.ttlMs ?? 10 * 60_000;
  if (!Number.isInteger(ttlMs) || ttlMs < 1_000 || ttlMs > 60 * 60_000) {
    throw new Error('owner auth request TTL이 잘못됐다');
  }
  assertSameOriginOrScopedStart(input.targetOrigin, input.startUrl);
  const core = OwnerAuthRequestCoreSchema.parse({
    schemaVersion: '1.0.0',
    requestId: `AUTH-${digest(`${input.selection.selectionSha256}:${input.actorId}:${randomBytes(16).toString('hex')}`).slice(0, 20)}`,
    runId: input.selection.runId,
    actorId: input.actorId,
    authKind: input.authKind,
    interactionMode: input.selection.mode,
    selectionSha256: input.selection.selectionSha256,
    targetOrigin: new URL(input.targetOrigin).origin,
    startUrl: input.startUrl,
    ...(input.providerOrigin ? { providerOrigin: new URL(input.providerOrigin).origin } : {}),
    requestedScopes: input.requestedScopes ?? [],
    requestedChainIds: input.requestedChainIds ?? [],
    purpose: input.purpose,
    postLoginGoal: input.postLoginGoal,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
  });
  const request = OwnerAuthRequestSchema.parse({
    ...core,
    requestSha256: digest(stableJson(core)),
  });
  const directory = join(resolve(input.engagementDir), REQUESTS_DIR);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  writeExclusive(join(directory, `${request.requestId}.json`), request);
  return request;
}

export function readOwnerAuthRequest(
  engagementDir: string,
  requestId: string,
  now = new Date(),
  options: { allowExpired?: boolean } = {},
): OwnerAuthRequest {
  const path = join(resolve(engagementDir), REQUESTS_DIR, `${requestId}.json`);
  const request = OwnerAuthRequestSchema.parse(JSON.parse(readFileSync(path, 'utf8')));
  const { requestSha256, ...core } = request;
  if (digest(stableJson(core)) !== requestSha256) throw new Error('owner auth request hash가 다르다');
  if (!options.allowExpired && Date.parse(request.expiresAt) <= now.getTime()) {
    throw new Error('owner auth request가 만료됐다');
  }
  return request;
}

export function sealOpaqueAuthSession(input: {
  engagementDir: string;
  selection: AuthInteractionSelection;
  request: OwnerAuthRequest;
  capture: AuthSessionCapture;
  ttlMs?: number;
  now?: Date;
}): OpaqueAuthSession {
  assertRequestSelectionBinding(input.request, input.selection);
  const now = input.now ?? new Date();
  if (Date.parse(input.request.expiresAt) <= now.getTime()) throw new Error('만료된 owner auth request다');
  const ttlMs = input.ttlMs ?? 30 * 60_000;
  if (!Number.isInteger(ttlMs) || ttlMs < 1_000 || ttlMs > 24 * 60 * 60_000) {
    throw new Error('auth session TTL이 잘못됐다');
  }
  if (input.capture.material.byteLength === 0 || input.capture.material.byteLength > 1_048_576) {
    throw new Error('auth session material 크기가 잘못됐다');
  }
  assertCaptureMatchesRequest(input.request, input.capture);
  const sessionId = `SESSION-${digest(`${input.request.requestSha256}:${randomBytes(16).toString('hex')}`).slice(0, 20)}`;
  const materialSha256 = digest(input.capture.material);
  const core = AuthSessionCoreSchema.parse({
    schemaVersion: '1.0.0',
    sessionId,
    runId: input.selection.runId,
    actorId: input.request.actorId,
    authKind: input.request.authKind,
    interactionMode: input.selection.mode,
    selectionSha256: input.selection.selectionSha256,
    requestId: input.request.requestId,
    requestSha256: input.request.requestSha256,
    targetOrigin: input.request.targetOrigin,
    materialKind: input.capture.materialKind,
    materialSha256,
    publicMetadata: input.capture.publicMetadata,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
  });
  const session = OpaqueAuthSessionSchema.parse({
    ...core,
    sessionSha256: digest(stableJson(core)),
  });
  writeSessionFiles(input.engagementDir, session, input.capture.material);
  return session;
}

export function sealHostSecretSession(input: {
  engagementDir: string;
  selection: AuthInteractionSelection;
  actorId: string;
  targetOrigin: string;
  material: Buffer;
  ttlMs?: number;
  now?: Date;
}): OpaqueAuthSession {
  const now = input.now ?? new Date();
  const ttlMs = input.ttlMs ?? 30 * 60_000;
  if (input.material.byteLength === 0 || input.material.byteLength > 1_048_576) {
    throw new Error('host-secret material 크기가 잘못됐다');
  }
  const nonce = randomBytes(16).toString('hex');
  const requestSha256 = digest(`${input.selection.selectionSha256}:${input.actorId}:${nonce}`);
  const sessionId = `SESSION-${digest(`${requestSha256}:host-secret`).slice(0, 20)}`;
  const core = AuthSessionCoreSchema.parse({
    schemaVersion: '1.0.0',
    sessionId,
    runId: input.selection.runId,
    actorId: input.actorId,
    authKind: 'host-secret',
    interactionMode: input.selection.mode,
    selectionSha256: input.selection.selectionSha256,
    requestId: `AUTH-${requestSha256.slice(0, 20)}`,
    requestSha256,
    targetOrigin: new URL(input.targetOrigin).origin,
    materialKind: 'host-secret',
    materialSha256: digest(input.material),
    publicMetadata: {},
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
  });
  const session = OpaqueAuthSessionSchema.parse({
    ...core,
    sessionSha256: digest(stableJson(core)),
  });
  writeSessionFiles(input.engagementDir, session, input.material);
  return session;
}

export function readOpaqueAuthSession(input: {
  engagementDir: string;
  sessionId: string;
  selection?: AuthInteractionSelection;
  actorId?: string;
  now?: Date;
}): OpaqueAuthSession {
  const path = join(resolve(input.engagementDir), SESSIONS_DIR, `${input.sessionId}.json`);
  const session = OpaqueAuthSessionSchema.parse(JSON.parse(readFileSync(path, 'utf8')));
  const { sessionSha256, ...core } = session;
  if (digest(stableJson(core)) !== sessionSha256) throw new Error('auth session hash가 다르다');
  if (Date.parse(session.expiresAt) <= (input.now ?? new Date()).getTime()) throw new Error('auth session이 만료됐다');
  if (input.selection && (
    session.runId !== input.selection.runId ||
    session.selectionSha256 !== input.selection.selectionSha256 ||
    session.interactionMode !== input.selection.mode
  )) {
    throw new Error('auth session interaction selection binding이 다르다');
  }
  if (input.actorId && session.actorId !== input.actorId) throw new Error('auth session actor binding이 다르다');
  return session;
}

export function readOpaqueAuthMaterial(input: {
  engagementDir: string;
  session: OpaqueAuthSession;
}): Buffer {
  const path = join(
    resolve(input.engagementDir),
    SESSIONS_DIR,
    PRIVATE_DIR,
    `${input.session.sessionId}.bin`,
  );
  const material = readFileSync(path);
  if (digest(material) !== input.session.materialSha256) throw new Error('auth session material hash가 다르다');
  return material;
}

function writeSessionFiles(
  engagementDir: string,
  session: OpaqueAuthSession,
  material: Buffer,
): void {
  const sessions = join(resolve(engagementDir), SESSIONS_DIR);
  const privateDirectory = join(sessions, PRIVATE_DIR);
  mkdirSync(privateDirectory, { recursive: true, mode: 0o700 });
  writeFileSync(join(privateDirectory, `${session.sessionId}.bin`), material, {
    flag: 'wx',
    mode: 0o600,
  });
  writeExclusive(join(sessions, `${session.sessionId}.json`), session);
}

function assertRequestSelectionBinding(
  request: OwnerAuthRequest,
  selection: AuthInteractionSelection,
): void {
  if (
    request.runId !== selection.runId ||
    request.selectionSha256 !== selection.selectionSha256 ||
    request.interactionMode !== selection.mode
  ) {
    throw new Error('owner auth request interaction selection binding이 다르다');
  }
}

function assertCaptureMatchesRequest(
  request: OwnerAuthRequest,
  capture: AuthSessionCapture,
): void {
  const allowedMaterialKinds: Readonly<Record<AuthKind, readonly OpaqueAuthSession['materialKind'][]>> = {
    none: [],
    'host-secret': [],
    'oauth-oidc': request.interactionMode === 'local-headed-browser'
      ? ['browser-storage-state']
      : ['oauth-token-set'],
    'device-code': request.interactionMode === 'local-headed-browser'
      ? ['browser-storage-state']
      : ['oauth-token-set'],
    passkey: ['browser-storage-state'],
    wallet: request.interactionMode === 'local-headed-browser'
      ? ['browser-storage-state']
      : ['wallet-session'],
  };
  if (!allowedMaterialKinds[request.authKind].includes(capture.materialKind)) {
    throw new Error(`auth session material kind가 request와 다르다: ${capture.materialKind}`);
  }
  const metadata = capture.publicMetadata;
  if (metadata.finalOrigin && new URL(metadata.finalOrigin).origin !== request.targetOrigin) {
    throw new Error('auth session final origin이 target origin과 다르다');
  }
  if (metadata.redirectUri && new URL(metadata.redirectUri).origin !== request.targetOrigin) {
    throw new Error('auth session redirect origin이 target origin과 다르다');
  }
  if (metadata.issuer) {
    if (!request.providerOrigin || new URL(metadata.issuer).origin !== request.providerOrigin) {
      throw new Error('auth session issuer가 요청한 provider origin과 다르다');
    }
  }
  if (metadata.scopes?.some((scope) => !request.requestedScopes.includes(scope))) {
    throw new Error('auth session scope가 요청 범위를 벗어났다');
  }
  if (metadata.chainId && !request.requestedChainIds.includes(metadata.chainId)) {
    throw new Error('auth session chain이 요청 범위를 벗어났다');
  }
  if (request.authKind === 'wallet' && !metadata.chainId) {
    throw new Error('wallet auth session에는 chain binding이 필요하다');
  }
}

function assertSameOriginOrScopedStart(targetOrigin: string, startUrl: string): void {
  const target = new URL(targetOrigin);
  const start = new URL(startUrl);
  if (start.origin !== target.origin) throw new Error('owner auth start URL은 target origin에서 시작해야 한다');
}

function writeExclusive(path: string, value: unknown): void {
  writeFileSync(path, `${JSON.stringify(value)}\n`, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function digest(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}
