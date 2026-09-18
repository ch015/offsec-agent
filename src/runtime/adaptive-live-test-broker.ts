import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { z } from 'zod';

import {
  applyAuthMaterial,
  encodeRequestBody,
  liveRequestUrl,
} from './adaptive-live-test-support.js';
import type { LiveScenarioJournal } from './live-scenario-journal.js';
import {
  readOpaqueAuthMaterial,
  readOpaqueAuthSession,
  type AuthInteractionSelection,
  type OpaqueAuthSession,
} from './live-auth-session.js';
import type { LiveScenario, LiveTestProfile } from './live-test-contract.js';

const RECEIPT_DIR = 'http-probe-receipts';
const ReceiptIdSchema = z.string().regex(/^HTTP-[a-f0-9]{20}$/);
const ResponseObservationSchema = z.object({
  status: z.number().int().min(100).max(599),
  headers: z.record(z.string(), z.string()),
  bodySha256: z.string().regex(/^[a-f0-9]{64}$/),
  capturedBytes: z.number().int().nonnegative(),
  truncated: z.boolean(),
  safeExcerpt: z.string().max(4096),
  elapsedMs: z.number().nonnegative(),
}).strict();

const AdaptiveLiveTestReceiptCoreSchema = z.object({
  schemaVersion: z.literal('2.0.0'),
  receiptId: ReceiptIdSchema,
  scenarioId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/),
  scenarioSha256: z.string().regex(/^[a-f0-9]{64}$/),
  planSha256: z.string().regex(/^[a-f0-9]{64}$/),
  profileSha256: z.string().regex(/^[a-f0-9]{64}$/),
  actorId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/),
  sessionId: z.string().regex(/^SESSION-[a-f0-9]{20}$/).nullable(),
  request: z.object({
    method: z.enum(['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE']),
    url: z.string().url(),
    headerNames: z.array(z.string()).max(64),
    bodySha256: z.string().regex(/^[a-f0-9]{64}$/).nullable(),
    riskClass: z.enum(['read-only', 'reversible-state-change']),
    requestSha256: z.string().regex(/^[a-f0-9]{64}$/),
  }).strict(),
  response: ResponseObservationSchema,
  cleanup: z.object({
    required: z.boolean(),
    status: z.enum(['not-required', 'succeeded', 'failed']),
    requestSha256: z.string().regex(/^[a-f0-9]{64}$/).nullable(),
    response: ResponseObservationSchema.nullable(),
    error: z.string().max(1024).nullable(),
  }).strict(),
  observedAt: z.string().datetime(),
}).strict();

export const AdaptiveLiveTestReceiptSchema = AdaptiveLiveTestReceiptCoreSchema.extend({
  receiptSha256: z.string().regex(/^[a-f0-9]{64}$/),
}).strict();
export type AdaptiveLiveTestReceipt = z.infer<typeof AdaptiveLiveTestReceiptSchema>;

export function createAdaptiveLiveTestBroker(input: {
  engagementDir: string;
  profile: LiveTestProfile;
  profileSha256: string;
  planSha256: string;
  selection: AuthInteractionSelection;
  journal: LiveScenarioJournal;
  authSessions?: ReadonlyMap<string, OpaqueAuthSession>;
  fetchImpl?: typeof fetch;
  now?: () => Date;
}) {
  if (input.selection.profileSha256 !== input.profileSha256) {
    throw new Error('adaptive broker profile과 interaction selection binding이 다르다');
  }
  const base = safeBaseUrl(input.profile.targetBaseUrl);
  const receiptsDir = join(resolve(input.engagementDir), RECEIPT_DIR);
  mkdirSync(receiptsDir, { recursive: true, mode: 0o700 });
  const fetchImpl = input.fetchImpl ?? fetch;
  const now = input.now ?? (() => new Date());

  return {
    async exchange(request: { scenarioId: string }): Promise<AdaptiveLiveTestReceipt> {
      const parsed = z.object({
        scenarioId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/),
      }).strict().parse(request);
      const { scenario, sha256: scenarioSha256 } = input.journal.approvedScenario(parsed.scenarioId);
      const usage = runUsage(input.journal, receiptsDir);
      const requiredRequests = scenario.cleanupRequired ? 2 : 1;
      assertRunLimits(input, scenario, usage, requiredRequests, now());
      const actor = input.profile.actors.find((candidate) => candidate.actorId === scenario.actorId);
      if (!actor) throw new Error(`Live DAST actor가 profile에 없다: ${scenario.actorId}`);
      const session = actor.authKind === 'none' ? undefined : input.authSessions?.get(actor.actorId);
      if (actor.authKind !== 'none' && !session) {
        input.journal.record('blocked', scenario.scenarioId, `actor session이 없다: ${actor.actorId}`);
        throw new Error(`Live DAST actor session이 없다: ${actor.actorId}`);
      }
      const verifiedSession = session
        ? readOpaqueAuthSession({
            engagementDir: input.engagementDir,
            sessionId: session.sessionId,
            selection: input.selection,
            actorId: actor.actorId,
            now: now(),
          })
        : undefined;
      input.journal.record('started', scenario.scenarioId, 'primary request budget reserved', undefined, now());
      const primary = await executeRequest({
        request: scenario.request,
        base,
        session: verifiedSession,
        engagementDir: input.engagementDir,
        profile: input.profile,
        fetchImpl,
        riskClass: scenario.riskClass,
      }).catch((error: unknown) => {
        input.journal.record('inconclusive', scenario.scenarioId, safeError('primary request failed', error), undefined, now());
        throw error;
      });
      const requestSha256 = hash(stableJson({
        ...primary.requestCore,
        actorId: actor.actorId,
        sessionId: verifiedSession?.sessionId ?? null,
      }));
      const receiptId = `HTTP-${hash(`${requestSha256}:${usage.requests + 1}:${randomBytes(16).toString('hex')}`).slice(0, 20)}`;
      const cleanup = scenario.cleanupRequired
        ? await executeCleanup({
            input,
            scenario,
            base,
            session: verifiedSession,
            fetchImpl,
            now,
          })
        : {
            required: false as const,
            status: 'not-required' as const,
            requestSha256: null,
            response: null,
            error: null,
          };
      const core = AdaptiveLiveTestReceiptCoreSchema.parse({
        schemaVersion: '2.0.0',
        receiptId,
        scenarioId: scenario.scenarioId,
        scenarioSha256,
        planSha256: input.planSha256,
        profileSha256: input.profileSha256,
        actorId: actor.actorId,
        sessionId: verifiedSession?.sessionId ?? null,
        request: { ...primary.requestCore, requestSha256 },
        response: primary.response,
        cleanup,
        observedAt: now().toISOString(),
      });
      const receipt = AdaptiveLiveTestReceiptSchema.parse({
        ...core,
        receiptSha256: hash(stableJson(core)),
      });
      writeFileSync(join(receiptsDir, `${receiptId}.json`), `${JSON.stringify(receipt)}\n`, {
        encoding: 'utf8',
        mode: 0o600,
        flag: 'wx',
      });
      input.journal.record(
        'executed',
        scenario.scenarioId,
        primary.response.status >= 300 && primary.response.status < 400
          ? 'primary request executed; redirect was not followed'
          : 'primary request executed and receipt recorded',
        receiptId,
        now(),
      );
      return receipt;
    },
  };
}

async function executeCleanup(input: {
  input: Parameters<typeof createAdaptiveLiveTestBroker>[0];
  scenario: LiveScenario;
  base: URL;
  session?: OpaqueAuthSession;
  fetchImpl: typeof fetch;
  now: () => Date;
}): Promise<AdaptiveLiveTestReceipt['cleanup']> {
  const cleanupRequest = input.scenario.cleanup?.request;
  if (!cleanupRequest) throw new Error('상태변경 scenario cleanup 계약이 없다');
  input.input.journal.record(
    'cleanup-started', input.scenario.scenarioId, 'cleanup request budget reserved', undefined, input.now(),
  );
  try {
    const cleanup = await executeRequest({
      request: cleanupRequest,
      base: input.base,
      session: input.session,
      engagementDir: input.input.engagementDir,
      profile: input.input.profile,
      fetchImpl: input.fetchImpl,
      riskClass: 'read-only',
    });
    const requestSha256 = hash(stableJson({
      ...cleanup.requestCore,
      actorId: input.scenario.actorId,
      sessionId: input.session?.sessionId ?? null,
    }));
    const succeeded = cleanup.response.status < 400;
    input.input.journal.record(
      succeeded ? 'cleanup-succeeded' : 'cleanup-failed',
      input.scenario.scenarioId,
      `cleanup returned HTTP ${cleanup.response.status}`,
      undefined,
      input.now(),
    );
    return {
      required: true,
      status: succeeded ? 'succeeded' : 'failed',
      requestSha256,
      response: cleanup.response,
      error: succeeded ? null : `cleanup returned HTTP ${cleanup.response.status}`,
    };
  } catch (error) {
    const reason = safeError('cleanup request failed', error);
    input.input.journal.record('cleanup-failed', input.scenario.scenarioId, reason, undefined, input.now());
    return { required: true, status: 'failed', requestSha256: null, response: null, error: reason };
  }
}

async function executeRequest(input: {
  request: LiveScenario['request'];
  base: URL;
  session?: OpaqueAuthSession;
  engagementDir: string;
  profile: LiveTestProfile;
  fetchImpl: typeof fetch;
  riskClass: LiveScenario['riskClass'];
}): Promise<{
  requestCore: {
    method: LiveScenario['request']['method'];
    url: string;
    headerNames: string[];
    bodySha256: string | null;
    riskClass: LiveScenario['riskClass'];
  };
  response: z.infer<typeof ResponseObservationSchema>;
}> {
  const url = liveRequestUrl(input.base, input.request);
  const body = encodeRequestBody(input.request);
  const headers = new Headers(input.request.headers);
  if (body?.contentType && !headers.has('content-type')) headers.set('content-type', body.contentType);
  if (input.session) {
    applyAuthMaterial(
      headers,
      input.session,
      readOpaqueAuthMaterial({ engagementDir: input.engagementDir, session: input.session }),
      url,
    );
  }
  const requestCore = {
    method: input.request.method,
    url: url.toString(),
    headerNames: [...headers.keys()].map((name) => name.toLowerCase()).sort(),
    bodySha256: body ? hash(body.bytes) : null,
    riskClass: input.riskClass,
  };
  const started = performance.now();
  const response = await input.fetchImpl(url, {
    method: input.request.method,
    redirect: 'manual',
    headers,
    body: body?.bytes,
    signal: AbortSignal.timeout(input.profile.policy.timeoutMs),
  });
  const redirectLocation = response.headers.get('location');
  if (response.status >= 300 && response.status < 400 && redirectLocation) {
    scopedUrl(input.base, new URL(redirectLocation, url).toString());
  }
  const captured = await readBoundedBody(response, input.profile.policy.maxResponseBytes);
  const contentType = response.headers.get('content-type') ?? '';
  const excerpt = /(?:text|json|xml|javascript|urlencoded)/i.test(contentType)
    ? redact(captured.bytes.toString('utf8').slice(0, 4000))
    : '';
  return {
    requestCore,
    response: {
      status: response.status,
      headers: selectedHeaders(response.headers),
      bodySha256: hash(captured.bytes),
      capturedBytes: captured.bytes.byteLength,
      truncated: captured.truncated,
      safeExcerpt: excerpt ? `[UNTRUSTED TARGET DATA]\n${excerpt}` : '',
      elapsedMs: Math.max(0, performance.now() - started),
    },
  };
}

function runUsage(journal: LiveScenarioJournal, receiptsDir: string): {
  requests: number;
  stateChanges: number;
  startedAt?: string;
  circuitReason?: string;
} {
  const events = journal.readEvents();
  const started = events.filter((event) => event.type === 'started');
  const cleanupStarted = events.filter((event) => event.type === 'cleanup-started');
  const stateChanges = started.filter((event) =>
    journal.approvedScenario(event.scenarioId).scenario.riskClass === 'reversible-state-change').length;
  const receipts = existsSync(receiptsDir)
    ? readdirSync(receiptsDir)
        .filter((name) => /^HTTP-[a-f0-9]{20}\.json$/.test(name))
        .map((name) => AdaptiveLiveTestReceiptSchema.safeParse(JSON.parse(readFileSync(join(receiptsDir, name), 'utf8'))))
        .filter((value): value is { success: true; data: AdaptiveLiveTestReceipt } => value.success)
        .map((value) => value.data)
    : [];
  const receiptsById = new Map(receipts.map((receipt) => [receipt.receiptId, receipt]));
  const statuses = events
    .filter((event) => event.type === 'executed' && event.receiptId)
    .flatMap((event) => {
      const receipt = receiptsById.get(event.receiptId!);
      return receipt
        ? [receipt.response.status, ...(receipt.cleanup.response ? [receipt.cleanup.response.status] : [])]
        : [];
    });
  const circuitReason = statuses.includes(429)
    ? 'target returned 429'
    : statuses.slice(-3).length === 3 && statuses.slice(-3).every((status) => status >= 500)
      ? 'three consecutive server errors'
      : undefined;
  return {
    requests: started.length + cleanupStarted.length,
    stateChanges,
    ...(started[0] ? { startedAt: started[0].observedAt } : {}),
    ...(circuitReason ? { circuitReason } : {}),
  };
}

function assertRunLimits(
  input: Parameters<typeof createAdaptiveLiveTestBroker>[0],
  scenario: LiveScenario,
  usage: ReturnType<typeof runUsage>,
  requiredRequests: number,
  now: Date,
): void {
  if (usage.circuitReason) throw new Error(`Live DAST circuit breaker가 열려 있다: ${usage.circuitReason}`);
  if (usage.startedAt && now.getTime() - Date.parse(usage.startedAt) > input.profile.policy.maxDurationMs) {
    throw new Error('Live DAST maximum duration을 초과했다');
  }
  if (usage.requests + requiredRequests > input.profile.policy.maxRequests) {
    throw new Error(`Live DAST request 상한을 초과했다: ${input.profile.policy.maxRequests}`);
  }
  if (
    scenario.riskClass === 'reversible-state-change' &&
    usage.stateChanges + 1 > input.profile.policy.maxStateChanges
  ) {
    input.journal.record('blocked', scenario.scenarioId, 'maximum state changes exceeded');
    throw new Error(`Live DAST state change 상한을 초과했다: ${input.profile.policy.maxStateChanges}`);
  }
}

function safeBaseUrl(value: string): URL {
  const base = new URL(value);
  if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password || base.hash) {
    throw new Error('HTTP probe base URL이 안전 계약과 다르다');
  }
  return base;
}

function scopedUrl(base: URL, candidate: string): URL {
  const url = new URL(candidate, base);
  const normalized = base.pathname.endsWith('/') ? base.pathname : `${base.pathname}/`;
  if (
    url.protocol !== base.protocol || url.hostname !== base.hostname || url.port !== base.port ||
    url.username || url.password || url.hash ||
    !(url.pathname === base.pathname || url.pathname.startsWith(normalized))
  ) {
    throw new Error(`HTTP probe target이 승인 범위 밖이다: ${url.toString()}`);
  }
  return url;
}

async function readBoundedBody(response: Response, maximum: number): Promise<{ bytes: Buffer; truncated: boolean }> {
  if (!response.body) return { bytes: Buffer.alloc(0), truncated: false };
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  let truncated = false;
  while (true) {
    const next = await reader.read();
    if (next.done) break;
    const chunk = Buffer.from(next.value);
    const remaining = maximum - total;
    if (chunk.byteLength > remaining) {
      if (remaining > 0) chunks.push(chunk.subarray(0, remaining));
      truncated = true;
      await reader.cancel();
      break;
    }
    chunks.push(chunk);
    total += chunk.byteLength;
  }
  return { bytes: Buffer.concat(chunks), truncated };
}

function selectedHeaders(headers: Headers): Record<string, string> {
  const selected: Record<string, string> = {};
  for (const name of ['content-type', 'content-length', 'cache-control']) {
    const value = headers.get(name);
    if (value) selected[name] = value.slice(0, 512);
  }
  return selected;
}

function redact(value: string): string {
  return value
    .replace(/\b(?:bearer\s+)?[A-Za-z0-9_-]{24,}\b/gi, '[REDACTED]')
    .replace(/("(?:password|token|secret|api[_-]?key)"\s*:\s*")[^"]*(")/gi, '$1[REDACTED]$2');
}

function safeError(prefix: string, error: unknown): string {
  return `${prefix}: ${redact(error instanceof Error ? error.message : String(error))}`.slice(0, 1024);
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function hash(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}
