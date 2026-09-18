import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { z } from 'zod';

export const AuthInteractionModeSchema = z.enum([
  'remote-handoff',
  'local-headed-browser',
  'none',
]);
export type AuthInteractionMode = z.infer<typeof AuthInteractionModeSchema>;

export const AuthKindSchema = z.enum([
  'none',
  'host-secret',
  'oauth-oidc',
  'device-code',
  'passkey',
  'wallet',
]);
export type AuthKind = z.infer<typeof AuthKindSchema>;

export const LiveTestMethodSchema = z.enum([
  'GET',
  'HEAD',
  'OPTIONS',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
]);
export type LiveTestMethod = z.infer<typeof LiveTestMethodSchema>;

export const LiveTestRiskClassSchema = z.enum([
  'read-only',
  'reversible-state-change',
]);
export type LiveTestRiskClass = z.infer<typeof LiveTestRiskClassSchema>;

export type LiveTestActor = Readonly<{
  actorId: string;
  role: string;
  authKind: AuthKind;
  secretRef?: string;
  allowedChainIds?: string[];
  allowedWalletMethods?: string[];
}>;

export type LiveTestProfile = Readonly<{
  schemaVersion: '1.0.0';
  environment: 'test';
  authorization: {
    nonProduction: true;
    approvedBy: string;
    approvedAt: string;
  };
  targetBaseUrl: string;
  authProviderOrigins?: string[];
  walletTransportOrigins?: string[];
  actors: LiveTestActor[];
  policy: {
    allowedMethods: LiveTestMethod[];
    maximumRiskClass: LiveTestRiskClass;
    allowedRequestHeaders?: string[];
    maxRequests: number;
    maxResponseBytes: number;
    timeoutMs: number;
    maxStateChanges: number;
    maxDurationMs: number;
    cleanupRequired?: boolean;
  };
}>;

type JsonSchemaInput = Parameters<typeof z.fromJSONSchema>[0];
const PROFILE_SCHEMA_PATH = resolve(
  import.meta.dirname,
  '..',
  '..',
  'domains',
  'offsec',
  'contracts',
  'offsec-live-test-profile-schema.v1.json',
);
const profileJsonSchema = JSON.parse(readFileSync(PROFILE_SCHEMA_PATH, 'utf8')) as JsonSchemaInput;
export const LiveTestProfileSchema = z.fromJSONSchema(profileJsonSchema) as z.ZodType<LiveTestProfile>;

const INTERACTIVE_AUTH_KINDS = new Set<AuthKind>([
  'oauth-oidc',
  'device-code',
  'passkey',
  'wallet',
]);

export function loadLiveTestProfile(path: string): { profile: LiveTestProfile; sha256: string } {
  const content = readFileSync(resolve(path));
  const profile = LiveTestProfileSchema.parse(JSON.parse(content.toString('utf8')));
  validateLiveTestProfile(profile);
  return {
    profile,
    sha256: createHash('sha256').update(content).digest('hex'),
  };
}

export function validateLiveTestProfile(profile: LiveTestProfile): void {
  assertSafeHttpUrl(profile.targetBaseUrl, 'targetBaseUrl', false);
  for (const origin of profile.authProviderOrigins ?? []) {
    assertSafeHttpUrl(origin, 'authProviderOrigins', true);
  }
  for (const origin of profile.walletTransportOrigins ?? []) {
    assertSafeHttpUrl(origin, 'walletTransportOrigins', true);
  }
  const actorIds = new Set<string>();
  for (const actor of profile.actors) {
    if (actorIds.has(actor.actorId)) throw new Error(`Live DAST actorId가 중복됐다: ${actor.actorId}`);
    actorIds.add(actor.actorId);
    if (actor.authKind === 'host-secret' && !actor.secretRef) {
      throw new Error(`host-secret actor에는 secretRef가 필요하다: ${actor.actorId}`);
    }
    if (actor.authKind !== 'host-secret' && actor.secretRef) {
      throw new Error(`secretRef는 host-secret actor에만 허용된다: ${actor.actorId}`);
    }
    if (actor.authKind !== 'wallet' && (actor.allowedChainIds || actor.allowedWalletMethods)) {
      throw new Error(`wallet 권한은 wallet actor에만 허용된다: ${actor.actorId}`);
    }
    if (actor.authKind === 'wallet' && (actor.allowedChainIds?.length ?? 0) === 0) {
      throw new Error(`wallet actor에는 allowedChainIds가 필요하다: ${actor.actorId}`);
    }
  }
}

export function assertInteractionModeCompatible(
  profile: LiveTestProfile,
  mode: AuthInteractionMode,
): void {
  const interactive = profile.actors.filter((actor) => INTERACTIVE_AUTH_KINDS.has(actor.authKind));
  if (interactive.length > 0 && mode === 'none') {
    throw new Error(
      `interactive actor에는 authInteractionMode가 필요하다: ${interactive.map((actor) => actor.actorId).join(', ')}`,
    );
  }
}

function assertSafeHttpUrl(value: string, label: string, originOnly: boolean): void {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`Live DAST ${label} URL이 유효하지 않다: ${value}`);
  }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash) {
    throw new Error(`Live DAST ${label} URL이 안전 계약과 다르다: ${value}`);
  }
  if (originOnly && (url.pathname !== '/' || url.search)) {
    throw new Error(`Live DAST ${label}에는 origin만 허용된다: ${value}`);
  }
}

export const SourceAnchorSchema = z.object({
  path: z.string().min(1),
  lineStart: z.number().int().positive(),
  lineEnd: z.number().int().positive(),
}).strict().refine((value) => value.lineEnd >= value.lineStart, 'source anchor line 범위가 역전됐다');

const RequestBodySchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('text'), value: z.string().max(65_536) }).strict(),
  z.object({ kind: z.literal('json'), value: z.unknown() }).strict(),
  z.object({ kind: z.literal('form'), value: z.record(z.string(), z.string().max(8_192)) }).strict(),
]);

const LiveScenarioRequestSchema = z.object({
  method: LiveTestMethodSchema,
  path: z.string().min(1).max(2048),
  query: z.record(z.string(), z.string().max(8_192)).optional(),
  headers: z.record(z.string(), z.string().max(8_192)).optional(),
  body: RequestBodySchema.optional(),
}).strict().refine(
  (value) => !/[?#]/.test(value.path),
  'scenario path에는 query 또는 fragment를 포함하지 않고 query 필드를 사용한다',
);

export const LiveScenarioSchema = z.object({
  schemaVersion: z.literal('2.0.0'),
  scenarioId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/),
  parentScenarioId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/).optional(),
  parentReceiptId: z.string().regex(/^HTTP-[a-f0-9]{20}$/).optional(),
  actorId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/),
  sourceAnchors: z.array(SourceAnchorSchema).max(64),
  standardIds: z.array(z.string().min(1).max(128)).max(64),
  request: LiveScenarioRequestSchema,
  riskClass: LiveTestRiskClassSchema,
  preconditions: z.array(z.string().min(1).max(1024)).max(64),
  oracle: z.object({
    kind: z.enum(['status', 'body', 'header', 'differential', 'state']),
    description: z.string().min(1).max(4096),
    compareActorId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/).optional(),
    relation: z.enum(['equal', 'different']).optional(),
    fields: z.array(z.enum(['status', 'body', 'headers'])).min(1).max(3).optional(),
    allowedRequestDelta: z.enum(['actor-only', 'query-only', 'body-only']).optional(),
  }).strict(),
  negativeControl: z.object({
    required: z.boolean(),
    description: z.string().min(1).max(4096).optional(),
  }).strict(),
  cleanupRequired: z.boolean(),
  cleanup: z.object({
    request: LiveScenarioRequestSchema,
    oracle: z.string().min(1).max(4096),
  }).strict().optional(),
  safety: z.enum(['ready', 'not-executable']),
}).strict().superRefine((value, context) => {
  if (value.parentReceiptId && !value.parentScenarioId) {
    context.addIssue({ code: 'custom', message: 'parentReceiptId에는 parentScenarioId가 필요하다' });
  }
  if (value.request.body && ['GET', 'HEAD'].includes(value.request.method)) {
    context.addIssue({ code: 'custom', message: 'GET/HEAD scenario에는 body를 허용하지 않는다' });
  }
  if (value.cleanup?.request.body && ['GET', 'HEAD'].includes(value.cleanup.request.method)) {
    context.addIssue({ code: 'custom', message: 'GET/HEAD cleanup에는 body를 허용하지 않는다' });
  }
  if (value.negativeControl.required && !value.negativeControl.description) {
    context.addIssue({ code: 'custom', message: '필수 negative control에는 description이 필요하다' });
  }
  if (value.oracle.kind === 'differential') {
    if (!value.oracle.relation || !value.oracle.fields || !value.oracle.allowedRequestDelta) {
      context.addIssue({ code: 'custom', message: 'differential oracle에는 relation, fields, allowedRequestDelta가 필요하다' });
    }
    if (value.oracle.allowedRequestDelta === 'actor-only' && !value.oracle.compareActorId) {
      context.addIssue({ code: 'custom', message: 'actor-only differential에는 compareActorId가 필요하다' });
    }
  }
  if (value.riskClass === 'reversible-state-change' && (!value.cleanupRequired || !value.cleanup)) {
    context.addIssue({ code: 'custom', message: '상태변경 scenario에는 실행 가능한 cleanup이 필요하다' });
  }
  if (value.riskClass === 'read-only' && (value.cleanupRequired || value.cleanup)) {
    context.addIssue({ code: 'custom', message: 'read-only scenario에는 cleanup을 선언하지 않는다' });
  }
});
export type LiveScenario = z.infer<typeof LiveScenarioSchema>;

export const LiveScenarioEventTypeSchema = z.enum([
  'proposed',
  'approved',
  'rejected',
  'executed',
  'blocked',
  'inconclusive',
  'started',
  'cleanup-started',
  'cleanup-succeeded',
  'cleanup-failed',
]);
export type LiveScenarioEventType = z.infer<typeof LiveScenarioEventTypeSchema>;

export const LiveScenarioJournalEventCoreSchema = z.object({
  schemaVersion: z.literal('1.0.0'),
  eventId: z.string().regex(/^JOURNAL-[a-f0-9]{20}$/),
  type: LiveScenarioEventTypeSchema,
  scenarioId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/),
  scenarioSha256: z.string().regex(/^[a-f0-9]{64}$/),
  profileSha256: z.string().regex(/^[a-f0-9]{64}$/),
  previousEventSha256: z.string().regex(/^[a-f0-9]{64}$/).nullable(),
  receiptId: z.string().regex(/^HTTP-[a-f0-9]{20}$/).optional(),
  reason: z.string().min(1).max(4096),
  observedAt: z.string().datetime(),
}).strict();

export const LiveScenarioJournalEventSchema = LiveScenarioJournalEventCoreSchema.extend({
  eventSha256: z.string().regex(/^[a-f0-9]{64}$/),
}).strict();
export type LiveScenarioJournalEvent = z.infer<typeof LiveScenarioJournalEventSchema>;
