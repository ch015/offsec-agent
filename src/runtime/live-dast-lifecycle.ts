import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';

import { z } from 'zod';

import {
  AuthInteractionModeSchema,
  assertInteractionModeCompatible,
  loadLiveTestProfile,
  type AuthInteractionMode,
  type LiveTestProfile,
} from './live-test-contract.js';
import {
  createOwnerAuthRequest,
  readActorAuthSessions,
  sealAuthInteractionSelection,
  sealHostSecretSession,
  type AuthInteractionSelection,
  type OpaqueAuthSession,
  type OwnerAuthRequest,
} from './live-auth-session.js';
import { LiveScenarioJournal } from './live-scenario-journal.js';
import type { LiveTestPlan } from './live-test-broker.js';
import type { LiveDastContext } from './live-dast-tools.js';

const PROFILE_NAME = 'live-test-profile.json';
const RESUME_INPUT_NAME = 'assess-resume-input.json';
const INTERACTIVE = new Set(['oauth-oidc', 'device-code', 'passkey', 'wallet']);

export const AssessResumeRecordSchema = z.object({
  schemaVersion: z.literal('1.0.0'),
  runId: z.string().min(1),
  target: z.string().min(1),
  scope: z.string().optional(),
  model: z.string().optional(),
  reviewModel: z.string().optional(),
  effort: z.enum(['low', 'medium', 'high', 'max', 'xhigh']).optional(),
  maxTurns: z.number().int().positive().optional(),
  maxBudgetUsd: z.number().positive().optional(),
  verificationMode: z.enum(['VA_PENTEST', 'VA_PENTEST_REDTEAM']),
  semgrepMode: z.enum(['required', 'best-effort', 'off']),
  workUnitMode: z.enum(['auto', 'force', 'off']),
  maxConcurrency: z.number().int().positive().optional(),
  engagementDir: z.string().min(1),
  liveTestProfilePath: z.string().min(1),
  authInteractionMode: AuthInteractionModeSchema,
}).strict();
export type AssessResumeRecord = z.infer<typeof AssessResumeRecordSchema>;

export type PreparedLiveDast = Readonly<{
  profilePath: string;
  profile: LiveTestProfile;
  profileSha256: string;
  selection: AuthInteractionSelection;
  authSessions: ReadonlyMap<string, OpaqueAuthSession>;
}>;

export function prepareLiveDast(input: {
  engagementDir: string;
  runId: string;
  testUrl?: string;
  profilePath?: string;
  mode?: AuthInteractionMode;
  now?: Date;
  env?: NodeJS.ProcessEnv;
}): PreparedLiveDast {
  const profilePath = join(resolve(input.engagementDir), PROFILE_NAME);
  if (!existsSync(profilePath)) {
    const content = input.profilePath
      ? readFileSync(resolve(input.profilePath))
      : Buffer.from(`${JSON.stringify(shortcutProfile(input.testUrl, input.now))}\n`);
    writeFileSync(profilePath, content, { flag: 'wx', mode: 0o600 });
  }
  const loaded = loadLiveTestProfile(profilePath);
  if (input.testUrl && new URL(input.testUrl).toString() !== new URL(loaded.profile.targetBaseUrl).toString()) {
    throw new Error('--test-url과 Live DAST profile targetBaseUrl이 다르다');
  }
  const mode = input.mode ?? 'none';
  assertInteractionModeCompatible(loaded.profile, mode);
  const selection = sealAuthInteractionSelection({
    engagementDir: input.engagementDir,
    runId: input.runId,
    mode,
    profileSha256: loaded.sha256,
    now: input.now,
  });
  const sessions = readActorAuthSessions({ engagementDir: input.engagementDir, selection, now: input.now });
  for (const actor of loaded.profile.actors.filter((candidate) => candidate.authKind === 'host-secret')) {
    if (sessions.has(actor.actorId)) continue;
    const reference = actor.secretRef!;
    if (!reference.startsWith('env:')) {
      throw new Error(`vault host-secret에는 host resolver가 필요하다: ${actor.actorId}`);
    }
    const value = (input.env ?? process.env)[reference.slice('env:'.length)];
    if (!value) throw new Error(`host-secret env reference를 해석할 수 없다: ${reference}`);
    const parsed = JSON.parse(value) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || !('headers' in parsed)) {
      throw new Error(`host-secret은 {headers} JSON이어야 한다: ${actor.actorId}`);
    }
    sessions.set(actor.actorId, sealHostSecretSession({
      engagementDir: input.engagementDir,
      selection,
      actorId: actor.actorId,
      targetOrigin: loaded.profile.targetBaseUrl,
      material: Buffer.from(value),
      now: input.now,
    }));
  }
  return {
    profilePath,
    profile: loaded.profile,
    profileSha256: loaded.sha256,
    selection,
    authSessions: sessions,
  };
}

export function nextOwnerAuthRequest(input: {
  engagementDir: string;
  prepared: PreparedLiveDast;
  now?: Date;
}): OwnerAuthRequest | undefined {
  const actor = input.prepared.profile.actors.find(
    (candidate) => INTERACTIVE.has(candidate.authKind) && !input.prepared.authSessions.has(candidate.actorId),
  );
  if (!actor) return undefined;
  const providerOrigin = actor.authKind === 'wallet'
    ? input.prepared.profile.walletTransportOrigins?.[0]
    : input.prepared.profile.authProviderOrigins?.[0];
  return createOwnerAuthRequest({
    engagementDir: input.engagementDir,
    selection: input.prepared.selection,
    actorId: actor.actorId,
    authKind: actor.authKind,
    targetOrigin: new URL(input.prepared.profile.targetBaseUrl).origin,
    startUrl: input.prepared.profile.targetBaseUrl,
    ...(providerOrigin ? { providerOrigin } : {}),
    requestedChainIds: actor.allowedChainIds,
    purpose: `승인된 테스트 actor ${actor.actorId} 인증`,
    postLoginGoal: '인증 뒤 동일 actor lineage로 post-auth 동적 검증을 수행한다.',
    now: input.now,
  });
}

export function writeResumeRecord(engagementDir: string, value: AssessResumeRecord): string {
  const path = join(resolve(engagementDir), RESUME_INPUT_NAME);
  const parsed = AssessResumeRecordSchema.parse(value);
  if (existsSync(path)) {
    const existing = AssessResumeRecordSchema.parse(JSON.parse(readFileSync(path, 'utf8')));
    if (stableJson(existing) !== stableJson(parsed)) throw new Error('assess resume input이 기존 run과 다르다');
    return path;
  }
  writeFileSync(path, `${JSON.stringify(parsed, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  return path;
}

export function readResumeRecord(engagementDir: string): AssessResumeRecord {
  return AssessResumeRecordSchema.parse(
    JSON.parse(readFileSync(join(resolve(engagementDir), RESUME_INPUT_NAME), 'utf8')),
  );
}

export function publicOwnerRequestArtifact(engagementDir: string, request: OwnerAuthRequest): string {
  const name = `owner_auth_request-${request.requestId}.json`;
  writeFileSync(join(resolve(engagementDir), name), `${JSON.stringify(request, null, 2)}\n`, {
    flag: 'wx',
    mode: 0o600,
  });
  return name;
}

export function createLiveDastContext(input: {
  engagementDir: string;
  prepared: PreparedLiveDast;
  plan: LiveTestPlan;
  planSha256: string;
}): LiveDastContext {
  const journal = new LiveScenarioJournal({
    engagementDir: input.engagementDir,
    profile: input.prepared.profile,
    profileSha256: input.prepared.profileSha256,
  });
  const actorId = input.prepared.profile.actors[0]?.actorId;
  if (!actorId) throw new Error('Live DAST profile actor가 없다');
  for (const scenario of input.plan.scenarios) {
    if (journal.readEvents().some((event) => event.scenarioId === scenario.scenarioId && event.type === 'approved')) continue;
    const request = legacyPlanRequest(scenario.path, scenario.method);
    const sourceAnchors = scenario.sourceEvidence
      ? [{
          path: scenario.sourceEvidence.file,
          lineStart: scenario.sourceEvidence.line ?? Math.min(...(scenario.sourceEvidence.lines ?? [1])),
          lineEnd: scenario.sourceEvidence.line ?? Math.max(...(scenario.sourceEvidence.lines ?? [1])),
        }]
      : [];
    // The legacy plan has no typed cleanup/body contract.  A non-read method is
    // therefore retained as a rejected inventory item until discovery submits a
    // complete reversible scenario through the typed tool.
    const readOnlyMethod = ['GET', 'HEAD', 'OPTIONS'].includes(scenario.method);
    journal.propose({
      schemaVersion: '2.0.0',
      scenarioId: scenario.scenarioId,
      actorId,
      sourceAnchors,
      standardIds: [],
      request,
      riskClass: 'read-only',
      preconditions: scenario.preconditions,
      oracle: { kind: 'status', description: scenario.successCriteria },
      negativeControl: { required: false },
      cleanupRequired: false,
      safety: readOnlyMethod && scenario.safety === 'ready' ? 'ready' : 'not-executable',
    }, 'sealed source-first pentest plan root scenario');
  }
  return {
    engagementDir: input.engagementDir,
    profile: input.prepared.profile,
    profileSha256: input.prepared.profileSha256,
    planSha256: input.planSha256,
    selection: input.prepared.selection,
    journal,
    authSessions: input.prepared.authSessions,
  };
}

function legacyPlanRequest(value: string, method: LiveTestPlan['scenarios'][number]['method']): {
  method: LiveTestPlan['scenarios'][number]['method'];
  path: string;
  query?: Record<string, string>;
} {
  const marker = value.indexOf('?');
  if (marker < 0) return { method, path: value };
  const path = value.slice(0, marker) || '/';
  const query = Object.fromEntries(new URLSearchParams(value.slice(marker + 1)).entries());
  return { method, path, ...(Object.keys(query).length > 0 ? { query } : {}) };
}

function shortcutProfile(testUrl: string | undefined, now = new Date()): LiveTestProfile {
  if (!testUrl) throw new Error('Live DAST profile 또는 --test-url이 필요하다');
  return {
    schemaVersion: '1.0.0',
    environment: 'test',
    authorization: { nonProduction: true, approvedBy: 'CLI operator', approvedAt: now.toISOString() },
    targetBaseUrl: new URL(testUrl).toString(),
    actors: [{ actorId: 'anonymous', role: 'unauthenticated', authKind: 'none' }],
    policy: {
      allowedMethods: ['GET', 'HEAD'],
      maximumRiskClass: 'read-only',
      maxRequests: 100,
      maxResponseBytes: 1_048_576,
      timeoutMs: 10_000,
      maxStateChanges: 0,
      maxDurationMs: 900_000,
    },
  };
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function fileSha256(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

export function profileArtifactName(path: string): string {
  return basename(path);
}

export function assertLiveDastLineageRepresented(
  reportPath: string,
  prepared: PreparedLiveDast,
): void {
  const report = readFileSync(resolve(reportPath), 'utf8');
  for (const hash of [prepared.profileSha256, prepared.selection.selectionSha256]) {
    if (!report.includes(hash)) throw new Error(`최종 보고서가 Live DAST lineage hash를 인용하지 않았다: ${hash}`);
  }
}
