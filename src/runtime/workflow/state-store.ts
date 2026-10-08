import {
  existsSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { isDeepStrictEqual } from 'node:util';

import { z } from 'zod';

import { ArtifactRefSchema, ProviderUsageSchema } from '../contracts/result-contract.js';
import { ArtifactReceiptSchema, type ArtifactReceipt } from './artifact-store.js';

import { appendLedger, recoverLedger } from './file-ledger.js';
import { atomicPrivateWrite, privateDirectory } from './storage-files.js';

export const HostInputRecordSchema = z.object({
  inputRevision: z.number().int().nonnegative(),
  contextEpoch: z.string().regex(/^[a-f0-9]{64}$/),
  manifest: ArtifactRefSchema,
  allowedReadFiles: z.array(z.string().min(1)).min(1),
  fileHashes: z.array(z.object({
    path: z.string().min(1),
    sha256: z.string().regex(/^[a-f0-9]{64}$/),
    bytes: z.number().int().nonnegative(),
  }).strict()).min(1),
  parent: z.object({
    manifestSha256: z.string().regex(/^[a-f0-9]{64}$/),
    triggerArtifactSha256: z.string().regex(/^[a-f0-9]{64}$/),
  }).strict().optional(),
}).strict();
export type HostInputRecord = z.infer<typeof HostInputRecordSchema>;

export const HostResourceReceiptSchema = z.object({
  path: z.string().min(1),
  sha256: z.string().regex(/^[a-f0-9]{64}$/),
  bytes: z.number().int().nonnegative(),
  semanticSha256: z.string().regex(/^[a-f0-9]{64}$/).optional(),
}).strict();
export type HostResourceReceipt = z.infer<typeof HostResourceReceiptSchema>;

const EventBaseSchema = z.object({
  seq: z.number().int().positive(),
  eventId: z.string().min(1),
  at: z.string().datetime(),
  runId: z.string().min(1),
  effects: z.object({
    artifactReceipts: z.array(ArtifactReceiptSchema).optional(),
    outbox: z.array(z.object({ id: z.string(), idempotencyKey: z.string(), topic: z.string(), payload: z.unknown() }).strict()).optional(),
  }).strict().optional(),
});

const AttemptIdentitySchema = z.object({
  phase: z.string().min(1),
  round: z.string().min(1).optional(),
  attempt: z.number().int().positive(),
});

export const RunEventSchema = z.discriminatedUnion('type', [
  EventBaseSchema.extend({
    type: z.literal('run.created'),
    contractId: z.string().min(1),
    contractVersion: z.string().min(1),
    domain: z.string().min(1),
    mission: z.string().min(1),
    maxBudgetUsd: z.number().finite().positive().optional(),
  }),
  EventBaseSchema.extend({
    type: z.literal('input.recorded'),
    input: HostInputRecordSchema,
  }),
  EventBaseSchema.extend({
    type: z.literal('input.revised'),
    input: HostInputRecordSchema,
  }),
  EventBaseSchema.merge(AttemptIdentitySchema).extend({
    type: z.literal('phase.started'),
    hostResources: z.array(HostResourceReceiptSchema).min(1).optional(),
  }),
  EventBaseSchema.merge(AttemptIdentitySchema).extend({
    type: z.literal('attempt.received'),
    usage: ProviderUsageSchema,
  }),
  EventBaseSchema.merge(AttemptIdentitySchema).extend({
    type: z.literal('usage.reconciled'),
    receiptId: z.string().min(1),
    usage: ProviderUsageSchema,
  }),
  EventBaseSchema.merge(AttemptIdentitySchema).extend({
    type: z.literal('phase.context-compacted'),
    provider: z.string().min(1),
    trigger: z.enum(['manual', 'auto']),
    preTokens: z.number().int().nonnegative(),
    postTokens: z.number().int().nonnegative().optional(),
    durationMs: z.number().int().nonnegative().optional(),
    boundaryId: z.string().min(1),
  }),
  EventBaseSchema.merge(AttemptIdentitySchema).extend({
    type: z.literal('phase.result-identity-bound'),
    source: z.literal('host'),
    providerIdentity: z.enum(['absent', 'matched', 'overridden']),
    provider: z.string().min(1).optional(),
  }),
  EventBaseSchema.merge(AttemptIdentitySchema).extend({
    type: z.literal('phase.completed'),
    artifacts: z.array(ArtifactRefSchema),
    result: z.unknown(),
    hostResources: z.array(HostResourceReceiptSchema).min(1).optional(),
  }),
  EventBaseSchema.merge(AttemptIdentitySchema).extend({
    type: z.literal('phase.failed'),
    reason: z.string().min(1),
  }),
  EventBaseSchema.extend({
    type: z.literal('run.budget-increased'),
    previousMaxBudgetUsd: z.number().finite().positive().nullable(),
    maxBudgetUsd: z.number().finite().positive().nullable(),
  }),
  EventBaseSchema.extend({
    type: z.literal('budget.reserved'),
    attemptKey: z.string().min(1),
    amountUsd: z.number().finite().positive(),
    recovered: z.boolean().optional(),
  }),
  EventBaseSchema.extend({
    type: z.literal('budget.settled'),
    attemptKey: z.string().min(1),
    chargedUsd: z.number().finite().nonnegative(),
    accountingComplete: z.boolean(),
  }),
  EventBaseSchema.extend({
    type: z.literal('analysis.checkpoint'),
    stage: z.enum(['units', 'review']),
    artifacts: z.array(ArtifactRefSchema).min(1),
  }),
  EventBaseSchema.extend({ type: z.literal('coverage.finalized'), artifact: ArtifactRefSchema }),
  EventBaseSchema.extend({ type: z.literal('run.completed') }),
  EventBaseSchema.extend({ type: z.literal('run.incomplete'), reason: z.string().min(1) }),
  EventBaseSchema.extend({
    type: z.literal('analysis.revised'),
    revision: z.number().int().positive(),
    reason: z.string().min(1),
    invalidatedAttemptKeys: z.array(z.string()),
    archivedArtifacts: z.array(ArtifactRefSchema),
    preserveAnalysisCheckpoint: z.boolean().optional(),
  }),
  EventBaseSchema.extend({
    type: z.literal('evaluation.reopened'),
    revision: z.number().int().positive(),
    reason: z.string().min(1),
    invalidatedAttemptKeys: z.array(z.string()),
    archivedArtifacts: z.array(ArtifactRefSchema),
  }),
  EventBaseSchema.extend({
    type: z.literal('run.awaiting-input'),
    reason: z.string().min(1),
    artifact: ArtifactRefSchema,
  }),
  EventBaseSchema.extend({ type: z.literal('run.resumed') }),
  EventBaseSchema.extend({
    type: z.literal('run.blocked'),
    reason: z.string().min(1),
  }),
  EventBaseSchema.extend({
    type: z.literal('publication.completed'),
    artifact: ArtifactRefSchema,
    sourceManifestSha256: z.string().regex(/^[a-f0-9]{64}$/),
  }),
]);

export type RunEvent = z.infer<typeof RunEventSchema>;
export type NewRunEvent = RunEvent extends infer Event
  ? Event extends RunEvent
    ? Omit<Event, 'seq' | 'at' | 'runId'>
    : never
  : never;

export type AttemptSnapshot = {
  superseded?: boolean;
  phase: string;
  round?: string;
  attempt: number;
  status: 'started' | 'received' | 'completed' | 'failed';
  hostResources?: HostResourceReceipt[];
  usage?: z.infer<typeof ProviderUsageSchema>;
  artifacts?: z.infer<typeof ArtifactRefSchema>[];
  result?: unknown;
  failureReason?: string;
};

export type RunSnapshot = {
  runId: string;
  contractId: string;
  contractVersion: string;
  domain: string;
  mission: string;
  status: 'running' | 'awaiting-input' | 'completed' | 'blocked' | 'incomplete';
  maxBudgetUsd?: number;
  totalCostUsd: number;
  lastSeq: number;
  completedPhases: string[];
  completionCoverage?: z.infer<typeof ArtifactRefSchema>;
  analysisRevision?: number;
  revisions?: Array<{ revision: number; reason: string; artifacts: z.infer<typeof ArtifactRefSchema>[] }>;
  evaluationRevisions?: Array<{ revision: number; reason: string; artifacts: z.infer<typeof ArtifactRefSchema>[] }>;
  usageReceiptIds?: string[];
  budgetReservations?: Record<string, { amountUsd: number; chargedUsd?: number; accountingComplete?: boolean }>;
  analysisCheckpoint?: { stage: 'units' | 'review'; artifacts: z.infer<typeof ArtifactRefSchema>[] };
  attempts: Record<string, AttemptSnapshot>;
  inputManifest?: HostInputRecord;
  publication?: {
    artifact: z.infer<typeof ArtifactRefSchema>;
    sourceManifestSha256: string;
  };
  effects?: Record<string, RunStateEffects>;
  blockReason?: string;
  awaitingInput?: {
    reason: string;
    artifact: z.infer<typeof ArtifactRefSchema>;
  };
};

export const RUN_EVENTS_FILE = 'run-events.jsonl';
export const RUN_STATE_FILE = 'run-state.json';

export interface RunStateStore {
  readonly backend: 'file';
  read(): Readonly<RunSnapshot>;
  append(event: NewRunEvent): Readonly<RunSnapshot>;
  appendBatch(events: readonly NewRunEvent[], expectedLastSeq?: number): Readonly<RunSnapshot>;
}

/** Async backend contract used by the PostgreSQL implementation. */
export interface AsyncRunStateStore {
  readonly backend: 'postgres';
  read(): Promise<Readonly<RunSnapshot>>;
  append(
    event: NewRunEvent,
    expectedLastSeq?: number,
    fencingToken?: number,
  ): Promise<Readonly<RunSnapshot>>;
  appendBatch(
    events: readonly NewRunEvent[],
    expectedLastSeq?: number,
    fencingToken?: number,
  ): Promise<Readonly<RunSnapshot>>;
  appendBatchWithEffects(
    events: readonly NewRunEvent[],
    expectedLastSeq: number,
    fencingToken: number,
    effects?: RunStateEffects,
  ): Promise<Readonly<RunSnapshot>>;
}

export type RunStateBackend = RunStateStore | AsyncRunStateStore;

export type RunOutboxEffect = {
  id: string;
  idempotencyKey: string;
  topic: string;
  payload: unknown;
};

export type RunStateEffects = {
  artifactReceipts?: readonly ArtifactReceipt[];
  outbox?: readonly RunOutboxEffect[];
};

export function eventWithEffects(event: NewRunEvent, effects: RunStateEffects = {}): NewRunEvent {
  if (!Object.keys(effects).length) return event;
  return { ...event, effects: {
    ...(effects.artifactReceipts ? { artifactReceipts: [...effects.artifactReceipts] } : {}),
    ...(effects.outbox ? { outbox: [...effects.outbox] } : {}),
  } };
}

export function phaseAttemptKey(phase: string, round: string | undefined, attempt: number): string {
  return `${phase}:${round ?? '-'}:${attempt}`;
}

function emptySnapshot(created: Extract<RunEvent, { type: 'run.created' }>): RunSnapshot {
  return {
    runId: created.runId,
    contractId: created.contractId,
    contractVersion: created.contractVersion,
    domain: created.domain,
    mission: created.mission,
    status: 'running',
    maxBudgetUsd: created.maxBudgetUsd,
    totalCostUsd: 0,
    lastSeq: 0,
    completedPhases: [],
    attempts: {},
  };
}

function applyEvent(snapshot: RunSnapshot, event: RunEvent): void {
  if (event.runId !== snapshot.runId) throw new Error(`run event identity 불일치: ${event.runId}`);
  if (event.seq !== snapshot.lastSeq + 1) {
    throw new Error(`run event seq 불연속: ${event.seq} != ${snapshot.lastSeq + 1}`);
  }
  const resumeEvent = event.type === 'input.revised' || event.type === 'run.resumed';
  const administrative = ['usage.reconciled', 'analysis.revised', 'evaluation.reopened', 'run.budget-increased'].includes(event.type);
  if (snapshot.status !== 'running' && event.type !== 'run.created' && !administrative && !(snapshot.status === 'awaiting-input' && resumeEvent)) {
    throw new Error(`종료된 run에는 event를 추가할 수 없다: ${snapshot.status}`);
  }
  if (event.effects) (snapshot.effects ??= {})[event.eventId] = event.effects;
  if (event.type === 'run.created') {
    if (snapshot.lastSeq !== 0) throw new Error('run.created가 중복됐다');
  } else if (event.type === 'run.budget-increased') {
    if ((snapshot.maxBudgetUsd ?? null) !== event.previousMaxBudgetUsd) throw new Error('budget revision conflicts with current limit');
    if (event.maxBudgetUsd !== null && (snapshot.maxBudgetUsd === undefined || event.maxBudgetUsd <= snapshot.maxBudgetUsd)) {
      throw new Error('resume budget must increase the current limit');
    }
    snapshot.maxBudgetUsd = event.maxBudgetUsd ?? undefined;
  } else if (event.type === 'budget.reserved') {
    const attempt = snapshot.attempts[event.attemptKey];
    if (!attempt || (attempt.status !== 'started' && !event.recovered)) throw new Error('budget reservation requires a started attempt');
    const reservations = snapshot.budgetReservations ??= {};
    if (reservations[event.attemptKey]) throw new Error('duplicate budget reservation');
    reservations[event.attemptKey] = { amountUsd: event.amountUsd };
  } else if (event.type === 'budget.settled') {
    const reservation = snapshot.budgetReservations?.[event.attemptKey];
    if (!reservation || reservation.chargedUsd !== undefined) throw new Error('budget settlement requires an unsettled reservation');
    reservation.chargedUsd = event.chargedUsd;
    reservation.accountingComplete = event.accountingComplete;
  } else if (event.type === 'usage.reconciled') {
    const key = phaseAttemptKey(event.phase, event.round, event.attempt);
    const attempt = snapshot.attempts[key];
    if (!attempt) throw new Error(`usage receipt has no attempt: ${key}`);
    const ids = snapshot.usageReceiptIds ??= [];
    if (ids.includes(event.receiptId)) throw new Error('duplicate usage receipt');
    if (attempt.usage?.accountingComplete && (!event.usage.accountingComplete || attempt.usage.costUsd !== event.usage.costUsd)) {
      throw new Error('usage receipt conflicts with settled accounting');
    }
    snapshot.totalCostUsd += event.usage.costUsd - (attempt.usage?.costUsd ?? 0);
    attempt.usage = { ...attempt.usage, ...event.usage };
    ids.push(event.receiptId);
  } else if (event.type === 'evaluation.reopened') {
    if (event.revision !== (snapshot.evaluationRevisions?.length ?? 0) + 1) throw new Error('evaluation revision is not consecutive');
    if (Object.values(snapshot.attempts).some(a => a.status === 'started' || a.status === 'received')) throw new Error('active attempts prevent evaluation reopening');
    for (const key of event.invalidatedAttemptKeys) {
      const attempt = snapshot.attempts[key];
      if (!attempt || !['evaluate', 'report'].includes(attempt.phase)) throw new Error(`evaluation reopening cannot invalidate attempt: ${key}`);
      attempt.superseded = true;
    }
    if (Object.values(snapshot.attempts).some(a => !a.superseded && ['evaluate', 'report'].includes(a.phase))) throw new Error('evaluation reopening must invalidate all downstream attempts');
    snapshot.completedPhases = [...new Set(Object.values(snapshot.attempts)
      .filter(a => a.status === 'completed' && !a.superseded).map(a => a.round ? `${a.phase}:${a.round}` : a.phase))];
    (snapshot.evaluationRevisions ??= []).push({ revision: event.revision, reason: event.reason, artifacts: event.archivedArtifacts });
    delete snapshot.publication;
    delete snapshot.blockReason;
    snapshot.status = 'running';
  } else if (event.type === 'analysis.revised') {
    if (event.revision !== (snapshot.analysisRevision ?? 0) + 1) throw new Error('analysis revision is not consecutive');
    if (Object.values(snapshot.attempts).some(a => a.status === 'started' || a.status === 'received')) throw new Error('active attempts prevent revision');
    for (const key of event.invalidatedAttemptKeys) {
      const attempt = snapshot.attempts[key];
      if (!attempt) throw new Error(`unknown revision attempt: ${key}`);
      attempt.superseded = true;
    }
    snapshot.completedPhases = [...new Set(Object.values(snapshot.attempts)
      .filter(a => a.status === 'completed' && !a.superseded).map(a => a.round ? `${a.phase}:${a.round}` : a.phase))];
    (snapshot.revisions ??= []).push({ revision: event.revision, reason: event.reason, artifacts: event.archivedArtifacts });
    snapshot.analysisRevision = event.revision;
    if (!event.preserveAnalysisCheckpoint) delete snapshot.analysisCheckpoint;
    delete snapshot.publication;
    delete snapshot.completionCoverage;
    delete snapshot.blockReason;
    snapshot.status = 'running';
  } else if (event.type === 'coverage.finalized') {
    snapshot.completionCoverage = event.artifact;
  } else if (event.type === 'analysis.checkpoint') {
    if (snapshot.analysisCheckpoint?.stage === 'review') throw new Error('review inputs are already sealed');
    snapshot.analysisCheckpoint = { stage: event.stage, artifacts: event.artifacts };
  } else if (event.type === 'input.recorded') {
    if (snapshot.inputManifest) throw new Error('host input manifest가 중복됐다');
    if (event.input.inputRevision !== 0 || event.input.parent) throw new Error('최초 host input revision이 잘못됐다');
    snapshot.inputManifest = event.input;
  } else if (event.type === 'input.revised') {
    if (snapshot.status !== 'awaiting-input' || !snapshot.inputManifest || !snapshot.awaitingInput) {
      throw new Error('대기 중인 host input만 revision할 수 있다');
    }
    if (event.input.inputRevision !== snapshot.inputManifest.inputRevision + 1) {
      throw new Error('host input revision이 연속적이지 않다');
    }
    if (!event.input.parent
      || event.input.parent.manifestSha256 !== snapshot.inputManifest.manifest.sha256
      || event.input.parent.triggerArtifactSha256 !== snapshot.awaitingInput.artifact.sha256) {
      throw new Error('host input revision lineage가 대기 상태와 다르다');
    }
    snapshot.inputManifest = event.input;
  } else if (
    event.type === 'phase.started' ||
    event.type === 'attempt.received' ||
    event.type === 'phase.context-compacted' ||
    event.type === 'phase.result-identity-bound' ||
    event.type === 'phase.completed' ||
    event.type === 'phase.failed'
  ) {
    const key = phaseAttemptKey(event.phase, event.round, event.attempt);
    const current = snapshot.attempts[key];
    if (event.type === 'phase.started') {
      if (current) throw new Error(`phase attempt가 이미 시작됐다: ${key}`);
      snapshot.attempts[key] = {
        phase: event.phase,
        ...(event.round ? { round: event.round } : {}),
        attempt: event.attempt,
        status: 'started',
        ...(event.hostResources ? { hostResources: event.hostResources } : {}),
      };
    } else {
      if (!current) throw new Error(`시작되지 않은 phase attempt다: ${key}`);
      if (current.status === 'completed' || current.status === 'failed') {
        throw new Error(`종료된 phase attempt에 event를 추가할 수 없다: ${key}`);
      }
      if (event.type === 'phase.context-compacted') {
        if (current.status !== 'started' && current.status !== 'received') {
          throw new Error(`종료된 phase attempt에는 compaction event를 추가할 수 없다: ${key}`);
        }
      } else if (event.type === 'phase.result-identity-bound') {
        if (current.status !== 'received') {
          throw new Error(`provider receipt 없이 identity binding event를 추가할 수 없다: ${key}`);
        }
      } else if (event.type === 'attempt.received') {
        if (current.status === 'received') throw new Error(`provider receipt가 중복됐다: ${key}`);
        current.status = 'received';
        snapshot.totalCostUsd += event.usage.costUsd - (current.usage?.costUsd ?? 0);
        current.usage = event.usage;
      } else if (event.type === 'phase.completed') {
        if (current.status !== 'received') {
          throw new Error(`provider receipt 없이 phase를 완료할 수 없다: ${key}`);
        }
        if (!isDeepStrictEqual(current.hostResources ?? [], event.hostResources ?? [])) {
          throw new Error(`phase host resource receipt가 시작 event와 다르다: ${key}`);
        }
        current.status = 'completed';
        current.artifacts = event.artifacts;
        current.result = event.result;
        const phaseKey = event.round ? `${event.phase}:${event.round}` : event.phase;
        if (!snapshot.completedPhases.includes(phaseKey)) snapshot.completedPhases.push(phaseKey);
      } else {
        current.status = 'failed';
        current.failureReason = event.reason;
      }
    }
  } else if (event.type === 'run.awaiting-input') {
    if (snapshot.status !== 'running') throw new Error(`awaiting-input 전환은 실행 중인 run에서만 가능하다: ${snapshot.status}`);
    snapshot.status = 'awaiting-input';
    snapshot.awaitingInput = { reason: event.reason, artifact: event.artifact };
  } else if (event.type === 'run.resumed') {
    if (snapshot.status !== 'awaiting-input' || !snapshot.inputManifest?.parent) {
      throw new Error('revised input 없이 run을 재개할 수 없다');
    }
    snapshot.status = 'running';
    delete snapshot.awaitingInput;
  } else if (event.type === 'run.completed' || event.type === 'run.incomplete') {
    if (Object.values(snapshot.attempts).some((attempt) => attempt.status === 'started' || attempt.status === 'received')) {
      throw new Error('미종료 phase attempt가 있어 run을 완료할 수 없다');
    }
    if ((snapshot.domain === 'feedback' || snapshot.domain === 'offsec') && !snapshot.publication) {
      throw new Error(`${snapshot.domain} run은 publication 없이 완료할 수 없다`);
    }
    snapshot.status = event.type === 'run.completed' ? 'completed' : 'incomplete';
    if (event.type === 'run.incomplete') snapshot.blockReason = event.reason;
  } else if (event.type === 'publication.completed') {
    if (snapshot.publication) throw new Error('publication event가 중복됐다');
    if (event.artifact.producer.role !== 'host') {
      throw new Error('publication artifact producer가 host가 아니다');
    }
    snapshot.publication = {
      artifact: event.artifact,
      sourceManifestSha256: event.sourceManifestSha256,
    };
  } else {
    snapshot.status = 'blocked';
    snapshot.blockReason = event.reason;
  }
  snapshot.lastSeq = event.seq;
}

export function replayRunEvents(events: readonly RunEvent[]): RunSnapshot {
  const created = events[0];
  if (created?.type !== 'run.created') throw new Error('첫 run event가 run.created가 아니다');
  const snapshot = emptySnapshot(created);
  const eventIds = new Set<string>();
  for (const event of events) {
    if (eventIds.has(event.eventId)) throw new Error(`run event id가 중복됐다: ${event.eventId}`);
    eventIds.add(event.eventId);
    applyEvent(snapshot, event);
  }
  return structuredClone(snapshot);
}

export class FileRunStateStore implements RunStateStore {
  readonly backend = 'file' as const;
  readonly eventsPath: string;
  readonly snapshotPath: string;
  private snapshot: RunSnapshot;
  private pendingLedger = false;
  readonly recoveryWarnings: string[] = [];
  private readonly eventIds = new Set<string>();
  private readonly eventsById = new Map<string, RunEvent>();

  private constructor(readonly engagementDir: string, snapshot: RunSnapshot, events: RunEvent[]) {
    this.eventsPath = join(engagementDir, RUN_EVENTS_FILE);
    this.snapshotPath = join(engagementDir, RUN_STATE_FILE);
    this.snapshot = snapshot;
    for (const event of events) {
      this.eventIds.add(event.eventId);
      this.eventsById.set(event.eventId, event);
    }
  }

  static create(input: {
    engagementDir: string;
    runId: string;
    contractId: string;
    contractVersion: string;
    domain: string;
    mission: string;
    maxBudgetUsd?: number;
  }): FileRunStateStore {
    const engagementDir = resolve(input.engagementDir);
    if (basename(engagementDir) === '' || dirname(engagementDir) === engagementDir) {
      throw new Error(`run state 경로가 지나치게 넓다: ${engagementDir}`);
    }
    privateDirectory(engagementDir);
    const eventsPath = join(engagementDir, RUN_EVENTS_FILE);
    if (existsSync(eventsPath)) throw new Error(`run event ledger가 이미 있다: ${eventsPath}`);
    writeFileSync(eventsPath, '', { flag: 'wx', mode: 0o600 });
    const created = RunEventSchema.parse({
      seq: 1,
      eventId: `${input.runId}:created`,
      at: new Date().toISOString(),
      runId: input.runId,
      type: 'run.created',
      contractId: input.contractId,
      contractVersion: input.contractVersion,
      domain: input.domain,
      mission: input.mission,
      maxBudgetUsd: input.maxBudgetUsd,
    });
    const snapshot = emptySnapshot(created as Extract<RunEvent, { type: 'run.created' }>);
    applyEvent(snapshot, created);
    const persisted = appendLedger(engagementDir, eventsPath, [created]);
    const store = new FileRunStateStore(engagementDir, snapshot, [created]);
    store.pendingLedger = persisted.pending;
    if (persisted.error) store.recoveryWarnings.push(persisted.error);
    store.writeSnapshot();
    return store;
  }

  static open(engagementDir: string): FileRunStateStore {
    const root = resolve(engagementDir);
    const eventsPath = join(root, RUN_EVENTS_FILE);
    if (!existsSync(eventsPath)) throw new Error(`run event ledger가 없다: ${eventsPath}`);
    const events = recoverLedger(root, eventsPath, value => RunEventSchema.parse(value));
    const snapshot = replayRunEvents(events);
    const store = new FileRunStateStore(root, snapshot, events);
    store.writeSnapshot();
    return store;
  }

  read(): Readonly<RunSnapshot> {
    return structuredClone(this.snapshot);
  }

  append(event: NewRunEvent): Readonly<RunSnapshot> {
    return this.appendBatch([event]);
  }

  appendBatch(events: readonly NewRunEvent[], expectedLastSeq = this.snapshot.lastSeq): Readonly<RunSnapshot> {
    if (expectedLastSeq !== this.snapshot.lastSeq) {
      throw new Error(`run state version 충돌: ${expectedLastSeq} != ${this.snapshot.lastSeq}`);
    }
    if (events.length === 0) return this.read();
    if (events.length === 1) {
      const event = events[0]!;
      const existing = this.eventsById.get(event.eventId);
      if (existing) {
        const { seq: _seq, at: _at, runId: _runId, ...existingPayload } = existing;
        if (!isDeepStrictEqual(existingPayload, event)) {
          throw new Error(`run event idempotency key 충돌: ${event.eventId}`);
        }
        return this.read();
      }
    }
    const batchIds = new Set<string>();
    for (const event of events) {
      if (batchIds.has(event.eventId) || this.eventIds.has(event.eventId)) {
        throw new Error(`run event batch id가 중복됐다: ${event.eventId}`);
      }
      batchIds.add(event.eventId);
    }
    const next = structuredClone(this.snapshot);
    const storedEvents: RunEvent[] = [];
    for (const [index, event] of events.entries()) {
      const stored = RunEventSchema.parse({
        ...event,
        seq: this.snapshot.lastSeq + index + 1,
        at: new Date().toISOString(),
        runId: this.snapshot.runId,
      });
      applyEvent(next, stored);
      storedEvents.push(stored);
    }
    if (this.pendingLedger) {
      try {
        recoverLedger(this.engagementDir, this.eventsPath, value => RunEventSchema.parse(value));
        this.pendingLedger = false;
      } catch (error) { this.recoveryWarnings.push(`ledger replay: ${String(error)}`); }
    }
    const persisted = appendLedger(this.engagementDir, this.eventsPath, storedEvents, this.pendingLedger);
    this.pendingLedger = persisted.pending;
    if (persisted.error) this.recoveryWarnings.push(persisted.error);
    this.snapshot = next;
    for (const stored of storedEvents) {
      this.eventIds.add(stored.eventId);
      this.eventsById.set(stored.eventId, stored);
    }
    this.writeSnapshot();
    return this.read();
  }

  private writeSnapshot(): void {
    // The fsynced ledger or write-ahead batch is authoritative. A projection failure
    // must not turn a successfully persisted provider result into a failed phase.
    try { atomicPrivateWrite(this.snapshotPath, `${JSON.stringify(this.snapshot, null, 2)}\n`); }
    catch (error) { this.recoveryWarnings.push(`snapshot projection: ${String(error)}`); }
  }
}
