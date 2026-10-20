import { createHash, randomBytes } from 'node:crypto';
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from 'node:fs';
import { join, resolve } from 'node:path';

import {
  LiveScenarioJournalEventCoreSchema,
  LiveScenarioJournalEventSchema,
  LiveScenarioSchema,
  type LiveScenario,
  type LiveScenarioEventType,
  type LiveScenarioJournalEvent,
  type LiveTestProfile,
} from './live-test-contract.js';

const JOURNAL = 'live-scenario-journal.jsonl';
const SCENARIOS = 'live-scenarios';

export type LiveScenarioProposalResult = Readonly<{
  decision: 'approved' | 'rejected';
  reason: string;
  scenarioSha256: string;
  event: LiveScenarioJournalEvent;
}>;

export class LiveScenarioJournal {
  readonly #engagementDir: string;
  readonly #profile: LiveTestProfile;
  readonly #profileSha256: string;

  constructor(input: {
    engagementDir: string;
    profile: LiveTestProfile;
    profileSha256: string;
  }) {
    this.#engagementDir = resolve(input.engagementDir);
    this.#profile = input.profile;
    this.#profileSha256 = input.profileSha256;
    mkdirSync(join(this.#engagementDir, SCENARIOS), { recursive: true, mode: 0o700 });
    if (!existsSync(this.path)) writeFileSync(this.path, '', { flag: 'wx', mode: 0o600 });
    this.verify();
  }

  get path(): string {
    return join(this.#engagementDir, JOURNAL);
  }

  propose(value: unknown, rationale: string, now = new Date()): LiveScenarioProposalResult {
    const scenario = LiveScenarioSchema.parse(value);
    const scenarioSha256 = digest(stableJson(scenario));
    const proposed = this.#append('proposed', scenario.scenarioId, scenarioSha256, rationale, now);
    const reason = this.#validatePolicy(scenario, scenarioSha256);
    if (reason) {
      const rejected = this.#append('rejected', scenario.scenarioId, scenarioSha256, reason, now);
      return { decision: 'rejected', reason, scenarioSha256, event: rejected };
    }
    const path = join(this.#engagementDir, SCENARIOS, `${scenarioSha256}.json`);
    writeFileSync(path, `${JSON.stringify(scenario)}\n`, { flag: 'wx', mode: 0o600 });
    const approved = this.#append(
      'approved',
      scenario.scenarioId,
      scenarioSha256,
      `host policy approved proposal ${proposed.eventId}`,
      now,
    );
    return { decision: 'approved', reason: 'host policy approved', scenarioSha256, event: approved };
  }

  approvedScenario(scenarioId: string): { scenario: LiveScenario; sha256: string } {
    return readApprovedLiveScenario({
      engagementDir: this.#engagementDir,
      scenarioId,
      profileSha256: this.#profileSha256,
    });
  }

  record(
    type: Exclude<LiveScenarioEventType, 'proposed' | 'approved' | 'rejected'>,
    scenarioId: string,
    reason: string,
    receiptId?: string,
    now = new Date(),
  ): LiveScenarioJournalEvent {
    const { sha256 } = this.approvedScenario(scenarioId);
    return this.#append(type, scenarioId, sha256, reason, now, receiptId);
  }

  readEvents(): LiveScenarioJournalEvent[] {
    return readFileSync(this.path, 'utf8')
      .split(/\r?\n/)
      .filter(Boolean)
      .map((line) => LiveScenarioJournalEventSchema.parse(JSON.parse(line)));
  }

  verify(): LiveScenarioJournalEvent[] {
    return readVerifiedEvents(this.#engagementDir, this.#profileSha256);
  }

  #validatePolicy(scenario: LiveScenario, scenarioSha256: string): string | undefined {
    const events = this.readEvents();
    const approvedEvents = events.filter((event) => event.type === 'approved');
    if (approvedEvents.some((event) => event.scenarioId === scenario.scenarioId)) {
      return `scenarioId가 이미 승인됐다: ${scenario.scenarioId}`;
    }
    if (approvedEvents.some((event) => event.scenarioSha256 === scenarioSha256)) {
      return `동일 scenario가 이미 승인됐다: ${scenario.scenarioId}`;
    }
    const scenarioFingerprint = digest(stableJson({ actorId: scenario.actorId, request: scenario.request }));
    for (const event of approvedEvents) {
      const existing = this.approvedScenario(event.scenarioId).scenario;
      const existingFingerprint = digest(stableJson({ actorId: existing.actorId, request: existing.request }));
      if (existingFingerprint === scenarioFingerprint) return '동일 actor/request fingerprint가 이미 승인됐다';
    }
    if (!this.#profile.actors.some((actor) => actor.actorId === scenario.actorId)) {
      return `profile에 없는 actor다: ${scenario.actorId}`;
    }
    if (!this.#profile.policy.allowedMethods.includes(scenario.request.method)) {
      return `profile에서 허용되지 않은 HTTP method다: ${scenario.request.method}`;
    }
    if (scenario.cleanup && !this.#profile.policy.allowedMethods.includes(scenario.cleanup.request.method)) {
      return `profile에서 허용되지 않은 cleanup HTTP method다: ${scenario.cleanup.request.method}`;
    }
    if (
      scenario.riskClass === 'reversible-state-change' &&
      this.#profile.policy.maximumRiskClass !== 'reversible-state-change'
    ) {
      return 'profile risk class를 초과했다';
    }
    if (scenario.riskClass === 'reversible-state-change' && !scenario.cleanupRequired) {
      return '상태변경 scenario에는 cleanupRequired가 필요하다';
    }
    if (
      scenario.riskClass === 'reversible-state-change' &&
      this.#profile.policy.maxStateChanges === 0
    ) {
      return 'profile이 상태변경을 허용하지 않는다';
    }
    try {
      scopedUrl(new URL(this.#profile.targetBaseUrl), scenario.request.path);
      if (scenario.cleanup) scopedUrl(new URL(this.#profile.targetBaseUrl), scenario.cleanup.request.path);
    } catch (error) {
      return error instanceof Error ? error.message : String(error);
    }
    const allowedHeaders = new Set((this.#profile.policy.allowedRequestHeaders ?? []).map((name) => name.toLowerCase()));
    for (const name of Object.keys(scenario.request.headers ?? {})) {
      const normalized = name.toLowerCase();
      if (normalized === 'authorization' || normalized === 'cookie') {
        return `인증 header는 host만 설정할 수 있다: ${name}`;
      }
      if (!allowedHeaders.has(normalized)) return `profile에서 허용되지 않은 request header다: ${name}`;
    }
    for (const name of Object.keys(scenario.cleanup?.request.headers ?? {})) {
      const normalized = name.toLowerCase();
      if (normalized === 'authorization' || normalized === 'cookie') {
        return `cleanup 인증 header는 host만 설정할 수 있다: ${name}`;
      }
      if (!allowedHeaders.has(normalized)) return `profile에서 허용되지 않은 cleanup header다: ${name}`;
    }
    if (scenario.safety !== 'ready') return 'not-executable scenario는 실행 queue에 승인하지 않는다';
    return undefined;
  }

  #append(
    type: LiveScenarioEventType,
    scenarioId: string,
    scenarioSha256: string,
    reason: string,
    now: Date,
    receiptId?: string,
  ): LiveScenarioJournalEvent {
    const events = this.verify();
    const previousEventSha256 = events.at(-1)?.eventSha256 ?? null;
    const core = LiveScenarioJournalEventCoreSchema.parse({
      schemaVersion: '1.0.0',
      eventId: `JOURNAL-${digest(`${scenarioId}:${type}:${randomBytes(16).toString('hex')}`).slice(0, 20)}`,
      type,
      scenarioId,
      scenarioSha256,
      profileSha256: this.#profileSha256,
      previousEventSha256,
      ...(receiptId ? { receiptId } : {}),
      reason,
      observedAt: now.toISOString(),
    });
    const event = LiveScenarioJournalEventSchema.parse({
      ...core,
      eventSha256: digest(stableJson(core)),
    });
    appendFileSync(this.path, `${JSON.stringify(event)}\n`, { encoding: 'utf8', mode: 0o600 });
    return event;
  }
}

export function readApprovedLiveScenario(input: {
  engagementDir: string;
  scenarioId: string;
  profileSha256?: string;
}): { scenario: LiveScenario; sha256: string } {
  const engagementDir = resolve(input.engagementDir);
  const approved = [...readVerifiedEvents(engagementDir, input.profileSha256)].reverse().find(
    (event) => event.scenarioId === input.scenarioId && event.type === 'approved',
  );
  if (!approved) throw new Error(`승인된 Live DAST scenario가 없다: ${input.scenarioId}`);
  const content = readFileSync(join(engagementDir, SCENARIOS, `${approved.scenarioSha256}.json`));
  const value = JSON.parse(content.toString('utf8')) as unknown;
  if (digest(stableJson(value)) !== approved.scenarioSha256) {
    throw new Error(`Live DAST scenario artifact hash가 다르다: ${input.scenarioId}`);
  }
  const scenario = LiveScenarioSchema.parse(value);
  if (scenario.scenarioId !== input.scenarioId) throw new Error('Live DAST scenario identity가 다르다');
  return { scenario, sha256: approved.scenarioSha256 };
}

function readVerifiedEvents(engagementDir: string, expectedProfileSha256?: string): LiveScenarioJournalEvent[] {
  const events = readFileSync(join(resolve(engagementDir), JOURNAL), 'utf8')
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => LiveScenarioJournalEventSchema.parse(JSON.parse(line)));
  let previous: string | null = null;
  const profileSha256 = expectedProfileSha256 ?? events[0]?.profileSha256;
  for (const event of events) {
    const { eventSha256, ...core } = event;
    if (event.profileSha256 !== profileSha256) throw new Error('Live DAST journal profile binding이 다르다');
    if (event.previousEventSha256 !== previous) throw new Error('Live DAST journal hash chain이 끊겼다');
    if (digest(stableJson(core)) !== eventSha256) throw new Error('Live DAST journal event hash가 다르다');
    previous = eventSha256;
  }
  const scenarioFiles = readdirSync(join(resolve(engagementDir), SCENARIOS));
  if (scenarioFiles.some((name) => !/^[a-f0-9]{64}\.json$/.test(name))) {
    throw new Error('Live DAST scenario directory에 비계약 파일이 있다');
  }
  return events;
}

function scopedUrl(base: URL, candidate: string): URL {
  const url = new URL(candidate, base);
  const normalized = base.pathname.endsWith('/') ? base.pathname : `${base.pathname}/`;
  if (
    url.protocol !== base.protocol ||
    url.hostname !== base.hostname ||
    url.port !== base.port ||
    url.username ||
    url.password ||
    url.hash ||
    !(url.pathname === base.pathname || url.pathname.startsWith(normalized))
  ) {
    throw new Error(`Live DAST target이 승인 범위 밖이다: ${url.toString()}`);
  }
  return url;
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
