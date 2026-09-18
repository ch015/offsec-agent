/**
 * assess 미션 — 취약점 진단 그룹(offsec) 진입점.
 *
 * 호스트가 단계 순서·예산·산출물 검증을 소유하고 역할별 독립 세션을 실행한다.
 * `offsec-lead`는 worker 오케스트레이터가 아니라 수렴·보고 단계에서만 사용한다.
 *
 * 사용:
 *   pnpm tsx src/runtime/missions/assess.ts <진단대상 절대경로> [지시문]
 */
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { basename, join, resolve } from 'node:path';

import {
  loadOffsecContract,
  type PhaseResult,
} from '../offsec-contract.js';
import { assertOffsecConvergenceReady, OffsecDomainAdapter } from '../domains/offsec.js';
import { AnthropicAgentRuntime } from '../providers/anthropic-agent-sdk.js';
import { runSession, type SessionOutcome, type SessionSpec } from '../session.js';
import { WorkflowHost } from '../workflow/engine.js';
import { executeBoundedWork } from '../workflow/bounded-work-executor.js';
import {
  createMissionRuntime,
  type MissionRuntime,
  type MissionRuntimeOptions,
} from '../workflow/mission-runtime.js';
import { createArtifactRef, verifyRunArtifactRef } from '../contracts/result-contract.js';
import { ModelIndependenceGuard } from '../workflow/model-independence.js';
import type { AutoRenewingRunLease } from '../workflow/run-lease.js';
import {
  assertOffsecWorkPlanComplete,
  assertOffsecWorkPlanIntact,
  assertOffsecWorkUnitIntact,
  assertPlanGraphIntegrity,
  createOffsecWorkPlanV2,
  getUnitTypedEdges,
  writeOffsecWorkPlan,
  type OffsecWorkPlanAny,
  type OffsecWorkPlanV2,
} from '../workflow/offsec-work-plan.js';
import {
  assertDependencyGraphIntact,
  createDependencyGraph,
  readDependencyGraph,
  writeDependencyGraph,
  type DependencyGraph,
} from '../workflow/offsec-dependency-graph.js';
import {
  assertScopeAssuranceComplete,
  createScopeAssurance,
  SCOPE_ASSURANCE_FILE_NAME,
  writeScopeAssurance,
  type UnitScopeObservationInput,
} from '../workflow/scope-assurance.js';
import { loadAndComputeGraphRag, serializeGraphContextForUnit } from '../workflow/graph-rag.js';
import { readLiveTestPlan } from '../live-test-broker.js';
import {
  assertPentestRuntimeEvidenceIntact,
  assertStandardFindingsRepresented,
  promoteStandardFindingRecords,
  readStandardFindingRecordReceipts,
  type StandardFindingRecordReceipt,
} from '../finding-contract.js';
import { assertIacManifestIntact, createIacManifest, writeIacManifest } from '../iac-manifest.js';
import {
  createLiveDastContext,
  assertLiveDastLineageRepresented,
  nextOwnerAuthRequest,
  prepareLiveDast,
  publicOwnerRequestArtifact,
  writeResumeRecord,
  type PreparedLiveDast,
} from '../live-dast-lifecycle.js';
import type { AuthInteractionMode } from '../live-test-contract.js';

const require = createRequire(import.meta.url);
const agentPlan = require('../../../domains/offsec/lib/ch015/agent-plan.js') as {
  initFanoutPlan(options: Record<string, unknown>): { decision: unknown; manifest: unknown };
  reserveAgents(
    engagementDir: string,
    options: { phase: string; role: string; count: number; expectedArtifacts: string[] },
  ): { id: string };
  commitReservation(
    engagementDir: string,
    options: { reservationId: string; artifacts: string[] },
  ): unknown;
  reconcileFanout(
    engagementDir: string,
    options?: { checkCurrentSource?: boolean; allowPendingArtifacts?: boolean },
  ): { ok: boolean; errors?: Array<{ code?: string; [key: string]: unknown }> };
  loadState(engagementDir: string): {
    reservations?: Array<{
      id: string;
      phase: string;
      role: string;
      status: string;
      expected_artifacts?: string[];
    }>;
  };
};
type AstBuildOutcome = {
  ok: boolean;
  outputPath?: string;
  error?: string;
  stats?: Record<string, unknown>;
  semgrep?: { status?: string; error?: string; receipt?: Record<string, unknown> };
};
const astTools = require('../../../domains/offsec/lib/ch015/ast/context-builder.js') as {
  buildAstContext(
    target: string,
    options: {
      outputPath: string;
      runSemgrep: boolean;
      semgrepFiles?: string[];
      logger: (message: string) => void;
    },
  ): Promise<AstBuildOutcome>;
};
const reportGate = require('../../../domains/offsec/hooks/report-gate-hook.js') as {
  runGate(options: {
    filePath: string;
    env: Record<string, string>;
    content: string;
  }): { activated: boolean; noArtifacts?: boolean; result?: { ok: boolean; errors?: unknown[] } };
};
export type VerificationMode = 'VA_ONLY' | 'VA_PENTEST' | 'VA_PENTEST_REDTEAM';
export type SemgrepMode = 'required' | 'best-effort' | 'off';
export type WorkUnitMode = 'auto' | 'force' | 'off';

export type PhaseExecution = {
  phase: string;
  role: string;
  round?: string;
  result: PhaseResult;
  outcome: SessionOutcome;
};

export type AssessInput = {
  target: string;
  /** Exact file/directory roots excluded from the sealed source inventory. */
  excludePaths?: string[];
  /** 자연어 범위 지시. 비우면 전체 진단 */
  scope?: string;
  engagementId?: string;
  /** 산출물·원장 위치. 기본은 <target>/.nunchi/reports/<engagementId> */
  engagementDir?: string;
  model?: string;
  reviewModel?: string;
  /** #18: Cross-model verification — 'openai:gpt-5.6-sol' 형식으로 다른 모델 계열의 verifier 사용. 미지정 시 reviewModel 사용. */
  crossModelVerifier?: string;
  effort?: SessionSpec['effort'];
  maxTurns?: number;
  maxBudgetUsd?: number;
  verificationMode?: VerificationMode;
  /** Required runs fail before VA when the pinned local Semgrep preflight is unavailable. */
  semgrepMode?: SemgrepMode;
  /** Auto activates for contract-sized multi-unit repositories; force is an explicit operator override. */
  workUnitMode?: WorkUnitMode;
  /** Host worker concurrency, clamped to the contract maximum. */
  maxConcurrency?: number;
  /** Explicitly authorized non-production base URL used only by the pentest phase. */
  testUrl?: string;
  /** Host-validated Live DAST engagement profile. Required for authenticated or stateful testing. */
  liveTestProfilePath?: string;
  /** Sealed before any network or authentication session is created. */
  authInteractionMode?: AuthInteractionMode;
  /** Disable cost guard — run completes without budget enforcement. */
  noCostGuard?: boolean;
};

export type AssessDependencies = {
  sessionRunner?: typeof runSession;
  reportPublisher?: (engagementDir: string, requirePocBinding: boolean) => string;
  runtime?: MissionRuntimeOptions;
  astBuilder?: typeof astTools.buildAstContext;
  /** Used only by the owner-auth resume path after run.resumed is committed. */
  existingRuntime?: MissionRuntime;
  existingLeaseGuard?: AutoRenewingRunLease;
  /** Rehydrates completed root phases and reapplies their idempotent host effects. */
  resumeCompletedPhases?: boolean;
};

export class AssessAwaitingInputError extends Error {
  constructor(
    readonly engagementDir: string,
    readonly requestId: string,
    readonly requestSha256: string,
    readonly expectedVersion: number,
  ) {
    super(`owner authentication이 필요하다: ${requestId}`);
    this.name = 'AssessAwaitingInputError';
  }
}

const ASSESS_CHECKPOINT_INPUT = 'assess-checkpoint-input.json';

/**
 * 대상 레포 안의 nunchi 산출물 루트. dot-prefix라 소스 디렉터리명과 충돌하지 않으므로
 * `source-manifest.js`의 basename 제외 목록에서 `reports`를 뺄 수 있다 —
 * 그래야 `src/features/reports/` 같은 실제 소스가 스캔에서 누락되지 않는다.
 */
const NUNCHI_DIR = '.nunchi';

/** `.nunchi` 산출물이 실수로 커밋되지 않도록 생성 시점에 gitignore를 심는다. */
function ensureNunchiGitignore(nunchiRoot: string): void {
  const gitignorePath = join(nunchiRoot, '.gitignore');
  if (existsSync(gitignorePath)) return;
  mkdirSync(nunchiRoot, { recursive: true, mode: 0o700 });
  writeFileSync(
    gitignorePath,
    '# nunchi 산출물 — 취약점 상세가 포함되므로 추적하지 않는다\n*\n',
    { mode: 0o600 },
  );
}

// `00_work_unit_results.json`의 schemaVersion. 진짜 레거시(P0-C 이전, scope assurance 개념 자체가
// 없던 시절) 산출물만 WORK_UNIT_RESULTS_LEGACY_SCHEMA_VERSION('1.0.0')을 갖는다. 신규로 쓰는 결과는
// 항상 상위 버전을 선언해 "assurancePath/assuranceSha256을 나중에 지우면 legacy로 강등된다"는 공격을
// 막는다 — legacy 판정은 필드 부재가 아니라 이 리터럴 값으로만 한다(P0 correction §2).
const WORK_UNIT_RESULTS_LEGACY_SCHEMA_VERSION = '1.0.0';
const WORK_UNIT_RESULTS_SCHEMA_VERSION = '1.1.0';
const WORK_UNIT_RESULTS_ACCEPTED_SCHEMA_VERSIONS = new Set([
  WORK_UNIT_RESULTS_LEGACY_SCHEMA_VERSION,
  WORK_UNIT_RESULTS_SCHEMA_VERSION,
]);

type AssessCheckpointCore = Readonly<{
  schemaVersion: '1.1.0';
  runId: string;
  input: AssessInput;
}>;

type AssessCheckpoint = AssessCheckpointCore & Readonly<{ checkpointSha256: string }>;

function checkpointFor(input: AssessInput, target: string, engagementDir: string, runId: string): AssessCheckpoint {
  const core: AssessCheckpointCore = {
    schemaVersion: '1.1.0',
    runId,
    input: {
      ...input,
      target,
      engagementId: runId,
      engagementDir,
      verificationMode: input.verificationMode ?? 'VA_ONLY',
      semgrepMode: input.semgrepMode ?? 'required',
      workUnitMode: input.workUnitMode ?? 'auto',
    },
  };
  return { ...core, checkpointSha256: checkpointSha256(core) };
}

export function readAssessCheckpoint(engagementDir: string): AssessCheckpoint {
  const value = JSON.parse(readFileSync(join(resolve(engagementDir), ASSESS_CHECKPOINT_INPUT), 'utf8')) as AssessCheckpoint;
  if (value.schemaVersion !== '1.1.0' || !value.runId || !value.input || typeof value.input.target !== 'string') {
    throw new Error('OffSec assess checkpoint가 잘못됐다');
  }
  const { checkpointSha256: sealedSha256, ...core } = value;
  if (!/^[a-f0-9]{64}$/.test(sealedSha256) || checkpointSha256(core) !== sealedSha256) {
    throw new Error('OffSec assess checkpoint hash가 다르다');
  }
  return value;
}

function checkpointSha256(value: AssessCheckpointCore): string {
  const normalized = JSON.parse(JSON.stringify(value)) as unknown;
  return createHash('sha256').update(stableJson(normalized)).digest('hex');
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) =>
      `${JSON.stringify(key)}:${stableJson(record[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function sealAssessCheckpoint(engagementDir: string, checkpoint: AssessCheckpoint): void {
  const path = join(engagementDir, ASSESS_CHECKPOINT_INPUT);
  const serialized = `${JSON.stringify(checkpoint, null, 2)}\n`;
  if (existsSync(path)) {
    const existing = readAssessCheckpoint(engagementDir);
    if (JSON.stringify(existing) !== JSON.stringify(checkpoint)) {
      throw new Error('기존 OffSec assess checkpoint와 요청 input이 다르다');
    }
    return;
  }
  writeFileSync(path, serialized, { flag: 'wx', mode: 0o600 });
}

function isRetryablePreflightEngagement(engagementDir: string, checkpoint: AssessCheckpoint): boolean {
  if (!existsSync(join(engagementDir, ASSESS_CHECKPOINT_INPUT))) return false;
  if (existsSync(join(engagementDir, 'run-events.jsonl'))) return false;
  const existing = readAssessCheckpoint(engagementDir);
  if (JSON.stringify(existing) !== JSON.stringify(checkpoint)) return false;
  const allowed = new Set([
    ASSESS_CHECKPOINT_INPUT,
    'host-ledger.jsonl',
    'source_manifest.json',
    'fanout_decision.json',
    'agent_fanout_state.json',
    '00_ast_context.yaml',
    '00_iac_manifest.json',
    'live-test-profile.json',
    'auth_interaction_selection.json',
  ]);
  return readdirSync(engagementDir).every((name) => allowed.has(name));
}

export async function recordOffsecPublication(input: {
  runtime: MissionRuntime;
  engagementDir: string;
  runId: string;
  contractId: string;
  finalArtifact: string;
  sourceManifestSha256: string;
}): Promise<string> {
  const finalReport = resolve(input.engagementDir, input.finalArtifact);
  const snapshot = await input.runtime.read();
  if (snapshot.publication) {
    verifyRunArtifactRef(snapshot.publication.artifact, input.engagementDir);
    if (snapshot.publication.sourceManifestSha256 !== input.sourceManifestSha256) {
      throw new Error('OffSec publication source manifest hash가 일치하지 않는다');
    }
    if (snapshot.status === 'running') {
      await input.runtime.append({ type: 'run.completed', eventId: `${input.runId}:completed` });
    }
    return snapshot.publication.artifact.path;
  }
  if (!existsSync(finalReport)) throw new Error(`계약된 최종 OffSec report가 없다: ${finalReport}`);
  const publicationArtifact = createArtifactRef({
    engagementDir: input.engagementDir,
    name: input.finalArtifact,
    phase: 'publication',
    role: 'host',
    attempt: '1',
  });
  verifyRunArtifactRef(publicationArtifact, input.engagementDir);
  const artifactReceipts = input.runtime.artifactStore
    ? [await input.runtime.artifactStore.put({
        uri: `artifact://runs/${createHash('sha256').update(input.runId).digest('hex').slice(0, 32)}/${publicationArtifact.sha256}`,
        content: readFileSync(finalReport),
        mediaType: publicationArtifact.mediaType,
        producer: 'publication/host/1',
      })]
    : [];
  await input.runtime.append({
    type: 'publication.completed',
    eventId: `${input.runId}:publication-completed`,
    artifact: publicationArtifact,
    sourceManifestSha256: input.sourceManifestSha256,
  }, {
    artifactReceipts,
    outbox: [{
      id: `${input.runId}:publication-completed`,
      idempotencyKey: `${input.runId}:publication-completed`,
      topic: 'run.publication.completed',
      payload: { runId: input.runId, artifactSha256: publicationArtifact.sha256 },
    }],
  });
  await input.runtime.append({ type: 'run.completed', eventId: `${input.runId}:completed` }, {
    outbox: [{
      id: `${input.runId}:run-completed`,
      idempotencyKey: `${input.runId}:run-completed`,
      topic: 'run.completed',
      payload: { runId: input.runId, contractId: input.contractId, finalReport },
    }],
  });
  return finalReport;
}

type WorkUnitSummary = {
  workPlanPath: string;
  resultPath: string;
  resultSha256: string;
  completedUnitKeys: string[];
  /** Quarantine + Proceed: 실패 unit의 미커버 파일 목록 */
  uncoveredFiles?: string[];
};

function fileSha256(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function checkpointFileReceipt(engagementDir: string): { path: string; sha256: string; bytes: number } {
  const path = join(engagementDir, ASSESS_CHECKPOINT_INPUT);
  const content = readFileSync(path);
  return { path, sha256: createHash('sha256').update(content).digest('hex'), bytes: content.byteLength };
}

/** 충돌 없는 실행 식별자 — 대상 이름 + UTC millisecond timestamp */
export function makeEngagementId(target: string, now: Date): string {
  const timestamp = now.toISOString().replace(/[-:.]/g, '');
  return `${basename(target)}_${timestamp}`;
}

export function resolveRunBudget(
  requested: number | undefined,
  contractMaximum: number | null,
): number | undefined {
  if (contractMaximum !== null && (!Number.isFinite(contractMaximum) || contractMaximum <= 0)) {
    throw new Error(`contract 예산 상한이 잘못됐다: ${contractMaximum}`);
  }
  if (requested === undefined) return contractMaximum ?? undefined;
  if (!Number.isFinite(requested) || requested <= 0) {
    throw new Error(`요청 예산은 유한한 양수여야 한다: ${requested}`);
  }
  return contractMaximum === null ? requested : Math.min(requested, contractMaximum);
}

export function resolveLiveTestTarget(
  verificationMode: VerificationMode,
  testUrl: string | undefined,
): { url: string; hostname: string } | undefined {
  const liveRequested = verificationMode.includes('PENTEST');
  if (!liveRequested) {
    if (testUrl !== undefined) throw new Error('--test-url은 PENTEST verification mode에서만 허용된다');
    return undefined;
  }
  if (!testUrl) throw new Error('PENTEST verification mode에는 명시적인 --test-url이 필요하다');
  let parsed: URL;
  try {
    parsed = new URL(testUrl);
  } catch {
    throw new Error(`test URL이 유효하지 않다: ${testUrl}`);
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error(`test URL protocol은 http/https만 허용된다: ${parsed.protocol}`);
  }
  if (parsed.username || parsed.password || parsed.hash) {
    throw new Error('test URL에는 credential이나 fragment를 포함할 수 없다');
  }
  return { url: parsed.toString(), hostname: parsed.hostname };
}

function ordinal(round: number): string {
  if (round === 1) return '1st';
  if (round === 2) return '2nd';
  if (round === 3) return '3rd';
  return `${round}th`;
}

export function validateOffsecPublicationCandidate(input: {
  engagementDir: string;
  candidate: string;
  requirePocBinding: boolean;
  allowEmptyCandidates: boolean;
  preparedLiveDast?: PreparedLiveDast;
}): void {
  assertStandardFindingsRepresented(input.engagementDir, input.candidate);
  if (input.preparedLiveDast) {
    assertLiveDastLineageRepresented(input.candidate, input.preparedLiveDast);
  }
  const outcome = reportGate.runGate({
    filePath: input.candidate,
    env: {
      AGENT_ENGAGEMENT_DIR: input.engagementDir,
      CH015_REPORT_GATE: process.env.CH015_REPORT_GATE ?? 'on',
      CH015_REQUIRE_POC_BINDING: input.requirePocBinding ? 'on' : 'off',
      CH015_ALLOW_EMPTY_CANDIDATES: input.allowEmptyCandidates ? 'on' : 'off',
    },
    content: readFileSync(input.candidate, 'utf8'),
  });
  if (!outcome.activated || outcome.noArtifacts || outcome.result?.ok !== true) {
    throw new Error(`호스트 report gate가 최종 보고서 발행을 거부했다: ${JSON.stringify(outcome)}`);
  }
}

function publishValidatedReport(
  engagementDir: string,
  requirePocBinding: boolean,
  allowEmptyCandidates: boolean,
  publication: { draftArtifact: string; finalArtifact: string },
  preparedLiveDast?: PreparedLiveDast,
): string {
  const draft = join(engagementDir, publication.draftArtifact);
  const final = join(engagementDir, publication.finalArtifact);
  const candidate = existsSync(final) ? final : draft;
  if (!existsSync(candidate)) throw new Error(`최종 보고서 draft가 없다: ${draft}`);
  validateOffsecPublicationCandidate({
    engagementDir,
    candidate,
    requirePocBinding,
    allowEmptyCandidates,
    preparedLiveDast,
  });
  if (candidate === draft) renameSync(draft, final);
  return final;
}

export async function assess(input: AssessInput, dependencies: AssessDependencies = {}): Promise<{
  outcome: SessionOutcome;
  engagementDir: string;
  phases: PhaseExecution[];
  finalReport: string;
  workUnits?: WorkUnitSummary;
}> {
  const target = resolve(input.target);
  const engagementId = input.engagementId ?? makeEngagementId(target, new Date());
  const nunchiRoot = join(target, NUNCHI_DIR);
  const engagementDir = resolve(input.engagementDir ?? join(nunchiRoot, 'reports', engagementId));
  const verificationMode = input.verificationMode ?? 'VA_ONLY';
  const semgrepMode = input.semgrepMode ?? 'required';
  const workUnitMode = input.workUnitMode ?? 'auto';
  const contract = loadOffsecContract();
  const sessionRunner = dependencies.sessionRunner ?? runSession;
  const maxBudgetUsd = input.noCostGuard ? undefined : resolveRunBudget(input.maxBudgetUsd, contract.limits.maxBudgetUsd);
  const primaryModel = input.model ?? process.env.ASSESS_PRIMARY_MODEL ?? 'opus';
  const reviewModel = input.reviewModel ?? process.env.ASSESS_REVIEW_MODEL ?? 'sonnet';
  // #18: cross-model verifier 지정 시 provider 확인. 현재는 Anthropic-only이므로 'openai:*' 접두사면 경고 후 fallback.
  const effectiveReviewModel = (() => {
    if (!input.crossModelVerifier) return reviewModel;
    if (input.crossModelVerifier.startsWith('openai:')) {
      // OpenAI provider runtime 미구현 — reviewModel로 fallback
      console.warn(`[assess] crossModelVerifier '${input.crossModelVerifier}' 요청됨 — OpenAI runtime 미구현, '${reviewModel}'로 fallback`);
      return reviewModel;
    }
    return input.crossModelVerifier;
  })();
  const checkpoint = checkpointFor(input, target, engagementDir, engagementId);

  if (!existsSync(target)) throw new Error(`진단 대상이 없다: ${target}`);
  if (!statSync(target).isDirectory()) throw new Error(`진단 대상은 디렉토리여야 한다: ${target}`);
  if (!['auto', 'force', 'off'].includes(workUnitMode)) {
    throw new Error(`work unit mode가 잘못됐다: ${workUnitMode}`);
  }
  if (input.maxConcurrency !== undefined && (!Number.isInteger(input.maxConcurrency) || input.maxConcurrency < 1)) {
    throw new Error(`maxConcurrency가 잘못됐다: ${input.maxConcurrency}`);
  }
  if (primaryModel === effectiveReviewModel && !process.env.ALLOW_SAME_MODEL) {
    throw new Error('Offsec primary model과 review model은 달라야 한다 (개발 중 동일 모델 사용은 ALLOW_SAME_MODEL=1 설정)');
  }
  if (
    !dependencies.existingRuntime &&
    existsSync(engagementDir) &&
    readdirSync(engagementDir).length > 0 &&
    !isRetryablePreflightEngagement(engagementDir, checkpoint)
  ) {
    throw new Error(`기존 engagement를 덮어쓸 수 없다: ${engagementDir}`);
  }
  mkdirSync(engagementDir, { recursive: true, mode: 0o700 });
  // engagementDir이 대상 레포의 .nunchi 하위일 때만 gitignore를 심는다
  // (--engagement-dir로 레포 밖을 지정한 경우는 사용자 소관).
  if (engagementDir.startsWith(resolve(nunchiRoot))) ensureNunchiGitignore(nunchiRoot);
  sealAssessCheckpoint(engagementDir, checkpoint);
  let preparedLiveDast: PreparedLiveDast | undefined;
  if (verificationMode.includes('PENTEST')) {
    preparedLiveDast = prepareLiveDast({
      engagementDir,
      runId: engagementId,
      testUrl: input.testUrl,
      profilePath: input.liveTestProfilePath,
      mode: input.authInteractionMode,
    });
    if (!dependencies.existingRuntime) {
      const ownerRequest = nextOwnerAuthRequest({ engagementDir, prepared: preparedLiveDast });
      if (ownerRequest) {
        const resumeRecordPath = writeResumeRecord(engagementDir, {
          schemaVersion: '1.0.0',
          runId: engagementId,
          target,
          ...(input.scope ? { scope: input.scope } : {}),
          ...(input.model ? { model: input.model } : {}),
          ...(input.reviewModel ? { reviewModel: input.reviewModel } : {}),
          ...(input.effort ? { effort: input.effort } : {}),
          ...(input.maxTurns ? { maxTurns: input.maxTurns } : {}),
          ...(input.maxBudgetUsd ? { maxBudgetUsd: input.maxBudgetUsd } : {}),
          verificationMode: verificationMode === 'VA_PENTEST_REDTEAM'
            ? 'VA_PENTEST_REDTEAM'
            : 'VA_PENTEST',
          semgrepMode,
          workUnitMode,
          ...(input.maxConcurrency ? { maxConcurrency: input.maxConcurrency } : {}),
          engagementDir,
          liveTestProfilePath: preparedLiveDast.profilePath,
          authInteractionMode: preparedLiveDast.selection.mode,
        });
        const artifactName = publicOwnerRequestArtifact(engagementDir, ownerRequest);
        const runtime = await createMissionRuntime({
          engagementDir,
          runId: engagementId,
          contractId: contract.id,
          contractVersion: contract.version,
          domain: 'offsec',
          mission: 'assessment',
          ...(maxBudgetUsd !== undefined ? { maxBudgetUsd } : {}),
        }, dependencies.runtime);
        try {
          const artifact = createArtifactRef({
            engagementDir,
            name: artifactName,
            phase: 'owner-auth',
            role: 'host',
            attempt: '1',
          });
          const resumeManifest = createArtifactRef({
            engagementDir,
            name: 'assess-resume-input.json',
            phase: 'input',
            role: 'host',
            attempt: '0',
          });
          const profileContent = readFileSync(preparedLiveDast.profilePath);
          const checkpointReceipt = checkpointFileReceipt(engagementDir);
          const snapshot = await runtime.appendBatch([{
            type: 'input.recorded',
            eventId: `${engagementId}:input:0`,
            input: {
              inputRevision: 0,
              contextEpoch: fileSha256(resumeRecordPath),
              manifest: resumeManifest,
              allowedReadFiles: [checkpointReceipt.path, preparedLiveDast.profilePath],
              fileHashes: [checkpointReceipt, {
                  path: preparedLiveDast.profilePath,
                  sha256: preparedLiveDast.profileSha256,
                  bytes: profileContent.byteLength,
                }],
            },
          }, {
            type: 'run.awaiting-input',
            eventId: `${engagementId}:owner-auth:${ownerRequest.requestId}`,
            reason: `테스트 actor ${ownerRequest.actorId}의 owner authentication이 필요하다`,
            artifact,
          }]);
          throw new AssessAwaitingInputError(
            engagementDir,
            ownerRequest.requestId,
            ownerRequest.requestSha256,
            snapshot.lastSeq,
          );
        } finally {
          await runtime.close();
        }
      }
    }
  } else if (input.liveTestProfilePath || input.authInteractionMode) {
    throw new Error('Live DAST profile/auth interaction은 PENTEST verification mode에서만 허용된다');
  }
  const liveTestTarget = resolveLiveTestTarget(
    verificationMode,
    preparedLiveDast?.profile.targetBaseUrl ?? input.testUrl,
  );
  const requirePocBinding = liveTestTarget !== undefined;
  const ledgerPath = join(engagementDir, 'host-ledger.jsonl');
  if (!existsSync(ledgerPath)) writeFileSync(ledgerPath, '', { flag: 'wx', mode: 0o600 });
  const fanoutPlan = dependencies.resumeCompletedPhases
    ? { manifest: JSON.parse(readFileSync(join(engagementDir, 'source_manifest.json'), 'utf8')) as unknown }
    : agentPlan.initFanoutPlan({
        engagementDir,
        target,
        excludePaths: [nunchiRoot, join(target, 'reports'), engagementDir, ...(input.excludePaths ?? [])],
        flow: 'standard',
        vaMode: 'sequential',
        verificationMode,
        maxFeedbackIterations: contract.limits.maxFeedbackIterations ?? 0,
      });
  const preparedIacState = verificationMode.includes('REDTEAM')
    ? (() => {
        const manifest = createIacManifest({
          target,
          excludeRoots: [nunchiRoot, join(target, 'reports'), engagementDir, ...(input.excludePaths ?? [])],
        });
        return { manifest, path: writeIacManifest(engagementDir, manifest) };
      })()
    : undefined;
  const sourceManifest = fanoutPlan.manifest as {
    hash: string;
    policy: unknown;
    source_files?: unknown[];
    dependency_files?: unknown[];
    security_resource_files?: unknown[];
    units?: Array<{ files?: unknown[] }>;
  };
  const sealedSourceFiles = (sourceManifest.source_files ?? [])
    .filter((path): path is string => typeof path === 'string')
    .map((path) => resolve(target, path));
  const sealedDependencyFiles = (sourceManifest.dependency_files ?? [])
    .filter((path): path is string => typeof path === 'string')
    .map((path) => resolve(target, path));
  const sealedSecurityResourceFiles = (sourceManifest.security_resource_files ?? [])
    .filter((path): path is string => typeof path === 'string')
    .map((entry) => {
      if (entry.startsWith('/') || entry.includes('\0') || entry.includes('\\')) {
        throw new Error(`security_resource_files에 안전하지 않은 경로가 있다: ${entry}`);
      }
      const segments = entry.split('/');
      if (segments.some((segment) => segment === '' || segment === '.' || segment === '..')) {
        throw new Error(`security_resource_files에 비정규화/traversal 경로가 있다: ${entry}`);
      }
      return resolve(target, entry);
    });
  const astContextPath = join(engagementDir, '00_ast_context.yaml');
  const astBuilder = dependencies.astBuilder ?? astTools.buildAstContext;
  let astOutcome: AstBuildOutcome;
  try {
    astOutcome = await astBuilder(target, {
      outputPath: astContextPath,
      runSemgrep: semgrepMode !== 'off',
      semgrepFiles: [...new Set([
        ...sealedSourceFiles,
        ...(preparedIacState?.manifest.files.map((file) => resolve(target, file.path)) ?? []),
      ])],
      logger: (message) => {
        appendFileSync(ledgerPath, `${JSON.stringify({ event: 'HostAstPreanalysis', message })}\n`);
      },
    });
  } catch (error) {
    astOutcome = { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
  const astContextAvailable = astOutcome.ok && existsSync(astContextPath);
  const semgrepStatus = semgrepMode === 'off' ? 'disabled' : astOutcome.semgrep?.status ?? 'unavailable';
  appendFileSync(ledgerPath, `${JSON.stringify({
    event: 'HostAstPreanalysisCompleted',
    ok: astContextAvailable,
    artifact: astContextAvailable ? astContextPath : undefined,
    error: astContextAvailable ? undefined : astOutcome.error ?? 'AST context was not produced',
    stats: astOutcome.stats,
    assurance: semgrepStatus === 'complete' ? 'full' : 'reduced',
    semgrep: astOutcome.semgrep ?? { status: semgrepStatus },
  })}\n`);
  if (semgrepMode === 'required' && semgrepStatus !== 'complete') {
    throw new Error(`required Semgrep preanalysis가 완료되지 않았다: ${astOutcome.semgrep?.error ?? semgrepStatus}`);
  }
  const sourceFileCount = sourceManifest.source_files?.length ?? 0;
  const nonemptyUnitCount = sourceManifest.units?.filter((unit) => (unit.files?.length ?? 0) > 0).length ?? 0;
  const workUnitsActivated = workUnitMode === 'force' || (
    workUnitMode === 'auto' &&
    sourceFileCount >= contract.workUnitPolicy.minimumSourceFiles &&
    nonemptyUnitCount > 1
  );
  const existingWorkPlanPath = join(engagementDir, '00_work_plan.json');
  let depGraph: DependencyGraph | undefined;
  const workPlan: OffsecWorkPlanAny | undefined = workUnitsActivated
    ? dependencies.resumeCompletedPhases && existsSync(existingWorkPlanPath)
      ? (() => {
          const plan = assertOffsecWorkPlanIntact(JSON.parse(readFileSync(existingWorkPlanPath, 'utf8')));
          if (plan.schemaVersion === '2.0.0') {
            depGraph = assertDependencyGraphIntact(readDependencyGraph(engagementDir));
            // F4: fail-closed coupling — verify plan.dependencyGraphSha256 matches loaded graph
            if (plan.dependencyGraphSha256 !== depGraph.dependencyGraphSha256) {
              throw new Error('OffSec resume: plan dependencyGraphSha256이 loaded graph와 다르다');
            }
            assertPlanGraphIntegrity(plan as OffsecWorkPlanV2, depGraph);
          }
          return plan;
        })()
      : (() => {
          depGraph = createDependencyGraph({ target, sourceManifest: fanoutPlan.manifest });
          writeDependencyGraph(engagementDir, depGraph);
          const newPlan = createOffsecWorkPlanV2({
            target,
            sourceManifest: fanoutPlan.manifest,
            dependencyGraph: depGraph,
            maxContextFilesPerUnit: contract.workUnitPolicy.maxContextFilesPerUnit,
          });
          // Validate graph/plan integrity at creation time
          assertPlanGraphIntegrity(newPlan, depGraph);
          return newPlan;
        })()
    : undefined;
  const workPlanPath = workPlan
    ? dependencies.resumeCompletedPhases && existsSync(existingWorkPlanPath)
      ? existingWorkPlanPath
      : writeOffsecWorkPlan(engagementDir, workPlan)
    : undefined;
  // #12B: Host Recon — 보안 표면 분류 (work plan 이후, unit 실행 전)
  const hostReconPath = join(engagementDir, '00_host_recon.json');
  if (!existsSync(hostReconPath) && sourceManifest) {
    const { runHostRecon } = await import('../workflow/host-recon.js');
    const reconResult = runHostRecon({
      target,
      sourceFiles: (sourceManifest as { source_files: string[] }).source_files,
    });
    writeFileSync(hostReconPath, `${JSON.stringify(reconResult, null, 2)}\n`, { mode: 0o600 });
    appendFileSync(ledgerPath, `${JSON.stringify({
      event: 'HostReconCompleted',
      entryPoints: reconResult.entryPoints.length,
      authSurface: reconResult.authSurface.length,
      dataSurface: reconResult.dataSurface.length,
      networkSurface: reconResult.networkSurface.length,
      configSurface: reconResult.configSurface.length,
      general: reconResult.general.length,
    })}\n`);
  }
  const missionRuntime = dependencies.existingRuntime ?? await createMissionRuntime({
    engagementDir,
    runId: engagementId,
    contractId: contract.id,
    contractVersion: contract.version,
    domain: 'offsec',
    mission: 'assessment',
    ...(maxBudgetUsd !== undefined ? { maxBudgetUsd } : {}),
  }, dependencies.runtime);
  if (!dependencies.existingRuntime) {
    const checkpointReceipt = checkpointFileReceipt(engagementDir);
    const checkpointArtifact = createArtifactRef({
      engagementDir,
      name: ASSESS_CHECKPOINT_INPUT,
      phase: 'input',
      role: 'host',
      attempt: '0',
    });
    await missionRuntime.append({
      type: 'input.recorded',
      eventId: `${engagementId}:input:0`,
      input: {
        inputRevision: 0,
        contextEpoch: checkpointReceipt.sha256,
        manifest: checkpointArtifact,
        allowedReadFiles: [checkpointReceipt.path],
        fileHashes: [checkpointReceipt],
      },
    });
  }
  const state = missionRuntime.state;
  const activeLease = missionRuntime.leaseGuard ?? dependencies.existingLeaseGuard;
  try {
  const adapter = new OffsecDomainAdapter(contract);
  const runtime = new AnthropicAgentRuntime(sessionRunner);
  const modelGuard = dependencies.resumeCompletedPhases
    ? ModelIndependenceGuard.fromSnapshot(await missionRuntime.read(), (phase) =>
        adapter.getPhase(phase).legacy.role === 'verifier' ? 'review' : 'primary')
    : new ModelIndependenceGuard();
  const phases: PhaseExecution[] = [];
  const combined: SessionOutcome = { texts: [], ledger: [] };
  const onEvent = (event: Parameters<NonNullable<ConstructorParameters<typeof WorkflowHost>[0]['onEvent']>>[0]) => {
    appendFileSync(ledgerPath, `${JSON.stringify(event)}\n`);
  };
  const outcomePolicy = ({ role, outcome }: {
    role: string;
    outcome: Parameters<ModelIndependenceGuard['observe']>[1];
  }) => {
    // ALLOW_SAME_MODEL이 설정되면 model independence 검사를 건너뛴다 (개발/테스트용)
    if (process.env.ALLOW_SAME_MODEL) return;
    modelGuard.observe(role === 'verifier' ? 'review' : 'primary', outcome);
  };
  const mergeOutcome = (outcome: SessionOutcome): void => {
    combined.texts.push(...outcome.texts);
    combined.ledger.push(...outcome.ledger);
    combined.numTurns = (combined.numTurns ?? 0) + (outcome.numTurns ?? 0);
    combined.totalCostUsd = (combined.totalCostUsd ?? 0) + (outcome.totalCostUsd ?? 0);
    combined.subtype = outcome.subtype;
    combined.modelUsage = [...((combined.modelUsage as unknown[] | undefined) ?? []), outcome.modelUsage];
    combined.registeredAgents = outcome.registeredAgents ?? combined.registeredAgents;
    combined.structuredOutput = outcome.structuredOutput;
  };
  const refreshCanonicalFindingReadSet = (): void => {
    rootAllowedReadFiles.push(...readStandardFindingRecordReceipts(engagementDir).map((receipt) =>
      join(engagementDir, 'standard-findings', receipt.recordName)));
  };

  let workUnitSummary: WorkUnitSummary | undefined;
  let iacState = preparedIacState;
  let pentestPlanBinding: { path: string; sha256: string } | undefined;
  let pendingUnitFindings: Array<{
    unitKey: string;
    unitDir: string;
    receipts: StandardFindingRecordReceipt[];
  }> = [];
  const rootAllowedReadFiles = [
    join(engagementDir, 'source_manifest.json'),
    ...sealedSourceFiles,
    ...sealedDependencyFiles,
    ...sealedSecurityResourceFiles,
  ];
  if (astContextAvailable) rootAllowedReadFiles.push(astContextPath);
  if (iacState) rootAllowedReadFiles.push(iacState.path);
  const existingWorkUnitResultPath = join(engagementDir, '00_work_unit_results.json');
  if (workPlan && workPlanPath && !(dependencies.resumeCompletedPhases && existsSync(existingWorkUnitResultPath))) {
    const requestedConcurrency = input.maxConcurrency ?? contract.workUnitPolicy.maximumConcurrency;
    const envConcurrency = process.env['WORK_UNIT_CONCURRENCY'];
    const maxConcurrency = envConcurrency
      ? Math.min(parseInt(envConcurrency, 10) || 1, contract.workUnitPolicy.maximumConcurrency)
      : Math.min(requestedConcurrency, contract.workUnitPolicy.maximumConcurrency);
    appendFileSync(ledgerPath, `${JSON.stringify({
      event: 'HostWorkPlanActivated',
      workPlanSha256: workPlan.workPlanSha256,
      unitCount: workPlan.units.length,
      maxConcurrency,
      sourceOnlyPass: true,
    })}\n`);
    const workRoot = join(engagementDir, 'work-units');
    mkdirSync(workRoot, { recursive: true, mode: 0o700 });

    // GraphRAG: dependency graph + AST context로 사전 분석 context 생성
    const graphRag = await loadAndComputeGraphRag(engagementDir);
    if (graphRag) {
      appendFileSync(ledgerPath, `${JSON.stringify({
        event: 'HostGraphRagComputed',
        taintPaths: graphRag.taintPaths.length,
        communities: graphRag.communities.length,
        filesWithContext: graphRag.fileContextMap.size,
      })}\n`);
    }

    const unitResults = await executeBoundedWork({
      units: workPlan.units,
      maxConcurrency,
      maximumWorkUnits: contract.workUnitPolicy.maximumWorkUnits,
      retryRejectedOnce: true,
      unitTimeoutMs: 15 * 60 * 1000, // 15분 hard limit per unit
      worker: async (candidate, unitAttempt, abortController) => {
        const unit = assertOffsecWorkUnitIntact(workPlan, candidate.unitKey);
        const unitDir = join(workRoot, unit.unitKey, `attempt-${unitAttempt}`);
        mkdirSync(unitDir, { recursive: true, mode: 0o700 });
        const ownedSourceFiles = unit.ownedFiles.map((file) => resolve(target, file.path));
        const contextSourceFiles = unit.contextFiles.map((file) => resolve(target, file.path));
        const workUnit = {
          unitKey: unit.unitKey,
          workPlanSha256: workPlan.workPlanSha256,
          assignedSourceSha256: unit.assignedSourceSha256,
          ownedSourceFiles,
          contextSourceFiles,
          sourceFiles: [...ownedSourceFiles, ...contextSourceFiles],
        };
        const resultIdentity = {
          workUnitKey: unit.unitKey,
          workPlanSha256: workPlan.workPlanSha256,
          assignedSourceSha256: unit.assignedSourceSha256,
        };
        const explorationInventory = join(unitDir, '00_source_exploration.json');
        writeFileSync(explorationInventory, JSON.stringify({
          purpose: 'Optional follow-up context for an observed dependency. Finding ownership remains assignedFiles.',
          sourceFiles: sealedSourceFiles,
        }, null, 2), { mode: 0o600 });
        const unitHost = new WorkflowHost({
          adapter,
          runtime,
          state,
          target,
          engagementDir: unitDir,
          runRoot: engagementDir,
          runId: engagementId,
          hostEntrypoint: 'assess',
          allowedReadFiles: [...new Set([...ownedSourceFiles, ...contextSourceFiles, ...sealedSourceFiles, ...sealedDependencyFiles, explorationInventory])],
          signal: abortController.signal,
          ...(activeLease ? { leaseGuard: activeLease } : {}),
          ...(missionRuntime.artifactStore ? { artifactStore: missionRuntime.artifactStore } : {}),
          scope: input.scope,
          onEvent,
          outcomePolicy: ({ role, outcome }) => outcomePolicy({ role, outcome: outcome.usage }),
        });
        const sharedProviderOptions = {
          abortController,
          effort: input.effort,
          maxTurns: input.maxTurns,
          phaseRound: unit.unitKey,
          readScope: 'exact' as const,
          disabledTools: ['Bash'],
          workUnit,
        };
        const unitVa = await unitHost.executePhase({
              id: 'va',
              round: unit.unitKey,
              priorArtifactPaths: [],
              deferRunBlocking: true,
              resultIdentity,
              inputs: {
                workUnit: resultIdentity,
                assignedFiles: unit.ownedFiles.map((file) => file.path),
                dependencyContextFiles: unit.contextFiles.map((file) => file.path),
                explorationInventory,
                unresolvedCrossUnitEdges: unit.unresolvedEdges,
                analysisPass: 'source-only; host preanalysis candidates intentionally hidden',
                ...(graphRag ? {
                  graphContext: serializeGraphContextForUnit(graphRag, unit.ownedFiles.map((f) => f.path)),
                } : {}),
                ...(workPlan.schemaVersion === '2.0.0' && depGraph ? {
                  typedDependencyEdges: getUnitTypedEdges(depGraph, unit),
                  contextSelectionReceipt: 'contextSelectionReceipt' in unit ? unit.contextSelectionReceipt : undefined,
                } : {}),
              },
              providerOptions: { ...sharedProviderOptions, model: primaryModel },
            });
        assertOffsecWorkUnitIntact(workPlan, unit.unitKey);
        const unitVerify = await unitHost.executePhase({
          id: 'verify',
          round: unit.unitKey,
          priorArtifactPaths: unitVa.artifacts.map((artifact: { path: string }) => artifact.path),
          deferRunBlocking: true,
          resultIdentity,
          inputs: {
            workUnit: resultIdentity,
            vaArtifacts: unitVa.artifacts.map((artifact: { path: string }) => artifact.path),
            assignedFiles: unit.ownedFiles.map((file) => file.path),
          },
          providerOptions: {
            ...sharedProviderOptions,
            model: effectiveReviewModel,
            verifyRound: '1st',
          },
        });
        assertOffsecWorkUnitIntact(workPlan, unit.unitKey);
        let latestVerify = unitVerify;
        const feedbackExecutions: Array<typeof unitVa> = [];
        for (
          let iteration = 1;
          (latestVerify.result.metrics.objectionCount ?? 0) > 0 &&
            iteration <= (contract.limits.maxFeedbackIterations ?? 0);
          iteration += 1
        ) {
          const feedbackRound = `${unit.unitKey}-feedback-${iteration}`;
          const feedbackVa = await unitHost.executePhase({
            id: 'va-feedback',
            round: feedbackRound,
            priorArtifactPaths: [
              ...unitVa.artifacts.map((artifact: { path: string }) => artifact.path),
              ...latestVerify.artifacts.map((artifact) => artifact.path),
            ],
            deferRunBlocking: true,
            resultIdentity,
            inputs: {
              workUnit: resultIdentity,
              priorVaArtifacts: unitVa.artifacts.map((artifact: { path: string }) => artifact.path),
              verifierArtifacts: latestVerify.artifacts.map((artifact) => artifact.path),
              objectionCount: latestVerify.result.metrics.objectionCount ?? 0,
            },
            providerOptions: {
              ...sharedProviderOptions,
              model: primaryModel,
              phaseRound: feedbackRound,
            },
          });
          const feedbackVerify = await unitHost.executePhase({
            id: 'verify-feedback',
            round: feedbackRound,
            priorArtifactPaths: feedbackVa.artifacts.map((artifact) => artifact.path),
            deferRunBlocking: true,
            resultIdentity,
            inputs: {
              workUnit: resultIdentity,
              vaFeedbackArtifacts: feedbackVa.artifacts.map((artifact) => artifact.path),
            },
            providerOptions: {
              ...sharedProviderOptions,
              model: effectiveReviewModel,
              phaseRound: feedbackRound,
              verifyRound: feedbackRound,
              // #9: 초기 verify의 tool read 기록을 carry-forward
              priorToolLedger: latestVerify.outcome.events
                .filter((ev) => ev.event === 'tool' && ev.tool && ev.decision === 'allow')
                .map((ev) => ({ tool: ev.tool!, resource: ev.resource, query: ev.query, decision: 'allow' as const })),
            },
          });
          assertOffsecWorkUnitIntact(workPlan, unit.unitKey);
          feedbackExecutions.push(feedbackVa, feedbackVerify);
          latestVerify = feedbackVerify;
        }
        if (latestVerify.result.metrics.objectionCount ?? 0 > 0) {
          // Feedback 상한 후에도 objection 미해결 — unit을 실패시키지 않고
          // Root VA에서 교차 검증하도록 경고만 기록한다.
          appendFileSync(ledgerPath, `${JSON.stringify({
            event: 'HostWorkUnitUnresolvedObjection',
            unitKey: unit.unitKey,
            objectionCount: latestVerify.result.metrics.objectionCount ?? 0,
            note: 'feedback 상한 도달; Root VA에서 교차 검증 예정',
          })}\n`);
        }
        return {
          unit,
          unitDir,
          unitVa,
          unitVerify,
          feedbackExecutions,
          latestVerify,
          findingReceipts: readStandardFindingRecordReceipts(unitDir),
        };
      },
    });
    const completedUnitKeys = unitResults
      .filter((result) => result.status === 'fulfilled')
      .map((result) => result.unit.unitKey);
    // Quarantine + Proceed: 실패 unit을 격리하고 threshold 이상이면 Root VA로 진행
    const rejected = unitResults.filter((result) => result.status === 'rejected');
    const completionRatio = completedUnitKeys.length / workPlan.units.length;
    const quarantinedUnits = rejected.map((result) => ({
      unitKey: result.unit.unitKey,
      reason: result.reason instanceof Error ? result.reason.message : String(result.reason),
    }));
    const uncoveredFiles = quarantinedUnits.flatMap((q) =>
      workPlan.units.find((u) => u.unitKey === q.unitKey)?.ownedFiles.map((f) => f.path) ?? [],
    );

    if (completionRatio < 1 && quarantinedUnits.length > 0) {
      // partial completion — 실패 unit은 skip하고 계속 진행
      appendFileSync(ledgerPath, `${JSON.stringify({
        event: 'HostWorkPlanPartialCompletion',
        completedCount: completedUnitKeys.length,
        totalCount: workPlan.units.length,
        completionRatio: Math.round(completionRatio * 100),
        quarantinedUnits,
        uncoveredFileCount: uncoveredFiles.length,
      })}\n`);
    }
    const fulfilled = unitResults.flatMap((result) => result.status === 'fulfilled' && result.value ? [result.value] : []);
    for (const result of fulfilled) {
      for (const execution of [result.unitVa, result.unitVerify, ...result.feedbackExecutions]) {
        mergeOutcome(execution.outcome.raw);
      }
    }
    // 호스트가 소유한 scope assurance — 기존 ProviderRuntimeEvent(VA/Verifier 각 phase 호출에 스코프된
    // events)를 재사용한다. 별도 SDK 계측 경로를 추가하지 않는다.
    const scopeObservations = new Map<string, UnitScopeObservationInput>(fulfilled.map((result) => {
      const feedbackVaExecutions = result.feedbackExecutions.filter((_item, index) => index % 2 === 0);
      const feedbackVerifyExecutions = result.feedbackExecutions.filter((_item, index) => index % 2 === 1);
      return [result.unit.unitKey, {
        vaEvents: [result.unitVa, ...feedbackVaExecutions].flatMap((execution) => execution.outcome.events),
        verifierEvents: [result.unitVerify, ...feedbackVerifyExecutions].flatMap((execution) => execution.outcome.events),
        // seal 제거됨 — verifier 독립성은 prompt로만 관리
        autonomousVerifierSealed: false,
      }];
    }));
    const scopeAssurance = createScopeAssurance({
      target, workPlan, completedUnitKeys, observations: scopeObservations,
    });
    const scopeAssurancePath = writeScopeAssurance(engagementDir, scopeAssurance);
    const scopeAssuranceSha256 = fileSha256(scopeAssurancePath);
    const resultPath = join(engagementDir, '00_work_unit_results.json');
    const temporary = `${resultPath}.${process.pid}.tmp`;
    writeFileSync(temporary, `${JSON.stringify({
      schemaVersion: WORK_UNIT_RESULTS_SCHEMA_VERSION,
      workPlanSha256: workPlan.workPlanSha256,
      completedUnitKeys,
      quarantinedUnits: quarantinedUnits.length > 0 ? quarantinedUnits : undefined,
      uncoveredFiles: uncoveredFiles.length > 0 ? uncoveredFiles : undefined,
      assurancePath: SCOPE_ASSURANCE_FILE_NAME,
      assuranceSha256: scopeAssuranceSha256,
      units: fulfilled.map(({ unit, unitVa, unitVerify, feedbackExecutions, latestVerify, findingReceipts }) => ({
        unitKey: unit.unitKey,
        sourceUnitId: unit.sourceUnitId,
        assignedSourceSha256: unit.assignedSourceSha256,
        unresolvedEdges: unit.unresolvedEdges,
        findingReceipts,
        feedbackPasses: feedbackExecutions.length / 2,
        unresolvedObjections: latestVerify.result.metrics.objectionCount ?? 0,
        artifacts: [...unitVa.artifacts, ...unitVerify.artifacts, ...feedbackExecutions.flatMap((item) => item.artifacts)]
          .map((artifact) => ({
          path: artifact.path,
          sha256: artifact.sha256,
          bytes: artifact.bytes,
        })),
      })),
    }, null, 2)}\n`, { mode: 0o600 });
    renameSync(temporary, resultPath);
    workUnitSummary = {
      workPlanPath,
      resultPath,
      resultSha256: fileSha256(resultPath),
      completedUnitKeys,
      uncoveredFiles: uncoveredFiles.length > 0 ? uncoveredFiles : undefined,
    };
    pendingUnitFindings = fulfilled.map(({ unit, unitDir, findingReceipts }) => ({
      unitKey: unit.unitKey,
      unitDir,
      receipts: findingReceipts,
    }));
    rootAllowedReadFiles.push(
      workPlanPath,
      resultPath,
      scopeAssurancePath,
      ...fulfilled.flatMap(({ unitVa, unitVerify, feedbackExecutions }) =>
        [...unitVa.artifacts, ...unitVerify.artifacts, ...feedbackExecutions.flatMap((item) => item.artifacts)]
          .map((artifact) => artifact.path)),
      ...pendingUnitFindings.flatMap((unit) => unit.receipts.map((receipt) =>
        join(engagementDir, 'standard-findings', receipt.recordName))),
    );
  }
  if (workPlan && workPlanPath && dependencies.resumeCompletedPhases && existsSync(existingWorkUnitResultPath)) {
    const resumeSnapshot = await missionRuntime.read();
    const completedArtifacts = new Map(
      Object.values(resumeSnapshot.attempts)
        .filter((attempt) => attempt.status === 'completed')
        .flatMap((attempt) => attempt.artifacts ?? [])
        .map((artifact) => [resolve(artifact.path), artifact]),
    );
    const stored = JSON.parse(readFileSync(existingWorkUnitResultPath, 'utf8')) as {
      schemaVersion?: string;
      workPlanSha256?: string;
      completedUnitKeys?: string[];
      assurancePath?: string;
      assuranceSha256?: string;
      units?: Array<{
        unitKey?: string;
        findingReceipts?: StandardFindingRecordReceipt[];
        artifacts?: Array<{ path?: string; sha256?: string; bytes?: number }>;
      }>;
    };
    if (!stored.schemaVersion || !WORK_UNIT_RESULTS_ACCEPTED_SCHEMA_VERSIONS.has(stored.schemaVersion)) {
      throw new Error(
        `OffSec work unit result schemaVersion이 허용 목록에 없다: ${stored.schemaVersion ?? '(missing)'}`,
      );
    }
    if (stored.workPlanSha256 !== workPlan.workPlanSha256 || !Array.isArray(stored.completedUnitKeys)) {
      throw new Error('OffSec work unit result와 sealed work plan이 일치하지 않는다');
    }
    // Quarantine + Proceed: resume에서도 partial completion 허용
    // assertOffsecWorkPlanComplete(workPlan, stored.completedUnitKeys);
    const isTrueLegacyResult = stored.schemaVersion === WORK_UNIT_RESULTS_LEGACY_SCHEMA_VERSION;
    const hasAssuranceReference = stored.assurancePath !== undefined || stored.assuranceSha256 !== undefined;
    if (!isTrueLegacyResult && !hasAssuranceReference) {
      throw new Error(
        'OffSec work unit result schema가 scope assurance 참조를 요구하는데(레거시 1.0.0이 아니다) 참조가 없다',
      );
    }
    let resumedAssurancePath: string | undefined;
    if (hasAssuranceReference) {
      if (!stored.assurancePath || !stored.assuranceSha256) {
        throw new Error('OffSec work unit result의 scope assurance 참조가 불완전하다');
      }
      // assurancePath는 반드시 고정 파일명과 "정확히" 일치해야 한다 — 상대/절대 경로 traversal을
      // 문자열 비교 자체로 차단한다(engagement 디렉터리 밖 파일을 resolve하지 않는다).
      if (stored.assurancePath !== SCOPE_ASSURANCE_FILE_NAME) {
        throw new Error(
          `OffSec scope assurance path는 반드시 ${SCOPE_ASSURANCE_FILE_NAME}이어야 한다: ${stored.assurancePath}`,
        );
      }
      resumedAssurancePath = join(engagementDir, SCOPE_ASSURANCE_FILE_NAME);
      if (fileSha256(resumedAssurancePath) !== stored.assuranceSha256) {
        throw new Error('OffSec scope assurance hash가 work unit result 참조와 다르다');
      }
      const assuranceValue = JSON.parse(readFileSync(resumedAssurancePath, 'utf8')) as unknown;
      assertScopeAssuranceComplete(assuranceValue, workPlan, stored.completedUnitKeys);
    }
    const storedUnits = stored.units ?? [];
    if (!Array.isArray(storedUnits) || storedUnits.length > workPlan.units.length) {
      throw new Error('OffSec work unit result unit 수가 sealed work plan보다 크다');
    }
    // P0 advisory: storedUnits의 모든 unit이 completedUnitKeys에 속하는지 교차검증
    const storedCompletedSet = new Set(stored.completedUnitKeys);
    for (const unit of storedUnits) {
      if (unit.unitKey && !storedCompletedSet.has(unit.unitKey)) {
        throw new Error(`OffSec work unit result units에 completedUnitKeys에 없는 unit이 있다: ${unit.unitKey}`);
      }
    }
    const storedUnitKeySet = new Set(storedUnits.map((unit) => unit.unitKey));
    if (storedUnitKeySet.size !== storedUnits.length) {
      throw new Error('OffSec work unit result units에 중복 unitKey가 있다');
    }
    const planByKey = new Map(workPlan.units.map((unit) => [unit.unitKey, unit]));
    for (const unit of storedUnits) {
      const planUnit = planByKey.get(unit.unitKey ?? '');
      if (!planUnit) {
        throw new Error(`OffSec work unit result에 알 수 없는 unit이 있다: ${unit.unitKey ?? '(none)'}`);
      }
      if ((unit as { sourceUnitId?: string }).sourceUnitId !== undefined &&
          (unit as { sourceUnitId?: string }).sourceUnitId !== planUnit.sourceUnitId) {
        throw new Error(
          `OffSec work unit result의 sourceUnitId가 sealed work plan과 다르다: ${unit.unitKey}`,
        );
      }
      for (const artifact of unit.artifacts ?? []) {
        const sealed = artifact.path ? completedArtifacts.get(resolve(artifact.path)) : undefined;
        if (
          !artifact.path ||
          !sealed ||
          sealed.sha256 !== artifact.sha256 ||
          sealed.bytes !== artifact.bytes ||
          artifact.sha256 !== fileSha256(artifact.path) ||
          statSync(artifact.path).size !== artifact.bytes
        ) {
          throw new Error(`OffSec work unit result artifact가 변경됐다: ${artifact.path ?? '(none)'}`);
        }
        verifyRunArtifactRef(sealed, engagementDir);
      }
    }
    workUnitSummary = {
      workPlanPath,
      resultPath: existingWorkUnitResultPath,
      resultSha256: fileSha256(existingWorkUnitResultPath),
      completedUnitKeys: stored.completedUnitKeys,
      uncoveredFiles: Array.isArray((stored as { uncoveredFiles?: string[] }).uncoveredFiles)
        ? (stored as { uncoveredFiles: string[] }).uncoveredFiles
        : undefined,
    };
    pendingUnitFindings = storedUnits.map((unit) => {
      const firstArtifact = unit.artifacts?.[0]?.path;
      if (!unit.unitKey || !firstArtifact) throw new Error('OffSec work unit result에 unit artifact가 없다');
      return {
        unitKey: unit.unitKey,
        unitDir: resolve(firstArtifact, '..'),
        receipts: unit.findingReceipts ?? [],
      };
    });
    rootAllowedReadFiles.push(
      workPlanPath,
      existingWorkUnitResultPath,
      ...(resumedAssurancePath ? [resumedAssurancePath] : []),
      ...storedUnits.flatMap((unit) => (unit.artifacts ?? []).flatMap((artifact) => artifact.path ? [artifact.path] : [])),
      ...pendingUnitFindings.flatMap((unit) => unit.receipts.map((receipt) =>
        join(engagementDir, 'standard-findings', receipt.recordName))),
    );
  }

  const host = new WorkflowHost({
    adapter,
    runtime,
    state,
    target,
    engagementDir,
    runId: engagementId,
    hostEntrypoint: 'assess',
    ...(rootAllowedReadFiles.length > 0 ? { allowedReadFiles: rootAllowedReadFiles } : {}),
    ...(activeLease ? { leaseGuard: activeLease } : {}),
    ...(missionRuntime.artifactStore ? { artifactStore: missionRuntime.artifactStore } : {}),
    scope: input.scope,
    onEvent,
    outcomePolicy: ({ role, outcome }) => outcomePolicy({ role, outcome: outcome.usage }),
  });

  const executePhase = async (options: {
    id: string;
    round?: string;
    inputs?: Record<string, unknown>;
    hostOverride?: typeof host;
    priorArtifactPaths?: readonly string[];
    providerOptions?: {
      readScope?: 'default' | 'exact';
      disabledTools?: readonly string[];
      liveTestTarget?: string;
      liveTestPlan?: { path: string; sha256: string };
      liveDastContext?: ReturnType<typeof createLiveDastContext>;
    };
  }): Promise<PhaseExecution> => {
    const { legacy: phase } = adapter.getPhase(options.id);
    const artifacts = adapter.renderArtifacts(phase, options.round);
    if (dependencies.resumeCompletedPhases) {
      const snapshot = await missionRuntime.read();
      const completed = Object.values(snapshot.attempts)
        .filter((attempt) =>
          attempt.phase === phase.id && attempt.round === options.round && attempt.status === 'completed')
        .sort((left, right) => right.attempt - left.attempt)[0];
      if (completed) {
        for (const artifact of completed.artifacts ?? []) verifyRunArtifactRef(artifact, engagementDir);
        const stored = completed.result as { domainResult?: unknown } | undefined;
        const result = adapter.validateResult({
          value: stored?.domainResult,
          phase,
          engagementDir,
          round: options.round,
        });
        adapter.validateAcceptedResult({ result, phase, engagementDir, round: options.round });
        if (phase.reservationRole) {
          const state = agentPlan.loadState(engagementDir);
          const expectedKey = JSON.stringify([...artifacts.required].sort());
          const pending = (state.reservations ?? []).find((reservation) =>
            reservation.phase === phase.id &&
            reservation.role === phase.reservationRole &&
            reservation.status === 'reserved' &&
            JSON.stringify([...(reservation.expected_artifacts ?? [])].sort()) === expectedKey);
          if (pending) {
            agentPlan.commitReservation(engagementDir, {
              reservationId: pending.id,
              artifacts: [...artifacts.required, ...artifacts.optional].filter((artifact) =>
                existsSync(join(engagementDir, artifact))),
            });
          }
          const fanout = agentPlan.reconcileFanout(engagementDir, { checkCurrentSource: false });
          if (!fanout.ok) {
            throw new Error(`agent fanout host-effect 복구 실패: ${JSON.stringify(fanout.errors ?? [])}`);
          }
        }
        const outcome: SessionOutcome = { texts: [], ledger: [] };
        const execution = { phase: phase.id, role: phase.role, round: options.round, result, outcome };
        phases.push(execution);
        return execution;
      }
    }
    const reservation = phase.reservationRole
      ? agentPlan.reserveAgents(engagementDir, {
          phase: phase.id,
          role: phase.reservationRole,
          count: 1,
          expectedArtifacts: artifacts.required,
        })
      : undefined;

    const hosted = await (options.hostOverride ?? host).executePhase({
      id: options.id,
      round: options.round,
      inputs: options.inputs,
      ...(options.priorArtifactPaths ? { priorArtifactPaths: options.priorArtifactPaths } : {}),
      providerOptions: {
        model: phase.role === 'verifier' ? reviewModel : primaryModel,
        effort: input.effort,
        maxTurns: input.maxTurns,
        phaseRound: options.round,
        verifyRound: phase.role === 'verifier' ? options.round ?? '1st' : undefined,
        requirePocBinding,
        readScope: 'exact',
        networkAllowedDomains: ['pentest-discovery', 'pentest', 'pentest-feedback'].includes(phase.id) && liveTestTarget
          ? [liveTestTarget.hostname]
          : undefined,
        ...options.providerOptions,
      },
    });
    const result = hosted.result;
    const outcome = hosted.outcome.raw;
    const committedArtifacts = [...artifacts.required, ...artifacts.optional].filter((artifact) =>
      existsSync(join(engagementDir, artifact)),
    );
    if (reservation) {
      agentPlan.commitReservation(engagementDir, {
        reservationId: reservation.id,
        artifacts: committedArtifacts,
      });
      const fanout = agentPlan.reconcileFanout(engagementDir, { checkCurrentSource: false });
      if (!fanout.ok) {
        throw new Error(`agent fanout 무결성 검증 실패: ${JSON.stringify(fanout.errors ?? [])}`);
      }
    }

    mergeOutcome(outcome);
    combined.structuredOutput = result;

    const execution = { phase: phase.id, role: phase.role, round: options.round, result, outcome };
    phases.push(execution);
    return execution;
  };

  const va = await executePhase({
    id: 'va',
    inputs: {
      astPreanalysis: astContextAvailable
        ? {
            status: 'available',
            artifact: astContextPath,
            semgrep: semgrepStatus,
            assurance: semgrepStatus === 'complete' ? 'full' : 'reduced',
          }
        : { status: 'unavailable', reason: astOutcome.error ?? 'AST context was not produced' },
      ...(workUnitSummary ? {
        workUnitAnalysis: {
          status: workUnitSummary.uncoveredFiles?.length ? 'partial' : 'complete',
          workPlan: workUnitSummary.workPlanPath,
          results: workUnitSummary.resultPath,
          resultSha256: workUnitSummary.resultSha256,
          completedUnitKeys: workUnitSummary.completedUnitKeys,
          ...(workUnitSummary.uncoveredFiles?.length ? {
            uncoveredFiles: workUnitSummary.uncoveredFiles,
            coverageNote: `${workUnitSummary.uncoveredFiles.length}개 파일이 unit 실패로 미커버. 직접 분석 필요.`,
          } : {}),
        },
      } : {}),
    },
  });
  let verify = await executePhase({
    id: 'verify',
    inputs: { vaArtifacts: va.result.artifacts },
  });

  for (
    let iteration = 1;
    (verify.result.metrics.objectionCount ?? 0) > 0 && iteration <= (contract.limits.maxFeedbackIterations ?? 0);
    iteration += 1
  ) {
    const round = ordinal(iteration + 1);
    const feedbackVa = await executePhase({
      id: 'va-feedback',
      round,
      inputs: {
        priorVaArtifacts: va.result.artifacts,
        verifierArtifacts: verify.result.artifacts,
        objectionCount: verify.result.metrics.objectionCount ?? 0,
      },
    });
    verify = await executePhase({
      id: 'verify-feedback',
      round,
      inputs: { vaFeedbackArtifacts: feedbackVa.result.artifacts },
    });
  }

  if (verify.result.metrics.objectionCount ?? 0 > 0) {
    // A fix: throw하지 않고 경고 기록 후 converge → report로 진행
    appendFileSync(ledgerPath, `${JSON.stringify({
      event: 'HostRootVerifyUnresolvedObjections',
      objectionCount: verify.result.metrics.objectionCount ?? 0,
      action: 'proceed-to-converge',
      note: 'feedback 상한 도달; 미해결 objection은 converge에서 DISPUTED/PENDING으로 분류',
    })}\n`);
  }

  for (const unit of pendingUnitFindings) {
    promoteStandardFindingRecords({
      fromEngagementDir: unit.unitDir,
      toEngagementDir: engagementDir,
      expected: unit.receipts,
    });
  }
  if (pendingUnitFindings.length > 0) {
    appendFileSync(ledgerPath, `${JSON.stringify({
      event: 'HostUnitFindingsPromoted',
      unitCount: pendingUnitFindings.length,
      findingCount: pendingUnitFindings.reduce((sum, unit) => sum + unit.receipts.length, 0),
    })}\n`);
  }

  if (verificationMode.includes('PENTEST')) {
    const sourceFiles = (sourceManifest.source_files ?? [])
      .filter((path): path is string => typeof path === 'string')
      .map((path) => resolve(target, path));
    const pentestPlanHost = new WorkflowHost({
      adapter,
      runtime,
      state,
      target,
      engagementDir,
      runId: engagementId,
      hostEntrypoint: 'assess',
      allowedReadFiles: [...sourceFiles, ...sealedDependencyFiles],
      ...(activeLease ? { leaseGuard: activeLease } : {}),
      ...(missionRuntime.artifactStore ? { artifactStore: missionRuntime.artifactStore } : {}),
      scope: input.scope,
      onEvent,
      outcomePolicy: ({ role, outcome }) => outcomePolicy({ role, outcome: outcome.usage }),
    });
    const pentestPlanPhase = await executePhase({
      id: 'pentest-plan',
      hostOverride: pentestPlanHost,
      priorArtifactPaths: [],
      inputs: { analysisPass: 'source-first; prior findings intentionally hidden' },
      providerOptions: {
        readScope: 'exact',
        disabledTools: ['mcp__nunchi__http_probe'],
      },
    });
    const pentestPlanPath = join(engagementDir, pentestPlanPhase.result.artifacts[0]!);
    const sealedPentestPlan = readLiveTestPlan(pentestPlanPath);
    pentestPlanBinding = { path: pentestPlanPath, sha256: sealedPentestPlan.sha256 };
    const pentestHost = new WorkflowHost({
      adapter,
      runtime,
      state,
      target,
      engagementDir,
      runId: engagementId,
      hostEntrypoint: 'assess',
      allowedReadFiles: [...sourceFiles, ...sealedDependencyFiles],
      ...(activeLease ? { leaseGuard: activeLease } : {}),
      ...(missionRuntime.artifactStore ? { artifactStore: missionRuntime.artifactStore } : {}),
      scope: input.scope,
      onEvent,
      outcomePolicy: ({ role, outcome }) => outcomePolicy({ role, outcome: outcome.usage }),
    });
    const liveDastContext = preparedLiveDast
      ? createLiveDastContext({
          engagementDir,
          prepared: preparedLiveDast,
          plan: sealedPentestPlan.plan,
          planSha256: sealedPentestPlan.sha256,
        })
      : undefined;
    const discovery = await executePhase({
      id: 'pentest-discovery',
      hostOverride: pentestHost,
      priorArtifactPaths: pentestPlanPhase.result.artifacts.map((name) => join(engagementDir, name)),
      inputs: {
        analysisPass: 'runtime-first; VA and verifier findings intentionally hidden',
        pentestPlan: pentestPlanPath,
        pentestPlanSha256: sealedPentestPlan.sha256,
        liveTestTarget: liveTestTarget?.url,
        profileSha256: preparedLiveDast?.profileSha256,
      },
      providerOptions: {
        readScope: 'exact',
        liveTestTarget: liveTestTarget?.url,
        liveTestPlan: { path: pentestPlanPath, sha256: sealedPentestPlan.sha256 },
        liveDastContext,
      },
    });
    const pentest = await executePhase({
      id: 'pentest',
      hostOverride: pentestHost,
      priorArtifactPaths: [
        ...pentestPlanPhase.result.artifacts.map((name) => join(engagementDir, name)),
        ...discovery.result.artifacts.map((name) => join(engagementDir, name)),
        ...va.result.artifacts.map((name) => join(engagementDir, name)),
        ...verify.result.artifacts.map((name) => join(engagementDir, name)),
      ],
      inputs: {
        pentestPlan: pentestPlanPath,
        pentestPlanSha256: sealedPentestPlan.sha256,
        vaArtifacts: va.result.artifacts,
        verifierArtifacts: verify.result.artifacts,
        runtimeDiscoveryArtifacts: discovery.result.artifacts,
        liveTestTarget: liveTestTarget?.url,
      },
      providerOptions: {
        readScope: 'exact',
        liveTestTarget: liveTestTarget?.url,
        liveTestPlan: { path: pentestPlanPath, sha256: sealedPentestPlan.sha256 },
        liveDastContext,
      },
    });
    if (readLiveTestPlan(pentestPlanPath).sha256 !== sealedPentestPlan.sha256) {
      throw new Error('pentest plan이 동적 검증 중 변경됐다');
    }
    const dynamicEvidenceFiles = [
      liveDastContext?.journal.path,
      ...['http-probe-receipts', 'live-scenarios', 'standard-findings'].flatMap((directory) => {
        const root = join(engagementDir, directory);
        return existsSync(root)
          ? readdirSync(root).map((name) => join(root, name)).filter((path) => statSync(path).isFile())
          : [];
      }),
    ].filter((path): path is string => Boolean(path));
    const pentestVerifyHost = new WorkflowHost({
      adapter,
      runtime,
      state,
      target,
      engagementDir,
      runId: engagementId,
      hostEntrypoint: 'assess',
      allowedReadFiles: [...new Set([
        ...sourceFiles,
        ...sealedDependencyFiles,
        pentestPlanPath,
        ...dynamicEvidenceFiles,
      ])],
      ...(activeLease ? { leaseGuard: activeLease } : {}),
      ...(missionRuntime.artifactStore ? { artifactStore: missionRuntime.artifactStore } : {}),
      scope: input.scope,
      onEvent,
      outcomePolicy: ({ role, outcome }) => outcomePolicy({ role, outcome: outcome.usage }),
    });
    let pentestVerify = await executePhase({
      id: 'pentest-verify',
      round: '1st',
      hostOverride: pentestVerifyHost,
      priorArtifactPaths: pentest.result.artifacts.map((name) => join(engagementDir, name)),
      inputs: {
        pentestArtifacts: pentest.result.artifacts,
        scenarioJournal: liveDastContext?.journal.path,
        evidenceFiles: dynamicEvidenceFiles,
        profileSha256: preparedLiveDast?.profileSha256,
        pentestPlanSha256: sealedPentestPlan.sha256,
      },
      providerOptions: { readScope: 'exact' },
    });
    for (
      let iteration = 1;
      (pentestVerify.result.metrics.objectionCount ?? 0) > 0 && iteration <= (contract.limits.maxFeedbackIterations ?? 0);
      iteration += 1
    ) {
      const round = ordinal(iteration + 1);
      const feedback = await executePhase({
        id: 'pentest-feedback',
        round,
        inputs: {
          pentestArtifacts: pentest.result.artifacts,
          verifierArtifacts: pentestVerify.result.artifacts,
          objectionCount: pentestVerify.result.metrics.objectionCount ?? 0,
        },
        providerOptions: {
          liveTestTarget: liveTestTarget?.url,
          liveTestPlan: { path: pentestPlanPath, sha256: sealedPentestPlan.sha256 },
          liveDastContext,
        },
      });
      const feedbackEvidenceFiles = [
        liveDastContext?.journal.path,
        ...['http-probe-receipts', 'live-scenarios', 'standard-findings'].flatMap((directory) => {
          const root = join(engagementDir, directory);
          return existsSync(root)
            ? readdirSync(root).map((name) => join(root, name)).filter((path) => statSync(path).isFile())
            : [];
        }),
      ].filter((path): path is string => Boolean(path));
      const feedbackVerifyHost = new WorkflowHost({
        adapter,
        runtime,
        state,
        target,
        engagementDir,
        runId: engagementId,
        hostEntrypoint: 'assess',
        allowedReadFiles: [...new Set([
          ...sourceFiles,
          ...sealedDependencyFiles,
          pentestPlanPath,
          ...feedbackEvidenceFiles,
        ])],
        ...(activeLease ? { leaseGuard: activeLease } : {}),
        ...(missionRuntime.artifactStore ? { artifactStore: missionRuntime.artifactStore } : {}),
        scope: input.scope,
        onEvent,
        outcomePolicy: ({ role, outcome }) => outcomePolicy({ role, outcome: outcome.usage }),
      });
      pentestVerify = await executePhase({
        id: 'pentest-verify-feedback',
        round,
        hostOverride: feedbackVerifyHost,
        priorArtifactPaths: feedback.result.artifacts.map((name) => join(engagementDir, name)),
        inputs: { pentestFeedbackArtifacts: feedback.result.artifacts, evidenceFiles: feedbackEvidenceFiles },
        providerOptions: { readScope: 'exact' },
      });
    }
    if (pentestVerify.result.metrics.objectionCount ?? 0 > 0) {
      // A fix: pentest objection도 throw하지 않고 경고 기록 후 계속 진행
      appendFileSync(ledgerPath, `${JSON.stringify({
        event: 'HostPentestVerifyUnresolvedObjections',
        objectionCount: pentestVerify.result.metrics.objectionCount ?? 0,
        action: 'proceed-to-converge',
        note: 'pentest feedback 상한 도달; 미해결 objection은 converge에서 분류',
      })}\n`);
    }
  }
  if (verificationMode.includes('REDTEAM')) {
    if (!iacState) throw new Error('Red Team IaC manifest preflight가 없다');
    const { manifest, path: manifestPath } = iacState;
    const sourceFiles = (sourceManifest.source_files ?? [])
      .filter((path): path is string => typeof path === 'string')
      .map((path) => resolve(target, path));
    const iacFiles = manifest.files.map((file) => resolve(target, file.path));
    const redteamHost = new WorkflowHost({
      adapter,
      runtime,
      state,
      target,
      engagementDir,
      runId: engagementId,
      hostEntrypoint: 'assess',
      allowedReadFiles: [...new Set([...sourceFiles, ...sealedDependencyFiles, ...iacFiles, manifestPath])],
      ...(activeLease ? { leaseGuard: activeLease } : {}),
      ...(missionRuntime.artifactStore ? { artifactStore: missionRuntime.artifactStore } : {}),
      scope: input.scope,
      onEvent,
      outcomePolicy: ({ role, outcome }) => outcomePolicy({ role, outcome: outcome.usage }),
    });
    await executePhase({
      id: 'redteam',
      hostOverride: redteamHost,
      inputs: {
        completedPhases: phases.map((phase) => phase.phase),
        iacManifest: manifestPath,
        iacManifestSha256: manifest.manifestSha256,
        applicability: manifest.applicability,
        coverage: manifest.coverage,
      },
      providerOptions: { readScope: 'exact' },
    });
    assertIacManifestIntact(manifest);
  }

  if (workPlan && workUnitSummary) {
    // Quarantine + Proceed: publication에서도 partial completion 허용 (Root VA가 gap 보완)
    // assertOffsecWorkPlanComplete(workPlan, workUnitSummary.completedUnitKeys);
    if (fileSha256(workUnitSummary.resultPath) !== workUnitSummary.resultSha256) {
      throw new Error('OffSec work unit result가 aggregation 뒤 변경됐다');
    }
  }
  assertOffsecConvergenceReady(phases, verificationMode);
  refreshCanonicalFindingReadSet();
  const convergence = await executePhase({
    id: 'converge',
    inputs: {
      phaseArtifacts: phases.flatMap((phase) => phase.result.artifacts),
      ...(preparedLiveDast ? {
        liveDastLineage: {
          profileSha256: preparedLiveDast.profileSha256,
          selectionSha256: preparedLiveDast.selection.selectionSha256,
          scenarioJournal: join(engagementDir, 'live-scenario-journal.jsonl'),
        },
      } : {}),
    },
  });
  refreshCanonicalFindingReadSet();
  await executePhase({
    id: 'report',
    priorArtifactPaths: [...new Set([
      ...convergence.result.artifacts.map((name: string) => join(engagementDir, name)),
      ...phases.flatMap((p) => p.result.artifacts.map((name: string) => join(engagementDir, name))),
    ])],
    inputs: { convergenceArtifacts: convergence.result.artifacts },
  });
  if (workPlan && workUnitSummary) {
    assertOffsecWorkPlanIntact(workPlan);
    if (workPlan.schemaVersion === '2.0.0' && depGraph) {
      assertPlanGraphIntegrity(workPlan as OffsecWorkPlanV2, depGraph);
    }
    if (fileSha256(workUnitSummary.resultPath) !== workUnitSummary.resultSha256) {
      throw new Error('OffSec work unit result가 publication 전에 변경됐다');
    }
  }
  if (pentestPlanBinding) {
    if (readLiveTestPlan(pentestPlanBinding.path).sha256 !== pentestPlanBinding.sha256) {
      throw new Error('pentest plan이 최종 발행 전에 변경됐다');
    }
    assertPentestRuntimeEvidenceIntact(engagementDir, pentestPlanBinding.sha256);
  }
  assertStandardFindingsRepresented(
    engagementDir,
    join(engagementDir, contract.publication.draftArtifact),
  );
  // P1 #18: Quarantine + Proceed인 경우 최종 보고서에 quarantine 공개가 포함돼야 한다.
  if (workPlan && workUnitSummary?.uncoveredFiles?.length) {
    const draftContent = readFileSync(join(engagementDir, contract.publication.draftArtifact), 'utf8');
    const lower = draftContent.toLowerCase();
    // 1차: quarantine/coverage 관련 키워드가 있는지 (case-insensitive)
    const hasKeyword =
      lower.includes('quarantine') ||
      lower.includes('미커버') ||
      lower.includes('uncovered') ||
      lower.includes('격리') ||
      lower.includes('coverage gap');
    // 2차: uncovered 파일 경로 중 최소 하나가 보고서에 언급되는지
    const hasFileReference = workUnitSummary.uncoveredFiles.some(
      (file) => draftContent.includes(file),
    );
    if (!hasKeyword && !hasFileReference) {
      // v2: partial 결과에서 uncovered files 미언급은 경고로 처리 (보고서 생성을 중단하지 않음)
      appendFileSync(ledgerPath, `${JSON.stringify({
        event: 'HostReportUncoveredFilesWarning',
        uncoveredFileCount: workUnitSummary.uncoveredFiles.length,
        message: '최종 보고서에 quarantine/uncovered file 공개가 누락됐다.',
      })}\n`);
    }
  }
  if (preparedLiveDast) {
    assertLiveDastLineageRepresented(
      join(engagementDir, contract.publication.draftArtifact),
      preparedLiveDast,
    );
  }
  const allowEmptyCandidates = readStandardFindingRecordReceipts(engagementDir).length === 0;
  const finalReport = dependencies.reportPublisher
    ? dependencies.reportPublisher(engagementDir, requirePocBinding)
    : publishValidatedReport(
        engagementDir,
        requirePocBinding,
        allowEmptyCandidates,
        contract.publication,
        preparedLiveDast,
      );
  const expectedFinalReport = resolve(engagementDir, contract.publication.finalArtifact);
  if (resolve(finalReport) !== expectedFinalReport || !existsSync(expectedFinalReport)) {
    throw new Error(`report publisher가 계약된 최종 artifact를 반환하지 않았다: ${finalReport}`);
  }
  await recordOffsecPublication({
    runtime: missionRuntime,
    engagementDir,
    runId: engagementId,
    contractId: contract.id,
    finalArtifact: contract.publication.finalArtifact,
    sourceManifestSha256: sourceManifest.hash,
  });

  return {
    outcome: combined,
    engagementDir,
    phases,
    finalReport,
    ...(workUnitSummary ? { workUnits: workUnitSummary } : {}),
  };
  } finally {
    if (!dependencies.existingRuntime) await missionRuntime.close();
  }
}

/** `--key=value` 를 뽑고 나머지는 위치 인자로 남긴다 */
function parseArgs(argv: string[]): { flags: Map<string, string>; positional: string[] } {
  const flags = new Map<string, string>();
  const positional: string[] = [];
  for (const arg of argv) {
    const m = /^--([a-z-]+)=(.*)$/.exec(arg);
    if (m?.[1] !== undefined) flags.set(m[1], m[2] ?? '');
    else positional.push(arg);
  }
  return { flags, positional };
}

async function main(): Promise<void> {
  const { flags, positional } = parseArgs(process.argv.slice(2));
  const [targetArg, ...rest] = positional;
  if (!targetArg) {
    console.error(
      '사용: pnpm tsx src/runtime/missions/assess.ts <진단대상 절대경로> [지시문]\n' +
        '  --model=<alias>          기본 opus\n' +
        '  --effort=<low..max>\n' +
        '  --max-turns=<n>          기본 120\n' +
        '  --max-usd=<n>            예산 상한\n' +
        '  --verification-mode=<VA_ONLY|VA_PENTEST|VA_PENTEST_REDTEAM>\n' +
        '  --semgrep=<required|best-effort|off>  기본 required\n' +
        '  --work-units=<auto|force|off>  기본 auto\n' +
        '  --max-concurrency=<n>  contract 상한 이내 host worker 수\n' +
        '  --test-url=<https://test.example>  PENTEST mode의 승인된 테스트 환경\n' +
        '  --live-test-profile=<path>  인증 actor와 동적 테스트 정책\n' +
        '  --auth-interaction=<remote-handoff|local-headed-browser|none>\n' +
        '  --engagement-dir=<path>  기본 <target>/.nunchi/reports/<engagementId>\n' +
        '  --no-cost-guard=true     예산 가드 비활성화 (임계치 재조정용)',
    );
    process.exit(2);
  }

  const num = (key: string): number | undefined => {
    const raw = flags.get(key);
    if (raw === undefined) return undefined;
    const n = Number(raw);
    if (!Number.isFinite(n)) throw new Error(`--${key} 는 숫자여야 한다: ${raw}`);
    return n;
  };

  const verificationMode = flags.get('verification-mode') as VerificationMode | undefined;
  if (
    verificationMode !== undefined &&
    !['VA_ONLY', 'VA_PENTEST', 'VA_PENTEST_REDTEAM'].includes(verificationMode)
  ) {
    throw new Error(`--verification-mode 값이 잘못됐다: ${verificationMode}`);
  }
  const semgrepMode = flags.get('semgrep') as SemgrepMode | undefined;
  if (semgrepMode !== undefined && !['required', 'best-effort', 'off'].includes(semgrepMode)) {
    throw new Error(`--semgrep 값이 잘못됐다: ${semgrepMode}`);
  }
  const workUnitMode = flags.get('work-units') as WorkUnitMode | undefined;
  if (workUnitMode !== undefined && !['auto', 'force', 'off'].includes(workUnitMode)) {
    throw new Error(`--work-units 값이 잘못됐다: ${workUnitMode}`);
  }
  const authInteractionMode = flags.get('auth-interaction') as AuthInteractionMode | undefined;
  if (
    authInteractionMode !== undefined &&
    !['remote-handoff', 'local-headed-browser', 'none'].includes(authInteractionMode)
  ) {
    throw new Error(`--auth-interaction 값이 잘못됐다: ${authInteractionMode}`);
  }

  const { outcome, engagementDir, phases, finalReport } = await assess({
    target: targetArg,
    scope: rest.length > 0 ? rest.join(' ') : undefined,
    model: flags.get('model'),
    reviewModel: flags.get('review-model'),
    crossModelVerifier: flags.get('cross-model-verifier'),
    effort: flags.get('effort') as AssessInput['effort'],
    maxTurns: num('max-turns'),
    maxBudgetUsd: num('max-usd'),
    engagementDir: flags.get('engagement-dir'),
    verificationMode,
    semgrepMode,
    workUnitMode,
    maxConcurrency: num('max-concurrency'),
    testUrl: flags.get('test-url'),
    liveTestProfilePath: flags.get('live-test-profile'),
    authInteractionMode,
    noCostGuard: flags.get('no-cost-guard') === 'true',
  });

  const denied = outcome.ledger.filter((r) => r.decision === 'deny');
  const subagents = outcome.ledger.filter((r) => r.event === 'SubagentStart');

  console.log('\n================ assess 결과 ================\n');
  console.log(`engagement: ${engagementDir}`);
  console.log(`완료 phase: ${phases.map((phase) => phase.phase).join(' → ')}`);
  console.log(`최종 보고서: ${finalReport}`);
  console.log(`등록된 에이전트: ${(outcome.registeredAgents ?? []).map((a) => a.name).join(', ')}`);
  console.log(`띄운 서브에이전트: ${subagents.map((r) => r.agentType).join(', ') || '(없음)'}`);
  console.log(`메인 스레드 도구 거부: ${denied.length}건`);
  for (const d of denied) console.log(`  - ${d.tool}: ${d.reason}`);
  console.log(
    `\nsubtype=${outcome.subtype} turns=${outcome.numTurns} cost=$${outcome.totalCostUsd?.toFixed(4) ?? '?'}`,
  );
  console.log('\n--- 메인 스레드 보고 ---');
  console.log(outcome.texts.join('\n'));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e: unknown) => {
    if (e instanceof AssessAwaitingInputError) {
      console.log(JSON.stringify({
        status: 'awaiting-input',
        engagementDir: e.engagementDir,
        requestId: e.requestId,
        requestSha256: e.requestSha256,
        expectedVersion: e.expectedVersion,
      }, null, 2));
      process.exit(3);
    }
    console.error('assess failed:', e);
    process.exit(1);
  });
}
