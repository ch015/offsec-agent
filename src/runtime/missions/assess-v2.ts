import { budgetAccounting, committedBudget, recoverLegacyBudget, increaseResumeBudget, type ResumeBudgetOptions } from './assessment-budget.js';
import { COVERAGE_FILE, coverageAppendix, legacyCompletedCoverage, sealAnalysisCheckpoint, restoreAnalysisCheckpoint } from './analysis-checkpoint.js';
import { acquireRunLock } from '../workflow/run-lock.js';
import { recoveryLogger } from '../workflow/recovery-log.js';
import { AnalysisInterruption, assertResumeSources, checkpointInput, partialCoverage, preservePartialReport, recoverableFailure, retryProvider } from './assessment-recovery.js';
import { allocateRunLocation, reportDirectory } from '../workflow/run-location.js';
import { atomicPrivateWrite, privateDirectory } from '../workflow/storage-files.js';
import { archiveRun } from '../workflow/run-archive.js';
import { ResilientArtifactStore, type StorageHealth } from '../workflow/resilient-artifacts.js';
import { copyPublication, recordPublicationIntent } from './publication-files.js';
import { assertRunInputsIntact } from '../workflow/host-integrity.js';
/**
 * assess-v2 미션 — OffSec v2 취약점 진단 진입점 (선형 6-phase 파이프라인).
 *
 * v1(assess.ts)과 달리 pentest/redteam/feedback loop·verifier·objection 시스템이 없다.
 * 계약: domains/offsec/contracts/offsec-contract.v2.json
 *
 * phase 순서:
 *   recon(host)  -> plan(host) -> analyze -> review -> evaluate -> report
 *
 * host phase(recon, plan)는 결정론적으로 실행되어 산출물을 만들고,
 * 나머지 4개 phase는 WorkflowHost가 계약 검증 아래 단일 세션으로 실행한다.
 *
 * 사용:
 *   pnpm tsx src/runtime/missions/assess-v2.ts <진단대상 절대경로> [지시문]
 */
import {
  existsSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  readdirSync,
  renameSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { basename, dirname, join, resolve } from 'node:path';

import { loadOffsecContract, type PhaseResult } from '../offsec-contract.js';
import { OffsecDomainAdapter } from '../domains/offsec.js';
import { AnthropicAgentRuntime } from '../providers/anthropic-agent-sdk.js';
import { BudgetedRuntime, MissionBudgetExhaustedError } from '../providers/budgeted-runtime.js';
import { runSession, type SessionOutcome, type SessionSpec } from '../session-runner.js';
import { WorkflowHost } from '../workflow/engine.js';
import { executePagedWork } from '../workflow/bounded-work-executor.js';
import {
  createMissionRuntime,
  selectedBackend,
  openMissionRuntime,
  type MissionRuntimeOptions,
} from '../workflow/mission-runtime.js';
import { createArtifactRef } from '../contracts/result-contract.js';
import { ModelIndependenceGuard } from '../workflow/model-independence.js';
import type { AutoRenewingRunLease } from '../workflow/run-lease.js';
import {
  assertOffsecWorkUnitIntact,
  createOffsecWorkPlanV2,
  getUnitTypedEdges,
  writeOffsecWorkPlan,
  type OffsecWorkPlanV2,
} from '../workflow/offsec-work-plan.js';
import {
  createDependencyGraph,
  writeDependencyGraph,
  type DependencyGraph,
} from '../workflow/offsec-dependency-graph.js';
import {
  createScopeAssurance,
  SCOPE_ASSURANCE_FILE_NAME,
  writeScopeAssurance,
  type UnitScopeObservationInput,
} from '../workflow/scope-assurance.js';
import { computeGraphRag, serializeGraphContextForUnit, type NativeTaintPath } from '../workflow/graph-rag.js';
import { runHostRecon } from '../workflow/host-recon.js';
import { loadPreanalysisEvidence, writeUnitEvidence } from '../workflow/preanalysis-evidence.js';
import { selectAnalysisFollowups } from '../workflow/analysis-followup.js';
import {
  assertStandardFindingsRepresented,
  promoteStandardFindingRecords,
  readStandardFindingRecordReceipts,
  type StandardFindingRecordReceipt,
} from '../finding-contract.js';
import { makeEngagementId, recordOffsecPublication, resolveRunBudget, validateSourcePublicationCandidate as validateOffsecPublicationCandidate } from './assessment-support.js';
import type { PhaseExecution, SemgrepMode, WorkUnitMode } from './assess.js';

const require = createRequire(import.meta.url);
const agentPlan = require('../../../domains/offsec/lib/ch015/agent-plan.js') as {
  initFanoutPlan(options: Record<string, unknown>): { manifest: unknown; decision: unknown };
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
      sourceFiles?: string[];
      logger: (message: string) => void;
    },
  ): Promise<AstBuildOutcome>;
};

/** v2 계약 경로 — 리포 루트 기준. */
const V2_CONTRACT_PATH = resolve(import.meta.dirname, '..', '..', '..', 'domains', 'offsec', 'contracts', 'offsec-contract.v2.json');

const NUNCHI_DIR = '.nunchi';
const ASSESS_V2_CHECKPOINT_INPUT = 'assess-v2-checkpoint-input.json';

export type AssessV2Input = {
  target: string;
  /** Exact file/directory roots excluded from the sealed source inventory. */
  excludePaths?: string[];
  scope?: string;
  engagementId?: string;
  engagementDir?: string;
  stateHome?: string;
  model?: string;
  reviewModel?: string;
  effort?: SessionSpec['effort'];
  maxTurns?: number;
  maxBudgetUsd?: number;
  semgrepMode?: SemgrepMode;
  workUnitMode?: WorkUnitMode;
  maxConcurrency?: number;
  /** At most one extra session for evidence-backed cross-unit questions. 0 disables it. */
  maxFollowupHypotheses?: number;
  noCostGuard?: boolean;
};

export type AssessV2ResumeOptions = ResumeBudgetOptions;

export type AssessV2Dependencies = {
  sessionRunner?: typeof runSession;
  runtime?: MissionRuntimeOptions;
  astBuilder?: typeof astTools.buildAstContext;
};

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

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) =>
      `${JSON.stringify(key)}:${stableJson(record[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function fileSha256(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function checkpointFileReceipt(engagementDir: string): { path: string; sha256: string; bytes: number } {
  const path = join(engagementDir, ASSESS_V2_CHECKPOINT_INPUT);
  const content = readFileSync(path);
  return { path, sha256: createHash('sha256').update(content).digest('hex'), bytes: content.byteLength };
}

type CheckpointCore = Readonly<{ schemaVersion: '1.0.0'; runId: string; input: AssessV2Input; storageBackend?: 'file' | 'postgres' }>;
type Checkpoint = CheckpointCore & Readonly<{ checkpointSha256: string }>;

function checkpointSha256(core: CheckpointCore): string {
  return createHash('sha256').update(stableJson(JSON.parse(JSON.stringify(core)) as unknown)).digest('hex');
}

function sealCheckpoint(engagementDir: string, input: AssessV2Input, target: string, runId: string, storageBackend: 'file' | 'postgres'): void {
  const core: CheckpointCore = {
    schemaVersion: '1.0.0',
    runId,
    storageBackend,
    input: {
      ...input,
      target,
      engagementId: runId,
      engagementDir,
      semgrepMode: input.semgrepMode ?? 'best-effort',
      workUnitMode: input.workUnitMode ?? 'auto',
    },
  };
  const checkpoint: Checkpoint = { ...core, checkpointSha256: checkpointSha256(core) };
  const path = join(engagementDir, ASSESS_V2_CHECKPOINT_INPUT);
  if (existsSync(path)) return;
  writeFileSync(path, `${JSON.stringify(checkpoint, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
}

/**
 * v2 최종 보고서 발행 — 완료 이벤트의 draft 참조를 보존하면서 final을 게시한다.
 * pentest/liveDast lineage 검증을 뺀 축약판이다.
 */
function publishV2Report(
  engagementDir: string,
  allowEmptyCandidates: boolean,
  publication: { draftArtifact: string; finalArtifact: string },
  appendix = '',
): string {
  const draft = join(engagementDir, publication.draftArtifact);
  const final = join(engagementDir, publication.finalArtifact);
  const candidate = existsSync(final) ? final : draft;
  if (!existsSync(candidate)) throw new Error(`최종 보고서 draft가 없다: ${draft}`);
  validateOffsecPublicationCandidate({
    engagementDir,
    candidate,
    requirePocBinding: false,
    allowEmptyCandidates,
  });
  return copyPublication(engagementDir, publication.draftArtifact, publication.finalArtifact, appendix);
}

async function executeAssessV2(input: AssessV2Input, dependencies: AssessV2Dependencies = {}, resume = false, resumeOptions: AssessV2ResumeOptions = {}): Promise<{
  outcome: SessionOutcome;
  engagementDir: string;
  phases: PhaseExecution[];
  finalReport: string;
  publicationStatus: 'published' | 'partial';
  storage: StorageHealth & { archiveUri?: string };
  coverage: { complete: boolean; completedUnits: number; totalUnits: number; uncoveredFiles: string[];
    semanticCoverage: 'not-proven'; ownedFilesRead: number; ownedFileCount: number;
    preanalysisAvailable: boolean; followupQuestions: number; deferredFollowupQuestions: number; requiredPreanalysisComplete?: boolean };
}> {
  // --- preflight ---------------------------------------------------------
  if (!input.engagementDir) input = { ...input, ...allocateRunLocation(input) };
  const target = resolve(input.target);
  const engagementId = input.engagementId ?? makeEngagementId(target, new Date());
  const nunchiRoot = join(target, NUNCHI_DIR);
  const engagementDir = resolve(input.engagementDir!);
  const prepared = resume && existsSync(join(engagementDir, '.recovery', 'preanalysis.json')) && existsSync(join(engagementDir, '00_work_plan.json'));
  const semgrepMode = input.semgrepMode ?? 'best-effort';
  const workUnitMode = input.workUnitMode ?? 'auto';
  const contract = loadOffsecContract(V2_CONTRACT_PATH);
  if (!contract.version.startsWith('2.')) {
    throw new Error(`assess-v2에는 v2 계약이 필요하다: ${contract.version}`);
  }
  const sessionRunner = dependencies.sessionRunner ?? runSession;
  let maxBudgetUsd = input.noCostGuard ? undefined : resolveRunBudget(input.maxBudgetUsd, contract.limits.maxBudgetUsd);
  const primaryModel = input.model ?? process.env.ASSESS_PRIMARY_MODEL ?? 'opus';
  const reviewModel = input.reviewModel ?? process.env.ASSESS_REVIEW_MODEL ?? 'sonnet';

  if (!existsSync(target)) throw new Error(`진단 대상이 없다: ${target}`);
  if (!statSync(target).isDirectory()) throw new Error(`진단 대상은 디렉토리여야 한다: ${target}`);
  if (!['required', 'best-effort', 'off'].includes(semgrepMode)) {
    throw new Error(`semgrepMode must be required, best-effort or off: ${semgrepMode}`);
  }
  if (input.maxTurns !== undefined && (!Number.isSafeInteger(input.maxTurns) || input.maxTurns < 1)) {
    throw new Error('maxTurns must be a positive safe integer');
  }
  if (input.effort !== undefined && !['low', 'medium', 'high', 'xhigh', 'max'].includes(input.effort)) {
    throw new Error('effort must be low, medium, high, xhigh or max');
  }
  if (!['auto', 'force'].includes(workUnitMode)) {
    throw new Error(`OffSec v2는 작업 분할을 항상 사용한다: workUnitMode=${workUnitMode}는 지원하지 않는다`);
  }
  if (input.maxConcurrency !== undefined && (!Number.isInteger(input.maxConcurrency) || input.maxConcurrency < 1)) {
    throw new Error(`maxConcurrency가 잘못됐다: ${input.maxConcurrency}`);
  }
  const maxFollowupHypotheses = input.maxFollowupHypotheses ?? 3;
  if (!Number.isInteger(maxFollowupHypotheses) || maxFollowupHypotheses < 0 || maxFollowupHypotheses > 8) {
    throw new Error('maxFollowupHypotheses must be an integer between 0 and 8');
  }
  if (primaryModel === reviewModel && !process.env.ALLOW_SAME_MODEL) {
    throw new Error('OffSec primary model과 review model은 달라야 한다 (개발 중 동일 모델 사용은 ALLOW_SAME_MODEL=1 설정)');
  }
  if (!resume && existsSync(engagementDir) && readdirSync(engagementDir).length > 0) {
    throw new Error(`기존 engagement를 덮어쓸 수 없다: ${engagementDir}`);
  }
  privateDirectory(engagementDir);
  if (engagementDir.startsWith(resolve(nunchiRoot))) ensureNunchiGitignore(nunchiRoot);
  sealCheckpoint(engagementDir, input, target, engagementId, selectedBackend(dependencies.runtime ?? {}));

  const storageWarnings: string[] = [];
  const log = recoveryLogger(engagementDir, 'host-ledger.jsonl', storageWarnings);

  // --- recon (host) ------------------------------------------------------
  // source manifest는 initFanoutPlan이 생성·기록(source_manifest.json)한다. v1과 동일한
  // 경로를 재사용하되 v2 flow에는 feedback iteration이 없다.
  const fanoutPlan = prepared ? { manifest: JSON.parse(readFileSync(join(engagementDir, 'source_manifest.json'), 'utf8')), decision: JSON.parse(readFileSync(join(engagementDir, 'fanout_decision.json'), 'utf8')) } : agentPlan.initFanoutPlan({
    engagementDir,
    target,
    excludePaths: [nunchiRoot, join(target, 'reports'), engagementDir, ...(input.excludePaths ?? [])],
    flow: 'standard',
    vaMode: 'sequential',
    verificationMode: 'VA_ONLY',
    maxFeedbackIterations: 0,
  });
  const sourceManifest = fanoutPlan.manifest as {
    hash: string; source_files: string[]; dependency_files?: string[];
    source_receipts?: Array<{ path: string }>; dependency_receipts?: Array<{ path: string }>;
    source_errors?: Array<{ path: string; code: string }>;
    units: Array<{ id: string; files: string[] }>;
  };
  const sourceIssues = sourceManifest.source_errors ?? [];
  const unreadablePaths = new Set(sourceIssues.map(issue => issue.path));
  const readableManifest = { ...sourceManifest,
    source_files: sourceManifest.source_files.filter(path => !unreadablePaths.has(path)),
    units: sourceManifest.units.map(unit => ({ ...unit, files: unit.files.filter(path => !unreadablePaths.has(path)) })).filter(unit => unit.files.length),
  };
  if (!readableManifest.source_files.length) throw new AnalysisInterruption('No readable source files; inventory and read errors are retained');
  const dependencyGraph: DependencyGraph = prepared ? JSON.parse(readFileSync(join(engagementDir, '00_dependency_graph.json'), 'utf8')) : createDependencyGraph({
    target, sourceManifest: readableManifest,
  });
  if (!prepared) writeDependencyGraph(engagementDir, dependencyGraph);
  const sealedSourceFiles = readableManifest.source_files.map(path => resolve(target, path));
  const sealedDependencyFiles = (sourceManifest.dependency_files ?? []).filter(path => !unreadablePaths.has(path)).map(path => resolve(target, path));

  const reconResult: ReturnType<typeof runHostRecon> = prepared ? JSON.parse(readFileSync(join(engagementDir, '00_recon.json'), 'utf8')) : runHostRecon({
    target,
    sourceFiles: readableManifest.source_files,
  });
  const reconPath = join(engagementDir, '00_recon.json');
  if (!prepared) writeFileSync(reconPath, `${JSON.stringify(reconResult, null, 2)}\n`, { mode: 0o600 });
  log({
    event: 'HostReconCompleted',
    entryPoints: reconResult.entryPoints.length,
    authSurface: reconResult.authSurface.length,
    dataSurface: reconResult.dataSurface.length,
    networkSurface: reconResult.networkSurface.length,
    configSurface: reconResult.configSurface.length,
    general: reconResult.general.length,
  });

  // AST + semgrep preanalysis (analyze phase가 참조).
  const astContextPath = join(engagementDir, '00_ast_context.yaml');
  const astBuilder = dependencies.astBuilder ?? astTools.buildAstContext;
  let astOutcome: AstBuildOutcome;
  try {
    astOutcome = prepared ? JSON.parse(readFileSync(join(engagementDir, '.recovery', 'preanalysis.json'), 'utf8')) : await astBuilder(target, {
      outputPath: astContextPath,
      runSemgrep: semgrepMode !== 'off',
      semgrepFiles: [...new Set(sealedSourceFiles)],
      sourceFiles: [...new Set(sealedSourceFiles)],
      logger: (message) => log({ event: 'HostAstPreanalysis', message }),
    });
  } catch (error) {
    astOutcome = { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
  if (!prepared) atomicPrivateWrite(join(engagementDir, '.recovery', 'preanalysis.json'), JSON.stringify(astOutcome));
  const astContextAvailable = astOutcome.ok && existsSync(astContextPath);
  const semgrepStatus = semgrepMode === 'off' ? 'disabled' : astOutcome.semgrep?.status ?? 'unavailable';
  log({
    event: 'HostAstPreanalysisCompleted',
    ok: astContextAvailable,
    artifact: astContextAvailable ? astContextPath : undefined,
    error: astContextAvailable ? undefined : astOutcome.error ?? 'AST context was not produced',
    semgrep: astOutcome.semgrep ?? { status: semgrepStatus },
  });
  const requiredPreanalysisComplete = semgrepMode !== 'required' || semgrepStatus === 'complete';
  if (!requiredPreanalysisComplete) log({ event: 'HostRequiredPreanalysisPending', reason: astOutcome.semgrep?.error ?? semgrepStatus });

  // --- plan (host) -------------------------------------------------------
  const workPlan: OffsecWorkPlanV2 = prepared ? JSON.parse(readFileSync(join(engagementDir, '00_work_plan.json'), 'utf8')) : createOffsecWorkPlanV2({
    target,
    sourceManifest: readableManifest,
    dependencyGraph,
    maxContextFilesPerUnit: contract.workUnitPolicy.maxContextFilesPerUnit,
  });
  for (const unit of workPlan.units) assertOffsecWorkUnitIntact(workPlan, unit.unitKey);
  const workPlanPath = prepared ? join(engagementDir, '00_work_plan.json') : writeOffsecWorkPlan(engagementDir, workPlan);
  // 계약이 요구하는 01_analysis_plan.json — work plan의 unit 요약을 host가 기록한다.
  const analysisPlanPath = join(engagementDir, '01_analysis_plan.json');
  if (!prepared) writeFileSync(analysisPlanPath, `${JSON.stringify({
    schemaVersion: '1.0.0',
    workPlanSha256: workPlan.workPlanSha256,
    sourceManifestSha256: workPlan.sourceManifestSha256,
    dependencyGraphSha256: workPlan.dependencyGraphSha256,
    unitCount: workPlan.units.length,
    reconSurface: {
      entryPoints: reconResult.entryPoints.length,
      authSurface: reconResult.authSurface.length,
      dataSurface: reconResult.dataSurface.length,
    },
    units: workPlan.units.map((unit) => ({
      unitKey: unit.unitKey,
      sourceUnitId: unit.sourceUnitId,
      ownedFileCount: unit.ownedFiles.length,
      contextFileCount: unit.contextFiles.length,
    })),
  }, null, 2)}\n`, { mode: 0o600 });
  log({
    event: 'HostWorkPlanActivated',
    workPlanSha256: workPlan.workPlanSha256,
    unitCount: workPlan.units.length,
  });

  // --- mission runtime + host wiring -------------------------------------
  const runtimeExists = resume && (selectedBackend(dependencies.runtime ?? {}) === 'postgres' || existsSync(join(engagementDir, 'run-events.jsonl')));
  const missionRuntime = await (runtimeExists ? openMissionRuntime : createMissionRuntime)({
    engagementDir,
    runId: engagementId,
    contractId: contract.id,
    contractVersion: contract.version,
    domain: 'offsec',
    mission: 'assessment',
    ...(maxBudgetUsd !== undefined ? { maxBudgetUsd } : {}),
  }, dependencies.runtime);
  const storage: StorageHealth & { archiveUri?: string } = { pendingReplication: 0, errors: storageWarnings };
  const state = missionRuntime.state;
  const activeLease: AutoRenewingRunLease | undefined = missionRuntime.leaseGuard;

  try {
    if (!(await missionRuntime.read()).inputManifest) {
      const checkpointReceipt = checkpointFileReceipt(engagementDir);
      const preparationReceipts = ['source_manifest.json', 'fanout_decision.json', '00_dependency_graph.json', '00_recon.json', '00_work_plan.json', '01_analysis_plan.json', '.recovery/preanalysis.json', ...(astContextAvailable ? ['00_ast_context.yaml'] : [])].map(name => { const path = join(engagementDir, name), content = readFileSync(path); return { path, sha256: createHash('sha256').update(content).digest('hex'), bytes: content.byteLength }; });
      const checkpointArtifact = createArtifactRef({
        engagementDir,
        name: ASSESS_V2_CHECKPOINT_INPUT,
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
          allowedReadFiles: [checkpointReceipt.path, ...preparationReceipts.map(r => r.path)],
          fileHashes: [checkpointReceipt, ...preparationReceipts],
        },
      });
    }
    let analysisFrozen = false, reviewFrozen = false;
    let resumedSnapshot = await missionRuntime.read();
    if (runtimeExists) {
      const snapshot = resumedSnapshot;
      await restoreAnalysisCheckpoint(missionRuntime, engagementDir, snapshot);
      assertRunInputsIntact(snapshot, engagementDir);
      assertResumeSources(target, engagementDir);
      if (snapshot.status === 'completed' && snapshot.publication) {
        const coverage = snapshot.analysisCheckpoint
          ? JSON.parse(readFileSync(join(engagementDir, COVERAGE_FILE), 'utf8'))
          : legacyCompletedCoverage({ snapshot, units: workPlan.units, sourceErrors: sourceIssues,
              requiredPreanalysisComplete, preanalysisAvailable: astContextAvailable });
        const finalReport = copyPublication(engagementDir, contract.publication.draftArtifact, contract.publication.finalArtifact,
          snapshot.analysisCheckpoint ? coverageAppendix(coverage) : '');
        return { outcome: { texts: [], ledger: [] }, engagementDir, phases: [], finalReport, publicationStatus: 'published', storage, coverage };
      }
      analysisFrozen = !!snapshot.analysisCheckpoint || Object.values(snapshot.attempts).some(a => a.phase !== 'analyze' || a.round === 'cross-unit-followup');
      reviewFrozen = snapshot.analysisCheckpoint?.stage === 'review';
      if (!snapshot.analysisCheckpoint && Object.values(snapshot.attempts).some(a => a.phase !== 'analyze')) {
        throw new AnalysisInterruption('Legacy review input has no sealed coverage checkpoint; retained results require coverage review');
      }
      await recoverLegacyBudget(missionRuntime, snapshot);
      for (const attempt of Object.values(snapshot.attempts)) if (attempt.status === 'started' || attempt.status === 'received') await missionRuntime.append({ type: 'phase.failed', eventId: `${engagementId}:${attempt.phase}:${attempt.round ?? '-'}:${attempt.attempt}:interrupted`, phase: attempt.phase, round: attempt.round, attempt: attempt.attempt, reason: 'Interrupted process; retained outputs and retrying incomplete work' });
    }
    if (resume) {
      resumedSnapshot = await increaseResumeBudget(missionRuntime, resumeOptions, contract.limits.maxBudgetUsd);
      maxBudgetUsd = resumedSnapshot.maxBudgetUsd;
    }
    const adapter = new OffsecDomainAdapter(contract);
    const maxConcurrency = Math.min(input.maxConcurrency ?? 2,
      contract.workUnitPolicy.maximumConcurrency);
    const provider = new AnthropicAgentRuntime(sessionRunner);
    const runtimeBudgetUsd = maxBudgetUsd;
    const runtime = runtimeBudgetUsd === undefined ? provider
      : new BudgetedRuntime(provider, runtimeBudgetUsd,
          request => request.phase === 'analyze' && request.options?.phaseRound !== 'cross-unit-followup' ? maxConcurrency : 1,
          request => runtimeBudgetUsd * ({ analyze: 0.30, review: 0.10, evaluate: 0.05 }[request.phase] ?? 0),
          budgetAccounting(missionRuntime, resumedSnapshot));
    const modelGuard = new ModelIndependenceGuard();
    const phases: PhaseExecution[] = [];
    const combined: SessionOutcome = { texts: [], ledger: [] };
    const onEvent = (event: Parameters<NonNullable<ConstructorParameters<typeof WorkflowHost>[0]['onEvent']>>[0]) => {
      log(event as unknown as Record<string, unknown>);
    };
    const outcomePolicy = ({ role, outcome }: {
      role: string;
      outcome: Parameters<ModelIndependenceGuard['observe']>[1];
    }) => {
      if (process.env.ALLOW_SAME_MODEL) return;
      modelGuard.observe(role === 'reviewer' ? 'review' : 'primary', outcome);
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

    const rootAllowedReadFiles = [
      join(engagementDir, 'source_manifest.json'),
      analysisPlanPath,
      reconPath,
      workPlanPath,
      ...sealedSourceFiles,
      ...sealedDependencyFiles,
    ];
    if (astContextAvailable) rootAllowedReadFiles.push(astContextPath);

    // --- analyze: bounded work (analyzer role, NO verify/feedback) -------
    const workRoot = join(engagementDir, 'work-units');
    mkdirSync(workRoot, { recursive: true, mode: 0o700 });

    const preanalysis = loadPreanalysisEvidence(astContextPath, target, sealedSourceFiles);
    const graphRag = computeGraphRag({ dependencyGraph, astContext: { taint_paths: preanalysis.taintPaths as unknown as NativeTaintPath[] } });
    if (graphRag) {
      log({
        event: 'HostGraphRagComputed',
        taintPaths: graphRag.taintPaths.length,
        communities: graphRag.communities.length,
        filesWithContext: graphRag.fileContextMap.size,
      });
    }

    const unitResults = await executePagedWork({
      units: workPlan.units,
      maxConcurrency,
      maximumWorkUnits: contract.workUnitPolicy.maximumWorkUnits,
      retryRejectedOnce: true,
      shouldRetryRejection: error => !(error instanceof MissionBudgetExhaustedError),
      unitTimeoutMs: 15 * 60 * 1000,
      worker: async (candidate, unitAttempt, abortController) => {
        const unit = assertOffsecWorkUnitIntact(workPlan, candidate.unitKey);
        const prior = resume ? Object.values((await missionRuntime.read()).attempts).filter(a => a.phase === 'analyze' && a.round === unit.unitKey) : [];
        const successful = prior.find(a => a.status === 'completed');
        if (analysisFrozen && !successful) throw new AnalysisInterruption('Unit remains quarantined in the sealed review input; retry it in a new analysis run');
        const previousDir = successful?.artifacts?.[0]?.path;
        const unitDir = previousDir ? resolve(previousDir, '..') : join(workRoot, unit.unitKey, `attempt-${resume ? Math.max(0, ...prior.map(a => a.attempt)) + 1 : unitAttempt}`);
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
        const evidence = writeUnitEvidence(unitDir, unit.ownedFiles.map(file => file.path), preanalysis);
        writeFileSync(explorationInventory, JSON.stringify({
          purpose: 'Optional follow-up context for an observed dependency. Finding ownership remains assignedFiles.',
          sourceFiles: sealedSourceFiles,
        }, null, 2), { mode: 0o600 });
        const unitHost = new WorkflowHost({
          adapter,
          runtime,
          state,
          appendEvent: missionRuntime.append,
          target,
          engagementDir: unitDir,
          runRoot: engagementDir,
          runId: engagementId,
          hostEntrypoint: 'assess',
          allowedReadFiles: [...new Set([...ownedSourceFiles, ...contextSourceFiles, ...sealedSourceFiles, ...sealedDependencyFiles, explorationInventory, evidence.indexPath, evidence.detailPath])],
          signal: abortController.signal,
          ...(activeLease ? { leaseGuard: activeLease } : {}),
          ...(missionRuntime.artifactStore ? { artifactStore: missionRuntime.artifactStore } : {}),
          scope: input.scope,
          onEvent,
          outcomePolicy: ({ role, outcome }) => outcomePolicy({ role, outcome: outcome.usage }),
        });
        const analyze = await unitHost.executePhase({
          id: 'analyze',
          round: unit.unitKey,
          priorArtifactPaths: [],
          deferRunBlocking: true,
          reuseCompleted: resume,
          resultIdentity,
          inputs: {
            workUnit: resultIdentity,
            assignedFiles: unit.ownedFiles.map((file) => file.path),
            dependencyContextFiles: unit.contextFiles.map((file) => file.path),
            explorationInventory,
            evidenceIndex: evidence.indexPath,
            evidenceDetails: evidence.detailPath,
            preanalysis: evidence.summary,
            unresolvedCrossUnitEdges: unit.unresolvedEdges,
            typedDependencyEdges: getUnitTypedEdges(dependencyGraph, unit),
            ...(graphRag ? {
              graphContext: serializeGraphContextForUnit(graphRag, unit.ownedFiles.map((f) => f.path)),
            } : {}),
          },
          providerOptions: {
            model: primaryModel,
            abortController,
            effort: input.effort,
            maxTurns: input.maxTurns,
            phaseRound: unit.unitKey,
            readScope: 'exact',
            workUnit,
            contractPath: V2_CONTRACT_PATH,
          },
        });
        assertOffsecWorkUnitIntact(workPlan, unit.unitKey);
        return {
          unit,
          unitDir,
          analyze,
          findingReceipts: readStandardFindingRecordReceipts(unitDir),
        };
      },
    });

    // A timed-out worker may still be unwinding. Close its attempt now so an
    // independent completed unit can reach review/publication. Late results remain
    // in their attempt directory and cannot complete an already closed attempt.
    const rejectedKeys = new Set(unitResults.filter(result => result.status === 'rejected').map(result => result.unit.unitKey));
    for (const attempt of Object.values((await missionRuntime.read()).attempts)) {
      if (attempt.phase !== 'analyze' || !attempt.round || !rejectedKeys.has(attempt.round)
        || (attempt.status !== 'started' && attempt.status !== 'received')) continue;
      await missionRuntime.append({ type: 'phase.failed', eventId: `${engagementId}:analyze:${attempt.round}:${attempt.attempt}:deferred`,
        phase: attempt.phase, round: attempt.round, attempt: attempt.attempt, reason: 'Work unit deferred; retained outputs and reservation' });
    }

    const completedUnitKeys = unitResults
      .filter((result) => result.status === 'fulfilled')
      .map((result) => result.unit.unitKey);
    const rejected = unitResults.filter((result) => result.status === 'rejected');
    const quarantinedUnits = rejected.map((result) => ({
      unitKey: result.unit.unitKey,
      reason: result.reason instanceof Error ? result.reason.message : String(result.reason),
    }));
    const uncoveredFiles = [...new Set([...sourceIssues.map(issue => issue.path), ...quarantinedUnits.flatMap((q) =>
      workPlan.units.find((u) => u.unitKey === q.unitKey)?.ownedFiles.map((f) => f.path) ?? [],
    )])];
    if (quarantinedUnits.length > 0) {
      log({
        event: 'HostWorkPlanPartialCompletion',
        completedCount: completedUnitKeys.length,
        totalCount: workPlan.units.length,
        quarantinedUnits,
        uncoveredFileCount: uncoveredFiles.length,
      });
    }
    if (completedUnitKeys.length === 0) {
      throw new AnalysisInterruption('OffSec v2 analyze: 완료된 work unit이 없다');
    }

    const fulfilled = unitResults.flatMap((result) =>
      result.status === 'fulfilled' && result.value ? [result.value] : []);
    for (const result of fulfilled) mergeOutcome(result.analyze.outcome.raw);

    // scope assurance — v2에는 verifier phase가 없으므로 verifierEvents를 생략한다.
    const scopeObservations = new Map<string, UnitScopeObservationInput>(fulfilled.map((result) => [
      result.unit.unitKey,
      { vaEvents: result.analyze.outcome.events },
    ]));
    const scopeAssurance: ReturnType<typeof createScopeAssurance> = analysisFrozen && existsSync(join(engagementDir, SCOPE_ASSURANCE_FILE_NAME)) ? JSON.parse(readFileSync(join(engagementDir, SCOPE_ASSURANCE_FILE_NAME), 'utf8')) : createScopeAssurance({
      target, workPlan, completedUnitKeys, observations: scopeObservations, analysisMode: 'v2',
    });
    const scopeAssurancePath = analysisFrozen ? join(engagementDir, SCOPE_ASSURANCE_FILE_NAME) : writeScopeAssurance(engagementDir, scopeAssurance);
    const scopeAssuranceSha256 = fileSha256(scopeAssurancePath);

    const workUnitResultPath = join(engagementDir, '00_work_unit_results.json');
    const temporary = `${workUnitResultPath}.${process.pid}.tmp`;
    if (!analysisFrozen) writeFileSync(temporary, `${JSON.stringify({
      schemaVersion: '1.1.0',
      workPlanSha256: workPlan.workPlanSha256,
      completedUnitKeys,
      quarantinedUnits: quarantinedUnits.length > 0 ? quarantinedUnits : undefined,
      uncoveredFiles: uncoveredFiles.length > 0 ? uncoveredFiles : undefined,
      assurancePath: SCOPE_ASSURANCE_FILE_NAME,
      assuranceSha256: scopeAssuranceSha256,
      units: fulfilled.map(({ unit, analyze, findingReceipts }) => ({
        unitKey: unit.unitKey,
        sourceUnitId: unit.sourceUnitId,
        assignedSourceSha256: unit.assignedSourceSha256,
        unresolvedEdges: unit.unresolvedEdges,
        findingReceipts,
        artifacts: analyze.artifacts.map(({ path, name, sha256, bytes }) => ({ path, name, sha256, bytes })),
      })),
    }, null, 2)}\n`, { mode: 0o600 });
    if (!analysisFrozen) renameSync(temporary, workUnitResultPath);

    // per-unit finding record를 root engagement로 승격.
    const pendingUnitFindings = fulfilled.map(({ unit, unitDir, findingReceipts }) => ({
      unitKey: unit.unitKey,
      unitDir,
      receipts: findingReceipts,
    }));
    for (const unit of pendingUnitFindings) {
      promoteStandardFindingRecords({
        fromEngagementDir: unit.unitDir,
        toEngagementDir: engagementDir,
        expected: unit.receipts,
      });
    }
    if (pendingUnitFindings.length > 0) {
      log({
        event: 'HostUnitFindingsPromoted',
        unitCount: pendingUnitFindings.length,
        findingCount: pendingUnitFindings.reduce((sum, unit) => sum + unit.receipts.length, 0),
      });
    }

    rootAllowedReadFiles.push(
      workUnitResultPath,
      scopeAssurancePath,
      ...fulfilled.flatMap(({ analyze }) => analyze.artifacts.map((artifact) => artifact.path)),
      ...pendingUnitFindings.flatMap((unit) => unit.receipts.map((receipt) =>
        join(engagementDir, 'standard-findings', receipt.recordName))),
    );

    const refreshCanonicalFindingReadSet = (): void => {
      rootAllowedReadFiles.push(...readStandardFindingRecordReceipts(engagementDir).map((receipt) =>
        join(engagementDir, 'standard-findings', receipt.recordName)));
    };

    // --- root host: review -> evaluate -> report -------------------------
    const host = new WorkflowHost({
      adapter,
      runtime,
      state,
      appendEvent: missionRuntime.append,
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
      priorArtifactPaths?: readonly string[];
    }): Promise<PhaseExecution> => {
      const { legacy: phase } = adapter.getPhase(options.id);
      const artifacts = adapter.renderArtifacts(phase);
      const hosted = await retryProvider(() => host.executePhase({
        id: options.id,
        deferRunBlocking: true,
        reuseCompleted: resume,
        round: options.round,
        inputs: options.inputs,
        ...(options.priorArtifactPaths ? { priorArtifactPaths: options.priorArtifactPaths } : {}),
        providerOptions: {
          model: phase.role === 'reviewer' ? reviewModel : primaryModel,
          effort: input.effort,
          maxTurns: options.round === 'cross-unit-followup' ? Math.min(input.maxTurns ?? 120, 32) : input.maxTurns,
          phaseRound: options.round,
          readScope: 'exact',
          contractPath: V2_CONTRACT_PATH,
        },
      }));
      void artifacts;
      const result = hosted.result;
      const outcome = hosted.outcome.raw;
      mergeOutcome(outcome);
      combined.structuredOutput = result;
      const execution: PhaseExecution = { phase: phase.id, role: phase.role, result, outcome };
      phases.push(execution);
      return execution;
    };

    // One bounded session for model-proposed questions grounded in real source.
    const discoveryBudgetExhausted = maxBudgetUsd !== undefined && committedBudget(await missionRuntime.read()) >= maxBudgetUsd * 0.7;
    const followups: ReturnType<typeof selectAnalysisFollowups> = analysisFrozen && existsSync(join(engagementDir, '00_followup_plan.json')) ? JSON.parse(readFileSync(join(engagementDir, '00_followup_plan.json'), 'utf8')) : selectAnalysisFollowups({
      target, units: workPlan.units, maximum: discoveryBudgetExhausted ? 0 : maxFollowupHypotheses,
      handoffs: fulfilled.flatMap(({ unit, analyze }) => analyze.artifacts
        .filter(artifact => artifact.name === '02_analysis_handoff.yaml')
        .map(artifact => ({ unitKey: unit.unitKey, path: artifact.path }))),
    });
    const followupPlanPath = join(engagementDir, '00_followup_plan.json');
    if (!analysisFrozen) writeFileSync(followupPlanPath, `${JSON.stringify(followups, null, 2)}\n`, { mode: 0o600 });
    rootAllowedReadFiles.push(followupPlanPath);
    const analysisCoveragePath = join(engagementDir, COVERAGE_FILE);
    const analysisCoverage = {
      complete: uncoveredFiles.length === 0 && followups.selected.length === 0 && requiredPreanalysisComplete,
      requiredPreanalysisComplete,
      sourceErrors: sourceIssues,
      completedUnits: completedUnitKeys.length, totalUnits: workPlan.units.length, uncoveredFiles,
      semanticCoverage: 'not-proven' as const,
      ownedFilesRead: scopeAssurance.units.reduce((sum, unit) => sum + unit.va.ownedFilesRead, 0),
      ownedFileCount: workPlan.units.reduce((sum, unit) => sum + unit.ownedFiles.length, 0),
      preanalysisAvailable: preanalysis.available,
      followupQuestions: followups.selected.length,
      deferredFollowupQuestions: followups.omitted + followups.selected.length,
    };
    if (!resumedSnapshot.analysisCheckpoint) {
      atomicPrivateWrite(analysisCoveragePath, JSON.stringify(analysisCoverage, null, 2) + '\n');
      await sealAnalysisCheckpoint(missionRuntime, engagementDir, 'units');
    }
    rootAllowedReadFiles.push(analysisCoveragePath);
    let followupFailure: string | undefined;
    if (followups.selected.length > 0 && !reviewFrozen) {
      for (const unit of workPlan.units) assertOffsecWorkUnitIntact(workPlan, unit.unitKey);
      refreshCanonicalFindingReadSet();
      try { await executePhase({ id: 'analyze', round: 'cross-unit-followup', inputs: {
        workUnitAnalysis: { resultsPath: workUnitResultPath }, followupHypotheses: followups.selected,
        instruction: 'Resolve only these cross-unit questions. Reuse observations and seek counterevidence. Do not restart a whole-repository audit or request another follow-up.',
      } }); } catch (error) {
        if (!recoverableFailure(error)) throw error;
        followupFailure = String(error); log({ event: 'HostFollowupDeferred', reason: followupFailure });
      }
      for (const unit of workPlan.units) assertOffsecWorkUnitIntact(workPlan, unit.unitKey);
    }
    if (!reviewFrozen) {
      analysisCoverage.complete = uncoveredFiles.length === 0 && !followupFailure && requiredPreanalysisComplete;
      analysisCoverage.deferredFollowupQuestions = followups.omitted + (followupFailure ? followups.selected.length : 0);
      atomicPrivateWrite(analysisCoveragePath, JSON.stringify({ ...analysisCoverage,
        disclosure: 'complete describes work-unit execution, not security completeness.',
        preanalysisLimitations: preanalysis.limitations,
        unresolved: [...(!requiredPreanalysisComplete ? ['Required Semgrep preanalysis did not complete'] : []), ...(followupFailure ? [followupFailure] : []), ...fulfilled.flatMap(({ analyze }) => analyze.result.unresolved ?? []), ...phases.flatMap(phase => phase.result.unresolved ?? [])],
        invalidFollowupRequests: followups.invalid,
      }, null, 2) + '\n');
      await sealAnalysisCheckpoint(missionRuntime, engagementDir, 'review');
    } else Object.assign(analysisCoverage, JSON.parse(readFileSync(analysisCoveragePath, 'utf8')));
    refreshCanonicalFindingReadSet();
    const review = await executePhase({
      id: 'review',
      inputs: {
        workUnitResults: workUnitResultPath,
        completedUnitKeys,
        analysisCoverage: analysisCoveragePath,
        followupPlan: followupPlanPath,
        ...(uncoveredFiles.length > 0 ? { uncoveredFiles } : {}),
      },
    });
    refreshCanonicalFindingReadSet();
    const evaluate = await executePhase({
      id: 'evaluate',
      priorArtifactPaths: review.result.artifacts.map((name) => join(engagementDir, name)),
      inputs: { reviewArtifacts: review.result.artifacts },
    });
    refreshCanonicalFindingReadSet();
    await executePhase({
      id: 'report',
      priorArtifactPaths: [...new Set([
        ...evaluate.result.artifacts.map((name) => join(engagementDir, name)),
        ...phases.flatMap((p) => p.result.artifacts.map((name) => join(engagementDir, name))),
      ])],
      inputs: { evaluationArtifacts: evaluate.result.artifacts,
        ...(!analysisCoverage.complete ? { publicationNotice: '분석 범위 미완료', uncoveredFiles } : {}) },
    });

    // --- publication -----------------------------------------------------
    assertRunInputsIntact(await missionRuntime.read(), engagementDir);
    const appendix = coverageAppendix(analysisCoverage);
    assertStandardFindingsRepresented(
      engagementDir,
      join(engagementDir, contract.publication.draftArtifact),
    );
    const allowEmptyCandidates = readStandardFindingRecordReceipts(engagementDir).length === 0;
    recordPublicationIntent(engagementDir, contract.publication.finalArtifact, contract.publication.draftArtifact, appendix);
    const finalReport = publishV2Report(engagementDir, allowEmptyCandidates, contract.publication, appendix);
    const expectedFinalReport = resolve(reportDirectory(engagementDir), contract.publication.finalArtifact);
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

    return { outcome: combined, engagementDir, phases, finalReport, publicationStatus: 'published', storage,
      coverage: analysisCoverage };
  } finally {
    try {
      if (missionRuntime.artifactStore) storage.archiveUri = (await archiveRun(engagementDir, missionRuntime.artifactStore)).uri;
    } catch (error) { storage.errors.push(`archive incomplete: ${String(error)}`); }
    if (missionRuntime.artifactStore instanceof ResilientArtifactStore) {
      const health = missionRuntime.artifactStore.health(); storage.pendingReplication = health.pendingReplication; storage.errors.push(...health.errors);
    }
    if ('recoveryWarnings' in state && Array.isArray(state.recoveryWarnings)) storage.errors.push(...state.recoveryWarnings);
    await missionRuntime.close();
  }
}

function parseArgs(argv: string[]): { flags: Map<string, string>; positional: string[] } {
  const flags = new Map<string, string>();
  const positional: string[] = [];
  for (const arg of argv) {
    const m = /^--([a-z-]+)=(.*)$/.exec(arg);
    if (m?.[1] !== undefined) flags.set(m[1], m[2] ?? '');
    else if (arg === '--resume' || arg === '--no-cost-guard') flags.set(arg.slice(2), 'true');
    else positional.push(arg);
  }
  return { flags, positional };
}

export type AssessV2Result = Awaited<ReturnType<typeof executeAssessV2>>;
async function assessmentBoundary(input: AssessV2Input, dependencies: AssessV2Dependencies, resume = false, resumeOptions: AssessV2ResumeOptions = {}): Promise<AssessV2Result> {
  if (!input.engagementDir) input = { ...input, ...allocateRunLocation(input) };
  try { return await executeAssessV2(input, dependencies, resume, resumeOptions); }
  catch (error) {
    if (!recoverableFailure(error)) throw error;
    const finalReport = preservePartialReport(input.engagementDir!, error);
    const storage: StorageHealth & { archiveUri?: string } = { pendingReplication: 0, errors: [String(error)] };
    try {
      const store = new ResilientArtifactStore(input.engagementDir!, dependencies.runtime?.artifactStore);
      storage.archiveUri = (await archiveRun(input.engagementDir!, store)).uri;
      const health = store.health(); storage.pendingReplication = health.pendingReplication; storage.errors.push(...health.errors);
    } catch (archiveError) { storage.errors.push(`partial archive incomplete: ${String(archiveError)}`); }
    return { outcome: { texts: [], ledger: [] }, engagementDir: input.engagementDir!, phases: [], finalReport,
      publicationStatus: 'partial', storage,
      coverage: partialCoverage(input.engagementDir!) };
  }
}

export async function assessV2(input: AssessV2Input, dependencies: AssessV2Dependencies = {}): Promise<AssessV2Result> {
  return assessmentBoundary(input, dependencies);
}

export async function resumeAssessV2(engagementDir: string, dependencies: AssessV2Dependencies = {}, options: AssessV2ResumeOptions = {}): Promise<AssessV2Result> {
  const checkpoint = checkpointInput<AssessV2Input>(engagementDir);
  if (checkpoint.storageBackend && checkpoint.storageBackend !== selectedBackend(dependencies.runtime ?? {})) throw new Error(`resume requires the original ${checkpoint.storageBackend} state backend`);
  return assessmentBoundary(checkpoint.input, dependencies, true, options);
}

async function main(): Promise<void> {
  const { flags, positional } = parseArgs(process.argv.slice(2));
  const [targetArg, ...rest] = positional;
  if (!targetArg) {
    console.error(
      '사용: pnpm tsx src/runtime/missions/assess-v2.ts <진단대상 절대경로> [지시문]\n' +
        '  --model=<alias>          기본 opus\n' +
        '  --review-model=<alias>   기본 sonnet\n' +
        '  --effort=<low..max>\n' +
        '  --max-turns=<n>\n' +
        '  --max-usd=<n>            예산 상한 (기본 무제한, 재개 시 증액 가능)\n' +
        '  --no-cost-guard         금액 예산 상한 해제 (재개 포함)\n' +
        '  --semgrep=<required|best-effort|off>\n' +
        '  --work-units=<auto|force>  v2는 항상 작업 분할 사용\n' +
        '  --max-concurrency=<n>\n' +
        '  --engagement-dir=<절대경로> [--resume]',
    );
    process.exitCode = 1;
    return;
  }
  if (!targetArg.startsWith('/')) throw new Error(`진단 대상은 절대경로여야 한다: ${targetArg}`);
  const scope = rest.length > 0 ? rest.join(' ') : undefined;
  const maxTurnsFlag = flags.get('max-turns');
  const maxUsdFlag = flags.get('max-usd');
  const maxConcurrencyFlag = flags.get('max-concurrency');
  const semgrepFlag = flags.get('semgrep');
  const workUnitsFlag = flags.get('work-units');
  const effortFlag = flags.get('effort');
  const engagementDirFlag = flags.get('engagement-dir');
  if (flags.has('resume') && !engagementDirFlag) throw new Error('--resume requires --engagement-dir');

  const input: AssessV2Input = {
    target: targetArg,
    ...(scope ? { scope } : {}),
    ...(flags.get('model') ? { model: flags.get('model') } : {}),
    ...(flags.get('review-model') ? { reviewModel: flags.get('review-model') } : {}),
    ...(effortFlag ? { effort: effortFlag as SessionSpec['effort'] } : {}),
    ...(maxTurnsFlag !== undefined ? { maxTurns: Number(maxTurnsFlag) } : {}),
    ...(maxUsdFlag ? { maxBudgetUsd: Number(maxUsdFlag) } : {}),
    ...(flags.has('no-cost-guard') ? { noCostGuard: flags.get('no-cost-guard') === 'true' } : {}),
    ...(semgrepFlag ? { semgrepMode: semgrepFlag as SemgrepMode } : {}),
    ...(workUnitsFlag ? { workUnitMode: workUnitsFlag as WorkUnitMode } : {}),
    ...(maxConcurrencyFlag !== undefined ? { maxConcurrency: Number(maxConcurrencyFlag) } : {}),
    ...(flags.has('max-followup-hypotheses') ? { maxFollowupHypotheses: Number(flags.get('max-followup-hypotheses')) } : {}),
    ...(engagementDirFlag ? { engagementDir: engagementDirFlag } : {}),
  };

  if (!input.engagementDir) Object.assign(input, allocateRunLocation(input));
  mkdirSync(dirname(input.engagementDir!), { recursive: true });
  input.engagementDir = existsSync(input.engagementDir!) ? realpathSync(input.engagementDir!) : join(realpathSync(dirname(input.engagementDir!)), basename(input.engagementDir!));
  const release = acquireRunLock(join(dirname(input.engagementDir), `.${basename(input.engagementDir)}.agent.lock`));
  let result: AssessV2Result;
  try { result = flags.has('resume') ? await resumeAssessV2(input.engagementDir, {}, { maxBudgetUsd: input.maxBudgetUsd, noCostGuard: input.noCostGuard }) : await assessV2(input); }
  finally { release(); }
  const { engagementDir, finalReport, phases, coverage } = result;
  console.log(`OffSec v2 ${coverage.complete ? '진단 완료' : '부분 분석 — 범위 미완료'}: ${engagementDir}`);
  console.log(`최종 보고서: ${finalReport}`);
  console.log(`실행 phase: ${phases.map((p) => p.phase).join(' -> ')}`);
  if (!coverage.complete) process.exitCode = 2;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.stack ?? error.message : String(error));
    process.exitCode = 1;
  });
}
