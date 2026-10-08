import { openAnalysisReuse } from '../planning/source-revision.js';
import { coordinateReview, hasPendingReview } from './review-loop.js';
import { retainFailedTaskClaims } from './retained-claims.js';
import { schedulerJournal } from '../workflow/scheduler-journal.js';
import { reconcileUsageReceipts } from '../workflow/usage-ledger.js';
import { beginAnalysisRevision, finishRevisionCleanup } from './analysis-revision.js';
import { finishEvaluationReopen } from './evaluation-recovery.js';
import { createAnalysisTasks, analysisTaskRequest } from '../planning/task-planner.js';
import { readAnalysisAssessments } from '../planning/analysis-assessments.js';
import { createSourceSnapshot, loadSourceSnapshot, SOURCE_SNAPSHOT_FILE } from '../source-snapshot.js';
import { readScannerPlan, saveScannerArtifacts, writeScannerDependencies } from '../planning/scanner-contract.js';
import { budgetAccounting, committedBudget, recoverLegacyBudget, increaseResumeBudget, type ResumeBudgetOptions } from './assessment-budget.js';
import { COVERAGE_FILE, coverageAppendix, sealAnalysisCheckpoint, restoreAnalysisCheckpoint, finalizeCoverage } from './analysis-checkpoint.js';
import { acquireRunLock } from '../workflow/run-lock.js';
import { recoveryLogger } from '../workflow/recovery-log.js';
import { AnalysisInterruption, assertResumeSources, checkpointInput, partialCoverage, preservePartialReport, recoverableFailure, retryProvider } from './assessment-recovery.js';
import { allocateRunLocation, reportDirectory } from '../workflow/run-location.js';
import { atomicPrivateWrite, privateDirectory } from '../workflow/storage-files.js';
import { archiveRun } from '../workflow/run-archive.js';
import { ResilientArtifactStore, type StorageHealth } from '../workflow/resilient-artifacts.js';
import { copyPublication, recordPublicationIntent } from './publication-files.js';
import { assertRunInputsIntact } from '../workflow/host-integrity.js';
/** Single source assessment pipeline: host snapshot/preanalysis -> Scanner ->
 * validated task graph -> adaptive Analyzer queue -> independent review and scoped
 * evidence loop -> evaluation -> draft -> host publication. */
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
import { basename, dirname, join, resolve, relative } from 'node:path';
import { createSourceReadCoverage, type SourceReadCoverage } from '../workflow/scope-assurance.js';
import { parseAssessV2Args, parseAnalysisTools, resolveAnalysisSelection, type AnalysisMode, type AnalysisTool } from './analysis-selection.js';

import { loadOffsecContract, type PhaseResult } from '../offsec-contract.js';
import { OffsecDomainAdapter } from '../domains/offsec.js';
import { ReviewFinalizationError } from '../v2-review-resolution.js';
import { REVIEW_PATCH_GUIDANCE } from '../review-artifact-patch.js';
import { loadReviewProgress, mergeReviewReuse, stageReviewReopen, finishReviewReopen, reviewProgressAdvance, type ReviewReuse } from '../review-progress.js';
import { readStandardFindings } from '../finding-contract.js';
import { ReviewSourceDeliveryError, validateV2ReviewSourceReads, validateV2EvaluationArtifact } from '../v2-evaluation.js';
import { EVALUATION_CLASSIFICATION, readEvaluationProjection, writeEvaluationProjection } from '../evaluation-projection.js';
import { canonicalFindingAppendix } from '../report-appendix.js';
import { ProviderRuntimeFailure, type ProviderRuntimeEvent } from '../providers/provider-runtime.js';
import { AnthropicAgentRuntime } from '../providers/anthropic-agent-sdk.js';
import { BudgetedRuntime, MissionBudgetExhaustedError } from '../providers/budgeted-runtime.js';
import { runSession, type SessionOutcome, type SessionSpec } from '../session-runner.js';
import { WorkflowHost } from '../workflow/engine.js';
import { executeTaskQueue, retryDisposition, TerminationUnknownError, type TaskControls } from '../workflow/task-scheduler.js';
import {
  createMissionRuntime,
  selectedBackend,
  openMissionRuntime,
  type MissionRuntimeOptions,
} from '../workflow/mission-runtime.js';
import { createArtifactRef, verifyRunArtifactRef } from '../contracts/result-contract.js';
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
import { SHARED_KNOWLEDGE_SNAPSHOT, snapshotSharedKnowledge, type SharedKnowledgeContext } from '../shared-knowledge.js';
import {
  assertStandardFindingsRepresented,
  promoteStandardFindingRecords,
  readStandardFindingRecordReceipts,
  type StandardFindingRecordReceipt,
} from '../finding-contract.js';
import { makeEngagementId, recordOffsecPublication, resolveAssessmentBudget, type CostPolicy, validateSourcePublicationCandidate as validateOffsecPublicationCandidate } from './assessment-support.js';
import type { PhaseExecution, SemgrepMode, WorkUnitMode } from './assessment-types.js';

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
export const DEFAULT_V2_AGENT_CAPACITY = {
  maxFilesPerAgent: 24,
  maxSourceTokensPerAgent: 24_000,
  maxContextEstimatedTokensPerUnit: 16_000,
} as const;

export type AssessV2Input = {
  target: string;
  /** Optional previous run for validated, dependency-scoped source reuse. */
  reuseFrom?: string;
  /** Explicit AST mode runs source assessment with optional selected tools. */
  mode?: AnalysisMode;
  /** [] disables external tools; ['semgrep'] requires Semgrep unless best-effort is explicit. */
  tools?: AnalysisTool[];
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
  /** Monetary accounting only by default; enforcement requires explicit opt-in. */
  costPolicy?: CostPolicy;
  maxBudgetUsd?: number;
  semgrepMode?: SemgrepMode;
  workUnitMode?: WorkUnitMode;
  maxConcurrency?: number;
  /** Maximum owned source files per analysis session; default 24. */
  maxFilesPerAgent?: number;
  /** Estimated source tokens per session; oversized files are isolated; default 24,000. */
  maxSourceTokensPerAgent?: number;
  /** At most one extra session for evidence-backed cross-unit questions. 0 disables it. */
  maxFollowupHypotheses?: number;
  noCostGuard?: boolean;
};

export type AssessV2ResumeOptions = ResumeBudgetOptions;

export type AssessV2Dependencies = {
  sessionRunner?: typeof runSession;
  runtime?: MissionRuntimeOptions;
  signal?: AbortSignal;
  onEvent?: (event: Record<string, unknown>) => void;
  scheduler?: { controlIntervalMs?: number; retryBaseMs?: number; unitTimeoutMs?: number; unitIdleTimeoutMs?: number; cancellationGraceMs?: number; resourceCapacity?: () => number; admissionController?: import('../workflow/admission-controller.js').AdmissionController };
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
 * 검토·분류·범위·출처 게이트를 모두 통과해야 발행한다.
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
    appendix: candidate === draft ? appendix : '',
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
    sourceReadCoverage?: SourceReadCoverage;
    semanticCoverage: 'not-proven'; ownedFilesRead: number; ownedFileCount: number;
    preanalysisAvailable: boolean; preanalysisLimitations?: string[]; followupQuestions: number; deferredFollowupQuestions: number; requiredPreanalysisComplete?: boolean };
}> {
  // --- preflight ---------------------------------------------------------
  if (!input.engagementDir) input = { ...input, ...allocateRunLocation(input) };
  let target = resolve(input.target);
  const engagementId = input.engagementId ?? makeEngagementId(target, new Date());
  const nunchiRoot = join(target, NUNCHI_DIR);
  const engagementDir = resolve(input.engagementDir!);
  const inventoried = resume && existsSync(join(engagementDir, SOURCE_SNAPSHOT_FILE));
  const prepared = resume && existsSync(join(engagementDir, '.recovery', 'preanalysis.json')) && existsSync(join(engagementDir, '00_work_plan.json'));
  const semgrepMode = input.semgrepMode ?? 'best-effort';
  const workUnitMode = input.workUnitMode ?? 'auto';
  const contract = loadOffsecContract(V2_CONTRACT_PATH);
  if (!contract.version.startsWith('2.')) {
    throw new Error(`assess-v2에는 v2 계약이 필요하다: ${contract.version}`);
  }
  const sessionRunner = dependencies.sessionRunner ?? runSession;
  let maxBudgetUsd = resolveAssessmentBudget(resume ? { ...input, ...resumeOptions, costPolicy: resumeOptions.costPolicy ?? 'record-only' } : input, contract.limits.maxBudgetUsd);
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
  if (input.maxConcurrency !== undefined && (!Number.isSafeInteger(input.maxConcurrency) || input.maxConcurrency < 1)) {
    throw new Error(`maxConcurrency가 잘못됐다: ${input.maxConcurrency}`);
  }
  const maxFilesPerAgent = input.maxFilesPerAgent ?? DEFAULT_V2_AGENT_CAPACITY.maxFilesPerAgent;
  const maxSourceTokensPerAgent = input.maxSourceTokensPerAgent ?? DEFAULT_V2_AGENT_CAPACITY.maxSourceTokensPerAgent;
  for (const [name, value] of Object.entries({ maxFilesPerAgent, maxSourceTokensPerAgent })) {
    if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${name} must be a positive safe integer`);
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
  const auditLog = recoveryLogger(engagementDir, 'host-ledger.jsonl', storageWarnings);
  const log = (event: Record<string, unknown>) => {
    auditLog({ at: new Date().toISOString(), ...event });
    try { dependencies.onEvent?.(event); } catch (error) { storageWarnings.push(`Event callback failed: ${String(error)}`); }
  };

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
  const schedulingEvent = await schedulerJournal(engagementDir, event => log(event as unknown as Record<string, unknown>));
  if (runtimeExists) {
    const priorState = await missionRuntime.read();
    if (priorState.contractVersion !== contract.version) throw new Error('This run uses an incompatible assessment contract; preserve it and start a new run.');
    finishRevisionCleanup(engagementDir, priorState.analysisRevision ?? 0);
    finishEvaluationReopen(engagementDir, priorState);
    await reconcileUsageReceipts(missionRuntime, engagementDir);
    await recoverLegacyBudget(missionRuntime, await missionRuntime.read());
    maxBudgetUsd = (await increaseResumeBudget(missionRuntime, resumeOptions, contract.limits.maxBudgetUsd)).maxBudgetUsd;
  }

  // --- recon (host) ------------------------------------------------------
  // Source inventory is deterministic; Scanner subsequently replaces structural ownership.
  const fanoutPlan = inventoried ? { manifest: JSON.parse(readFileSync(join(engagementDir, 'source_manifest.json'), 'utf8')), decision: JSON.parse(readFileSync(join(engagementDir, 'fanout_decision.json'), 'utf8')) } : agentPlan.initFanoutPlan({
    engagementDir,
    target,
    excludePaths: [nunchiRoot, join(target, 'reports'), engagementDir, ...(input.excludePaths ?? [])],
    flow: 'standard',
    vaMode: 'sequential',
    verificationMode: 'VA_ONLY',
    maxFeedbackIterations: 0,
  });
  const sourceManifest = fanoutPlan.manifest as {
    hash: string; content_hash?: string; target_realpath: string; source_files: string[]; dependency_files?: string[]; security_resource_files?: string[]; security_resource_receipts?: Array<{ path: string; sha256?: string }>; source_file_count?: number;
    source_receipts?: Array<{ path: string; sha256?: string }>; dependency_receipts?: Array<{ path: string; sha256?: string }>;
    source_errors?: Array<{ path: string; code: string }>;
    units: Array<{ id: string; files: string[] }>;
  };
  if (!prepared) {
    const extra = [...(sourceManifest.dependency_files ?? []), ...(sourceManifest.security_resource_files ?? [])]
      .filter(file => !sourceManifest.source_files.includes(file));
    for (const file of extra) {
      const owner = [...sourceManifest.units].sort((a, b) => b.id.length - a.id.length)
        .find(unit => file.startsWith(`${unit.id}/`)) ?? sourceManifest.units[0];
      if (owner) owner.files.push(file);
      else sourceManifest.units.push({ id: 'resources', files: [file] });
    }
    sourceManifest.source_files = [...new Set([...sourceManifest.source_files, ...extra])].sort();
    sourceManifest.source_file_count = sourceManifest.source_files.length;
    sourceManifest.source_receipts = [...new Map([...(sourceManifest.source_receipts ?? []), ...(sourceManifest.dependency_receipts ?? []), ...(sourceManifest.security_resource_receipts ?? [])].map(file => [file.path, file])).values()];
  }
  const frozen = createSourceSnapshot({ target: input.target, engagementDir,
    files: [...(sourceManifest.source_receipts ?? sourceManifest.source_files.map(path => ({ path }))), ...(sourceManifest.dependency_receipts ?? []), ...(sourceManifest.security_resource_receipts ?? [])],
  });
  target = frozen.target;
  if (!prepared) {
    sourceManifest.target_realpath = target;
    const manifestTools = require('../../../domains/offsec/lib/ch015/source-manifest.js');
    sourceManifest.hash = sourceManifest.content_hash = manifestTools.sourceManifestContentHash(sourceManifest);
    atomicPrivateWrite(join(engagementDir, 'source_manifest.json'), JSON.stringify(sourceManifest, null, 2) + '\n');
  }
  const sourceIssues = sourceManifest.source_errors ?? [];
  const unreadablePaths = new Set(sourceIssues.map(issue => issue.path));
  let readableManifest = { ...sourceManifest,
    source_files: sourceManifest.source_files.filter(path => !unreadablePaths.has(path)),
    units: sourceManifest.units.map(unit => ({ ...unit, files: unit.files.filter(path => !unreadablePaths.has(path)) })).filter(unit => unit.files.length),
  };
  if (!readableManifest.source_files.length) throw new AnalysisInterruption('No readable source files; inventory and read errors are retained');
  let dependencyGraph: DependencyGraph = prepared ? JSON.parse(readFileSync(join(engagementDir, '00_dependency_graph.json'), 'utf8')) : createDependencyGraph({
    target, sourceManifest: readableManifest,
  });
  if (!prepared) atomicPrivateWrite(join(engagementDir, '00_inventory_graph.json'), JSON.stringify(dependencyGraph, null, 2) + '\n');
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
    stats: astOutcome.stats,
  });
  if (Number(astOutcome.stats?.files_failed) > 0 || Number(astOutcome.stats?.files_with_syntax_errors) > 0 || Number(astOutcome.stats?.semgrep_diagnostics) > 0) {
    log({ event: 'HostPreanalysisWarning', reason: 'Parser failures or partial syntax evidence are recorded; original source analysis remains required.', stats: astOutcome.stats });
  }
  const requiredPreanalysisComplete = semgrepMode !== 'required' || semgrepStatus === 'complete';
  if (!requiredPreanalysisComplete) log({ event: 'HostRequiredPreanalysisPending', reason: astOutcome.semgrep?.error ?? semgrepStatus });
  if (!requiredPreanalysisComplete) {
    throw new AnalysisInterruption(`Selected tool semgrep did not complete (${semgrepStatus}): ${astOutcome.semgrep?.error ?? 'no completion receipt'}. No model analysis started; repair the tool and resume, or start a new run with --tools none / --semgrep best-effort.`);
  }

  const sourceReuse = input.reuseFrom ? openAnalysisReuse(resolve(input.reuseFrom), engagementDir, readableManifest.source_files, dependencyGraph, contract.version, input.scope) : undefined;
  if (!prepared) {
    const scannerDependencies = writeScannerDependencies(engagementDir, dependencyGraph);
    const scannerProvider = new AnthropicAgentRuntime(sessionRunner);
    const scannerRuntime = maxBudgetUsd === undefined ? scannerProvider : new BudgetedRuntime(scannerProvider, maxBudgetUsd, () => 1, () => maxBudgetUsd! * 0.8, budgetAccounting(missionRuntime, await missionRuntime.read()));
    let scannerControls: TaskControls | undefined;
    const scannerHost = new WorkflowHost({ adapter: new OffsecDomainAdapter(contract), runtime: scannerRuntime,
      state, appendEvent: missionRuntime.append, target, engagementDir, runId: engagementId, hostEntrypoint: 'assess',
      allowedReadFiles: [...sealedSourceFiles, ...sealedDependencyFiles, join(engagementDir, 'source_manifest.json'), join(engagementDir, '00_inventory_graph.json'), scannerDependencies, reconPath],
      ...(activeLease ? { leaseGuard: activeLease } : {}), artifactStore: missionRuntime.artifactStore,
      onEvent: event => {
        if (event.event === 'ProviderPressure') scannerControls?.pressure(event.reason ?? 'Provider pressure', event.retryAfterMs);
        else scannerControls?.progress();
        log(event as unknown as Record<string, unknown>);
      },
    });
    const scannerTasks = await executeTaskQueue({ units: [{ unitKey: 'scanner' }], ...dependencies.scheduler, signal: dependencies.signal, maxConcurrency: 1,
      unitIdleTimeoutMs: dependencies.scheduler?.unitIdleTimeoutMs ?? 15 * 60 * 1000,
      onEvent: schedulingEvent,
      worker: async (_, __, abortController, controls) => { scannerControls = controls; return scannerHost.executePhase({ id: 'recon', maximumAttempts: 1, reuseCompleted: resume, trustedOutcome: sourceReuse?.scanner(engagementDir),
        inputs: { sourceSnapshotId: frozen.snapshot.id, inventory: join(engagementDir, 'source_manifest.json'),
          dependencyGraph: join(engagementDir, '00_inventory_graph.json'), recon: reconPath,
          resolvedDependencies: scannerDependencies,
          sourceFiles: readableManifest.source_files, instruction: 'Inspect project structure and assign all source files; the host splits large units into execution tasks. Do not report vulnerabilities.' },
        providerOptions: { model: primaryModel, effort: input.effort, maxTurns: input.maxTurns, contractPath: V2_CONTRACT_PATH, readScope: 'exact', abortController },
      }); },
    });
    if (scannerTasks[0]?.status !== 'fulfilled') throw new AnalysisInterruption(`Scanner planning failed: ${String(scannerTasks[0]?.reason)}`);
    const scannerPlan = readScannerPlan(engagementDir, readableManifest.source_files, dependencyGraph);
    saveScannerArtifacts(engagementDir, scannerPlan, frozen.snapshot.id);
    readableManifest = { ...readableManifest, units: scannerPlan.units.map(unit => ({ id: unit.id, files: unit.files })) };
    dependencyGraph = createDependencyGraph({ target, sourceManifest: readableManifest });
    writeDependencyGraph(engagementDir, dependencyGraph);
  }

  // --- plan (host) -------------------------------------------------------
  const workPlan: OffsecWorkPlanV2 = prepared ? JSON.parse(readFileSync(join(engagementDir, '00_work_plan.json'), 'utf8')) : createOffsecWorkPlanV2({
    target,
    sourceManifest: readableManifest,
    dependencyGraph,
    maxContextFilesPerUnit: contract.workUnitPolicy.maxContextFilesPerUnit,
    maxContextEstimatedTokensPerUnit: DEFAULT_V2_AGENT_CAPACITY.maxContextEstimatedTokensPerUnit,
    maxOwnedFilesPerUnit: maxFilesPerAgent,
    maxOwnedEstimatedTokensPerUnit: maxSourceTokensPerAgent,
  });
  const analysisTasks = createAnalysisTasks(workPlan, readScannerPlan(engagementDir, readableManifest.source_files), maxSourceTokensPerAgent);
  const maxConcurrency = Math.min(input.maxConcurrency ?? analysisTasks.length, analysisTasks.length);
  if (!prepared) atomicPrivateWrite(join(engagementDir, '01_execution_tasks.json'), JSON.stringify(analysisTasks, null, 2) + '\n');
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
    maxConcurrency,
    planningPolicy: workPlan.planningPolicy,
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
      estimatedTokens: unit.estimatedTokens,
      ownedEstimatedTokens: unit.contextSelectionReceipt.ownedEstimatedTokens,
      oversizedOwnedFiles: unit.oversizedOwnedFiles ?? [],
    })),
  }, null, 2)}\n`, { mode: 0o600 });
  log({
    event: 'HostWorkPlanActivated',
    workPlanSha256: workPlan.workPlanSha256,
    unitCount: workPlan.units.length,
    maxConcurrency,
    planningPolicy: workPlan.planningPolicy,
  });

    if (!(await missionRuntime.read()).inputManifest) {
      const checkpointReceipt = checkpointFileReceipt(engagementDir);
      const preparationReceipts = [SOURCE_SNAPSHOT_FILE, '00_scanner_dependencies.json', '00_scanner_plan.json', 'scan_manifest.json', 'security_surface_map.json', 'interface_inventory.json', 'scan_plan.json', 'source_manifest.json', 'fanout_decision.json', '00_dependency_graph.json', '00_recon.json', '00_work_plan.json', '01_analysis_plan.json', '01_execution_tasks.json', '.recovery/preanalysis.json', ...(astContextAvailable ? ['00_ast_context.yaml'] : [])].map(name => { const path = join(engagementDir, name), content = readFileSync(path); return { path, sha256: createHash('sha256').update(content).digest('hex'), bytes: content.byteLength }; });
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
      let snapshot = resumedSnapshot;
      await restoreAnalysisCheckpoint(missionRuntime, engagementDir, snapshot);
      assertRunInputsIntact(snapshot, engagementDir);
      assertResumeSources(target, engagementDir);
      finishReviewReopen({ engagementDir, target, runId: engagementId, model: reviewModel, revision: snapshot.analysisRevision ?? 0 });
      const completedReview = Object.values(snapshot.attempts).findLast(attempt => attempt.phase === 'review'
        && attempt.status === 'completed' && !attempt.superseded);
      if (completedReview && !hasPendingReview(engagementDir)) {
        // Old completed reviews may have treated unread "inconclusive" claims
        // as reviewed. Recheck their actual independent-source receipts before
        // returning a cached publication. Previous completed review rounds can
        // supply source observations against the same immutable snapshot.
        const reviewEvents = Object.values(snapshot.attempts).filter(attempt => attempt.phase === 'review' && attempt.status === 'completed')
          .flatMap(attempt => (attempt.result as { recoveryOutcome?: { events?: ProviderRuntimeEvent[] } })?.recoveryOutcome?.events ?? []);
        try { validateV2ReviewSourceReads(engagementDir, target, reviewEvents,
          loadReviewProgress({ engagementDir, target, runId: engagementId, model: reviewModel, revision: snapshot.analysisRevision ?? 0 })?.reuse); }
        catch (error) {
          if (!(error instanceof ReviewSourceDeliveryError) && !(error instanceof ReviewFinalizationError)) throw error;
          if (error instanceof ReviewFinalizationError) {
            const context = { engagementDir, target, runId: engagementId, model: reviewModel, revision: snapshot.analysisRevision ?? 0 };
            const progress = loadReviewProgress(context);
            stageReviewReopen(context, progress?.reuse ?? {
              ids: readStandardFindings(engagementDir).map(record => record.id), events: reviewEvents,
            });
          }
          for (const attempt of Object.values(snapshot.attempts)) if (attempt.status === 'started' || attempt.status === 'received') {
            await missionRuntime.append({ type: 'phase.failed', eventId: `${engagementId}:${attempt.phase}:${attempt.round ?? '-'}:${attempt.attempt}:review-coverage-recovery`,
              phase: attempt.phase, round: attempt.round, attempt: attempt.attempt, reason: 'Interrupted before incomplete review recovery' });
          }
          await beginAnalysisRevision(missionRuntime, engagementDir,
            error instanceof ReviewFinalizationError ? 'Explicit reviewer severity decisions require repair' : 'Independent source review is incomplete', [], true);
          snapshot = resumedSnapshot = await missionRuntime.read();
          finishReviewReopen({ engagementDir, target, runId: engagementId, model: reviewModel, revision: snapshot.analysisRevision ?? 0 });
          log({ event: error instanceof ReviewFinalizationError ? 'ReviewDecisionsReopened' : 'ReviewCoverageReopened', reason: error.message });
        }
      }
      if (snapshot.status === 'completed' && snapshot.publication) {
        if (!snapshot.analysisCheckpoint || !snapshot.completionCoverage) throw new AnalysisInterruption('Completed run has no sealed coverage checkpoint; preserve its report without claiming verified coverage');
        const coverage = JSON.parse(readFileSync(snapshot.completionCoverage.path, 'utf8'));
        verifyRunArtifactRef(snapshot.publication.artifact, engagementDir);
        if (resolve(snapshot.publication.artifact.path) !== resolve(engagementDir, contract.publication.finalArtifact)) {
          throw new Error('Published artifact does not match the contracted final report');
        }
        // A completed publication is immutable. Restore its sealed bytes rather
        // than rebuilding appendices with the currently installed host version.
        const finalReport = copyPublication(engagementDir, contract.publication.finalArtifact, contract.publication.finalArtifact);
        return { outcome: { texts: [], ledger: [], totalCostUsd: snapshot.totalCostUsd,
          costAccountingComplete: Object.values(snapshot.attempts).every(attempt => attempt.usage?.accountingComplete === true) },
          engagementDir, phases: [], finalReport, publicationStatus: 'published', storage, coverage };
      }
      // A published partial report is not terminal. Reopen failed/range-gap tasks,
      // while complete independent analyzer attempts retain their identity.
      const priorCoverage = snapshot.analysisCheckpoint && existsSync(join(engagementDir, COVERAGE_FILE))
        ? JSON.parse(readFileSync(snapshot.completionCoverage?.path ?? join(engagementDir, COVERAGE_FILE), 'utf8')) : undefined;
      if (priorCoverage?.complete === false && snapshot.analysisCheckpoint?.stage === 'review' && !hasPendingReview(engagementDir)) {
        const gaps = new Set<string>([...(priorCoverage.uncoveredFiles ?? []), ...(priorCoverage.sourceReadCoverage?.filesWithDeliveryGaps ?? [])]);
        const invalidated = analysisTasks.filter(task => Array.isArray(priorCoverage.incompleteTaskIds)
          ? priorCoverage.incompleteTaskIds.includes(task.unitKey) : task.ownedSources.some(file => gaps.has(file.path))).map(task => task.unitKey);
        for (const a of Object.values(snapshot.attempts)) if (a.status === 'started' || a.status === 'received') {
          await missionRuntime.append({ type: 'phase.failed', eventId: `${engagementId}:${a.phase}:${a.round ?? '-'}:${a.attempt}:revision-interrupted`, phase: a.phase, round: a.round, attempt: a.attempt, reason: 'Interrupted process before analysis revision' });
        }
        await beginAnalysisRevision(missionRuntime, engagementDir, 'Resume incomplete required coverage', invalidated);
        snapshot = resumedSnapshot = await missionRuntime.read();
      }
      analysisFrozen = !!snapshot.analysisCheckpoint || Object.values(snapshot.attempts).some(a => !a.superseded && ((['review', 'evaluate', 'report'].includes(a.phase)) || a.round === 'cross-unit-followup'));
      reviewFrozen = snapshot.analysisCheckpoint?.stage === 'review';
      if (!snapshot.analysisCheckpoint && Object.values(snapshot.attempts).some(a => !a.superseded && ['review', 'evaluate', 'report'].includes(a.phase))) {
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
      join(engagementDir, 'scan_plan.json'),
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

    const sharedKnowledge: SharedKnowledgeContext = {
      engagementDir, namespace: workPlan.workPlanSha256,
      sourceFiles: [...sealedSourceFiles, ...sealedDependencyFiles],
    };
    const unitResults = await executeTaskQueue({
      units: analysisTasks,
      dependencies: task => task.prerequisiteTaskIds ?? [],
      ...dependencies.scheduler, signal: dependencies.signal,
      maxConcurrency,
      dynamic: true,
      onEvent: schedulingEvent,
      shouldRetry: error => !(error instanceof MissionBudgetExhaustedError) && retryDisposition(error).retryable,
      unitIdleTimeoutMs: dependencies.scheduler?.unitIdleTimeoutMs ?? 15 * 60 * 1000,
      worker: async (candidate, unitAttempt, abortController, controls) => {
        assertOffsecWorkUnitIntact(workPlan, candidate.parentUnitKey);
        const unit = workPlan.units.find(unit => unit.unitKey === candidate.parentUnitKey)!;
        const prior = resume ? Object.values((await missionRuntime.read()).attempts).filter(a => a.phase === 'analyze' && a.round === candidate.unitKey) : [];
        const successful = prior.find(a => !a.superseded && a.status === 'completed');
        if (analysisFrozen && !successful) throw new AnalysisInterruption('Unit remains quarantined in the sealed review input; retry it in a new analysis run');
        const previousDir = successful?.artifacts?.[0]?.path;
        const unitDir = previousDir ? resolve(previousDir, '..') : join(workRoot, candidate.unitKey, `attempt-${resume ? Math.max(0, ...prior.map(a => a.attempt)) + 1 : unitAttempt}`);
        mkdirSync(unitDir, { recursive: true, mode: 0o700 });
        const ownedSourceFiles = candidate.ownedSources.map((file) => resolve(target, file.path));
        const contextSourceFiles = unit.contextFiles.map((file) => resolve(target, file.path));
        const prerequisiteResults = Object.values((await missionRuntime.read()).attempts)
          .filter(attempt => attempt.phase === 'analyze' && !attempt.superseded && attempt.status === 'completed' && candidate.prerequisiteTaskIds?.includes(attempt.round ?? ''))
          .flatMap(attempt => attempt.artifacts ?? []);
        const workUnit = {
          unitKey: candidate.unitKey,
          workPlanSha256: workPlan.workPlanSha256,
          assignedSourceSha256: unit.assignedSourceSha256,
          ownedSourceFiles,
          findingSourceFiles: [...new Set([...ownedSourceFiles, ...candidate.flowResponsibilities.flatMap(flow => flow.files.map(file => resolve(target, file)))])],
          contextSourceFiles,
          sourceFiles: [...ownedSourceFiles, ...contextSourceFiles],
        };
        const resultIdentity = {
          workUnitKey: candidate.unitKey,
          workPlanSha256: workPlan.workPlanSha256,
          assignedSourceSha256: unit.assignedSourceSha256,
        };
        const explorationInventory = join(unitDir, '00_source_exploration.json');
        const evidence = writeUnitEvidence(unitDir, unit.ownedFiles.map(file => file.path), preanalysis);
        writeFileSync(explorationInventory, JSON.stringify({
          purpose: 'Optional follow-up context for an observed dependency. Finding ownership remains assignedFiles.',
          sharedKnowledgeContext: sharedKnowledge,
          sourceFiles: sealedSourceFiles,
          dependencyFiles: sealedDependencyFiles,
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
          allowedReadFiles: [...new Set([...ownedSourceFiles, ...contextSourceFiles, ...sealedSourceFiles, ...sealedDependencyFiles, ...prerequisiteResults.map(artifact => artifact.path), explorationInventory, evidence.indexPath, evidence.detailPath])],
          signal: abortController.signal,
          ...(activeLease ? { leaseGuard: activeLease } : {}),
          ...(missionRuntime.artifactStore ? { artifactStore: missionRuntime.artifactStore } : {}),
          scope: input.scope,
          onEvent: event => {
            if (event.event === 'ProviderPressure') controls.pressure(event.reason ?? 'Provider pressure', event.retryAfterMs);
            else controls.progress();
            onEvent(event);
          },
          outcomePolicy: ({ role, outcome }) => outcomePolicy({ role, outcome: outcome.usage }),
        });
        const analyze = await unitHost.executePhase({
          id: 'analyze',
          trustedOutcome: sourceReuse?.task(candidate, unitDir, [...unit.contextFiles.map(file => file.path), ...(sourceManifest.dependency_files ?? [])]),
          maximumAttempts: 1,
          round: candidate.unitKey,
          priorArtifactPaths: [],
          deferRunBlocking: true,
          reuseCompleted: resume,
          resultIdentity,
          inputs: {
            workUnit: resultIdentity,
            prerequisiteResults,
            flowResponsibilities: candidate.flowResponsibilities,
            taskRequest: analysisTaskRequest(candidate, { runId: engagementId, snapshotId: frozen.snapshot.id, planRevision: workPlan.workPlanSha256, attempt: unitAttempt, contextRefs: contextSourceFiles, toolPolicy: { mode: input.mode, tools: input.tools } }),
            sharedKnowledge: {
              tools: ['lookup_shared_knowledge', 'get_shared_knowledge', 'publish_shared_observation'],
              instruction: 'Query shared context for dependencies before repeating investigation. Publish reusable observations with exact evidence. Accepted findings are shared automatically. Reuse K- IDs in analysis/handoff; do not resubmit identical claims. Shared claims remain unreviewed and do not complete your owned-file coverage.',
            },
            assignedFiles: candidate.ownedSources.map((file) => file.path),
            dependencyContextFiles: unit.contextFiles.map((file) => file.path),
            dependencyFiles: sealedDependencyFiles,
            sourceCapacity: {
              maxFiles: workPlan.planningPolicy.maxOwnedFilesPerUnit,
              maxEstimatedTokens: workPlan.planningPolicy.maxOwnedEstimatedTokensPerUnit,
              ownedEstimatedTokens: unit.contextSelectionReceipt.ownedEstimatedTokens,
              oversizedFilesRequiringRangeReads: unit.oversizedOwnedFiles ?? [],
              assignedRanges: candidate.ownedSources,
            },
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
            phaseRound: candidate.unitKey,
            readScope: 'exact',
            workUnit,
            sharedKnowledge,
            contractPath: V2_CONTRACT_PATH,
          },
        });
        abortController.signal.throwIfAborted();
        assertOffsecWorkUnitIntact(workPlan, unit.unitKey);
        return {
          unit,
          task: candidate,
          unitDir,
          analyze,
          findingReceipts: readStandardFindingRecordReceipts(unitDir),
          assessments: readAnalysisAssessments({ directory: unitDir, target, files: candidate.ownedSources.map(file => file.path), ranges: candidate.ownedSources, flows: candidate.flowResponsibilities,
            flowIds: candidate.flowResponsibilities.map(flow => flow.id),securityObligations:candidate.securityObligations,contextFiles:[...candidate.contextRanges.map(r=>r.path),...contextSourceFiles.map(path=>relative(target,path))] }),
        };
      },
    });

    if (unitResults.some(result => result.reason instanceof TerminationUnknownError)) {
      throw new AnalysisInterruption('Worker termination is unknown; admission and publication suspended. Retained attempts must be reconciled before resume.');
    }

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

    const completedUnitKeys = workPlan.units.filter(unit => analysisTasks.filter(task => task.parentUnitKey === unit.unitKey).every(task => unitResults.some(result => result.unit.unitKey === task.unitKey && result.status === 'fulfilled'))).map(unit => unit.unitKey);
    const rejected = unitResults.filter((result) => result.status === 'rejected');
    const quarantinedUnits = rejected.map((result) => ({
      unitKey: result.unit.parentUnitKey,
      taskId: result.unit.unitKey,
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
    const retainedClaims = retainFailedTaskClaims(engagementDir, [...rejectedKeys]);
    if (retainedClaims.claims.length) log({ event: 'FailedTaskClaimsRetained', count: retainedClaims.claims.length });
    rootAllowedReadFiles.push(retainedClaims.path);
    if (completedUnitKeys.length === 0) {
      throw new AnalysisInterruption('OffSec v2 analyze: 완료된 work unit이 없다');
    }

    const fulfilled = unitResults.flatMap((result) =>
      result.status === 'fulfilled' && result.value ? [result.value] : []);
    for (const result of fulfilled) mergeOutcome(result.analyze.outcome.raw);

    // scope assurance — v2에는 verifier phase가 없으므로 verifierEvents를 생략한다.
    const scopeObservations = new Map<string, UnitScopeObservationInput>();
    for (const result of fulfilled) {
      const prior = scopeObservations.get(result.unit.unitKey)?.vaEvents ?? [];
      scopeObservations.set(result.unit.unitKey, { vaEvents: [...prior, ...result.analyze.outcome.events] });
    }
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
      units: workPlan.units.filter(unit => completedUnitKeys.includes(unit.unitKey)).map(unit => ({
        unitKey: unit.unitKey, sourceUnitId: unit.sourceUnitId, assignedSourceSha256: unit.assignedSourceSha256,
        unresolvedEdges: unit.unresolvedEdges,
        findingReceipts: fulfilled.filter(result => result.unit.unitKey === unit.unitKey).flatMap(result => result.findingReceipts),
        artifacts: fulfilled.filter(result => result.unit.unitKey === unit.unitKey).flatMap(result => result.analyze.artifacts.map(({ path, name, sha256, bytes }) => ({ path, name, sha256, bytes }))),
      })),
      tasks: fulfilled.map(({ task, unitDir }) => ({ taskId: task.unitKey, parentUnitKey: task.parentUnitKey, unitDir, ownedSources: task.ownedSources })),
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
    const findingRecordInputs = () => readStandardFindingRecordReceipts(engagementDir).map(receipt => ({
      findingId: receipt.findingId,
      path: join(engagementDir, 'standard-findings', receipt.recordName),
      sha256: receipt.sha256,
    }));

    // Freeze the common context before review: late workers cannot change its inputs.
    const sharedSnapshotPath = join(engagementDir, SHARED_KNOWLEDGE_SNAPSHOT);
    if (!analysisFrozen) snapshotSharedKnowledge(sharedKnowledge);
    const rootSharedKnowledge = existsSync(sharedSnapshotPath) ? { ...sharedKnowledge, snapshotPath: sharedSnapshotPath } : undefined;
    if (rootSharedKnowledge) rootAllowedReadFiles.push(sharedSnapshotPath);

    // --- root host: review -> evaluate -> report -------------------------
    let phaseControls: TaskControls | undefined;
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
      onEvent: event => {
        if (event.event === 'ProviderPressure') phaseControls?.pressure(event.reason ?? 'Provider pressure', event.retryAfterMs);
        else phaseControls?.progress();
        onEvent(event);
      },
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
      const scheduled = await executeTaskQueue({ units: [{ unitKey: `${options.id}:${options.round ?? 'root'}` }], ...dependencies.scheduler, signal: dependencies.signal, maxConcurrency: 1, onEvent: schedulingEvent,
        unitIdleTimeoutMs: dependencies.scheduler?.unitIdleTimeoutMs ?? 15 * 60 * 1000,
        worker: async (_, __, abortController, controls) => {
          phaseControls = controls;
          while (true) {
          abortController.signal.throwIfAborted();
          const progressContext = { engagementDir, target, runId: engagementId, model: reviewModel,
            revision: (await missionRuntime.read()).analysisRevision ?? 0 };
          const progress = options.id === 'review' ? loadReviewProgress(progressContext) : undefined;
          const reviewReuse = mergeReviewReuse(options.inputs?.reviewReuse as ReviewReuse | undefined, progress?.reuse);
          // A failed reviewer may have submitted valid corrections. Each new
          // attempt needs their exact paths and IDs, not the old input list.
          refreshCanonicalFindingReadSet();
          try { return await host.executePhase({
        maximumAttempts: 1,
        id: options.id,
        deferRunBlocking: true,
        reuseCompleted: resume,
        round: options.round,
        inputs: { ...options.inputs, ...(['review', 'evaluate'].includes(options.id) ? { findingRecords: findingRecordInputs() } : {}),
          ...(options.id === 'review' ? { reviewRevision: progressContext.revision,
            ...(reviewReuse ? { reviewReuse } : {}), ...(progress ? { reviewContinuation: {
              artifact: progress.path, reviewedIds: progress.reviewedIds, remainingIds: progress.remainingIds,
              finalizationIssues: progress.finalizationIssues,
              instruction: 'Continue this same review from the host-validated draft. Preserve valid staged decisions and their verified independent source receipts. Repair finalizationIssues in bounded reviewPatch batches: explicitly choose reviewedSeverity from the source-grounded assessment, and submit_finding if the canonical severity must change. Do not merely copy a rating that contradicts the reason. Work on remainingIds in small batches, reading their records and cited originals. Do not reread every completed source. Read the draft in bounded line ranges as needed. Finalize after all IDs and issues are resolved, then return the phase result.' } } : {}) } : {}),
          ...(rootSharedKnowledge ? { sharedKnowledge: {
          snapshot: sharedSnapshotPath,
          tools: ['lookup_shared_knowledge', 'get_shared_knowledge'],
          instruction: 'Use lookup_shared_knowledge with paths/query and paginated offset/limit (at most 20), then get_shared_knowledge for relevant K- IDs. The snapshot is an audit archive and can exceed SDK Read/context limits; do not load it in full. Reuse common observations by K- ID. These are source-grounded claims, not reviewed findings; preserve independent validation and classify duplicates once.',
        } } : {}) },
        ...(options.priorArtifactPaths ? { priorArtifactPaths: options.priorArtifactPaths } : {}),
        providerOptions: {
          model: phase.role === 'reviewer' ? reviewModel : primaryModel,
          effort: input.effort,
          maxTurns: options.round === 'cross-unit-followup' ? Math.min(input.maxTurns ?? 120, 32) : input.maxTurns,
          phaseRound: options.round,
          readScope: 'exact',
          contractPath: V2_CONTRACT_PATH,
          sharedKnowledge: rootSharedKnowledge,
          abortController,
        },
      }); } catch (error) {
        if (options.id !== 'review' || !(error instanceof ProviderRuntimeFailure) || error.terminal?.subtype !== 'error_max_turns'
          || abortController.signal.aborted) throw error;
        const next = loadReviewProgress(progressContext);
        const originalIds = new Set(readStandardFindings(engagementDir).filter(record => record.role !== 'reviewer').map(record => record.id));
        const advancement = reviewProgressAdvance(progress, next, originalIds);
        // A turn cap bounds each native session. Continue only after durable,
        // source-verified progress on original work; no-progress loops stop.
        if (!advancement.advanced) throw error;
        log({ event: 'ReviewContinuationScheduled', reason: error.message, newlyReviewed: advancement.newlyReviewed,
          newlyFinalized: advancement.newlyFinalized,
          reviewed: next!.reviewedIds.length, remaining: next!.remainingIds.length });
        controls.progress();
      }
      } } });
      const completed = scheduled[0];
      if (completed?.status !== 'fulfilled' || !completed.value) throw completed?.reason ?? new AnalysisInterruption('Phase did not complete');
      const hosted = completed.value;
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
    const sourceReadCoverage: SourceReadCoverage | undefined = analysisFrozen
      ? (existsSync(analysisCoveragePath) ? JSON.parse(readFileSync(analysisCoveragePath, 'utf8')).sourceReadCoverage : undefined)
      : createSourceReadCoverage({ target, workPlan, observations: scopeObservations });
    const assessmentsComplete = fulfilled.every(result => result.assessments.complete);
    const deliveryComplete = (sourceReadCoverage?.allAssignedFilesSatisfied ?? sourceReadCoverage?.allAssignedFilesDelivered) === true;
    const incompleteTaskIds = [...new Set([...rejectedKeys, ...fulfilled.filter(result => !result.assessments.complete).map(result => result.task.unitKey)])];
    uncoveredFiles.push(...[...new Set([
      ...(sourceReadCoverage?.filesWithDeliveryGaps ?? []).filter(file => !sourceReadCoverage?.filesValidatedReuse?.includes(file)),
      ...fulfilled.flatMap(result => [...result.assessments.value.files.filter(file => file.status === 'deferred').map(file => file.path),
        ...result.assessments.value.flows.filter(flow => flow.status === 'deferred').flatMap(flow => result.task.flowResponsibilities.find(assigned => assigned.id === flow.id)?.files ?? []),
        ...result.assessments.security.rows.filter(row=>row.cases.some(c=>c.result==='unresolved')).flatMap(row=>result.task.securityObligations?.find(o=>o.id===row.id)?.files ?? [])]),
    ])].filter(file => !uncoveredFiles.includes(file)));
    const analysisCoverage = {
      complete: uncoveredFiles.length === 0 && followups.selected.length === 0 && requiredPreanalysisComplete && deliveryComplete && assessmentsComplete,
      requiredPreanalysisComplete,
      incompleteTaskIds,
      sourceErrors: sourceIssues,
      completedUnits: completedUnitKeys.length, totalUnits: workPlan.units.length, uncoveredFiles,
      semanticCoverage: 'not-proven' as const,
      securityControlCoverage: {basis:'Explicit assessments of conservative source-surface hints; not proof of exhaustive semantic coverage',
        obligations:analysisTasks.reduce((n,t)=>n+(t.securityObligations?.length ?? 0),0),
        assessed:fulfilled.reduce((n,r)=>n+r.assessments.security.totalObligations,0),
        counts:Object.fromEntries(['violated','enforced','not-applicable','unresolved'].map(key=>[key,fulfilled.reduce((n,r)=>n+(r.assessments.security.counts[key as keyof typeof r.assessments.security.counts] ?? 0),0)]))},
      ...(sourceReadCoverage ? { sourceReadCoverage } : {}),
      ownedFilesRead: scopeAssurance.units.reduce((sum, unit) => sum + unit.va.ownedFilesRead, 0),
      ownedFileCount: workPlan.units.reduce((sum, unit) => sum + unit.ownedFiles.length, 0),
      preanalysisAvailable: preanalysis.available,
      preanalysisLimitations: preanalysis.limitations,
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
      analysisCoverage.complete = uncoveredFiles.length === 0 && !followupFailure && requiredPreanalysisComplete && deliveryComplete && assessmentsComplete;
      analysisCoverage.deferredFollowupQuestions = followups.omitted + (followupFailure ? followups.selected.length : 0);
      atomicPrivateWrite(analysisCoveragePath, JSON.stringify({ ...analysisCoverage,
        disclosure: 'complete requires task, source delivery, file/flow assessment and tool completion; it does not prove absence of vulnerabilities.',
        preanalysisLimitations: preanalysis.limitations,
        unresolved: [...(!requiredPreanalysisComplete ? ['Required Semgrep preanalysis did not complete'] : []), ...(followupFailure ? [followupFailure] : []), ...fulfilled.flatMap(({ analyze }) => analyze.result.unresolved ?? []), ...phases.flatMap(phase => phase.result.unresolved ?? [])],
        invalidFollowupRequests: followups.invalid,
      }, null, 2) + '\n');
      await sealAnalysisCheckpoint(missionRuntime, engagementDir, 'review');
    } else Object.assign(analysisCoverage, JSON.parse(readFileSync(analysisCoveragePath, 'utf8')));
    refreshCanonicalFindingReadSet();
    const coordinated = await coordinateReview({
      root: engagementDir, target, files: sourceManifest.source_files,
      flowIds: analysisTasks.flatMap(task => task.flowResponsibilities.map(flow => flow.id)), runtime: missionRuntime,
      analysisCoveragePath, findings: findingRecordInputs, refreshReadSet: refreshCanonicalFindingReadSet,
      allowRead: paths => rootAllowedReadFiles.push(...paths), log, execute: executePhase,
      initialInputs: {
        independentCounting: true,
        flowIds: [...new Set(analysisTasks.flatMap(task => task.flowResponsibilities.map(flow => flow.id)))], flowPlan: join(engagementDir, 'scan_plan.json'),
        workUnitResults: workUnitResultPath, completedUnitKeys, analysisCoverage: analysisCoveragePath,
        followupPlan: followupPlanPath, findingRecords: findingRecordInputs(), failedTaskClaims: retainedClaims.path,
        sourceFiles: workPlan.units.flatMap(unit => unit.ownedFiles.map(file => resolve(target, file.path))),
        instruction: REVIEW_PATCH_GUIDANCE + ' Read the exact absolute sourceFiles paths to verify every finding, including ones classified inconclusive. Use the cited line ranges and bounded reads; a large number of tool calls is not evidence of context exhaustion. evidence.path is relative to target, not the engagement directory. A quotation or analyzer report alone does not constitute source verification. Inconclusive means uncertainty after examining the source, not a substitute for performing the review.',
        ...(uncoveredFiles.length > 0 ? { uncoveredFiles } : {}),
      },
    });
    const { review, rounds: reviewRound, deferred: deferredReviewRequests } = coordinated;
    if (deferredReviewRequests.length) {
      analysisCoverage.complete = false;
      log({ event: 'ReviewEvidenceDeferred', requests: deferredReviewRequests });
    }
    Object.assign(analysisCoverage, await finalizeCoverage(missionRuntime, engagementDir, { ...analysisCoverage, deferredReviewRequests }));
    const reviewCoveragePath = join(engagementDir, '03_review_coverage.json');
    atomicPrivateWrite(reviewCoveragePath, JSON.stringify({ revisions: reviewRound, deferred: deferredReviewRequests }, null, 2));
    rootAllowedReadFiles.push(reviewCoveragePath);
    // Canonical bookkeeping is deterministic host work. Preserve completed
    // evaluations on resume; otherwise create a checked, immutable projection.
    const evaluationComplete = Object.values((await missionRuntime.read()).attempts).some(attempt =>
      attempt.phase === 'evaluate' && attempt.status === 'completed' && !attempt.superseded);
    const evaluationProjection = evaluationComplete ? readEvaluationProjection(engagementDir) : writeEvaluationProjection({ root: engagementDir, coverage: analysisCoverage, preanalysis,
      validate: content => validateV2EvaluationArtifact(engagementDir, EVALUATION_CLASSIFICATION, content, target, { prepareHostProjection: true }) });
    if (evaluationProjection) {
      rootAllowedReadFiles.push(evaluationProjection.path, evaluationProjection.classificationPath);
      log({ event: evaluationComplete ? 'HostEvaluationProjectionReused' : 'HostEvaluationProjectionCreated', ...evaluationProjection });
    }
    const evaluate = await executePhase({
      id: 'evaluate',
      priorArtifactPaths: review.result.artifacts.map((name) => join(engagementDir, name)),
      inputs: { reviewArtifacts: review.result.artifacts, reviewCoverage: reviewCoveragePath, findingRecords: findingRecordInputs(), evaluationProjection,
        instruction: 'Read evaluationProjection.path first; the path and SHA-256 identify the sealed file. The host has already serialized and validated every Reviewer decision in 04_evaluation_classification.yaml. Do not rewrite that immutable classification or enumerate every record again. Write only your assessment, coverage interpretation and limitations in 04_evaluation.json. Omit vulnerabilityInventory, severityDistribution and actualToolCoverage: the host validates the sealed files and attaches these objects unchanged. Include both evaluation artifacts in the result. Read exact findingRecords.path only for selected supporting context. Use actualToolCoverage from the host projection, not dependency-graph parser support metadata.' },
    });
    refreshCanonicalFindingReadSet();
    await executePhase({
      id: 'report',
      priorArtifactPaths: [...new Set([
        ...evaluate.result.artifacts.map((name) => join(engagementDir, name)),
        ...phases.flatMap((p) => p.result.artifacts.map((name) => join(engagementDir, name))),
      ])],
      inputs: { evaluationArtifacts: evaluate.result.artifacts, findingRecords: findingRecordInputs(), evaluationProjection,
        canonicalAppendix: { generatedBy: 'host', instruction: 'Write a concise narrative: risk, selected evidence, remediation priorities, scope and limitations. The host appends every canonical finding ID, disposition, severity, confidence, original citations, preconditions, unresolved items and remediation without omissions. Do not manually transcribe the entire catalog or reread every ledger file. Use selected records for the narrative. classificationSha256 identifies the classification file; inputSha256 identifies the evaluation input file.' },
        ...(!analysisCoverage.complete ? { publicationNotice: '분석 범위 미완료', uncoveredFiles } : {}) },
    });

    // --- publication -----------------------------------------------------
    assertRunInputsIntact(await missionRuntime.read(), engagementDir);
    const appendix = canonicalFindingAppendix(engagementDir) + coverageAppendix(analysisCoverage);
    assertStandardFindingsRepresented(
      engagementDir,
      join(engagementDir, contract.publication.draftArtifact),
      appendix,
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
      coverageComplete: analysisCoverage.complete,
    });

    await reconcileUsageReceipts(missionRuntime, engagementDir);
    const finalState = await missionRuntime.read();
    combined.totalCostUsd = finalState.totalCostUsd;
    combined.costAccountingComplete = Object.values(finalState.attempts).every(attempt => attempt.usage?.accountingComplete === true);
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

export type AssessV2Result = Awaited<ReturnType<typeof executeAssessV2>>;
async function assessmentBoundary(input: AssessV2Input, dependencies: AssessV2Dependencies, resume = false, resumeOptions: AssessV2ResumeOptions = {}): Promise<AssessV2Result> {
  input = { ...input, ...resolveAnalysisSelection(input) };
  if (!input.engagementDir) input = { ...input, ...allocateRunLocation(input) };
  mkdirSync(dirname(input.engagementDir!), { recursive: true });
  input.engagementDir = existsSync(input.engagementDir!) ? realpathSync(input.engagementDir!) : join(realpathSync(dirname(input.engagementDir!)), basename(input.engagementDir!));
  const release = acquireRunLock(join(dirname(input.engagementDir), `.${basename(input.engagementDir)}.agent.lock`));
  try { return await executeAssessV2(input, dependencies, resume, resumeOptions); }
  catch (error) {
    if (!recoverableFailure(error)) throw error;
    const finalReport = preservePartialReport(input.engagementDir!, error);
    const storage: StorageHealth & { archiveUri?: string } = { pendingReplication: 0, errors: [String(error)] };
    const outcome: SessionOutcome = { texts: [], ledger: [], costAccountingComplete: false };
    // Result failure and usage accounting are independent. Reopen the original
    // backend after executeAssessV2 has released its lease and provider handles.
    try {
      const checkpoint = checkpointInput<AssessV2Input>(input.engagementDir!);
      const accounting = await openMissionRuntime({ engagementDir: input.engagementDir!, runId: checkpoint.runId }, dependencies.runtime);
      try {
        try { await reconcileUsageReceipts(accounting, input.engagementDir!); }
        catch (usageError) { storage.errors.push(`usage reconciliation incomplete: ${String(usageError)}`); }
        const snapshot = await accounting.read();
        outcome.totalCostUsd = snapshot.totalCostUsd;
        outcome.costAccountingComplete = Object.values(snapshot.attempts).every(attempt => attempt.usage?.accountingComplete === true);
      } finally { await accounting.close(); }
    } catch (usageError) { storage.errors.push(`usage accounting unavailable: ${String(usageError)}`); }
    try {
      const store = new ResilientArtifactStore(input.engagementDir!, dependencies.runtime?.artifactStore);
      storage.archiveUri = (await archiveRun(input.engagementDir!, store)).uri;
      const health = store.health(); storage.pendingReplication = health.pendingReplication; storage.errors.push(...health.errors);
    } catch (archiveError) { storage.errors.push(`partial archive incomplete: ${String(archiveError)}`); }
    return { outcome, engagementDir: input.engagementDir!, phases: [], finalReport,
      publicationStatus: 'partial', storage,
      coverage: partialCoverage(input.engagementDir!) };
  } finally { release(); }
}

export async function assessV2(input: AssessV2Input, dependencies: AssessV2Dependencies = {}): Promise<AssessV2Result> {
  return assessmentBoundary(input, dependencies);
}

export async function resumeAssessV2(engagementDir: string, dependencies: AssessV2Dependencies = {}, options: AssessV2ResumeOptions = {}): Promise<AssessV2Result> {
  const checkpoint = checkpointInput<AssessV2Input>(engagementDir);
  if (checkpoint.storageBackend && checkpoint.storageBackend !== selectedBackend(dependencies.runtime ?? {})) throw new Error(`resume requires the original ${checkpoint.storageBackend} state backend`);
  return assessmentBoundary(checkpoint.input, dependencies, true, options);
}

export async function runAssessCli(): Promise<void> {
  const { flags, positional } = parseAssessV2Args(process.argv.slice(2));
  const [targetArg, ...rest] = positional;
  if (!targetArg || flags.get('help') === 'true') {
    console.error(
      '사용: pnpm assess <진단대상 절대경로> [지시문]\n' +
        '  --reuse-from=<run-dir>  새 snapshot의 관련 변경만 재분석, 검증된 기존 근거 재사용\n' +
        '  --mode ast              AST 기반 소스 진단 (추가 도구는 명시적으로 선택)\n' +
        '  --tools semgrep|none     Semgrep 필수 사용 / 외부 도구 비활성화\n' +
        '  --model=<alias>          기본 opus\n' +
        '  --review-model=<alias>   기본 sonnet\n' +
        '  --effort=<low..max>\n' +
        '  --max-turns=<n>\n' +
        '  --cost-policy=<record-only|enforce>  비용 기록만 (기본 record-only)\n' +
        '  --max-usd=<n>            enforce 정책에서만 적용할 비용 상한\n' +
        '  --no-cost-guard         금액 예산 상한 해제 (재개 포함)\n' +
        '  --semgrep=<required|best-effort|off>\n' +
        '  --work-units=<auto|force>  v2는 항상 작업 분할 사용\n' +
        '  --max-concurrency=<n>     선택적 사용자 상한. 생략하면 자원·진행에 따라 동적 배치\n' +
        '  --max-files-per-agent=<n>  담당 소스 파일 상한 (기본 24)\n' +
        '  --max-source-tokens-per-agent=<n>  소스 토큰 추정량 (기본 24000)\n' +
        '  --engagement-dir=<절대경로> [--resume]',
    );
    process.exitCode = flags.get('help') === 'true' ? 0 : 1;
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
  const resume = flags.get('resume') === 'true';
  if (resume && !engagementDirFlag) throw new Error('--resume requires --engagement-dir');
  if (resume && ['mode', 'tools', 'semgrep'].some(name => flags.has(name))) throw new Error('--resume preserves the sealed mode/tools; omit --mode, --tools and --semgrep');

  const input: AssessV2Input = {
    target: targetArg,
    ...(flags.has('mode') ? { mode: flags.get('mode') as AnalysisMode } : {}),
    ...(flags.has('tools') ? { tools: parseAnalysisTools(flags.get('tools')!) } : {}),
    ...(scope ? { scope } : {}),
    ...(flags.get('reuse-from') ? { reuseFrom: flags.get('reuse-from') } : {}),
    ...(flags.get('model') ? { model: flags.get('model') } : {}),
    ...(flags.get('review-model') ? { reviewModel: flags.get('review-model') } : {}),
    ...(effortFlag ? { effort: effortFlag as SessionSpec['effort'] } : {}),
    ...(maxTurnsFlag !== undefined ? { maxTurns: Number(maxTurnsFlag) } : {}),
    ...(flags.has('cost-policy') ? { costPolicy: flags.get('cost-policy') as CostPolicy } : {}),
    ...(maxUsdFlag ? { maxBudgetUsd: Number(maxUsdFlag) } : {}),
    ...(flags.has('no-cost-guard') ? { noCostGuard: flags.get('no-cost-guard') === 'true' } : {}),
    ...(semgrepFlag ? { semgrepMode: semgrepFlag as SemgrepMode } : {}),
    ...(workUnitsFlag ? { workUnitMode: workUnitsFlag as WorkUnitMode } : {}),
    ...(maxConcurrencyFlag !== undefined ? { maxConcurrency: Number(maxConcurrencyFlag) } : {}),
    ...(flags.has('max-files-per-agent') ? { maxFilesPerAgent: Number(flags.get('max-files-per-agent')) } : {}),
    ...(flags.has('max-source-tokens-per-agent') ? { maxSourceTokensPerAgent: Number(flags.get('max-source-tokens-per-agent')) } : {}),
    ...(flags.has('max-followup-hypotheses') ? { maxFollowupHypotheses: Number(flags.get('max-followup-hypotheses')) } : {}),
    ...(engagementDirFlag ? { engagementDir: engagementDirFlag } : {}),
  };

  if (!input.engagementDir) Object.assign(input, allocateRunLocation(input));
  mkdirSync(dirname(input.engagementDir!), { recursive: true });
  input.engagementDir = existsSync(input.engagementDir!) ? realpathSync(input.engagementDir!) : join(realpathSync(dirname(input.engagementDir!)), basename(input.engagementDir!));
  const notifyCli = (event: Record<string, unknown>) => {
    if (/Deferred|Partial|Backoff|Failed|Pending|Unknown|Recovered|EvidenceRequested/.test(String(event.event)) || event.state === 'termination-unknown') process.stderr.write(`[${new Date().toISOString()}] ${JSON.stringify(event)}\n`);
  };
  let result: AssessV2Result;
  result = resume ? await resumeAssessV2(input.engagementDir, { onEvent: notifyCli }, { costPolicy: input.costPolicy, maxBudgetUsd: input.maxBudgetUsd, noCostGuard: input.noCostGuard }) : await assessV2(input, { onEvent: notifyCli });
  const { engagementDir, finalReport, phases, coverage } = result;
  console.log(`OffSec v2 ${coverage.complete ? '작업 실행 완료' : '부분 분석 — 범위 미완료'}: ${engagementDir}`);
  if (result.publicationStatus === 'partial' && result.storage.errors.length > 0) console.error(`중단 사유: ${result.storage.errors[0]}`);
  if (coverage.sourceReadCoverage) console.log(`담당 분석의 Read 요청 미관측: ${coverage.sourceReadCoverage.filesWithoutReadRequest.length}/${coverage.ownedFileCount}개 파일 (전체 내용 읽기 여부는 입증되지 않음)`);
  console.log(`최종 보고서: ${finalReport}`);
  console.log(`실행 phase: ${phases.map((p) => p.phase).join(' -> ')}`);
  if (!coverage.complete) process.exitCode = 2;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  runAssessCli().catch((error) => {
    console.error(error instanceof Error ? error.stack ?? error.message : String(error));
    process.exitCode = 1;
  });
}
