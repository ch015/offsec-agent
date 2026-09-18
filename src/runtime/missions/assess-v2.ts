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

import { loadOffsecContract, type PhaseResult } from '../offsec-contract.js';
import { OffsecDomainAdapter } from '../domains/offsec.js';
import { AnthropicAgentRuntime } from '../providers/anthropic-agent-sdk.js';
import { BudgetedRuntime } from '../providers/budgeted-runtime.js';
import { runSession, type SessionOutcome, type SessionSpec } from '../session.js';
import { WorkflowHost } from '../workflow/engine.js';
import { executeBoundedWork } from '../workflow/bounded-work-executor.js';
import {
  createMissionRuntime,
  openMissionRuntime,
  type MissionRuntime,
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
import { loadAndComputeGraphRag, serializeGraphContextForUnit } from '../workflow/graph-rag.js';
import { runHostRecon } from '../workflow/host-recon.js';
import {
  assertStandardFindingsRepresented,
  promoteStandardFindingRecords,
  readStandardFindingRecordReceipts,
  type StandardFindingRecordReceipt,
} from '../finding-contract.js';
import {
  makeEngagementId,
  recordOffsecPublication,
  resolveRunBudget,
  validateOffsecPublicationCandidate,
  type PhaseExecution,
  type SemgrepMode,
  type WorkUnitMode,
} from './assess.js';

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
  model?: string;
  reviewModel?: string;
  effort?: SessionSpec['effort'];
  maxTurns?: number;
  maxBudgetUsd?: number;
  semgrepMode?: SemgrepMode;
  workUnitMode?: WorkUnitMode;
  maxConcurrency?: number;
  noCostGuard?: boolean;
};

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

type CheckpointCore = Readonly<{ schemaVersion: '1.0.0'; runId: string; input: AssessV2Input }>;
type Checkpoint = CheckpointCore & Readonly<{ checkpointSha256: string }>;

function checkpointSha256(core: CheckpointCore): string {
  return createHash('sha256').update(stableJson(JSON.parse(JSON.stringify(core)) as unknown)).digest('hex');
}

function sealCheckpoint(engagementDir: string, input: AssessV2Input, target: string, runId: string): void {
  const core: CheckpointCore = {
    schemaVersion: '1.0.0',
    runId,
    input: {
      ...input,
      target,
      engagementId: runId,
      engagementDir,
      semgrepMode: input.semgrepMode ?? 'required',
      workUnitMode: input.workUnitMode ?? 'auto',
    },
  };
  const checkpoint: Checkpoint = { ...core, checkpointSha256: checkpointSha256(core) };
  const path = join(engagementDir, ASSESS_V2_CHECKPOINT_INPUT);
  if (existsSync(path)) return;
  writeFileSync(path, `${JSON.stringify(checkpoint, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
}

/**
 * v2 최종 보고서 발행 — v1 publishValidatedReport와 동일한 draft→final rename 흐름을 쓰되
 * pentest/liveDast lineage 검증을 뺀 축약판이다.
 */
function publishV2Report(
  engagementDir: string,
  allowEmptyCandidates: boolean,
  publication: { draftArtifact: string; finalArtifact: string },
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
  if (candidate === draft) renameSync(draft, final);
  return final;
}

export async function assessV2(input: AssessV2Input, dependencies: AssessV2Dependencies = {}): Promise<{
  outcome: SessionOutcome;
  engagementDir: string;
  phases: PhaseExecution[];
  finalReport: string;
  coverage: { complete: boolean; completedUnits: number; totalUnits: number; uncoveredFiles: string[] };
}> {
  // --- preflight ---------------------------------------------------------
  const target = resolve(input.target);
  const engagementId = input.engagementId ?? makeEngagementId(target, new Date());
  const nunchiRoot = join(target, NUNCHI_DIR);
  const engagementDir = resolve(input.engagementDir ?? join(nunchiRoot, 'reports', engagementId));
  const semgrepMode = input.semgrepMode ?? 'required';
  const workUnitMode = input.workUnitMode ?? 'auto';
  const contract = loadOffsecContract(V2_CONTRACT_PATH);
  if (!contract.version.startsWith('2.')) {
    throw new Error(`assess-v2에는 v2 계약이 필요하다: ${contract.version}`);
  }
  const sessionRunner = dependencies.sessionRunner ?? runSession;
  const maxBudgetUsd = input.noCostGuard ? undefined : resolveRunBudget(input.maxBudgetUsd, contract.limits.maxBudgetUsd);
  const primaryModel = input.model ?? process.env.ASSESS_PRIMARY_MODEL ?? 'opus';
  const reviewModel = input.reviewModel ?? process.env.ASSESS_REVIEW_MODEL ?? 'sonnet';

  if (!existsSync(target)) throw new Error(`진단 대상이 없다: ${target}`);
  if (!statSync(target).isDirectory()) throw new Error(`진단 대상은 디렉토리여야 한다: ${target}`);
  if (!['auto', 'force'].includes(workUnitMode)) {
    throw new Error(`OffSec v2는 작업 분할을 항상 사용한다: workUnitMode=${workUnitMode}는 지원하지 않는다`);
  }
  if (input.maxConcurrency !== undefined && (!Number.isInteger(input.maxConcurrency) || input.maxConcurrency < 1)) {
    throw new Error(`maxConcurrency가 잘못됐다: ${input.maxConcurrency}`);
  }
  if (primaryModel === reviewModel && !process.env.ALLOW_SAME_MODEL) {
    throw new Error('OffSec primary model과 review model은 달라야 한다 (개발 중 동일 모델 사용은 ALLOW_SAME_MODEL=1 설정)');
  }
  if (existsSync(engagementDir) && readdirSync(engagementDir).length > 0) {
    throw new Error(`기존 engagement를 덮어쓸 수 없다: ${engagementDir}`);
  }
  mkdirSync(engagementDir, { recursive: true, mode: 0o700 });
  if (engagementDir.startsWith(resolve(nunchiRoot))) ensureNunchiGitignore(nunchiRoot);
  sealCheckpoint(engagementDir, input, target, engagementId);

  const ledgerPath = join(engagementDir, 'host-ledger.jsonl');
  if (!existsSync(ledgerPath)) writeFileSync(ledgerPath, '', { flag: 'wx', mode: 0o600 });
  const log = (event: Record<string, unknown>): void => {
    appendFileSync(ledgerPath, `${JSON.stringify(event)}\n`);
  };

  // --- recon (host) ------------------------------------------------------
  // source manifest는 initFanoutPlan이 생성·기록(source_manifest.json)한다. v1과 동일한
  // 경로를 재사용하되 v2 flow에는 feedback iteration이 없다.
  const fanoutPlan = agentPlan.initFanoutPlan({
    engagementDir,
    target,
    excludePaths: [nunchiRoot, join(target, 'reports'), engagementDir, ...(input.excludePaths ?? [])],
    flow: 'standard',
    vaMode: 'sequential',
    verificationMode: 'VA_ONLY',
    maxFeedbackIterations: 0,
  });
  const dependencyGraph: DependencyGraph = createDependencyGraph({
    target,
    sourceManifest: fanoutPlan.manifest,
  });
  writeDependencyGraph(engagementDir, dependencyGraph);
  const sourceManifest = fanoutPlan.manifest as {
    hash: string;
    source_files?: unknown[];
    dependency_files?: unknown[];
    units?: Array<{ files?: unknown[] }>;
  };
  const sealedSourceFiles = (sourceManifest.source_files ?? [])
    .filter((path): path is string => typeof path === 'string')
    .map((path) => resolve(target, path));
  const sealedDependencyFiles = (sourceManifest.dependency_files ?? [])
    .filter((path): path is string => typeof path === 'string')
    .map((path) => resolve(target, path));

  const reconResult = runHostRecon({
    target,
    sourceFiles: (sourceManifest.source_files ?? []).filter((p): p is string => typeof p === 'string'),
  });
  const reconPath = join(engagementDir, '00_recon.json');
  writeFileSync(reconPath, `${JSON.stringify(reconResult, null, 2)}\n`, { mode: 0o600 });
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
    astOutcome = await astBuilder(target, {
      outputPath: astContextPath,
      runSemgrep: semgrepMode !== 'off',
      semgrepFiles: [...new Set(sealedSourceFiles)],
      logger: (message) => log({ event: 'HostAstPreanalysis', message }),
    });
  } catch (error) {
    astOutcome = { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
  const astContextAvailable = astOutcome.ok && existsSync(astContextPath);
  const semgrepStatus = semgrepMode === 'off' ? 'disabled' : astOutcome.semgrep?.status ?? 'unavailable';
  log({
    event: 'HostAstPreanalysisCompleted',
    ok: astContextAvailable,
    artifact: astContextAvailable ? astContextPath : undefined,
    error: astContextAvailable ? undefined : astOutcome.error ?? 'AST context was not produced',
    semgrep: astOutcome.semgrep ?? { status: semgrepStatus },
  });
  if (semgrepMode === 'required' && semgrepStatus !== 'complete') {
    throw new Error(`required Semgrep preanalysis가 완료되지 않았다: ${astOutcome.semgrep?.error ?? semgrepStatus}`);
  }

  // --- plan (host) -------------------------------------------------------
  const workPlan: OffsecWorkPlanV2 = createOffsecWorkPlanV2({
    target,
    sourceManifest,
    dependencyGraph,
    maxContextFilesPerUnit: contract.workUnitPolicy.maxContextFilesPerUnit,
  });
  const workPlanPath = writeOffsecWorkPlan(engagementDir, workPlan);
  // 계약이 요구하는 01_analysis_plan.json — work plan의 unit 요약을 host가 기록한다.
  const analysisPlanPath = join(engagementDir, '01_analysis_plan.json');
  writeFileSync(analysisPlanPath, `${JSON.stringify({
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
  const missionRuntime = await createMissionRuntime({
    engagementDir,
    runId: engagementId,
    contractId: contract.id,
    contractVersion: contract.version,
    domain: 'offsec',
    mission: 'assessment',
    ...(maxBudgetUsd !== undefined ? { maxBudgetUsd } : {}),
  }, dependencies.runtime);
  void openMissionRuntime; // resume 경로 예약 (현재 미사용)
  {
    const checkpointReceipt = checkpointFileReceipt(engagementDir);
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
        allowedReadFiles: [checkpointReceipt.path],
        fileHashes: [checkpointReceipt],
      },
    });
  }
  const state = missionRuntime.state;
  const activeLease: AutoRenewingRunLease | undefined = missionRuntime.leaseGuard;

  try {
    const adapter = new OffsecDomainAdapter(contract);
    const maxConcurrency = Math.min(input.maxConcurrency ?? contract.workUnitPolicy.maximumConcurrency,
      contract.workUnitPolicy.maximumConcurrency);
    const provider = new AnthropicAgentRuntime(sessionRunner);
    const runtime = maxBudgetUsd === undefined ? provider
      : new BudgetedRuntime(provider, maxBudgetUsd, request => request.phase === 'analyze' ? maxConcurrency : 1);
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

    const graphRag = await loadAndComputeGraphRag(engagementDir);
    if (graphRag) {
      log({
        event: 'HostGraphRagComputed',
        taintPaths: graphRag.taintPaths.length,
        communities: graphRag.communities.length,
        filesWithContext: graphRag.fileContextMap.size,
      });
    }

    const unitResults = await executeBoundedWork({
      units: workPlan.units,
      maxConcurrency,
      maximumWorkUnits: contract.workUnitPolicy.maximumWorkUnits,
      retryRejectedOnce: true,
      unitTimeoutMs: 15 * 60 * 1000,
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
        const analyze = await unitHost.executePhase({
          id: 'analyze',
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

    const completedUnitKeys = unitResults
      .filter((result) => result.status === 'fulfilled')
      .map((result) => result.unit.unitKey);
    const rejected = unitResults.filter((result) => result.status === 'rejected');
    const quarantinedUnits = rejected.map((result) => ({
      unitKey: result.unit.unitKey,
      reason: result.reason instanceof Error ? result.reason.message : String(result.reason),
    }));
    const uncoveredFiles = quarantinedUnits.flatMap((q) =>
      workPlan.units.find((u) => u.unitKey === q.unitKey)?.ownedFiles.map((f) => f.path) ?? [],
    );
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
      throw new Error('OffSec v2 analyze: 완료된 work unit이 없다');
    }

    const fulfilled = unitResults.flatMap((result) =>
      result.status === 'fulfilled' && result.value ? [result.value] : []);
    for (const result of fulfilled) mergeOutcome(result.analyze.outcome.raw);

    // scope assurance — v2에는 verifier phase가 없으므로 verifierEvents를 생략한다.
    const scopeObservations = new Map<string, UnitScopeObservationInput>(fulfilled.map((result) => [
      result.unit.unitKey,
      { vaEvents: result.analyze.outcome.events },
    ]));
    const scopeAssurance = createScopeAssurance({
      target, workPlan, completedUnitKeys, observations: scopeObservations, analysisMode: 'v2',
    });
    const scopeAssurancePath = writeScopeAssurance(engagementDir, scopeAssurance);
    const scopeAssuranceSha256 = fileSha256(scopeAssurancePath);

    const workUnitResultPath = join(engagementDir, '00_work_unit_results.json');
    const temporary = `${workUnitResultPath}.${process.pid}.tmp`;
    writeFileSync(temporary, `${JSON.stringify({
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
    renameSync(temporary, workUnitResultPath);

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
      inputs?: Record<string, unknown>;
      priorArtifactPaths?: readonly string[];
    }): Promise<PhaseExecution> => {
      const { legacy: phase } = adapter.getPhase(options.id);
      const artifacts = adapter.renderArtifacts(phase);
      const hosted = await host.executePhase({
        id: options.id,
        inputs: options.inputs,
        ...(options.priorArtifactPaths ? { priorArtifactPaths: options.priorArtifactPaths } : {}),
        providerOptions: {
          model: phase.role === 'reviewer' ? reviewModel : primaryModel,
          effort: input.effort,
          maxTurns: input.maxTurns,
          readScope: 'exact',
          contractPath: V2_CONTRACT_PATH,
        },
      });
      void artifacts;
      const result = hosted.result;
      const outcome = hosted.outcome.raw;
      mergeOutcome(outcome);
      combined.structuredOutput = result;
      const execution: PhaseExecution = { phase: phase.id, role: phase.role, result, outcome };
      phases.push(execution);
      return execution;
    };

    refreshCanonicalFindingReadSet();
    const review = await executePhase({
      id: 'review',
      inputs: {
        workUnitResults: workUnitResultPath,
        completedUnitKeys,
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
        ...(uncoveredFiles.length ? { publicationNotice: '분석 범위 미완료', uncoveredFiles } : {}) },
    });

    // --- publication -----------------------------------------------------
    if (uncoveredFiles.length > 0) {
      const draft = readFileSync(join(engagementDir, contract.publication.draftArtifact), 'utf8');
      if (!draft.includes('분석 범위 미완료') || uncoveredFiles.some(file => !draft.includes(file))) {
        throw new Error('부분 분석 보고서는 분석 범위 미완료와 모든 미검토 파일을 명시해야 한다');
      }
    }
    assertStandardFindingsRepresented(
      engagementDir,
      join(engagementDir, contract.publication.draftArtifact),
    );
    const allowEmptyCandidates = readStandardFindingRecordReceipts(engagementDir).length === 0;
    const finalReport = publishV2Report(engagementDir, allowEmptyCandidates, contract.publication);
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

    return { outcome: combined, engagementDir, phases, finalReport,
      coverage: { complete: uncoveredFiles.length === 0, completedUnits: completedUnitKeys.length,
        totalUnits: workPlan.units.length, uncoveredFiles } };
  } finally {
    await missionRuntime.close();
  }
}

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
      '사용: pnpm tsx src/runtime/missions/assess-v2.ts <진단대상 절대경로> [지시문]\n' +
        '  --model=<alias>          기본 opus\n' +
        '  --review-model=<alias>   기본 sonnet\n' +
        '  --effort=<low..max>\n' +
        '  --max-turns=<n>\n' +
        '  --max-usd=<n>            예산 상한\n' +
        '  --semgrep=<required|best-effort|off>\n' +
        '  --work-units=<auto|force>  v2는 항상 작업 분할 사용\n' +
        '  --max-concurrency=<n>\n' +
        '  --engagement-dir=<절대경로>',
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

  const input: AssessV2Input = {
    target: targetArg,
    ...(scope ? { scope } : {}),
    ...(flags.get('model') ? { model: flags.get('model') } : {}),
    ...(flags.get('review-model') ? { reviewModel: flags.get('review-model') } : {}),
    ...(effortFlag ? { effort: effortFlag as SessionSpec['effort'] } : {}),
    ...(maxTurnsFlag ? { maxTurns: Number.parseInt(maxTurnsFlag, 10) } : {}),
    ...(maxUsdFlag ? { maxBudgetUsd: Number.parseFloat(maxUsdFlag) } : {}),
    ...(semgrepFlag ? { semgrepMode: semgrepFlag as SemgrepMode } : {}),
    ...(workUnitsFlag ? { workUnitMode: workUnitsFlag as WorkUnitMode } : {}),
    ...(maxConcurrencyFlag ? { maxConcurrency: Number.parseInt(maxConcurrencyFlag, 10) } : {}),
    ...(engagementDirFlag ? { engagementDir: engagementDirFlag } : {}),
  };

  const { engagementDir, finalReport, phases, coverage } = await assessV2(input);
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
