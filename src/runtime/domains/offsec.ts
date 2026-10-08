import { FollowupAnswersSchema, validateFollowupAnswers, reviewRequests, type ReviewRequest } from '../planning/review-coordinator.js';
import { ANALYSIS_ASSESSMENTS, readAnalysisAssessments, validateAnalysisAssessments, validateAssessmentDelivery, assessmentContextFiles, assessmentFindingIds, type AssessmentTask } from '../planning/analysis-assessments.js';
import { ScannerPlanSchema, readScannerPlan, validateScannerPlan } from '../planning/scanner-contract.js';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import {
  buildPhasePrompt,
  buildOffsecAgentDefinitions,
  getOffsecPhase,
  loadOffsecContract,
  phaseOutputFormat,
  renderPhaseArtifacts,
  resolvePhaseMethodFiles,
  resolvePhaseMethodologyFiles,
  validatePhaseResult,
  type OffsecContract,
  type OffsecPhase,
  type PhaseResult,
} from '../offsec-contract.js';
import { countStandardFindings } from '../finding-contract.js';
import { validateOffsecClassificationSyntax, validateV2Evaluation, validateV2EvaluationArtifact, validateV2ReviewSourceReads } from '../v2-evaluation.js';
import { prepareReviewPatch } from '../review-artifact-patch.js';
import { canonicalV2Findings } from '../v2-review-resolution.js';
import type { ProviderRuntimeEvent } from '../providers/provider-runtime.js';
import { getWorkflowPhase, parseWorkflowContract, type WorkflowContract } from '../contracts/workflow-contract.js';
import { resolveKnowledgeFiles as resolveKnowledgeFilesForPhase } from '../knowledge/loader.js';
import type { DomainAdapter, PhaseTransitionState, TransitionDecision } from './domain-adapter.js';

const REQUIRED_CAPABILITIES = [
  'structured-output',
  'strict-tool-input',
  'local-mcp',
  'sandbox',
  'tool-policy',
] as const;

export function createOffsecWorkflowContract(contract = loadOffsecContract()): WorkflowContract {
  const resultSchemaId = 'nunchi.offsec.phase-result.v2';
  const workerPhases = ['analyze'];
  const hostPhaseIds = new Set(contract.phases.filter((p) => p.role === 'host').map((p) => p.id));
  return parseWorkflowContract({
    id: contract.id,
    version: contract.version,
    domain: 'offsec',
    mission: 'assessment',
    lifecycle: 'finite',
    forbiddenModelTools: contract.forbiddenModelTools,
    limits: {
      ...(contract.limits.maxBudgetUsd !== null
        ? { maxBudgetUsd: contract.limits.maxBudgetUsd }
        : {}),
      ...(contract.limits.maxFeedbackIterations !== undefined
        ? { maxIterations: contract.limits.maxFeedbackIterations }
        : {}),
      maxSubagentDepth: contract.limits.maxSubagentDepth,
    },
    isolation: {
      settingSources: contract.isolation.settingSources,
      strictMcpConfig: contract.isolation.strictMcpConfig,
      disableAutoMemory: contract.isolation.disableAutoMemory,
      inheritParentSecrets: contract.isolation.inheritParentSecrets,
      sandboxRequired: contract.isolation.sandboxRequired,
      networkDefaultDeny: contract.isolation.networkDefaultDeny,
      permissionMode: contract.isolation.permissionMode,
    },
    roles: Object.fromEntries(
      Object.entries(contract.roles).map(([name, role]) => [
        name,
        {
          agentFile: role.agentFile,
          description: role.description,
          tools: role.tools,
          skills: role.skills,
          allowedDelegates: role.allowedDelegates,
          requiredCapabilities: REQUIRED_CAPABILITIES,
        },
      ]),
    ),
    phases: contract.phases
      .filter((phase) => phase.role !== 'host')
      .map((phase) => ({
        id: phase.id,
        role: phase.role,
        requires: phase.requires.filter((dep) => !hostPhaseIds.has(dep)),
        controller: 'host' as const,
        strategy: 'single' as const,
        resultSchemaId,
        requiredMethodFiles: phase.requiredMethodFiles,
        requiredArtifacts: phase.requiredArtifacts,
        optionalArtifacts: phase.optionalArtifacts,
        approvals: [],
      })),
    hostExecution: {
      kind: 'sealed-work-set' as const,
      entrypoint: 'assess',
      workerPhases,
      maximumWorkUnits: contract.workUnitPolicy.maximumWorkUnits,
      maximumConcurrency: contract.workUnitPolicy.maximumConcurrency,
      completionBarrier: 'all-settled-all-required' as const,
      directPhaseExecution: 'forbidden' as const,
    },
    resources: contract.resources,
    publication: contract.publication,
  });
}

export class OffsecDomainAdapter
  implements DomainAdapter<OffsecContract, OffsecPhase, PhaseResult>
{
  readonly domain = 'offsec';
  readonly mission = 'assessment';
  readonly legacyContract: OffsecContract;
  readonly contract: WorkflowContract;

  constructor(contract = loadOffsecContract()) {
    this.legacyContract = contract;
    this.contract = createOffsecWorkflowContract(contract);
  }

  buildAgentDefinitions() {
    return buildOffsecAgentDefinitions({ contract: this.legacyContract });
  }

  outputFormat() {
    return phaseOutputFormat(this.legacyContract);
  }

  getPhase(id: string): { workflow: WorkflowContract['phases'][number]; legacy: OffsecPhase } {
    return {
      workflow: getWorkflowPhase(this.contract, id),
      legacy: getOffsecPhase(id, this.legacyContract),
    };
  }

  buildPrompt(input: {
    phase: OffsecPhase;
    target: string;
    engagementDir: string;
    runId: string;
    attempt: string;
    scope?: string;
    round?: string;
    inputs?: Record<string, unknown>;
  }): string {
    // Delivery receipts are host validation data. Keep them out of model
    // context; the model needs the reusable IDs and pending work, not hashes
    // and hundreds of historic tool events.
    const reuse = input.inputs?.reviewReuse as { ids: string[]; events: unknown[] } | undefined;
    return buildPhasePrompt({ ...input, ...(reuse ? { inputs: { ...input.inputs,
      reviewReuse: { ids: reuse.ids, verifiedSourceObservations: reuse.events.length } } } : {}), contract: this.legacyContract });
  }

  validateResult(input: {
    value: unknown;
    phase: OffsecPhase;
    engagementDir: string;
    round?: string;
  }): PhaseResult {
    return validatePhaseResult({ ...input, contract: this.legacyContract });
  }

  validateAcceptedResult(input: {
    result: PhaseResult;
    phase: OffsecPhase;
    engagementDir: string;
    round?: string;
    target?: string;
    events?: readonly ProviderRuntimeEvent[];
    taskData?: Record<string, unknown>;
  }): void {
    if (input.phase.id === 'recon') {
      const inventory = JSON.parse(readFileSync(join(input.engagementDir, 'source_manifest.json'), 'utf8'));
      const graph = JSON.parse(readFileSync(join(input.engagementDir, '00_inventory_graph.json'), 'utf8'));
      readScannerPlan(input.engagementDir, inventory.source_files.filter((file: string) => !(inventory.source_errors ?? []).some((error: { path: string }) => error.path === file)), graph);
      return;
    }
    const accepted = countStandardFindings(
      input.engagementDir,
      input.phase.id,
      input.phase.role,
      input.round,
    );
    if (accepted !== input.result.metrics.findingCount) {
      // 모델이 보고한 findingCount를 host 실측값으로 자동 보정.
      input.result.metrics.findingCount = accepted;
    }

    if (input.phase.id === 'analyze' && input.target && input.taskData?.taskRequest) {
      const request = input.taskData.taskRequest as AssessmentTask;
      const assessments = readAnalysisAssessments({ directory: input.engagementDir, target: input.target, files: request.ownedSources.map(file => file.path),
        ranges: request.ownedSources, flows: request.flowResponsibilities, flowIds: request.flowResponsibilities.map(flow => flow.id),
        securityObligations:request.securityObligations,contextFiles:request.contextRanges.map(r=>r.path) });
      validateAssessmentDelivery(request, assessments, input.target, input.events ?? []);
    }
    if (input.phase.id === 'analyze' && input.target && input.taskData?.reviewRequests) validateFollowupAnswers(input.engagementDir, input.target, input.taskData.reviewRequests as ReviewRequest[]);
    if (input.phase.id === 'review' && input.target) {
      if (input.taskData?.independentCounting === true && JSON.parse(readFileSync(join(input.engagementDir, '03_review_result.json'), 'utf8')).countingSchemaVersion !== 1) {
        throw new Error('Review requires countingSchemaVersion: 1 and explicit vulnerability/observation counting assessments before completion.');
      }
      validateV2ReviewSourceReads(input.engagementDir, input.target, input.events ?? [], input.taskData?.reviewReuse as Parameters<typeof validateV2ReviewSourceReads>[3]);
      const path = join(input.engagementDir, 'source_manifest.json');
      if (existsSync(path)) reviewRequests(input.engagementDir, JSON.parse(readFileSync(path, 'utf8')).source_files,
        [...canonicalV2Findings(input.engagementDir).keys()], (input.taskData?.flowIds ?? []) as string[], new Set());
    }
    if (input.phase.id === 'evaluate') validateV2Evaluation(input.engagementDir);
  }

  validateArtifactWrite(input: { phase: OffsecPhase; engagementDir: string; target: string; name: string; content: string; taskData?: Record<string, unknown>; events?: readonly ProviderRuntimeEvent[] }): void | { content: string; additionalContext?: string } {
    if (input.phase.id === 'recon' && input.name === '00_scanner_plan.json') {
      const plan = ScannerPlanSchema.parse(JSON.parse(input.content));
      const manifestPath = join(input.engagementDir, 'source_manifest.json'), graphPath = join(input.engagementDir, '00_inventory_graph.json');
      if (existsSync(manifestPath)) {
        const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
        const unreadable = new Set((manifest.source_errors ?? []).map((issue: { path: string }) => issue.path));
        validateScannerPlan(plan, manifest.source_files.filter((path: string) => !unreadable.has(path)), existsSync(graphPath) ? JSON.parse(readFileSync(graphPath, 'utf8')) : undefined);
      }
    }
    if (input.phase.id === 'analyze' && input.name === ANALYSIS_ASSESSMENTS && input.taskData?.taskRequest) {
      const request = input.taskData.taskRequest as AssessmentTask;
      const assessments = validateAnalysisAssessments({ value: JSON.parse(input.content), target: input.target,
        files: request.ownedSources.map(file => file.path), ranges: request.ownedSources,
        flows: request.flowResponsibilities, flowIds: request.flowResponsibilities.map(flow => flow.id),
        securityObligations:request.securityObligations,contextFiles:[...request.contextRanges.map(r=>r.path),...assessmentContextFiles(input.engagementDir,input.target)],findingIds:assessmentFindingIds(input.engagementDir) });
      validateAssessmentDelivery(request, assessments, input.target, input.events ?? []);
    }
    if (input.name === '02_followup_answers.json') FollowupAnswersSchema.parse(JSON.parse(input.content));
    if (input.name.endsWith('classification.yaml')) validateOffsecClassificationSyntax(input.content);
    if (input.phase.id === 'review' && input.name === '03_review_result.json') {
      const patch = prepareReviewPatch({ engagementDir: input.engagementDir, target: input.target, content: input.content,
        requireIndependentCounting: input.taskData?.independentCounting === true,
        events: input.events ?? [], reuse: input.taskData?.reviewReuse as Parameters<typeof validateV2ReviewSourceReads>[3] });
      if (patch) return patch;
      const proposedReview = JSON.parse(input.content);
      if (input.taskData?.independentCounting === true) proposedReview.countingSchemaVersion = 1;
      validateV2ReviewSourceReads(input.engagementDir, input.target, input.events ?? [],
        input.taskData?.reviewReuse as Parameters<typeof validateV2ReviewSourceReads>[3], proposedReview);
      if (input.taskData?.independentCounting === true) return { content: JSON.stringify(proposedReview, null, 2) + '\n' };
    }
    if (input.phase.id === 'evaluate') {
      validateV2EvaluationArtifact(input.engagementDir, input.name, input.content, input.target);
    }
  }

  renderArtifacts(phase: OffsecPhase, round?: string): { required: string[]; optional: string[] } {
    return renderPhaseArtifacts(phase, round);
  }

  resolveMethodFiles(phase: OffsecPhase): string[] {
    return resolvePhaseMethodFiles(phase);
  }

  resolveMethodologyFiles(phase: OffsecPhase): string[] {
    return resolvePhaseMethodologyFiles(phase, this.legacyContract);
  }

  resolveKnowledgeFiles(phase: OffsecPhase): string[] {
    return resolveKnowledgeFilesForPhase('offsec', phase.id);
  }

  canTransition(
    from: string,
    to: string,
    state: PhaseTransitionState,
  ): TransitionDecision {
    if (!this.contract.phases.some(phase => phase.id === to)) return { allowed: false, reason: `Unsupported phase: ${to}` };
    // Budget exhaustion — universal guard
    if (state.maxBudgetUsd !== undefined && state.totalCostUsd >= state.maxBudgetUsd) {
      return { allowed: false, reason: `예산 소진: ${state.totalCostUsd.toFixed(2)} >= ${state.maxBudgetUsd.toFixed(2)} USD` };
    }


    if (to === 'evaluate' && !state.completedPhases.has('review')) return { allowed: false, reason: 'evaluate는 review 완료 후에만 전이할 수 있다' };
    if (to === 'report' && !state.completedPhases.has('evaluate')) return { allowed: false, reason: 'report는 evaluate 완료 후에만 전이할 수 있다' };
    return { allowed: true };
  }
}
