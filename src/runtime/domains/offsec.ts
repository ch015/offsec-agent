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
import { countStandardFindings, readStandardFindings } from '../finding-contract.js';
import { validateObjectionCount } from '../objection-contract.js';
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
  const isV2 = contract.version.startsWith('2.');
  const resultSchemaId = isV2 ? 'nunchi.offsec.phase-result.v2' : 'nunchi.offsec.phase-result.v1';
  const workerPhases = isV2 ? ['analyze'] : ['va', 'verify'];
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
    return buildPhasePrompt({ ...input, contract: this.legacyContract });
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
  }): void {
    const isV2 = this.legacyContract.version.startsWith('2.');
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

    if (isV2) {
      // v2: objection 시스템 없음. findingCount 보정만 수행.
      return;
    }

    // v1: verifier/objection 로직 (기존 유지)
    if (input.phase.role === 'verifier') {
      if (input.phase.id === 'verify' || input.phase.id === 'verify-feedback') {
        // seal 시스템 제거 — autonomous artifact 존재/봉인 검증 불필요
      }
      const hostObjectionCount = validateObjectionCount({
        engagementDir: input.engagementDir,
        phase: input.phase.id,
        round: input.round,
        artifactNames: input.result.artifacts,
        declaredCount: input.result.metrics.objectionCount ?? 0,
      });
      input.result.metrics.objectionCount = hostObjectionCount;
      if (input.phase.id.startsWith('pentest-verify') && hostObjectionCount === 0) {
        const findings = readStandardFindings(input.engagementDir);
        const expected = new Set(findings.filter(
          (finding) =>
            (finding.phase === 'pentest' || finding.phase === 'pentest-feedback') &&
            finding.verdict === 'supported' && finding.reachability === 'confirmed',
        ).map((finding) => finding.id));
        const reviewed = findings.filter(
          (finding) =>
            finding.phase === input.phase.id &&
            finding.round === (input.round ?? null) &&
            finding.verdict === 'supported',
        );
        const reviewedIds = new Set(reviewed.map((finding) => finding.id));
        if (expected.size !== reviewedIds.size || [...expected].some((id) => !reviewedIds.has(id))) {
          throw new Error('pentest 독립 검증이 모든 live-confirmed Finding을 재확인하지 않았다');
        }
      }
    } else if (input.result.metrics.objectionCount !== undefined && input.result.metrics.objectionCount !== 0) {
      input.result.metrics.objectionCount = 0;
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
    // Budget exhaustion — universal guard
    if (state.maxBudgetUsd !== undefined && state.totalCostUsd >= state.maxBudgetUsd) {
      return { allowed: false, reason: `예산 소진: ${state.totalCostUsd.toFixed(2)} >= ${state.maxBudgetUsd.toFixed(2)} USD` };
    }

    const isV2 = this.legacyContract.version.startsWith('2.');

    if (isV2) {
      // v2: 선형 파이프라인. DAG 선행 조건은 engine이 assertWorkflowPrerequisites로 검사.
      // 도메인 가드는 evaluate가 review 완료 후에만 가능한지 확인.
      if (to === 'evaluate' && !state.completedPhases.has('review')) {
        return { allowed: false, reason: 'evaluate는 review 완료 후에만 전이할 수 있다' };
      }
      if (to === 'report' && !state.completedPhases.has('evaluate')) {
        return { allowed: false, reason: 'report는 evaluate 완료 후에만 전이할 수 있다' };
      }
      return { allowed: true };
    }

    // v1: Feedback iteration cap
    const FEEDBACK_PHASES = ['va-feedback', 'verify-feedback', 'pentest-feedback', 'pentest-verify-feedback'] as const;
    const maxIterations = this.legacyContract.limits.maxFeedbackIterations ?? 2;
    if (FEEDBACK_PHASES.includes(to as typeof FEEDBACK_PHASES[number])) {
      const completedFeedbackRounds = state.completedAttemptsByPhase[to] ?? 0;
      if (completedFeedbackRounds >= maxIterations) {
        return { allowed: false, reason: `${to} 반복 상한 초과: ${completedFeedbackRounds} >= ${maxIterations}` };
      }
    }

    if (to === 'converge' && !state.completedPhases.has('verify')) {
      return { allowed: false, reason: 'converge는 verify 완료 후에만 전이할 수 있다' };
    }

    return { allowed: true };
  }
}

export function assertOffsecConvergenceReady(
  executions: ReadonlyArray<{ phase: string; result: PhaseResult }>,
  verificationMode: 'VA_ONLY' | 'VA_PENTEST' | 'VA_PENTEST_REDTEAM',
): void {
  const latestVerifier = [...executions]
    .reverse()
    .find((execution) => execution.phase === 'verify' || execution.phase === 'verify-feedback');
  if (!latestVerifier) throw new Error('converge 전에 verifier 결과가 없다');
  // A fix: objection 미해결이어도 converge 진행 허용 — converge가 DISPUTED/PENDING으로 분류
  const lastFeedback = executions.findLastIndex((execution) => execution.phase === 'va-feedback');
  const lastVerifier = executions.findLastIndex(
    (execution) => execution.phase === 'verify' || execution.phase === 'verify-feedback',
  );
  if (lastFeedback > lastVerifier) throw new Error('최신 feedback 뒤 verifier 재검증이 없다');
  if (verificationMode.includes('PENTEST') && !executions.some((execution) => execution.phase === 'pentest')) {
    throw new Error('configured pentest phase가 완료되지 않았다');
  }
  if (verificationMode.includes('PENTEST')) {
    const lastPentestFeedback = executions.findLastIndex(
      (execution) => execution.phase === 'pentest-feedback',
    );
    const lastPentestVerifier = executions.findLastIndex(
      (execution) => execution.phase === 'pentest-verify' || execution.phase === 'pentest-verify-feedback',
    );
    if (lastPentestVerifier < 0) throw new Error('configured pentest 독립 검증이 완료되지 않았다');
    if (lastPentestFeedback > lastPentestVerifier) {
      throw new Error('최신 pentest feedback 뒤 독립 재검증이 없다');
    }
    // A fix: pentest objection 미해결이어도 converge 진행 허용
  }
  if (verificationMode.includes('REDTEAM') && !executions.some((execution) => execution.phase === 'redteam')) {
    throw new Error('configured redteam phase가 완료되지 않았다');
  }
}
