import { managedProviderProcess } from './provider-process.js';
import { observeSourceDelivery } from './source-delivery.js';
import { ACTION_GUIDANCE } from './workflow/action-guidance.js';
import { prepareReviewProgress, finishReviewProgress, type ReviewProgressContext, type ReviewReuse } from './review-progress.js';
/**
 * 세션 조립 — 미션 요청을 SDK `query()` 호출로 번역하는 유일한 지점.
 *
 * 여기 없는 것: 취약점 판정, 페르소나 프롬프트 내용, 증거·커버리지 게이트 로직,
 * 에이전트 실행 순서. 판정 방법론과 저수준 게이트는 도메인 플러그인이 갖고,
 * 실행 순서와 phase 전이는 호스트 미션이 갖는다.
 *
 * 관측된 계약에 의존한다 — 근거는 docs/002-plugin-contract-findings.md:
 *   F1  플러그인의 `hooks/hooks.json` 커맨드 훅이 발화한다. `settingSources: []`와 무관하다.
 *   F2  에이전트 정식 이름은 `<플러그인>:<하위경로>:<이름>`.
 *   F5  위임 시 bare 이름도 정식 이름으로 해석된다.
 *   F4  벤더 트리는 CommonJS이고 `domains/<d>/package.json`이 그것을 국소화한다.
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, unlinkSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { atomicPrivateWrite } from './workflow/storage-files.js';
import { SHARED_KNOWLEDGE_TOOLS } from './shared-knowledge.js';

import {
  query,
  type HookInput,
  type Options,
  type OutputFormat,
  type Query,
} from '@anthropic-ai/claude-agent-sdk';

import { createFindingMcpServer } from './finding-mcp-server.js';
import {
  DOMAINS,
  SessionExecutionError,
  type CompactBoundaryMetadata,
  type Domain,
  type LedgerRow,
  type SessionSpec,
} from './session-types.js';
export {
  DOMAINS,
  type CompactBoundaryMetadata,
  type Domain,
  type LedgerRow,
  type SessionSpec,
} from './session-types.js';
import {
  authorizeToolCall,
  canonicalPotentialPath,
  createToolPolicy,
} from './workflow/policy.js';
import { getDomainAdapter } from './domains/registry.js';
import { OffsecDomainAdapter } from './domains/offsec.js';
import { loadOffsecContract, type OffsecContract } from './offsec-contract.js';
import { domainAgentNames, domainPluginPath, safeParentEnv } from './session-support.js';
export { domainAgentNames, domainPluginPath } from './session-support.js';
import { buildFilteredPrompt } from './agents/phase-prompt-filter.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function sanitizeReminderText(value: string): string {
  return value.replace(/[\r\n]+/g, ' ').replace(/<[^>]*>/g, '').slice(0, 200);
}

function buildCompactionReminder(
  engagementDir: string,
  ledger: readonly LedgerRow[],
  workUnitReminder: string | undefined,
): string {
  const parts: string[] = ['--- Post-compaction context recovery ---'];
  const findingsDir = resolve(engagementDir, 'standard-findings');
  if (existsSync(findingsDir)) {
    const files = readdirSync(findingsDir).filter(n => n.endsWith('.json')).sort();
    const loaded: Array<{ id: string; severity: string; title: string }> = [];
    for (const name of files) {
      try {
        const record = JSON.parse(readFileSync(resolve(findingsDir, name), 'utf8'));
        if (
          record && typeof record === 'object' &&
          typeof record.id === 'string' &&
          typeof record.severity === 'string' &&
          typeof record.title === 'string'
        ) {
          loaded.push({ id: record.id, severity: record.severity, title: record.title });
        }
      } catch { /* skip malformed record */ }
    }
    if (loaded.length > 0) {
      parts.push(`Submitted findings (${loaded.length}):`);
      for (const f of loaded) {
        parts.push(`  ${sanitizeReminderText(f.id)} [${sanitizeReminderText(f.severity)}] ${sanitizeReminderText(f.title)}`);
      }
    }
  }
  const readFiles = [...new Set(
    ledger.filter(r => r.event === 'PreToolUse' && r.tool === 'Read' && r.resource).map(r => r.resource!),
  )];
  if (readFiles.length > 0) {
    parts.push(`Already analyzed (${readFiles.length} files):`);
    for (const file of readFiles.slice(0, 30)) parts.push(`  ${sanitizeReminderText(file)}`);
    if (readFiles.length > 30) parts.push(`  ... and ${readFiles.length - 30} more`);
  }
  if (workUnitReminder) parts.push('', workUnitReminder);
  return parts.length > 1 ? parts.join('\n') : (workUnitReminder ?? '');
}

function bindWorkUnitOutputFormat(
  outputFormat: OutputFormat,
  workUnit: NonNullable<SessionSpec['workUnit']>,
): OutputFormat {
  const schema = outputFormat.schema;
  const properties = schema.properties;
  const workUnitSchema = isRecord(properties) ? properties.workUnit : undefined;
  const workUnitProperties = isRecord(workUnitSchema) ? workUnitSchema.properties : undefined;
  if (!isRecord(properties) || !isRecord(workUnitSchema) || !isRecord(workUnitProperties)) {
    throw new Error('workUnit 세션의 출력 스키마에 workUnit identity 정의가 없다');
  }

  const required = Array.isArray(schema.required)
    ? schema.required.filter((value): value is string => typeof value === 'string')
    : [];
  return {
    ...outputFormat,
    schema: {
      ...schema,
      required: required.filter((name) => name !== 'workUnit'),
      properties: {
        ...properties,
        workUnit: {
          // The provider may omit, alter, or emit malformed identity here. The
          // WorkflowHost discards it and binds the request identity before domain
          // validation; keeping this placeholder permissive avoids identity-only
          // SDK retries while the root schema remains strict for every other field.
        },
      },
    },
  };
}

/**
 * Options 조립. 순수 함수 — 격리 회귀를 단위테스트 하나로 잡기 위해 분리한다.
 */
export function buildOptions(spec: SessionSpec, sourceLedger: readonly LedgerRow[] = []): Options {
  if (!isAbsolute(spec.target)) {
    throw new Error(`target 은 절대경로여야 한다: ${spec.target}`);
  }
  if (!existsSync(spec.target)) {
    throw new Error(`진단 대상이 없다: ${spec.target}`);
  }
  const targetRealpath = realpathSync(spec.target);
  const homeRealpath = process.env.HOME && existsSync(process.env.HOME)
    ? realpathSync(process.env.HOME)
    : undefined;
  if (targetRealpath === resolve('/') || targetRealpath === homeRealpath) {
    throw new Error(`진단 대상이 지나치게 넓다: ${targetRealpath}`);
  }
  if (!isAbsolute(spec.engagementDir)) {
    throw new Error(`engagementDir은 절대경로여야 한다: ${spec.engagementDir}`);
  }
  const engagementPath = canonicalPotentialPath(spec.engagementDir, spec.target);
  if (
    engagementPath === targetRealpath ||
    engagementPath === resolve('/') ||
    engagementPath === homeRealpath
  ) {
    throw new Error(`engagementDir 쓰기 범위가 지나치게 넓다: ${engagementPath}`);
  }

  const pluginPath = domainPluginPath(spec.domain);
  // contractPath가 있으면 해당 계약(v2)을 로드해 adapter를 만들고, MCP finding server에도 전달한다.
  // 없으면 단일 기본 계약 adapter를 사용한다.
  const loadedContract: OffsecContract | undefined =
    spec.domain === 'offsec' && spec.contractPath
      ? loadOffsecContract(spec.contractPath)
      : undefined;
  const adapter: import('./domains/domain-adapter.js').DomainAdapter = loadedContract
    ? new OffsecDomainAdapter(loadedContract)
    : getDomainAdapter(spec.domain, spec.mission);
  const workflowContract = adapter.contract;
  if (!spec.phase) throw new Error(`${spec.domain}/${adapter.mission} 세션에는 contract phase가 필요하다`);
  const { workflow: workflowPhase, legacy: phase } = adapter.getPhase(spec.phase);
  const reviewProgressContext: ReviewProgressContext | undefined = spec.domain === 'offsec' && spec.phase === 'review'
    && spec.model && spec.attemptId ? { engagementDir: spec.engagementDir, target: spec.target, runId: spec.engagementId,
      model: spec.model, revision: Number(spec.taskData?.reviewRevision ?? 0) } : undefined;
  const explicitAgents = adapter.buildAgentDefinitions();
  if (spec.domain !== 'offsec' && (!spec.allowedReadFiles || spec.allowedReadFiles.length === 0)) {
    throw new Error(`${spec.domain}/${adapter.mission} 세션에는 host exact read allow-list가 필요하다`);
  }
  const entryAgent = workflowPhase.role;
  const agentRole = workflowPhase.role;
  const entryAgentDefinition = explicitAgents[entryAgent];
  if (!entryAgentDefinition) {
    throw new Error(`entryAgent가 ${workflowContract.id} roles에 없다: ${entryAgent}`);
  }
  const phaseArtifacts = adapter.renderArtifacts(phase, spec.phaseRound);
  const phaseOutput = adapter.outputFormat(phase);
  // Bind provider output to the same artifact names that the host accepts.
  // Keep filesystem Write paths separate from the returned artifact identifiers.
  const outputProperties = phaseOutput.schema.properties;
  if (isRecord(outputProperties) && isRecord(outputProperties.artifacts)) {
    phaseOutput.schema = {
      ...phaseOutput.schema,
      properties: {
        ...outputProperties,
        artifacts: {
          ...outputProperties.artifacts,
          items: { type: 'string', enum: [...phaseArtifacts.required, ...phaseArtifacts.optional] },
        },
      },
    };
  }
  const allowedPhaseArtifacts = new Set([...phaseArtifacts.required, ...phaseArtifacts.optional]);
  const allowedMethodFiles = new Set(
    adapter.resolveMethodFiles(phase),
  );
  if (spec.entryAgent && explicitAgents && !explicitAgents[spec.entryAgent]) {
    throw new Error(`entryAgent가 ${workflowContract.id} roles에 없다: ${spec.entryAgent}`);
  }
  if (workflowPhase && spec.entryAgent !== undefined && spec.entryAgent !== workflowPhase.role) {
    throw new Error(`phase/entryAgent 계약 불일치: ${workflowPhase.id}/${workflowPhase.role} != ${String(spec.entryAgent)}`);
  }
  if (workflowPhase && spec.agentRole && workflowPhase.role !== spec.agentRole) {
    throw new Error(`phase/role 계약 불일치: ${workflowPhase.id}/${workflowPhase.role} != ${spec.agentRole}`);
  }
  const roleContract = workflowContract.roles[workflowPhase.role];
  if (!roleContract) throw new Error(`세션 role 계약이 없다: ${workflowPhase.role}`);
  const sourceReadable =
    spec.domain !== 'offsec' ||
    workflowPhase.role === 'scanner' ||
    workflowPhase.role === 'analyzer' ||
    workflowPhase.role === 'reviewer';
  const exactReadScope = spec.readScope === 'exact';
  if (exactReadScope && (!spec.allowedReadFiles || spec.allowedReadFiles.length === 0)) {
    throw new Error(`${spec.domain}/${workflowPhase.id} exact read scope에는 file allow-list가 필요하다`);
  }
  const networkAllowedDomains = [...new Set(spec.networkAllowedDomains ?? [])];
  if (networkAllowedDomains.length || spec.liveTestTarget || spec.liveTestPlan || spec.liveDastContext) {
    throw new Error('Live testing and network options are unsupported by source assessment');
  }
  const disabledTools = new Set(spec.disabledTools ?? []);
  for (const tool of disabledTools) {
    if (!roleContract.tools.includes(tool)) throw new Error(`비계약 도구를 disable할 수 없다: ${tool}`);
  }
  const effectiveTools = roleContract.tools.filter(
    (tool) =>
      !disabledTools.has(tool) &&
      !(SHARED_KNOWLEDGE_TOOLS.some(name => tool === `mcp__nunchi__${name}`) && !spec.sharedKnowledge) &&
      !(tool === 'mcp__nunchi__publish_shared_observation' && spec.sharedKnowledge?.snapshotPath),
  );
  const methodologyFiles = adapter.resolveMethodologyFiles?.(phase) ?? [];
  const knowledgeFiles = adapter.resolveKnowledgeFiles?.(phase) ?? [];
  const phaseVisibleReadFiles = [
    ...(spec.allowedReadFiles ?? []),
    ...[...phaseArtifacts.required, ...phaseArtifacts.optional].map((name) =>
      join(spec.engagementDir, name),
    ),
    ...knowledgeFiles,
  ];
  const toolPolicy = createToolPolicy({
    contractId: workflowContract.id,
    domain: spec.domain,
    phase: workflowPhase.id,
    role: agentRole,
    targetDir: spec.target,
    engagementDir: spec.engagementDir,
    allowedTools: new Set(effectiveTools),
    allowedReadRoots: spec.domain === 'offsec'
      ? sourceReadable && !exactReadScope
        ? [spec.target, spec.engagementDir]
        : []
      : [],
    allowImplicitRootRead: spec.domain === 'offsec' && !exactReadScope,
    ...(phaseVisibleReadFiles.length > 0 ? { allowedReadFiles: phaseVisibleReadFiles } : {}),
    allowedMethodFiles: new Set([...allowedMethodFiles, ...methodologyFiles]),
    allowedArtifacts: allowedPhaseArtifacts,
    allowedDelegates: new Set(roleContract.allowedDelegates),
  });
  const emit = (row: LedgerRow): void => spec.onLedger?.(row);
  const observedLedger: LedgerRow[] = [];
  let pendingWorkUnitReminder = false;
  let pendingFindingReminder = false;
  let pendingReviewWrite: string | undefined;
  const workUnitReminder = spec.workUnit
    ? `Host-owned immutable work-unit identity for subsequent tool work: ${JSON.stringify({
        workUnitKey: spec.workUnit.unitKey,
        workPlanSha256: spec.workUnit.workPlanSha256,
        assignedSourceSha256: spec.workUnit.assignedSourceSha256,
      })}. Preserve these exact values; do not derive identity from model memory or compact context.`
    : undefined;

  const record = (input: HookInput, extra: Partial<LedgerRow> = {}): void => {
    const toolInput =
      'tool_input' in input ? (input.tool_input as Record<string, unknown> | null) : null;
    const resource = toolInput?.file_path ?? toolInput?.path ?? toolInput?.notebook_path;
    const row: LedgerRow = {
      at: new Date().toISOString(),
      event: input.hook_event_name,
      agentId: input.agent_id,
      agentType: input.agent_type,
      tool: 'tool_name' in input ? String(input.tool_name) : undefined,
      resource: typeof resource === 'string' ? resource : undefined,
      query:
        typeof toolInput?.pattern === 'string'
          ? toolInput.pattern
          : typeof toolInput?.query === 'string'
            ? toolInput.query
            : undefined,
      ...extra,
    };
    observedLedger.push(row);
    emit(row);
  };

  return {
    cwd: sourceReadable && !exactReadScope ? spec.target : spec.engagementDir,
    // SDK 0.3.220은 `agent`와 `outputFormat`을 함께 지정하면 success여도
    // structured_output을 생략한다. 주 실행은 root에 두고 역할 계약만 system prompt로 주입한다.
    systemPrompt: {
      type: 'preset',
      preset: 'claude_code',
      append: `${buildFilteredPrompt(entryAgentDefinition.prompt, entryAgent, spec.phase)}\n\n${ACTION_GUIDANCE}`,
    },
    ...(explicitAgents ? { agents: explicitAgents } : {}),
    model: spec.model ?? 'opus',
    ...(spec.effort ? { effort: spec.effort } : {}),
    maxTurns: spec.maxTurns ?? 120,
    ...(spec.maxBudgetUsd !== undefined ? { maxBudgetUsd: spec.maxBudgetUsd } : {}),
    ...(spec.abortController ? { abortController: spec.abortController } : {}),
    ...(spec.onStderr ? { stderr: spec.onStderr } : {}),
    ...(spec.onProgress ? { forwardSubagentText: true } : {}),
    outputFormat: spec.workUnit
      ? bindWorkUnitOutputFormat(phaseOutput, spec.workUnit)
      : phaseOutput,
    tools: [...effectiveTools],
    allowedTools: [...effectiveTools],
    disallowedTools: [...workflowContract.forbiddenModelTools],
    ...(spec.domain === 'offsec'
      ? {
          mcpServers: {
            nunchi: createFindingMcpServer({
              sharedKnowledge: spec.sharedKnowledge,
              target: spec.target,
              engagementDir: spec.engagementDir,
              phase: workflowPhase.id,
              role: agentRole,
              round: spec.phaseRound,
              evidenceAllowedFiles: spec.workUnit?.findingSourceFiles ?? spec.workUnit?.ownedSourceFiles,
              sourceReadFiles: spec.allowedReadFiles,
              ...(loadedContract ? { contract: loadedContract } : {}),
            }),
          },
        }
      : {}),

    // 격리 — 사용자/프로젝트 settings.json 과 외부 MCP 를 차단한다.
    // 플러그인 훅은 이것과 무관하게 발화한다 (F1).
    settingSources: [],
    persistSession: false, // Host checkpoints own recovery; do not leave unmanaged SDK transcripts.
    strictMcpConfig: true,
    sandbox: {
      enabled: true,
      failIfUnavailable: true,
      autoAllowBashIfSandboxed: true,
      allowUnsandboxedCommands: false,
      network: { allowedDomains: networkAllowedDomains, strictAllowlist: true },
      filesystem: {
        allowWrite: [spec.engagementDir],
        denyWrite: [spec.target],
        ...(!sourceReadable || exactReadScope
          ? {
              denyRead: [spec.target],
              allowRead: [...phaseVisibleReadFiles, ...allowedMethodFiles, ...methodologyFiles],
            }
          : {}),
      },
    },
    permissionMode: workflowContract.isolation.permissionMode,

    // 도메인 하나만 로드한다. 다른 그룹의 에이전트는 이 세션에 존재하지 않는다.
    plugins: [{ type: 'local', path: pluginPath }],
    skills: [...roleContract.skills],

    // 벤더 훅이 읽는 런타임 환경. ANTHROPIC_API_KEY는 SDK 인증에 필수이므로
    // 예외적으로 전달한다 — sandbox network strictAllowlist로 유출 경로를 통제한다.
    env: {
      ...safeParentEnv(),
      CH015_COST_POLICY: spec.maxBudgetUsd === undefined ? 'record-only' : 'enforce',
      // P1: 인증 모드에 따라 API 키 전달 여부 결정
      // AUTH_MODE=oauth이면 API 키를 전달하지 않아 SDK가 OAuth 경로를 사용하도록 한다.
      // AUTH_MODE=api_key(기본)이면 API 키를 명시적으로 전달한다.
      ...((spec.authMode ?? (spec.apiKey !== undefined ? 'api_key' : process.env.AUTH_MODE)) !== 'oauth' && (spec.apiKey ?? process.env.ANTHROPIC_API_KEY)
        ? { ANTHROPIC_API_KEY: spec.apiKey ?? process.env.ANTHROPIC_API_KEY }
        : {}),
      PROJECT_DIR: spec.target,
      AGENT_ENGAGEMENT_DIR: spec.engagementDir,
      AGENT_ENGAGEMENT_ID: spec.engagementId,
      AGENT_REPORTS_DIR: spec.engagementDir,
      ...(agentRole ? { AGENT_ROLE: agentRole } : {}),
      ...(spec.phase ? { AGENT_PHASE: spec.phase } : {}),
      AGENT_MISSION: adapter.mission,
      ...(spec.phaseRound ? { AGENT_PHASE_ROUND: spec.phaseRound } : {}),
      ...(spec.verifyRound ? { AGENT_VERIFY_ROUND: spec.verifyRound } : {}),
      ...(spec.verifyGroup ? { AGENT_VERIFY_GROUP: spec.verifyGroup } : {}),
      ...(spec.requirePocBinding !== undefined
        ? { CH015_REQUIRE_POC_BINDING: spec.requirePocBinding ? 'on' : 'off' }
        : {}),
      CLAUDE_CODE_DISABLE_AUTO_MEMORY: '1',
      CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH: '1',
      ...(spec.domain === 'offsec'
        ? { CH015_REPORT_GATE: spec.phase === 'report' ? (process.env.CH015_REPORT_GATE_OVERRIDE ?? process.env.CH015_REPORT_GATE ?? 'on') : 'on' }
        : {}),
      AGENT_CONTRACT_ID: workflowContract.id,
      AGENT_CONTRACT_VERSION: workflowContract.version,
      ...(spec.domain === 'offsec' && loadedContract ? { AGENT_REPORT_DRAFT_ARTIFACT: loadedContract.publication.draftArtifact } : {}),
    },

    hooks: {
      PreToolUse: [
        {
          hooks: [
            async (input) => {
              const tool = 'tool_name' in input ? String(input.tool_name) : '';
              const toolInput =
                'tool_input' in input
                  ? (input.tool_input as Record<string, unknown> | null)
                  : null;
              let decision = authorizeToolCall(toolPolicy, {
                tool,
                input: toolInput,
                ...(input.agent_type ? { agentType: input.agent_type } : {}),
              });
              if (spec.abortController?.signal.aborted) {
                decision = { decision: 'deny', reason: 'The work unit was cancelled or exceeded its execution limit.' };
              }
              const artifactPath = toolInput?.file_path;
              let artifactContext: string | undefined;
              const reviewWrite = spec.domain === 'offsec' && spec.phase === 'review' && tool === 'Write'
                && typeof artifactPath === 'string' && basename(artifactPath) === '03_review_result.json';
              if (decision.decision === 'allow' && tool === 'Write' && adapter.validateArtifactWrite && typeof artifactPath === 'string') {
                try {
                  if (reviewWrite && pendingReviewWrite !== undefined) throw new Error('A review Write is still in progress. Wait for its result, then retry this patch; send review Writes sequentially.');
                  if (typeof toolInput?.content !== 'string') throw new Error('Write requires string content');
                  const prepared = adapter.validateArtifactWrite({ phase, engagementDir: spec.engagementDir,
                    target: spec.target, name: basename(artifactPath), content: toolInput.content,
                    taskData: spec.taskData, events: sourceLedger });
                  if (prepared) {
                    decision = { ...decision, updatedInput: { ...(decision.updatedInput ?? toolInput), content: prepared.content } };
                    artifactContext = prepared.additionalContext;
                  }
                  if (reviewWrite && 'tool_use_id' in input) {
                    if (reviewProgressContext) prepareReviewProgress(reviewProgressContext, {
                      attempt: spec.attemptId!, content: prepared?.content ?? toolInput.content,
                      events: sourceLedger.map(row => ({ ...row, actor: row.agentType ?? workflowPhase.role })),
                      reuse: spec.taskData?.reviewReuse as ReviewReuse | undefined,
                    });
                    pendingReviewWrite = String(input.tool_use_id);
                  }
                } catch (error) {
                  decision = { decision: 'deny', reason: `Artifact validation failed; repair this Write in the current session: ${error instanceof Error ? error.message : String(error)}` };
                }
              }
              let additionalContext: string | undefined = artifactContext;
              if (pendingFindingReminder) {
                additionalContext = [additionalContext, buildCompactionReminder(spec.engagementDir, observedLedger, workUnitReminder)].filter(Boolean).join('\n');
                pendingFindingReminder = false;
                pendingWorkUnitReminder = false;
              } else if (pendingWorkUnitReminder) {
                additionalContext = [additionalContext, workUnitReminder].filter(Boolean).join('\n');
                pendingWorkUnitReminder = false;
              }
              record(input, { decision: decision.decision, reason: decision.reason });
              if (
                decision.decision === 'allow' &&
                decision.updatedInput === undefined &&
                additionalContext === undefined
              ) {
                return { continue: true };
              }
              return {
                continue: true,
                hookSpecificOutput: {
                  hookEventName: 'PreToolUse',
                  permissionDecision: decision.decision,
                  permissionDecisionReason: decision.reason,
                  ...(decision.updatedInput ? { updatedInput: decision.updatedInput } : {}),
                  ...(additionalContext ? { additionalContext } : {}),
                },
              };
            },
          ],
        },
      ],
      PostToolUse: [
        {
          matcher: 'Write',
          hooks: [
            async (input) => {
              if (input.hook_event_name !== 'PostToolUse') return { continue: true };
              if (String(input.tool_use_id) === pendingReviewWrite) {
                if (reviewProgressContext) finishReviewProgress(reviewProgressContext, true);
                pendingReviewWrite = undefined;
              }
              return { continue: true };
            },
          ],
        },
      ],
      PostToolUseFailure: [{ matcher: 'Write', hooks: [async input => {
        if ('tool_use_id' in input && String(input.tool_use_id) === pendingReviewWrite) {
          if (reviewProgressContext) finishReviewProgress(reviewProgressContext, false);
          pendingReviewWrite = undefined;
        }
        return { continue: true };
      }] }],
      // 위임 그래프 — 누가 언제 어떤 워커를 띄웠는지
      SubagentStart: [{ hooks: [async (i) => (record(i), { continue: true })] }],
      SubagentStop: [{ hooks: [async (i) => (record(i), { continue: true })] }],
      PostCompact: [{
        hooks: [async (input) => {
          if (input.hook_event_name === 'PostCompact') {
            if (spec.workUnit) pendingWorkUnitReminder = true;
            pendingFindingReminder = true;
          }
          return { continue: true };
        }],
      }],
    },
  };
}

export type SessionOutcome = {
  /** 메인 스레드가 남긴 텍스트 */
  texts: string[];
  ledger: LedgerRow[];
  /** SDK 가 보고한 종료 사유 */
  subtype?: string;
  terminalReason?: string;
  resultText?: string;
  errors?: string[];
  numTurns?: number;
  totalCostUsd?: number;
  /** False means some provider usage is unknown; totalCostUsd is only the known total. */
  costAccountingComplete?: boolean;
  /** 모델별 토큰 회계 */
  modelUsage?: unknown;
  /** outputFormat JSON schema로 검증된 phase 결과 */
  structuredOutput?: unknown;
  /** SDK structured_output 또는 엄격한 최종 assistant JSON 복구 경로 */
  structuredOutputSource?: 'sdk' | 'assistant-json';
  /** 세션에 등록된 서브에이전트 — 도메인 플러그인이 실제로 로드됐는지 확증한다 */
  registeredAgents?: { name: string; description: string; model?: string }[];
};

/**
 * 세션 구동. 스트림을 소비하며 원장과 회계를 모은다.
 */
export async function runSession(spec: SessionSpec): Promise<SessionOutcome> {
  const ledger: LedgerRow[] = [];
  const emitLedger = (row: LedgerRow): void => {
    ledger.push(row);
    spec.onLedger?.(row);
  };
  const options = buildOptions({
    ...spec,
    onLedger: emitLedger,
  }, ledger);
  options.includePartialMessages = true;
  mkdirSync(spec.engagementDir, { recursive: true, mode: 0o700 });

  const processLifetime = managedProviderProcess(spec.engagementDir, spec.attemptId, options.stderr);
  options.spawnClaudeCodeProcess = processLifetime.start;
  const q: Query = query({ prompt: spec.prompt, options });
  const readCalls = new Map<string, { file: string; offset?: number; limit?: number }>();
  // close() ends the local CLI and its transports; it does not prove remote billing stopped.
  const closeQuery = () => q.close?.();
  spec.abortController?.signal.addEventListener('abort', closeQuery, { once: true });
  if (spec.abortController?.signal.aborted) closeQuery();
  const outcome: SessionOutcome = { texts: [], ledger };
  let lastHeartbeat = 0;
  const usageReceiptPath = join(spec.engagementDir, 'session-usage', `${randomUUID()}.json`);

  try {
    for await (const message of q) {
      // Report that bytes are arriving without logging reasoning, partial tool
      // arguments or model text. Heartbeats are transient, not evidence/usage.
      if (message.type === 'stream_event' && message.parent_tool_use_id === null && Date.now() - lastHeartbeat >= 5000) {
        lastHeartbeat = Date.now(); spec.onProgress?.({ kind: 'heartbeat', from: 'provider', detail: '' });
      }
      if (message.type === 'system' && message.subtype === 'api_retry') {
        const delay = Number.isFinite(message.retry_delay_ms) && message.retry_delay_ms >= 0 ? message.retry_delay_ms : 1000;
        emitLedger({ at: new Date().toISOString(), event: [429, 503, 529].includes(message.error_status ?? 0) ? 'ProviderPressure' : 'ProviderRetry',
          reason: `SDK API retry ${message.attempt}/${message.max_retries}; HTTP ${message.error_status ?? 'unknown'}`, retryAfterMs: delay });
      }
      if (message.type === 'rate_limit_event' && message.rate_limit_info.status === 'rejected') {
        emitLedger({ at: new Date().toISOString(), event: 'ProviderPressure', reason: 'SDK subscription rate limit rejected a request', retryAfterMs: 1000 });
      }
      if (message.type === 'system' && message.subtype === 'compact_boundary') {
        const metadata: CompactBoundaryMetadata = {
          trigger: message.compact_metadata.trigger,
          preTokens: message.compact_metadata.pre_tokens,
          ...(message.compact_metadata.post_tokens !== undefined
            ? { postTokens: message.compact_metadata.post_tokens }
            : {}),
          ...(message.compact_metadata.duration_ms !== undefined
            ? { durationMs: message.compact_metadata.duration_ms }
            : {}),
          boundaryId: message.uuid,
        };
        emitLedger({ at: new Date().toISOString(), event: 'compact_boundary', compaction: metadata });
      }
      if (message.type === 'system' && message.subtype === 'init') {
        outcome.registeredAgents = await q.supportedAgents().catch(() => undefined);
      }
      if (message.type === 'user' && message.parent_tool_use_id === null && Array.isArray(message.message.content)) {
        for (const block of message.message.content) {
          if (block.type !== 'tool_result') continue;
          const call = readCalls.get(block.tool_use_id);
          if (!call) continue;
          readCalls.delete(block.tool_use_id);
          const observed = observeSourceDelivery({ target: spec.target, ...call,
            allowedFiles: spec.allowedReadFiles ?? [], toolCallId: block.tool_use_id,
            content: block.content, isError: block.is_error });
          if (observed) {
            emitLedger({ at: new Date().toISOString(), event: 'SourceDelivery',
              tool: 'Read', decision: 'allow', agentType: spec.agentRole, ...observed });
            if (observed.delivery.status === 'error') emitLedger({ at: new Date().toISOString(), event: 'SourceReadFailed', tool: 'Read', resource: observed.resource, reason: observed.reason });
          }
        }
      }
      if (message.type === 'assistant') {
        // parent_tool_use_id 가 있으면 서브에이전트의 발화다 (forwardSubagentText).
        const fromSubagent =
          'parent_tool_use_id' in message && message.parent_tool_use_id !== null;
        for (const block of message.message.content) {
          if (block.type === 'text') {
            if (fromSubagent) {
              spec.onProgress?.({ kind: 'text', from: 'subagent', detail: block.text });
            } else {
              outcome.texts.push(block.text);
            }
          } else if (block.type === 'tool_use') {
            const args = block.input as Record<string, unknown> | null;
            if (!fromSubagent && ['Read', 'mcp__nunchi__read_source'].includes(block.name) && typeof args?.file_path === 'string') {
              readCalls.set(block.id, { file: args.file_path,
                ...(typeof args.offset === 'number' ? { offset: args.offset } : {}),
                ...(typeof args.limit === 'number' ? { limit: args.limit } : {}),
              });
            }
            spec.onProgress?.({
              kind: 'tool',
              from: fromSubagent ? 'subagent' : 'main',
              detail: block.name,
            });
          }
        }
      }
      if (message.type === 'result') {
        outcome.subtype = message.subtype;
        outcome.terminalReason = message.terminal_reason;
        outcome.numTurns = message.num_turns;
        outcome.totalCostUsd = message.total_cost_usd;
        if ('modelUsage' in message) outcome.modelUsage = message.modelUsage;
        atomicPrivateWrite(usageReceiptPath, JSON.stringify({
          runId: spec.engagementId, attemptId: spec.attemptId,
          phase: spec.phase, round: spec.phaseRound, model: spec.model,
          subtype: outcome.subtype, terminalReason: outcome.terminalReason,
          turns: outcome.numTurns, costUsd: outcome.totalCostUsd, modelUsage: outcome.modelUsage,
        }) + '\n');
        if (message.subtype === 'success') outcome.resultText = message.result;
        else outcome.errors = message.errors;
        if ('structured_output' in message && message.structured_output !== undefined) {
          outcome.structuredOutput = message.structured_output;
          outcome.structuredOutputSource = 'sdk';
        }
      }
    }
  } catch (cause) {
    throw new SessionExecutionError(outcome, cause);
  } finally {
    spec.abortController?.signal.removeEventListener('abort', closeQuery);
    closeQuery();
    await processLifetime.exited();
  }

  if (outcome.subtype === 'success' && outcome.structuredOutput === undefined) {
    const recovered = recoverStructuredOutput(outcome.resultText ? [outcome.resultText] : outcome.texts);
    if (recovered !== undefined) {
      outcome.structuredOutput = recovered;
      outcome.structuredOutputSource = 'assistant-json';
    }
  }

  return outcome;
}

export function recoverStructuredOutput(texts: readonly string[]): unknown | undefined {
  const last = [...texts].reverse().find((text) => text.trim().length > 0)?.trim();
  if (!last) return undefined;
  const fenced = /^```(?:json)?\s*\n([\s\S]*?)\n```$/i.exec(last);
  const candidate = fenced?.[1] ?? last;
  try {
    return JSON.parse(candidate);
  } catch {
    return undefined;
  }
}
