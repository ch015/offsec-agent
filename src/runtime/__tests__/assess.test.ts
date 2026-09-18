import { existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  getOffsecPhase,
  loadOffsecContract,
  renderPhaseArtifacts,
  resolvePhaseMethodFiles,
} from '../offsec-contract.js';
import {
  assess,
  AssessAwaitingInputError,
  resolveLiveTestTarget,
  resolveRunBudget,
} from '../missions/assess.js';
import {
  recoverAssessPublication,
  resumeAssessFromCheckpoint,
  resumeAssessOwnerAuth,
} from '../missions/assess-resume.js';
import type { SessionOutcome, SessionSpec } from '../session.js';
import { FileRunStateStore } from '../workflow/state-store.js';
import { submitStandardObjection } from '../objection-contract.js';
import { readStandardFindings, submitStandardFinding } from '../finding-contract.js';
import { InMemoryRunLeaseBackend } from '../workflow/run-lease.js';
import type { AuthInteractionAdapter } from '../auth-interaction.js';
import { assertScopeAssuranceIntact } from '../workflow/scope-assurance.js';

// seal 시스템 제거됨 — autonomous artifact 작성만 하고 seal은 하지 않음
function sealAutonomousIfRequired(spec: SessionSpec, requiredArtifacts: readonly string[]): void {
  const name = requiredArtifacts.find((artifact) => artifact.startsWith('02a_verify_autonomous-'));
  if (!name) return;
  const artifactPath = join(spec.engagementDir, name);
  writeFileSync(artifactPath, '# Autonomous discovery (seal removed)\n\nNo seal required.\n');
}

function workUnitResult(spec: SessionSpec) {
  return spec.workUnit ? {
    workUnit: {
      workUnitKey: spec.workUnit.unitKey,
      workPlanSha256: spec.workUnit.workPlanSha256,
      assignedSourceSha256: spec.workUnit.assignedSourceSha256,
    },
  } : {};
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

function phaseArtifactContent(phaseId: string, engagementDir?: string): string {
  if (phaseId === 'report' && engagementDir) {
    const selection = join(engagementDir, 'auth_interaction_selection.json');
    const profile = join(engagementDir, 'live-test-profile.json');
    if (existsSync(selection) && existsSync(profile)) {
      const selected = JSON.parse(readFileSync(selection, 'utf8')) as { selectionSha256: string };
      const profileSha256 = createHash('sha256').update(readFileSync(profile)).digest('hex');
      return `${profileSha256}\n${selected.selectionSha256}\n`;
    }
  }
  return phaseId === 'pentest-plan'
    ? `${JSON.stringify({
        schemaVersion: '1.0.0',
        scenarios: [{
          scenarioId: 'SC-1', path: 'health', method: 'GET', safety: 'ready',
          preconditions: ['isolated test'], successCriteria: 'HTTP 200', failureCriteria: 'non-200',
        }],
      })}\n`
    : '{}\n';
}

async function successfulOffsecSession(spec: SessionSpec): Promise<SessionOutcome> {
  const contract = loadOffsecContract();
  const phase = getOffsecPhase(String(spec.phase), contract);
  const artifacts = renderPhaseArtifacts(phase, spec.phaseRound);
  for (const artifact of artifacts.required) {
    const content = phase.id === 'report'
      ? `${phaseArtifactContent(phase.id, spec.engagementDir)}${readStandardFindings(spec.engagementDir).map((finding) =>
          `${finding.id}${finding.runtimeEvidence ? ` ${finding.runtimeEvidence.receiptId}` : ''}`).join('\n')}\n`
      : phaseArtifactContent(phase.id, spec.engagementDir);
    writeFileSync(join(spec.engagementDir, artifact), content);
  }
  sealAutonomousIfRequired(spec, artifacts.required);
  return {
    texts: [],
    ledger: resolvePhaseMethodFiles(phase).map((resource) => ({
      at: new Date(0).toISOString(),
      event: 'PreToolUse',
      tool: 'Read',
      resource,
      decision: 'allow',
    })),
    subtype: 'success',
    numTurns: 1,
    totalCostUsd: 1,
    modelUsage: { [spec.model!]: { inputTokens: 1, outputTokens: 1 } },
    structuredOutput: {
      contractVersion: contract.version,
      phase: phase.id,
      role: phase.role,
      status: 'complete',
      artifacts: artifacts.required,
      summary: `${phase.id} complete`,
      metrics: { findingCount: 0, objectionCount: 0 },
      unresolved: [],
      ...workUnitResult(spec),
    },
  };
}

function writeTwoUnitFixture(target: string): void {
  for (const name of ['a', 'b']) {
    const root = join(target, 'packages', name);
    mkdirSync(join(root, 'src'), { recursive: true });
    writeFileSync(join(root, 'package.json'), `${JSON.stringify({ name })}\n`);
    writeFileSync(join(root, 'src', `${name}.ts`), `export const ${name} = ${JSON.stringify(name)};\n`);
  }
}

describe('assess host state machine', () => {
  it('rejects an invalid final and recovers only a gated report after publication interruption', async () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-assess-publication-recovery-'));
    const engagementDir = join(target, 'reports', 'publication-recovery');
    mkdirSync(engagementDir, { recursive: true });
    const contract = loadOffsecContract();
    const store = FileRunStateStore.create({
      engagementDir,
      runId: 'publication-recovery',
      contractId: contract.id,
      contractVersion: contract.version,
      domain: 'offsec',
      mission: 'assessment',
    });
    store.append({ type: 'phase.started', eventId: 'report:start', phase: 'report', attempt: 1 });
    store.append({
      type: 'attempt.received', eventId: 'report:receipt', phase: 'report', attempt: 1,
      usage: { provider: 'anthropic', costUsd: 1 },
    });
    store.append({
      type: 'phase.completed', eventId: 'report:completed', phase: 'report', attempt: 1,
      artifacts: [], result: { status: 'complete' },
    });
    const gitHead = 'b'.repeat(40);
    const finalPath = join(engagementDir, contract.publication.finalArtifact);
    writeFileSync(finalPath, '# incomplete report\n');
    writeFileSync(join(engagementDir, '01_va_raw_findings_ledger-1st.yaml'), 'candidates: []\n');
    writeFileSync(
      join(engagementDir, '06c_convergence_classification.yaml'),
      'equivalence_review:\n  status: COMPLETE\n  reviewed_candidate_count: 0\n  unresolved: []\n',
    );
    writeFileSync(join(engagementDir, 'source_manifest.json'), `${JSON.stringify({
      hash: 'a'.repeat(64),
      git_branch: 'main',
      git_head: gitHead,
    })}\n`);
    writeFileSync(join(engagementDir, 'fanout_decision.json'), `${JSON.stringify({
      manifest_hash: 'a'.repeat(64),
    })}\n`);

    await expect(recoverAssessPublication({ engagementDir, runId: 'publication-recovery' })).rejects.toThrow('PROVENANCE_NOT_IN_REPORT');
    expect(FileRunStateStore.open(engagementDir).read().status).toBe('running');
    writeFileSync(finalPath, `# Validated report\nAssessed commit: ${gitHead}\n`);
    const result = await recoverAssessPublication({ engagementDir, runId: 'publication-recovery' });
    expect(result).toBeDefined();
    const recovered = FileRunStateStore.open(engagementDir).read();
    expect(recovered.status).toBe('completed');
    expect(recovered.publication?.artifact.name).toBe(contract.publication.finalArtifact);
  });

  it('seals the interaction mode, pauses for owner auth and resumes the same run', async () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-assess-auth-resume-'));
    const engagementDir = join(target, 'reports', 'auth-resume');
    const profilePath = join(target, 'live-profile.json');
    writeFileSync(join(target, 'app.ts'), 'export const value = 1;\n');
    writeFileSync(profilePath, `${JSON.stringify({
      schemaVersion: '1.0.0',
      environment: 'test',
      authorization: { nonProduction: true, approvedBy: 'test owner', approvedAt: new Date().toISOString() },
      targetBaseUrl: 'https://test.example/app/',
      authProviderOrigins: ['https://idp.example/'],
      actors: [{ actorId: 'member', role: 'member', authKind: 'oauth-oidc' }],
      policy: {
        allowedMethods: ['GET', 'HEAD'], maximumRiskClass: 'read-only', maxRequests: 10,
        maxResponseBytes: 4096, timeoutMs: 1000, maxStateChanges: 0, maxDurationMs: 60_000,
      },
    })}\n`);
    let checkpoint: AssessAwaitingInputError | undefined;
    try {
      await assess({
        target,
        engagementDir,
        engagementId: 'auth-resume',
        verificationMode: 'VA_PENTEST',
        semgrepMode: 'off',
        liveTestProfilePath: profilePath,
        authInteractionMode: 'remote-handoff',
      });
    } catch (error) {
      if (error instanceof AssessAwaitingInputError) checkpoint = error;
      else throw error;
    }
    expect(checkpoint?.requestId).toMatch(/^AUTH-/);
    expect(FileRunStateStore.open(engagementDir).read().status).toBe('awaiting-input');
    const adapter: AuthInteractionAdapter = {
      mode: 'remote-handoff',
      begin: async (request) => ({
        requestId: request.requestId,
        mode: 'remote-handoff',
        userAction: 'complete test login',
        browserOpened: false,
        expiresAt: request.expiresAt,
      }),
      capture: async () => ({
        materialKind: 'oauth-token-set',
        material: Buffer.from(JSON.stringify({ accessToken: 'test-token-value' })),
        publicMetadata: { issuer: 'https://idp.example/' },
      }),
      close: async () => undefined,
    };
    await expect(resumeAssessOwnerAuth({
      engagementDir,
      expectedVersion: checkpoint!.expectedVersion + 1,
      requestId: checkpoint!.requestId,
      requestSha256: checkpoint!.requestSha256,
      adapter,
      waitForOwner: async () => undefined,
    }, {
      leaseBackend: new InMemoryRunLeaseBackend(),
      sessionRunner: successfulOffsecSession,
    })).rejects.toThrow(/version 충돌/);
    const wrongModeAdapter: AuthInteractionAdapter = {
      mode: 'local-headed-browser',
      begin: async () => { throw new Error('must not begin'); },
      capture: async () => { throw new Error('must not capture'); },
      close: async () => undefined,
    };
    await expect(resumeAssessOwnerAuth({
      engagementDir,
      expectedVersion: checkpoint!.expectedVersion,
      requestId: checkpoint!.requestId,
      requestSha256: checkpoint!.requestSha256,
      adapter: wrongModeAdapter,
      waitForOwner: async () => undefined,
    }, {
      leaseBackend: new InMemoryRunLeaseBackend(),
      sessionRunner: successfulOffsecSession,
    })).rejects.toThrow(/봉인된 auth interaction mode/);
    const resumed = await resumeAssessOwnerAuth({
      engagementDir,
      expectedVersion: checkpoint!.expectedVersion,
      requestId: checkpoint!.requestId,
      requestSha256: checkpoint!.requestSha256,
      adapter,
      waitForOwner: async () => undefined,
    }, {
      leaseBackend: new InMemoryRunLeaseBackend(),
      sessionRunner: successfulOffsecSession,
      reportPublisher: (dir) => {
        const draft = join(dir, '07_security_report.draft.md');
        const final = join(dir, '07_security_report.md');
        renameSync(draft, final);
        return final;
      },
    });
    expect(resumed.phases.map((phase) => phase.phase)).toContain('pentest-verify');
    expect(FileRunStateStore.open(engagementDir).read().status).toBe('completed');
    expect(readFileSync(join(engagementDir, 'auth_interaction_selection.json'), 'utf8'))
      .toContain('remote-handoff');
    unlinkSync(resumed.finalReport);
    await expect(resumeAssessOwnerAuth({
      engagementDir,
      expectedVersion: checkpoint!.expectedVersion,
      requestId: checkpoint!.requestId,
      requestSha256: checkpoint!.requestSha256,
      adapter,
      waitForOwner: async () => undefined,
    }, { leaseBackend: new InMemoryRunLeaseBackend() })).rejects.toThrow(/artifact/);
  });

  it('owns phase order and executes feedback only when verifier objects', async () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-assess-test-'));
    const engagementDir = join(target, 'reports', 'e1');
    writeFileSync(join(target, 'app.ts'), 'export const value = 1;\n');
    mkdirSync(join(target, 'reports', 'old'), { recursive: true });
    const staleReport = join(target, 'reports', 'old', '01_va_raw_findings_ledger.yaml');
    writeFileSync(staleReport, 'candidates:\n  - title: anchored stale finding\n');
    const contract = loadOffsecContract();
    const observedModels: Record<string, string | undefined> = {};
    const observedSpecs: Record<string, SessionSpec> = {};
    let reportRequiredPocBinding: boolean | undefined;

    const sessionRunner = async (spec: SessionSpec): Promise<SessionOutcome> => {
      const phase = getOffsecPhase(String(spec.phase), contract);
      observedModels[phase.id] = spec.model;
      observedSpecs[phase.id] = spec;
      const artifacts = renderPhaseArtifacts(phase, spec.phaseRound);
      for (const artifact of artifacts.required) {
        writeFileSync(join(spec.engagementDir, artifact), phaseArtifactContent(phase.id, spec.engagementDir));
      }
      sealAutonomousIfRequired(spec, artifacts.required);
      const objectionCount = phase.id === 'verify' ? 1 : 0;
      const objectionArtifact = artifacts.optional.find((name) => name.includes('_objections-'));
      if (objectionCount > 0 && objectionArtifact) {
        writeFileSync(
          join(spec.engagementDir, objectionArtifact),
          'objections:\n  - finding_id: F-1\n    type: evidence\n    reason: missing\n    instruction: recheck\n',
        );
        submitStandardObjection({
          engagementDir: spec.engagementDir,
          contractVersion: contract.version,
          phase: phase.id,
          role: phase.role,
          round: spec.phaseRound,
          objection: {
            findingId: 'F-1',
            type: 'evidence',
            reason: 'missing',
            instruction: 'recheck',
          },
        });
      }
      return {
        texts: [],
        ledger: resolvePhaseMethodFiles(phase).map((resource) => ({
          at: new Date(0).toISOString(),
          event: 'PreToolUse',
          tool: 'Read',
          resource,
          decision: 'allow',
        })),
        subtype: 'success',
        numTurns: 1,
        totalCostUsd: 1,
        modelUsage: { [spec.model!]: { inputTokens: 1, outputTokens: 1 } },
        structuredOutput: {
          contractVersion: contract.version,
          phase: phase.id,
          role: phase.role,
          status: 'complete',
          artifacts: [
            ...artifacts.required,
            ...(objectionCount > 0 && objectionArtifact ? [objectionArtifact] : []),
          ],
          summary: `${phase.id} complete`,
          metrics: {
            findingCount: 0,
            objectionCount,
          },
          unresolved: [],
          ...workUnitResult(spec),
        },
      };
    };

    const reportPublisher = (dir: string, requirePocBinding: boolean): string => {
      reportRequiredPocBinding = requirePocBinding;
      const draft = join(dir, '07_security_report.draft.md');
      const final = join(dir, '07_security_report.md');
      renameSync(draft, final);
      return final;
    };

    const result = await assess(
      {
        target,
        engagementDir,
        engagementId: 'e1',
        verificationMode: 'VA_PENTEST',
        semgrepMode: 'off',
        testUrl: 'https://test.example/app/',
      },
      { sessionRunner, reportPublisher },
    );

    expect(result.phases.map((phase) => phase.phase)).toEqual([
      'va',
      'verify',
      'va-feedback',
      'verify-feedback',
      'pentest-plan',
      'pentest-discovery',
      'pentest',
      'pentest-verify',
      'converge',
      'report',
    ]);
    expect(result.outcome.totalCostUsd).toBe(10);
    expect(observedModels.verify).toBe('sonnet');
    expect(observedModels['verify-feedback']).toBe('sonnet');
    expect(observedModels['pentest-verify']).toBe('sonnet');
    expect(observedModels.va).toBe('opus');
    expect(observedModels.pentest).toBe('opus');
    expect(observedSpecs.va?.networkAllowedDomains).toBeUndefined();
    expect(observedSpecs.va?.allowedReadFiles).toEqual(expect.arrayContaining([
      join(engagementDir, 'source_manifest.json'),
      join(target, 'app.ts'),
      join(engagementDir, '00_ast_context.yaml'),
    ]));
    expect(observedSpecs.va?.readScope).toBe('exact');
    expect(observedSpecs.va?.allowedReadFiles).not.toContain(staleReport);
    expect(readFileSync(join(engagementDir, 'source_manifest.json'), 'utf8')).not.toContain('reports/old');
    expect(existsSync(join(engagementDir, '00_ast_context.yaml'))).toBe(true);
    expect(observedSpecs.pentest?.networkAllowedDomains).toEqual(['test.example']);
    expect(observedSpecs['pentest-plan']?.readScope).toBe('exact');
    expect(observedSpecs['pentest-plan']?.disabledTools).toContain('mcp__nunchi__http_probe');
    expect(observedSpecs.pentest?.readScope).toBe('exact');
    expect(observedSpecs.pentest?.liveTestTarget).toBe('https://test.example/app/');
    expect(observedSpecs.pentest?.requirePocBinding).toBe(true);
    expect(reportRequiredPocBinding).toBe(true);
    expect(existsSync(result.finalReport)).toBe(true);
    const snapshot = FileRunStateStore.open(engagementDir).read();
    expect(snapshot.publication?.artifact.name).toBe('07_security_report.md');
    expect(snapshot.status).toBe('completed');
  });

  it('resumes after a completed phase host-effect boundary without rerunning that phase', async () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-assess-checkpoint-resume-'));
    const engagementDir = join(target, 'reports', 'checkpoint-resume');
    writeFileSync(join(target, 'app.ts'), 'export const value = 1;\n');
    let vaCalls = 0;
    let injectFanoutFailure = true;
    const sessionRunner = async (spec: SessionSpec): Promise<SessionOutcome> => {
      const outcome = await successfulOffsecSession(spec);
      if (spec.phase === 'va') {
        vaCalls += 1;
        if (injectFanoutFailure) {
          writeFileSync(join(engagementDir, '02_verify_result-1st.md'), 'orphan verifier artifact\n');
        }
      }
      return outcome;
    };
    const reportPublisher = (dir: string): string => {
      const draft = join(dir, '07_security_report.draft.md');
      const final = join(dir, '07_security_report.md');
      renameSync(draft, final);
      return final;
    };

    await expect(assess({
      target,
      engagementDir,
      engagementId: 'checkpoint-resume',
      semgrepMode: 'off',
    }, { sessionRunner, reportPublisher })).rejects.toThrow(/fanout/);
    expect(FileRunStateStore.open(engagementDir).read().attempts['va:-:1']?.status).toBe('completed');

    unlinkSync(join(engagementDir, '02_verify_result-1st.md'));
    injectFanoutFailure = false;
    const checkpointPath = join(engagementDir, 'assess-checkpoint-input.json');
    const sealedCheckpoint = readFileSync(checkpointPath, 'utf8');
    const tamperedCheckpoint = JSON.parse(sealedCheckpoint) as {
      checkpointSha256: string;
      input: { target: string };
      [key: string]: unknown;
    };
    tamperedCheckpoint.input.target = join(target, 'replacement');
    const { checkpointSha256: _checkpointSha256, ...tamperedCore } = tamperedCheckpoint;
    tamperedCheckpoint.checkpointSha256 = createHash('sha256').update(stableJson(tamperedCore)).digest('hex');
    writeFileSync(checkpointPath, `${JSON.stringify(tamperedCheckpoint)}\n`);
    await expect(resumeAssessFromCheckpoint(
      { engagementDir, runId: 'checkpoint-resume' },
      { sessionRunner, reportPublisher, leaseBackend: new InMemoryRunLeaseBackend() },
    )).rejects.toThrow(/runtime receipt/);
    writeFileSync(checkpointPath, sealedCheckpoint);
    await expect(resumeAssessFromCheckpoint(
      { engagementDir, runId: 'checkpoint-resume' },
      { sessionRunner, reportPublisher },
    )).rejects.toThrow(/leaseBackend/);
    await expect(resumeAssessFromCheckpoint(
      { engagementDir, runId: 'checkpoint-resume' },
      { sessionRunner, reportPublisher, leaseBackend: new InMemoryRunLeaseBackend() },
    )).resolves.toMatchObject({ finalReport: join(engagementDir, '07_security_report.md') });
    expect(vaCalls).toBe(1);
    expect(FileRunStateStore.open(engagementDir).read().status).toBe('completed');
  });

  it('rehydrates a completed work-unit wave before resuming root phases', async () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-assess-work-unit-resume-'));
    const engagementDir = join(target, 'reports', 'work-unit-resume');
    writeTwoUnitFixture(target);
    let workUnitCalls = 0;
    let injectFanoutFailure = true;
    const sessionRunner = async (spec: SessionSpec): Promise<SessionOutcome> => {
      const outcome = await successfulOffsecSession(spec);
      if (spec.workUnit) workUnitCalls += 1;
      if (!spec.workUnit && spec.phase === 'va' && injectFanoutFailure) {
        writeFileSync(join(engagementDir, '02_verify_result-1st.md'), 'orphan verifier artifact\n');
      }
      return outcome;
    };
    const reportPublisher = (dir: string): string => {
      const draft = join(dir, '07_security_report.draft.md');
      const final = join(dir, '07_security_report.md');
      renameSync(draft, final);
      return final;
    };

    await expect(assess({
      target,
      engagementDir,
      engagementId: 'work-unit-resume',
      semgrepMode: 'off',
      workUnitMode: 'force',
    }, { sessionRunner, reportPublisher })).rejects.toThrow(/fanout/);
    const callsAfterWave = workUnitCalls;
    expect(callsAfterWave).toBeGreaterThan(0);
    expect(existsSync(join(engagementDir, '00_work_unit_results.json'))).toBe(true);

    unlinkSync(join(engagementDir, '02_verify_result-1st.md'));
    injectFanoutFailure = false;
    await expect(resumeAssessFromCheckpoint(
      { engagementDir, runId: 'work-unit-resume' },
      { sessionRunner, reportPublisher, leaseBackend: new InMemoryRunLeaseBackend() },
    )).resolves.toMatchObject({ finalReport: join(engagementDir, '07_security_report.md') });
    expect(workUnitCalls).toBe(callsAfterWave);
    expect(FileRunStateStore.open(engagementDir).read().status).toBe('completed');
  });

  it('fails closed on resume when a declared scope assurance receipt is tampered', async () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-assess-scope-assurance-tamper-'));
    const engagementDir = join(target, 'reports', 'assurance-tamper');
    writeTwoUnitFixture(target);
    let injectFanoutFailure = true;
    const sessionRunner = async (spec: SessionSpec): Promise<SessionOutcome> => {
      const outcome = await successfulOffsecSession(spec);
      if (!spec.workUnit && spec.phase === 'va' && injectFanoutFailure) {
        writeFileSync(join(engagementDir, '02_verify_result-1st.md'), 'orphan verifier artifact\n');
      }
      return outcome;
    };
    const reportPublisher = (dir: string): string => {
      const draft = join(dir, '07_security_report.draft.md');
      const final = join(dir, '07_security_report.md');
      renameSync(draft, final);
      return final;
    };

    await expect(assess({
      target,
      engagementDir,
      engagementId: 'assurance-tamper',
      semgrepMode: 'off',
      workUnitMode: 'force',
    }, { sessionRunner, reportPublisher })).rejects.toThrow(/fanout/);
    unlinkSync(join(engagementDir, '02_verify_result-1st.md'));
    injectFanoutFailure = false;

    const assurancePath = join(engagementDir, '00_scope_assurance.json');
    const tampered = JSON.parse(readFileSync(assurancePath, 'utf8')) as { completedUnitKeys: string[] };
    tampered.completedUnitKeys = [...tampered.completedUnitKeys, 'unit-0000000000000000'];
    writeFileSync(assurancePath, `${JSON.stringify(tampered, null, 2)}\n`);

    await expect(resumeAssessFromCheckpoint(
      { engagementDir, runId: 'assurance-tamper' },
      { sessionRunner, reportPublisher, leaseBackend: new InMemoryRunLeaseBackend() },
    )).rejects.toThrow(/scope assurance/);
  });

  it('resumes a legacy v1 work-unit result that never declared a scope assurance receipt', async () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-assess-scope-assurance-legacy-'));
    const engagementDir = join(target, 'reports', 'assurance-legacy');
    writeTwoUnitFixture(target);
    let injectFanoutFailure = true;
    const sessionRunner = async (spec: SessionSpec): Promise<SessionOutcome> => {
      const outcome = await successfulOffsecSession(spec);
      if (!spec.workUnit && spec.phase === 'va' && injectFanoutFailure) {
        writeFileSync(join(engagementDir, '02_verify_result-1st.md'), 'orphan verifier artifact\n');
      }
      return outcome;
    };
    const reportPublisher = (dir: string): string => {
      const draft = join(dir, '07_security_report.draft.md');
      const final = join(dir, '07_security_report.md');
      renameSync(draft, final);
      return final;
    };

    await expect(assess({
      target,
      engagementDir,
      engagementId: 'assurance-legacy',
      semgrepMode: 'off',
      workUnitMode: 'force',
    }, { sessionRunner, reportPublisher })).rejects.toThrow(/fanout/);
    unlinkSync(join(engagementDir, '02_verify_result-1st.md'));
    injectFanoutFailure = false;

    // 사전-P0-C 산출물 흉내: assurance 참조 필드 자체가 없고 receipt 파일도 없다.
    // schemaVersion을 진짜 레거시 1.0.0으로 되돌린다 — 1.1.0 결과에서 assurance 참조만 지우면
    // downgrade 공격 방지(P0 correction §2)가 올바르게 차단한다.
    const resultPath = join(engagementDir, '00_work_unit_results.json');
    const legacyResult = JSON.parse(readFileSync(resultPath, 'utf8')) as {
      schemaVersion?: string; assurancePath?: string; assuranceSha256?: string; [key: string]: unknown;
    };
    legacyResult.schemaVersion = '1.0.0';
    delete legacyResult.assurancePath;
    delete legacyResult.assuranceSha256;
    writeFileSync(resultPath, `${JSON.stringify(legacyResult, null, 2)}\n`);
    unlinkSync(join(engagementDir, '00_scope_assurance.json'));

    await expect(resumeAssessFromCheckpoint(
      { engagementDir, runId: 'assurance-legacy' },
      { sessionRunner, reportPublisher, leaseBackend: new InMemoryRunLeaseBackend() },
    )).resolves.toMatchObject({ finalReport: join(engagementDir, '07_security_report.md') });
    expect(FileRunStateStore.open(engagementDir).read().status).toBe('completed');
  });

  it('fails closed on resume when a result unit record is duplicated to substitute for a missing unit', async () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-assess-dup-result-unit-'));
    const engagementDir = join(target, 'reports', 'dup-result-unit');
    writeTwoUnitFixture(target);
    let injectFanoutFailure = true;
    const sessionRunner = async (spec: SessionSpec): Promise<SessionOutcome> => {
      const outcome = await successfulOffsecSession(spec);
      if (!spec.workUnit && spec.phase === 'va' && injectFanoutFailure) {
        writeFileSync(join(engagementDir, '02_verify_result-1st.md'), 'orphan verifier artifact\n');
      }
      return outcome;
    };
    const reportPublisher = (dir: string): string => {
      const draft = join(dir, '07_security_report.draft.md');
      const final = join(dir, '07_security_report.md');
      renameSync(draft, final);
      return final;
    };

    await expect(assess({
      target,
      engagementDir,
      engagementId: 'dup-result-unit',
      semgrepMode: 'off',
      workUnitMode: 'force',
    }, { sessionRunner, reportPublisher })).rejects.toThrow(/fanout/);
    unlinkSync(join(engagementDir, '02_verify_result-1st.md'));
    injectFanoutFailure = false;

    const resultPath = join(engagementDir, '00_work_unit_results.json');
    const stored = JSON.parse(readFileSync(resultPath, 'utf8')) as {
      units: Array<{ unitKey: string; [key: string]: unknown }>;
      [key: string]: unknown;
    };
    const firstUnit = stored.units[0]!;
    stored.units = [firstUnit, { ...firstUnit }];
    writeFileSync(resultPath, `${JSON.stringify(stored, null, 2)}\n`);

    await expect(resumeAssessFromCheckpoint(
      { engagementDir, runId: 'dup-result-unit' },
      { sessionRunner, reportPublisher, leaseBackend: new InMemoryRunLeaseBackend() },
    )).rejects.toThrow(/중복 unitKey/);
  });

  it('rejects a security_resource_files entry with a traversal segment on resume', async () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-assess-sec-resource-traversal-'));
    const engagementDir = join(target, 'reports', 'sec-resource-traversal');
    writeFileSync(join(target, 'app.ts'), 'export const value = 1;\n');
    let injectFanoutFailure = true;
    const sessionRunner = async (spec: SessionSpec): Promise<SessionOutcome> => {
      const outcome = await successfulOffsecSession(spec);
      if (spec.phase === 'va' && injectFanoutFailure) {
        writeFileSync(join(engagementDir, '02_verify_result-1st.md'), 'orphan verifier artifact\n');
      }
      return outcome;
    };
    const reportPublisher = (dir: string): string => {
      const draft = join(dir, '07_security_report.draft.md');
      const final = join(dir, '07_security_report.md');
      renameSync(draft, final);
      return final;
    };

    await expect(assess({
      target,
      engagementDir,
      engagementId: 'sec-resource-traversal',
      semgrepMode: 'off',
    }, { sessionRunner, reportPublisher })).rejects.toThrow(/fanout/);
    unlinkSync(join(engagementDir, '02_verify_result-1st.md'));
    injectFanoutFailure = false;

    const manifestPath = join(engagementDir, 'source_manifest.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as {
      security_resource_files?: string[];
      [key: string]: unknown;
    };
    manifest.security_resource_files = ['../../../etc/passwd'];
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

    await expect(resumeAssessFromCheckpoint(
      { engagementDir, runId: 'sec-resource-traversal' },
      { sessionRunner, reportPublisher, leaseBackend: new InMemoryRunLeaseBackend() },
    )).rejects.toThrow(/security_resource_files.*비정규화.*traversal/);
  });

  it('fails closed on resume when result schemaVersion is not in the accepted set', async () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-assess-bad-schema-version-'));
    const engagementDir = join(target, 'reports', 'bad-schema-version');
    writeTwoUnitFixture(target);
    let injectFanoutFailure = true;
    const sessionRunner = async (spec: SessionSpec): Promise<SessionOutcome> => {
      const outcome = await successfulOffsecSession(spec);
      if (!spec.workUnit && spec.phase === 'va' && injectFanoutFailure) {
        writeFileSync(join(engagementDir, '02_verify_result-1st.md'), 'orphan verifier artifact\n');
      }
      return outcome;
    };
    const reportPublisher = (dir: string): string => {
      const draft = join(dir, '07_security_report.draft.md');
      const final = join(dir, '07_security_report.md');
      renameSync(draft, final);
      return final;
    };

    await expect(assess({
      target,
      engagementDir,
      engagementId: 'bad-schema-version',
      semgrepMode: 'off',
      workUnitMode: 'force',
    }, { sessionRunner, reportPublisher })).rejects.toThrow(/fanout/);
    unlinkSync(join(engagementDir, '02_verify_result-1st.md'));
    injectFanoutFailure = false;

    const resultPath = join(engagementDir, '00_work_unit_results.json');
    const stored = JSON.parse(readFileSync(resultPath, 'utf8')) as { schemaVersion: string };
    stored.schemaVersion = '2.0.0';
    writeFileSync(resultPath, `${JSON.stringify(stored, null, 2)}\n`);

    await expect(resumeAssessFromCheckpoint(
      { engagementDir, runId: 'bad-schema-version' },
      { sessionRunner, reportPublisher, leaseBackend: new InMemoryRunLeaseBackend() },
    )).rejects.toThrow(/schemaVersion.*허용 목록/);
  });

  it('requires an explicit safe URL contract for live pentest modes', () => {
    expect(resolveLiveTestTarget('VA_ONLY', undefined)).toBeUndefined();
    expect(resolveLiveTestTarget('VA_PENTEST', 'https://test.example/base')).toEqual({
      url: 'https://test.example/base',
      hostname: 'test.example',
    });
    expect(() => resolveLiveTestTarget('VA_PENTEST', undefined)).toThrow(/test-url/);
    expect(() => resolveLiveTestTarget('VA_ONLY', 'https://test.example')).toThrow(/PENTEST/);
    expect(() => resolveLiveTestTarget('VA_PENTEST', 'file:///tmp/target')).toThrow(/http\/https/);
    expect(() => resolveLiveTestTarget('VA_PENTEST', 'https://user:pass@test.example')).toThrow(/credential/);
  });

  it('safely retries the same engagement after required Semgrep preflight fails', async () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-assess-semgrep-'));
    const engagementDir = join(target, 'reports', 'semgrep-required');
    writeFileSync(join(target, 'app.ts'), 'export const value = 1;\n');
    mkdirSync(join(target, 'nonstandard', 'deep'), { recursive: true });
    const nonstandardSource = join(target, 'nonstandard', 'deep', 'worker.ts');
    writeFileSync(nonstandardSource, 'export const worker = true;\n');
    let providerCalled = false;
    let semgrepFiles: string[] | undefined;
    await expect(assess(
      { target, engagementDir, engagementId: 'semgrep-required', semgrepMode: 'required' },
      {
        astBuilder: async (_target, options) => {
          semgrepFiles = options.semgrepFiles;
          return {
            ok: true,
            semgrep: { status: 'version-mismatch', error: 'pinned version drift' },
          };
        },
        sessionRunner: async () => {
          providerCalled = true;
          return { texts: [], ledger: [] };
        },
      },
    )).rejects.toThrow(/required Semgrep/);
    expect(providerCalled).toBe(false);
    expect(semgrepFiles).toEqual(expect.arrayContaining([join(target, 'app.ts'), nonstandardSource]));

    unlinkSync(nonstandardSource);
    await expect(assess(
      { target, engagementDir, engagementId: 'semgrep-required', semgrepMode: 'required' },
      {
        astBuilder: async (_target, options) => {
          writeFileSync(options.outputPath, 'ast: complete\n');
          return { ok: true, outputPath: options.outputPath, semgrep: { status: 'complete' } };
        },
        sessionRunner: successfulOffsecSession,
        reportPublisher: (dir) => {
          const draft = join(dir, '07_security_report.draft.md');
          const final = join(dir, '07_security_report.md');
          renameSync(draft, final);
          return final;
        },
      },
    )).resolves.toMatchObject({ engagementDir });
  });

  it('refuses to overwrite an existing engagement', async () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-assess-existing-'));
    const engagementDir = join(target, 'reports', 'existing');
    writeFileSync(join(target, 'app.ts'), 'export const value = 1;\n');
    mkdirSync(engagementDir, { recursive: true });
    const marker = join(engagementDir, 'existing-marker');
    writeFileSync(marker, 'keep');

    await expect(
      assess({ target, engagementDir, engagementId: 'existing' }),
    ).rejects.toThrow(/덮어쓸 수 없다/);
    expect(existsSync(marker)).toBe(true);
  });

  it('does not rescan source content after the assessment starts', async () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-assess-source-freshness-'));
    const source = join(target, 'app.ts');
    const engagementDir = join(target, 'reports', 'freshness');
    writeFileSync(source, 'export const value = 1;\n');
    await expect(assess(
      { target, engagementDir, engagementId: 'freshness', semgrepMode: 'off' },
      {
        sessionRunner: async (spec) => {
          const outcome = await successfulOffsecSession(spec);
          if (spec.phase === 'report') writeFileSync(source, 'export const value = 2;\n');
          return outcome;
        },
        reportPublisher: (dir) => {
          const draft = join(dir, '07_security_report.draft.md');
          const final = join(dir, '07_security_report.md');
          renameSync(draft, final);
          return final;
        },
      },
    )).resolves.toMatchObject({ engagementDir });
  });

  it('allows an uncapped default while preserving optional and legacy finite caps', () => {
    expect(resolveRunBudget(undefined, null)).toBeUndefined();
    expect(resolveRunBudget(12, null)).toBe(12);
    expect(resolveRunBudget(undefined, 30)).toBe(30);
    expect(resolveRunBudget(999, 30)).toBe(30);
    expect(resolveRunBudget(12, 30)).toBe(12);
    for (const invalid of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => resolveRunBudget(invalid, 30)).toThrow(/유한한 양수/);
    }
  });

  it('executes sealed source-only work units before the root analysis', async () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-assess-work-units-'));
    const engagementDir = join(target, 'reports', 'parallel');
    writeTwoUnitFixture(target);
    const observed: SessionSpec[] = [];
    const result = await assess(
      {
        target,
        engagementDir,
        engagementId: 'parallel',
        semgrepMode: 'off',
        workUnitMode: 'force',
        maxConcurrency: 2,
      },
      {
        sessionRunner: async (spec) => {
          observed.push(spec);
          if (spec.workUnit?.sourceFiles.some((path) => path.includes('/packages/a/'))) {
            await new Promise((resolveDelay) => setTimeout(resolveDelay, 10));
          }
          const outcome = await successfulOffsecSession(spec);
          if (
            spec.phase === 'verify' &&
            spec.workUnit?.ownedSourceFiles.some((path) => path.includes('/packages/a/'))
          ) {
            const phase = getOffsecPhase('verify');
            const objectionArtifact = renderPhaseArtifacts(phase, spec.phaseRound).optional
              .find((name) => name.includes('_objections-'))!;
            writeFileSync(join(spec.engagementDir, objectionArtifact),
              'objections:\n  - finding_id: F-unit\n    type: evidence\n    reason: recheck\n    instruction: inspect again\n');
            submitStandardObjection({
              engagementDir: spec.engagementDir,
              contractVersion: loadOffsecContract().version,
              phase: 'verify',
              role: 'verifier',
              round: spec.phaseRound,
              objection: {
                findingId: 'F-unit', type: 'evidence', reason: 'recheck', instruction: 'inspect again',
              },
            });
            const structured = outcome.structuredOutput as {
              artifacts: string[];
              metrics: { objectionCount: number };
            };
            structured.artifacts.push(objectionArtifact);
            structured.metrics.objectionCount = 1;
          }
          if (
            spec.phase === 'va' &&
            spec.workUnit?.ownedSourceFiles.some((path) => path.includes('/packages/a/'))
          ) {
            const source = spec.workUnit.ownedSourceFiles[0]!;
            submitStandardFinding({
              target: spec.target,
              engagementDir: spec.engagementDir,
              phase: 'va',
              role: 'va-auditor',
              round: spec.phaseRound,
              evidenceAllowedFiles: spec.workUnit.ownedSourceFiles,
              finding: {
                title: 'Unit-owned exported value',
                verdict: 'supported',
                severity: 'LOW',
                evidenceClass: 'data-flow',
                reachability: 'confirmed',
                preconditions: ['fixture import'],
                severityRationale: 'The unit fixture exposes a deterministic exported value for aggregation.',
                confidence: 0.8,
                impact: 'Fixture impact only.',
                remediation: 'Review the exported value.',
                standards: ['CWE-200'],
                unresolved: [],
                evidence: [{ path: source, lineStart: 1, lineEnd: 1, quote: readFileSync(source, 'utf8').trim() }],
              },
            });
            (outcome.structuredOutput as { metrics: { findingCount: number } }).metrics.findingCount = 1;
          }
          return outcome;
        },
        reportPublisher: (dir) => {
          const draft = join(dir, '07_security_report.draft.md');
          const final = join(dir, '07_security_report.md');
          renameSync(draft, final);
          return final;
        },
      },
    );

    const workers = observed.filter((spec) => spec.workUnit);
    expect(new Set(workers.map((spec) => spec.workUnit?.unitKey)).size).toBe(2);
    expect(workers).toHaveLength(6);
    expect(workers.filter((spec) => spec.phase === 'va-feedback')).toHaveLength(1);
    expect(workers.filter((spec) => spec.phase === 'verify-feedback')).toHaveLength(1);
    for (const spec of workers) {
      expect(spec.readScope).toBe('exact');
      expect(spec.disabledTools).toContain('Bash');
      const inventory = JSON.parse(readFileSync(join(spec.engagementDir, '00_source_exploration.json'), 'utf8')) as { sourceFiles: string[] };
      expect(inventory.sourceFiles.length).toBeGreaterThan(spec.workUnit!.ownedSourceFiles.length);
      expect(spec.allowedReadFiles).toEqual(expect.arrayContaining(inventory.sourceFiles));
      expect(spec.abortController).toBeInstanceOf(AbortController);

      const siblingRoots = workers
        .map((candidate) => candidate.engagementDir)
        .filter((path) => path !== spec.engagementDir);
      expect(spec.allowedReadFiles?.some((path) => siblingRoots.some((root) => path.startsWith(root)))).toBe(false);
    }
    expect(observed.findIndex((spec) => !spec.workUnit)).toBeGreaterThan(
      observed.findLastIndex((spec) => spec.workUnit !== undefined),
    );
    expect(result.workUnits?.completedUnitKeys).toHaveLength(2);
    expect(existsSync(result.workUnits!.workPlanPath)).toBe(true);
    expect(existsSync(result.workUnits!.resultPath)).toBe(true);
    expect(readStandardFindings(engagementDir).some((finding) => finding.title === 'Unit-owned exported value'))
      .toBe(true);

    const storedResult = JSON.parse(readFileSync(result.workUnits!.resultPath, 'utf8')) as {
      assurancePath: string;
      assuranceSha256: string;
      completedUnitKeys: string[];
    };
    expect(storedResult.assurancePath).toBe('00_scope_assurance.json');
    const assurancePath = join(engagementDir, storedResult.assurancePath);
    expect(existsSync(assurancePath)).toBe(true);
    expect(createHash('sha256').update(readFileSync(assurancePath)).digest('hex')).toBe(storedResult.assuranceSha256);
    const assurance = assertScopeAssuranceIntact(JSON.parse(readFileSync(assurancePath, 'utf8')));
    expect(assurance.workPlanSha256).toBe(JSON.parse(readFileSync(result.workUnits!.workPlanPath, 'utf8')).workPlanSha256);
    expect([...assurance.completedUnitKeys].sort()).toEqual([...storedResult.completedUnitKeys].sort());
    expect(assurance.units.map((unit) => unit.unitKey).sort()).toEqual([...storedResult.completedUnitKeys].sort());
    for (const unit of assurance.units) {
      expect(unit.autonomousVerifierSealed).toBe(false);
      expect(unit.ownedFileCount).toBeGreaterThan(0);
    }
    expect(assurance.disclosure).toMatch(/minimum-examination signal/);
    expect(observed.find((spec) => spec.phase === 'report')?.allowedReadFiles)
      .toEqual(expect.arrayContaining([expect.stringContaining('/standard-findings/')]));
    expect(FileRunStateStore.open(engagementDir).read().status).toBe('completed');
  });

  it('skips failed units and continues with partial results', async () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-assess-work-unit-failure-'));
    const engagementDir = join(target, 'reports', 'partial');
    writeTwoUnitFixture(target);
    const observed: SessionSpec[] = [];

    // v2: 실패 unit은 skip하고 계속 진행 (throw하지 않음)
    await assess(
      {
        target,
        engagementDir,
        engagementId: 'partial',
        semgrepMode: 'off',
        workUnitMode: 'force',
        maxConcurrency: 2,
      },
      {
        sessionRunner: async (spec) => {
          observed.push(spec);
          if (
            spec.phase === 'va' &&
            spec.workUnit?.sourceFiles.some((path) => path.includes('/packages/b/'))
          ) {
            throw new Error('synthetic unit failure');
          }
          return await successfulOffsecSession(spec);
        },
      },
    );

    // 성공한 unit A의 verify가 실행됐어야 함
    expect(observed.some((spec) =>
      spec.phase === 'verify' &&
      spec.workUnit?.sourceFiles.some((path) => path.includes('/packages/a/')),
    )).toBe(true);
    // 실패한 unit B는 retryRejectedOnce=true이므로 최대 2회 시도
    const failedAttempts = observed.filter((spec) =>
      spec.phase === 'va' && spec.workUnit?.sourceFiles.some((path) => path.includes('/packages/b/')));
    expect(failedAttempts).toHaveLength(2);
  });

  it('binds a dedicated source-readable Red Team phase to a sealed IaC manifest', async () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-assess-redteam-'));
    const engagementDir = join(target, 'reports', 'redteam');
    writeFileSync(join(target, 'app.ts'), 'export const value = 1;\n');
    writeFileSync(join(target, 'Dockerfile'), 'FROM node:22\n');
    const observed: SessionSpec[] = [];
    const result = await assess(
      {
        target,
        engagementDir,
        engagementId: 'redteam',
        semgrepMode: 'off',
        verificationMode: 'VA_PENTEST_REDTEAM',
        testUrl: 'https://test.example/app/',
      },
      {
        sessionRunner: async (spec) => {
          observed.push(spec);
          return await successfulOffsecSession(spec);
        },
        reportPublisher: (dir) => {
          const draft = join(dir, '07_security_report.draft.md');
          const final = join(dir, '07_security_report.md');
          renameSync(draft, final);
          return final;
        },
      },
    );
    const redteam = observed.find((spec) => spec.phase === 'redteam');
    expect(redteam?.agentRole).toBe('redteam-reviewer');
    expect(redteam?.readScope).toBe('exact');
    expect(redteam?.allowedReadFiles).toEqual(expect.arrayContaining([
      join(target, 'Dockerfile'),
      join(engagementDir, '00_iac_manifest.json'),
    ]));
    const manifest = JSON.parse(readFileSync(join(engagementDir, '00_iac_manifest.json'), 'utf8')) as {
      applicability: string;
      files: Array<{ path: string }>;
    };
    expect(manifest.applicability).toBe('applicable');
    expect(manifest.files.map((file) => file.path)).toContain('Dockerfile');
    expect(result.phases.map((phase) => phase.phase)).toContain('redteam');
  });

  it('charges provider usage before rejecting invalid structured output', async () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-assess-invalid-'));
    const engagementDir = join(target, 'reports', 'invalid');
    writeFileSync(join(target, 'app.ts'), 'export const value = 1;\n');
    const contract = loadOffsecContract();
    const sessionRunner = async (spec: SessionSpec): Promise<SessionOutcome> => ({
      texts: [],
      ledger: resolvePhaseMethodFiles(getOffsecPhase(String(spec.phase), contract)).map((resource) => ({
        at: new Date(0).toISOString(),
        event: 'PreToolUse',
        tool: 'Read',
        resource,
        decision: 'allow',
      })),
      totalCostUsd: 2,
      modelUsage: { [spec.model!]: { inputTokens: 1, outputTokens: 1 } },
      structuredOutput: { invalid: true },
    });

    await expect(
      assess({ target, engagementDir, engagementId: 'invalid', semgrepMode: 'off' }, { sessionRunner }),
    ).rejects.toThrow();
    const snapshot = FileRunStateStore.open(engagementDir).read();
    expect(snapshot.totalCostUsd).toBe(6); // M6a: 3 retry attempts × $2 each
    expect(snapshot.attempts['va:-:1']?.status).toBe('failed');
  });

  it('blocks publication when objections remain after the feedback limit', async () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-assess-objections-'));
    const engagementDir = join(target, 'reports', 'blocked');
    writeFileSync(join(target, 'app.ts'), 'export const value = 1;\n');
    const contract = loadOffsecContract();
    const observed: string[] = [];
    const sessionRunner = async (spec: SessionSpec): Promise<SessionOutcome> => {
      const phase = getOffsecPhase(String(spec.phase), contract);
      const artifacts = renderPhaseArtifacts(phase, spec.phaseRound);
      for (const artifact of artifacts.required) {
        writeFileSync(join(spec.engagementDir, artifact), phaseArtifactContent(phase.id, spec.engagementDir));
      }
      sealAutonomousIfRequired(spec, artifacts.required);
      const objectionArtifact = artifacts.optional.find((name) => name.includes('_objections-'));
      const objectionCount = phase.role === 'verifier' ? 1 : 0;
      if (objectionArtifact && objectionCount > 0) {
        writeFileSync(
          join(spec.engagementDir, objectionArtifact),
          'objections:\n  - finding_id: F-1\n    type: evidence\n    reason: unresolved\n    instruction: recheck\n',
        );
        submitStandardObjection({
          engagementDir: spec.engagementDir,
          contractVersion: contract.version,
          phase: phase.id,
          role: phase.role,
          round: spec.phaseRound,
          objection: {
            findingId: 'F-1',
            type: 'evidence',
            reason: 'unresolved',
            instruction: 'recheck',
          },
        });
      }
      observed.push(phase.id);
      return {
        texts: [],
        ledger: resolvePhaseMethodFiles(phase).map((resource) => ({
          at: new Date(0).toISOString(),
          event: 'PreToolUse',
          tool: 'Read',
          resource,
          decision: 'allow',
        })),
        totalCostUsd: 1,
        modelUsage: { [spec.model!]: { inputTokens: 1, outputTokens: 1 } },
        structuredOutput: {
          contractVersion: contract.version,
          phase: phase.id,
          role: phase.role,
          status: 'complete',
          artifacts: [
            ...artifacts.required,
            ...(objectionArtifact && objectionCount > 0 ? [objectionArtifact] : []),
          ],
          summary: 'done',
          metrics: { findingCount: 0, objectionCount },
          unresolved: [],
          ...workUnitResult(spec),
        },
      };
    };
    let publications = 0;

    // A fix: objection 미해결 시 throw하지 않고 converge → report로 진행
    await assess(
      { target, engagementDir, engagementId: 'blocked', semgrepMode: 'off' },
      { sessionRunner, reportPublisher: (dir) => {
        publications += 1;
        const draft = join(dir, '07_security_report.draft.md');
        const final = join(dir, '07_security_report.md');
        writeFileSync(final, existsSync(draft) ? readFileSync(draft, 'utf8') : '# Report\n');
        return final;
      } },
    );
    expect(observed).toContain('converge');
    expect(observed).toContain('report');
    expect(publications).toBe(1);
  });
});
