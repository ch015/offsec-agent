import { protocolFixture, deliveryFixture } from './assessment-protocol-fixture.js';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { assessV2 } from '../missions/assess-v2.js';
import { loadOffsecContract, getOffsecPhase, renderPhaseArtifacts, resolvePhaseMethodFiles } from '../offsec-contract.js';
import { assertScopeAssuranceIntact } from '../workflow/scope-assurance.js';
import { buildOptions, type SessionSpec, type SessionOutcome } from '../session.js';
import { readStandardFindings, submitStandardFinding } from '../finding-contract.js';
import { createOffsecAgent } from '../../api/agent.js';
const contract = loadOffsecContract(resolve(import.meta.dirname, '../../../domains/offsec/contracts/offsec-contract.v2.json'));
const gate = createRequire(import.meta.url)('../../../domains/offsec/lib/ch015/scope-assurance-gate.js') as { evaluateScopeAssurance(dir: string): { ok: boolean } };
function fixture() {
  const target = mkdtempSync(join(tmpdir(), 'offsec-v2-publication-'));
  for (const name of ['a', 'b']) {
    const dir = join(target, 'packages', name); mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name }));
    writeFileSync(join(dir, `${name}.ts`), `export const ${name} = 1;\n`);
  }
  return { target, engagementDir: join(target, '.secops/run'), engagementId: 'v2-publication-test', excludePaths: [join(target, '.secops')], semgrepMode: 'off' as const };
}
function runner(options: { failB?: boolean; disclose?: boolean; corruptScope?: boolean; handoff?: boolean; onSession?: (spec: SessionSpec) => void } = {}) {
  return async (spec: SessionSpec): Promise<SessionOutcome> => {
    options.onSession?.(spec);
    if (options.failB && spec.workUnit?.ownedSourceFiles.some(f => f.endsWith('/b.ts'))) throw new Error('fixture unavailable unit');
    const phase = getOffsecPhase(spec.phase!, contract), artifacts = renderPhaseArtifacts(phase, spec.phaseRound);
    const handoff = options.handoff && spec.workUnit?.ownedSourceFiles.some(file => file.endsWith('/a.ts'));
    if (handoff) artifacts.required.push('02_analysis_handoff.yaml');
    for (const artifact of artifacts.required) {
      if (spec.phase === 'evaluate' && artifact === '04_evaluation_classification.yaml' && spec.taskData?.evaluationProjection) continue;
      let content = '{}\n';
      if (artifact === '02_analysis_handoff.yaml') content = JSON.stringify({ hypotheses: [{
        question: 'Does the value from package a cross the boundary into package b?', impact: 'high',
        files: ['packages/a/a.ts', 'packages/b/b.ts'],
        observations: [{ path: 'packages/a/a.ts', lineStart: 1, lineEnd: 1, quote: 'export const a = 1;' }],
      }] });
      if (phase.id === 'report') {
        content = '# Fixture report\nNo confirmed findings.\n';
        if (options.disclose) content += '분석 범위 미완료\npackages/b/b.ts\n';
        if (options.corruptScope) writeFileSync(join(spec.engagementDir, '00_scope_assurance.json'), '{}');
      }
      writeFileSync(join(spec.engagementDir, artifact), content);
    }
    const sourceLedger = protocolFixture(spec);
    return { texts: [], ledger: [...sourceLedger, ...resolvePhaseMethodFiles(phase).map(resource => ({ at: new Date(0).toISOString(), event: 'PreToolUse', tool: 'Read', resource, decision: 'allow' as const }))], subtype: 'success', numTurns: 1, totalCostUsd: 0.01, modelUsage: { [spec.model!]: { inputTokens: 1, outputTokens: 1 } }, structuredOutput: {
      contractVersion: contract.version, phase: phase.id, role: phase.role, status: 'complete', artifacts: artifacts.required, summary: 'fixture', metrics: { findingCount: 0 }, unresolved: [],
      ...(spec.workUnit ? { workUnit: { workUnitKey: spec.workUnit.unitKey, workPlanSha256: spec.workUnit.workPlanSha256, assignedSourceSha256: spec.workUnit.assignedSourceSha256 } } : {}),
    } };
  };
}
describe('v2 publication evidence and coverage', () => {
  it('publishes host-captured Git provenance even when a zero-finding narrative omits it', async () => {
    const input = fixture();
    execFileSync('git', ['init', '-q', '-b', 'fixture'], { cwd: input.target });
    execFileSync('git', ['add', 'packages'], { cwd: input.target });
    execFileSync('git', ['-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture'], { cwd: input.target });
    const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: input.target, encoding: 'utf8' }).trim();
    const result = await assessV2(input, { sessionRunner: runner() });
    expect(result.publicationStatus).toBe('published');
    expect(readFileSync(result.finalReport, 'utf8')).toContain(commit);
    expect(readFileSync(result.finalReport, 'utf8')).toContain('Git branch');
    expect(readFileSync(join(input.engagementDir, '07_security_report.draft.md'), 'utf8')).not.toContain(commit);
    const published = readFileSync(result.finalReport), sessions: string[] = [];
    const agent = createOffsecAgent({ sessionRunner: runner({ onSession: spec => sessions.push(spec.phase!) }) });
    expect((await agent.resume(input.engagementDir)).status).toBe('published');
    expect(readFileSync(result.finalReport)).toEqual(published);
    expect(sessions).toEqual([]);
    writeFileSync(join(input.engagementDir, '07_security_report.md'), '# Tampered final report\n');
    await expect(agent.resume(input.engagementDir)).rejects.toThrow('artifact hash');
    expect(sessions).toEqual([]);
  });
  it('carries corrected review IDs through local repair and publication in one evaluation attempt', async () => {
    const input = fixture(), sessions: string[] = [], base = runner();
    let originalId = '', correctedId = '', localDenials = 0;
    const submit = (spec: SessionSpec, title: string) => submitStandardFinding({
      target: spec.target, engagementDir: spec.engagementDir, contract,
      phase: spec.phase!, role: spec.phase === 'review' ? 'reviewer' : 'analyzer',
      finding: { title, verdict: 'supported', severity: 'LOW', evidenceClass: 'configuration',
        reachability: 'plausible', preconditions: ['Fixture only'], severityRationale: 'Fixture evidence',
        confidence: 0.8, impact: 'Fixture impact', remediation: 'Fixture correction', standards: [], unresolved: [],
        evidence: [{ path: 'packages/a/a.ts', lineStart: 1, lineEnd: 1, quote: 'export const a = 1;' }] },
    });
    const result = await assessV2(input, { sessionRunner: async spec => {
      sessions.push(spec.phase!);
      const outcome = await base(spec);
      if (spec.phase === 'analyze' && spec.workUnit?.ownedSourceFiles.some(p => p.endsWith('/a.ts'))) {
        originalId = submit(spec, 'Original fixture claim').id;
      }
      if (spec.phase === 'review') {
        expect(readStandardFindings(spec.engagementDir).map(r => r.id)).toContain(originalId);
        const corrected = submit(spec, 'Corrected fixture claim'); correctedId = corrected.id;
        writeFileSync(join(spec.engagementDir, '03_review_result.json'), JSON.stringify({
          countingSchemaVersion: 1,
          reviewedFindings: [{ originalFindingId: originalId, action: 'corrected', correctedFindingId: correctedId, reviewedSeverity: 'LOW', reason: 'Verified correction against original source',
            counting: {kind:'vulnerability',causeId:'VC-corrected-fixture-control',component:'packages/a',
              rootCause:'Synthetic isolated fixture control failure',fixBoundary:'Repair the corrected fixture control independently',primaryEvidence:corrected.evidence} }], newFindings: [],
        }));
        outcome.ledger.push(...deliveryFixture(spec, join(spec.target, 'packages/a/a.ts')));
      }
      if (spec.phase === 'evaluate') {
        expect(spec.taskData?.resolvedReview).toBeUndefined();
        expect(spec.prompt).not.toContain('resolvedReview');
        expect(spec.prompt).not.toContain('foldedInto');
        expect(spec.taskData?.evaluationProjection).toMatchObject({ path: expect.any(String), inputSha256: expect.stringMatching(/^[a-f0-9]{64}$/) });
        const classification = JSON.parse(readFileSync(join(spec.engagementDir, '04_evaluation_classification.yaml'), 'utf8'));
        expect(classification.candidates).toEqual(expect.arrayContaining([
          expect.objectContaining({ id: originalId, final_status: 'FOLDED_INTO', folded_into: correctedId }),
          expect.objectContaining({ id: correctedId, final_status: 'CONFIRMED' }),
        ]));
        const originalContent = readFileSync(join(spec.engagementDir, '04_evaluation_classification.yaml'), 'utf8');
        classification.equivalence_review.groups[0].decision = 'FOLD';
        const options = buildOptions({ ...spec, onLedger: row => outcome.ledger.push(row) });
        const hook = options.hooks!.PreToolUse![0]!.hooks[0] as unknown as (input: Record<string, unknown>) => Promise<{ hookSpecificOutput?: { permissionDecision?: string; updatedInput?: { content: string } } }>;
        const path = join(spec.engagementDir, '04_evaluation_classification.yaml');
        const write = () => hook({ hook_event_name: 'PreToolUse', tool_name: 'Write', tool_input: { file_path: path, content: JSON.stringify(classification) } });
        expect((await write()).hookSpecificOutput?.permissionDecision).toBe('deny'); localDenials++;
        expect((await hook({ hook_event_name: 'PreToolUse', tool_name: 'Write', tool_input: { file_path: path, content: originalContent } })).hookSpecificOutput?.permissionDecision).not.toBe('deny');
        expect(readFileSync(path, 'utf8')).toBe(originalContent);
        const evaluationPath = join(spec.engagementDir, '04_evaluation.json');
        const prepared = await hook({ hook_event_name: 'PreToolUse', tool_name: 'Write', tool_input: {
          file_path: evaluationPath, content: JSON.stringify({ overallAssessment: 'One reviewed LOW fixture cause; see the sealed source.' }),
        } });
        expect(prepared.hookSpecificOutput?.permissionDecision).not.toBe('deny');
        writeFileSync(evaluationPath, prepared.hookSpecificOutput!.updatedInput!.content);
      }
      if (spec.phase === 'report') {
        expect(spec.prompt).not.toContain('resolvedReview');
        expect(spec.taskData?.canonicalAppendix).toBeDefined();
        writeFileSync(join(spec.engagementDir, '07_security_report.draft.md'), '# Fixture narrative\nOne accepted LOW fixture finding. See the host canonical appendix for its source and history.\n');
      }
      return outcome;
    } });
    expect(result.publicationStatus, JSON.stringify(result.storage)).toBe('published');
    expect(localDenials).toBe(1);
    expect(sessions).toEqual(['recon', 'analyze', 'analyze', 'review', 'evaluate', 'report']);
    expect(readFileSync(result.finalReport, 'utf8')).toContain(correctedId);
    expect(readFileSync(result.finalReport, 'utf8')).toContain(originalId);
    expect(readFileSync(result.finalReport, 'utf8')).toContain('FOLDED_INTO');
    expect(JSON.parse(readFileSync(join(input.engagementDir, '04_evaluation.json'), 'utf8')).vulnerabilityInventory)
      .toMatchObject({independentVulnerabilityCount:1,acceptedRecordCount:1});
    expect(readFileSync(join(input.engagementDir, '07_security_report.draft.md'), 'utf8')).not.toContain(correctedId);
    const published = readFileSync(result.finalReport);
    const resumed = await createOffsecAgent({ sessionRunner: async () => { throw new Error('Completed report must not call a model'); } }).resume(input.engagementDir);
    expect(resumed.status).toBe('published');
    expect(readFileSync(resumed.finalReport)).toEqual(published);
  });
  it('runs one bounded cross-unit follow-up only when an evidence-backed handoff exists', async () => {
    const sessions: SessionSpec[] = [];
    const input = fixture();
    const result = await assessV2(input, { sessionRunner: runner({ handoff: true, onSession: spec => sessions.push(spec) }) });
    const followups = sessions.filter(spec => spec.phaseRound === 'cross-unit-followup');
    expect(followups).toHaveLength(1);
    expect(followups[0].maxTurns).toBe(32);
    expect(followups[0].prompt).toContain('Does the value');
    expect(sessions.map(spec => spec.phase)).toEqual(['recon', 'analyze', 'analyze', 'analyze', 'review', 'evaluate', 'report']);
    expect(result.coverage).toMatchObject({ followupQuestions: 1, semanticCoverage: 'not-proven', ownedFilesRead: 4 });
  });
  it('can disable extra sessions and reports deferred questions', async () => {
    const sessions: SessionSpec[] = [];
    const result = await assessV2({ ...fixture(), maxFollowupHypotheses: 0 }, { sessionRunner: runner({ handoff: true, onSession: spec => sessions.push(spec) }) });
    expect(sessions).toHaveLength(6);
    expect(result.coverage.deferredFollowupQuestions).toBe(1);
  });
  it('gives analyzers scoped static evidence and explicit gaps without requiring the global AST', async () => {
    const input = fixture();
    const sessions: SessionSpec[] = [];
    await assessV2(input, { sessionRunner: runner({ onSession: spec => sessions.push(spec) }) });
    const analyzes = sessions.filter(spec => spec.phase === 'analyze');
    expect(analyzes).toHaveLength(2);
    for (const spec of analyzes) {
      const index = join(spec.engagementDir, '00_evidence_index.json');
      const details = join(spec.engagementDir, '00_evidence_details.json');
      expect(spec.allowedReadFiles).toContain(index);
      expect(spec.allowedReadFiles).toContain(details);
      expect(spec.prompt).toContain(index);
      expect(JSON.parse(readFileSync(details, 'utf8')).parsedFiles).toHaveLength(1);
      expect(JSON.parse(readFileSync(index, 'utf8')).limitations.join()).toContain('disabled');
    }
  });
  it('rejects unsupported work-unit disabling before creating run state', async () => {
    const input = fixture();
    await expect(assessV2({ ...input, workUnitMode: 'off' as never }, { sessionRunner: runner() })).rejects.toThrow('지원하지 않는다');
    expect(existsSync(input.engagementDir)).toBe(false);
  });
  it('round-trips sealed scope evidence through both validators and publishes real work-unit artifact paths', async () => {
    const input = fixture(), result = await assessV2(input, { sessionRunner: runner() });
    expect(result.coverage.complete).toBe(true);
    expect(gate.evaluateScopeAssurance(input.engagementDir).ok).toBe(true);
    expect(() => assertScopeAssuranceIntact(JSON.parse(readFileSync(join(input.engagementDir, '00_scope_assurance.json'), 'utf8')))).not.toThrow();
    const units = JSON.parse(readFileSync(join(input.engagementDir, '00_work_unit_results.json'), 'utf8')).units;
    for (const unit of units) for (const artifact of unit.artifacts) {
      expect(existsSync(artifact.path)).toBe(true);
      expect(createHash('sha256').update(readFileSync(artifact.path)).digest('hex')).toBe(artifact.sha256);
      expect(artifact.path).toContain('attempt-1');
    }
  });
  it('does not publish if scope evidence is corrupted even when the model phase reports success', async () => {
    const input = fixture();
    await expect(assessV2(input, { sessionRunner: runner({ corruptScope: true }) })).rejects.toThrow('artifact hash');
    expect(existsSync(join(input.engagementDir, '07_security_report.md'))).toBe(false);
  });
  it('adds host disclosure when the model omits an unreviewed unit', async () => {
    const input = fixture();
    const result = await assessV2(input, { sessionRunner: runner({ failB: true }) });
    expect(result.coverage.complete).toBe(false);
    const report = readFileSync(result.finalReport, 'utf8');
    expect(report).toContain('분석 범위 미완료');
    for (const file of result.coverage.uncoveredFiles) expect(report).toContain(file);
  });
  it('retains useful partial work with explicit coverage and report disclosure', async () => {
    const input = fixture(), result = await assessV2(input, { sessionRunner: runner({ failB: true, disclose: true }) });
    expect(result.coverage).toMatchObject({ complete: false, completedUnits: 1, totalUnits: 2, uncoveredFiles: ['packages/b/b.ts', 'packages/b/package.json'] });
    expect(readFileSync(result.finalReport, 'utf8')).toContain('분석 범위 미완료');
  });
  it('continues review after optional follow-up provider failures and discloses the gap', async () => {
    const phases: string[] = [];
    const result = await assessV2(fixture(), { sessionRunner: runner({ handoff: true, disclose: true, onSession: spec => {
      phases.push(spec.phase!);
      if (spec.phaseRound === 'cross-unit-followup') throw new Error('fixture follow-up unavailable');
    } }) });
    expect(phases.slice(-3)).toEqual(['review', 'evaluate', 'report']);
    expect(result.coverage.complete).toBe(false);
    expect(result.coverage.deferredFollowupQuestions).toBeGreaterThan(0);
    expect(readFileSync(result.finalReport, 'utf8')).toContain('분석 범위 미완료');
  });

});
