import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { assessV2 } from '../missions/assess-v2.js';
import { loadOffsecContract, getOffsecPhase, renderPhaseArtifacts, resolvePhaseMethodFiles } from '../offsec-contract.js';
import { assertScopeAssuranceIntact } from '../workflow/scope-assurance.js';
import type { SessionSpec, SessionOutcome } from '../session.js';
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
    return { texts: [], ledger: resolvePhaseMethodFiles(phase).map(resource => ({ at: new Date(0).toISOString(), event: 'PreToolUse', tool: 'Read', resource, decision: 'allow' })), subtype: 'success', numTurns: 1, totalCostUsd: 0.01, modelUsage: { [spec.model!]: { inputTokens: 1, outputTokens: 1 } }, structuredOutput: {
      contractVersion: contract.version, phase: phase.id, role: phase.role, status: 'complete', artifacts: artifacts.required, summary: 'fixture', metrics: { findingCount: 0 }, unresolved: [],
      ...(spec.workUnit ? { workUnit: { workUnitKey: spec.workUnit.unitKey, workPlanSha256: spec.workUnit.workPlanSha256, assignedSourceSha256: spec.workUnit.assignedSourceSha256 } } : {}),
    } };
  };
}
describe('v2 publication evidence and coverage', () => {
  it('runs one bounded cross-unit follow-up only when an evidence-backed handoff exists', async () => {
    const sessions: SessionSpec[] = [];
    const input = fixture();
    const result = await assessV2(input, { sessionRunner: runner({ handoff: true, onSession: spec => sessions.push(spec) }) });
    const followups = sessions.filter(spec => spec.phaseRound === 'cross-unit-followup');
    expect(followups).toHaveLength(1);
    expect(followups[0].maxTurns).toBe(32);
    expect(followups[0].prompt).toContain('Does the value');
    expect(sessions.map(spec => spec.phase)).toEqual(['analyze', 'analyze', 'analyze', 'review', 'evaluate', 'report']);
    expect(result.coverage).toMatchObject({ followupQuestions: 1, semanticCoverage: 'not-proven', ownedFilesRead: 0 });
  });
  it('can disable extra sessions and reports deferred questions', async () => {
    const sessions: SessionSpec[] = [];
    const result = await assessV2({ ...fixture(), maxFollowupHypotheses: 0 }, { sessionRunner: runner({ handoff: true, onSession: spec => sessions.push(spec) }) });
    expect(sessions).toHaveLength(5);
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
    await expect(assessV2({ ...input, workUnitMode: 'off' }, { sessionRunner: runner() })).rejects.toThrow('지원하지 않는다');
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
    expect(result.coverage).toMatchObject({ complete: false, completedUnits: 1, totalUnits: 2, uncoveredFiles: ['packages/b/b.ts'] });
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
