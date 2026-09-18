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
function runner(options: { failB?: boolean; disclose?: boolean; corruptScope?: boolean } = {}) {
  return async (spec: SessionSpec): Promise<SessionOutcome> => {
    if (options.failB && spec.workUnit?.ownedSourceFiles.some(f => f.endsWith('/b.ts'))) throw new Error('fixture unavailable unit');
    const phase = getOffsecPhase(spec.phase!, contract), artifacts = renderPhaseArtifacts(phase, spec.phaseRound);
    for (const artifact of artifacts.required) {
      let content = '{}\n';
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
    await expect(assessV2(input, { sessionRunner: runner({ corruptScope: true }) })).rejects.toThrow('report gate');
    expect(existsSync(join(input.engagementDir, '07_security_report.md'))).toBe(false);
  });
  it('blocks a partial report that conceals an unreviewed unit', async () => {
    const input = fixture();
    await expect(assessV2(input, { sessionRunner: runner({ failB: true }) })).rejects.toThrow('미검토 파일');
    expect(existsSync(join(input.engagementDir, '07_security_report.md'))).toBe(false);
  });
  it('retains useful partial work with explicit coverage and report disclosure', async () => {
    const input = fixture(), result = await assessV2(input, { sessionRunner: runner({ failB: true, disclose: true }) });
    expect(result.coverage).toMatchObject({ complete: false, completedUnits: 1, totalUnits: 2, uncoveredFiles: ['packages/b/b.ts'] });
    expect(readFileSync(result.finalReport, 'utf8')).toContain('분석 범위 미완료');
  });
});
