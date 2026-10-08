import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createOffsecAgent } from '../../index.js';
import { DEFAULT_V2_AGENT_CAPACITY } from '../missions/assess-v2.js';
import { executePagedWork } from '../workflow/bounded-work-executor.js';
import { createDependencyGraph } from '../workflow/offsec-dependency-graph.js';
import { assertOffsecWorkPlanIntact, assertPlanGraphIntegrity, createOffsecWorkPlanV2, type OffsecWorkPlanV2 } from '../workflow/offsec-work-plan.js';
import { syntheticOutcome } from './resumption-fixture.js';

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function fixture(count: number, content = 'export const value = 1;\n') {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'offsec-capacity-'))); roots.push(root);
  const target = join(root, 'project'); mkdirSync(target);
  const files = Array.from({ length: count }, (_, index) => `file-${String(index).padStart(4, '0')}.ts`);
  for (const file of files) writeFileSync(join(target, file), content);
  writeFileSync(join(target, 'package.json'), '{"name":"capacity-test"}');
  const manifest = { target_realpath: target, hash: 'a'.repeat(64), source_files: files, units: [{ id: '.', files }] };
  return { root, target, manifest, engagementDir: join(root, 'run'), semgrepMode: 'off' as const };
}
function reseal(plan: OffsecWorkPlanV2) {
  const stable = (value: unknown): string => Array.isArray(value) ? `[${value.map(stable).join(',')}]`
    : value && typeof value === 'object' ? `{${Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([k, v]) => `${JSON.stringify(k)}:${stable(v)}`).join(',')}}` : JSON.stringify(value);
  const { generatedAt: _at, workPlanSha256: _hash, ...core } = plan;
  plan.workPlanSha256 = createHash('sha256').update(stable(core)).digest('hex');
}

describe('source capacity planning', () => {
  it('assigns all 382 files exactly once to 16 deterministic 24-file tasks', () => {
    const { target, manifest } = fixture(382);
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const input = { target, sourceManifest: manifest, dependencyGraph: graph, maxOwnedFilesPerUnit: 24, maxOwnedEstimatedTokensPerUnit: 24_000 };
    const plan = createOffsecWorkPlanV2(input);
    expect(plan.units).toHaveLength(16);
    expect(Math.max(...plan.units.map(unit => unit.ownedFiles.length))).toBe(24);
    expect(plan.units.flatMap(unit => unit.ownedFiles.map(file => file.path)).sort()).toEqual([...manifest.source_files].sort());
    expect(new Set(plan.units.map(unit => unit.unitKey)).size).toBe(16);
    expect(plan.units.every(unit => unit.sourceUnitId === '.')).toBe(true);
    expect(() => assertOffsecWorkPlanIntact(plan)).not.toThrow();
    expect(() => assertPlanGraphIntegrity(plan, graph)).not.toThrow();
    const reordered = { ...manifest, source_files: [...manifest.source_files].reverse(), units: [{ id: '.', files: [...manifest.source_files].reverse() }] };
    expect(createOffsecWorkPlanV2({ ...input, sourceManifest: reordered }).workPlanSha256).toBe(plan.workPlanSha256);
  });

  it('splits at the token budget while preserving sibling dependency context', () => {
    const { target, manifest } = fixture(7, '// ' + 'x'.repeat(180) + '\n');
    writeFileSync(join(target, manifest.source_files[0]!), "import './file-0006';\n// " + 'x'.repeat(160));
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const plan = createOffsecWorkPlanV2({ target, sourceManifest: manifest, dependencyGraph: graph,
      maxOwnedFilesPerUnit: 24, maxOwnedEstimatedTokensPerUnit: 100, maxContextEstimatedTokensPerUnit: 100 });
    expect(plan.units).toHaveLength(4);
    expect(plan.units.every(unit => unit.contextSelectionReceipt.ownedEstimatedTokens <= 100)).toBe(true);
    expect(plan.units.find(unit => unit.ownedFiles[0]?.path === 'file-0000.ts')!.contextFiles.map(file => file.path)).toEqual(['file-0006.ts']);
    expect(() => assertPlanGraphIntegrity(plan, graph)).not.toThrow();
  });

  it('isolates an oversized file and rejects missing or false exception receipts, even after resealing', () => {
    const { target, manifest } = fixture(3);
    writeFileSync(join(target, 'file-0001.ts'), '// ' + 'x'.repeat(2_000));
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const plan = createOffsecWorkPlanV2({ target, sourceManifest: manifest, dependencyGraph: graph,
      maxOwnedFilesPerUnit: 24, maxOwnedEstimatedTokensPerUnit: 100 });
    expect(plan.units).toHaveLength(3);
    const big = plan.units.find(unit => unit.oversizedOwnedFiles?.length)!;
    expect(big.ownedFiles.map(file => file.path)).toEqual(['file-0001.ts']);
    expect(big.oversizedOwnedFiles).toEqual(['file-0001.ts']);
    expect(() => assertPlanGraphIntegrity(plan, graph)).not.toThrow();
    const missing = structuredClone(plan);
    delete missing.units.find(unit => unit.unitKey === big.unitKey)!.oversizedOwnedFiles;
    reseal(missing);
    expect(() => assertOffsecWorkPlanIntact(missing)).toThrow(/owned token cap/);
    expect(() => assertPlanGraphIntegrity(missing, graph)).toThrow(/owned token cap/);
    const falseException = structuredClone(plan);
    const small = falseException.units.find(unit => unit.unitKey !== big.unitKey)!;
    small.oversizedOwnedFiles = [small.ownedFiles[0]!.path]; reseal(falseException);
    expect(() => assertOffsecWorkPlanIntact(falseException)).toThrow(/oversized file/);
  });

  it('rejects resealed plans that exceed their file cap and preserves uncapped legacy plans', () => {
    const { target, manifest } = fixture(3);
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const legacy = createOffsecWorkPlanV2({ target, sourceManifest: manifest, dependencyGraph: graph });
    expect(legacy.planningPolicy.maxOwnedFilesPerUnit).toBeUndefined();
    expect(legacy.units).toHaveLength(1);
    expect(() => assertOffsecWorkPlanIntact(legacy)).not.toThrow();
    expect(() => assertPlanGraphIntegrity(legacy, graph)).not.toThrow();
    const invalid = structuredClone(legacy); invalid.planningPolicy.maxOwnedFilesPerUnit = 2; reseal(invalid);
    expect(() => assertPlanGraphIntegrity(invalid, graph)).toThrow(/owned file cap/);
  });

  it.each([0, -1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1])('rejects invalid capacity %s before executing sessions', async value => {
    const { target, engagementDir, semgrepMode, manifest } = fixture(1);
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    for (const name of ['maxOwnedFilesPerUnit', 'maxOwnedEstimatedTokensPerUnit']) {
      expect(() => createOffsecWorkPlanV2({ target, sourceManifest: manifest, dependencyGraph: graph, [name]: value })).toThrow(/positive safe integer/);
    }
    let calls = 0;
    const agent = createOffsecAgent({ sessionRunner: async spec => { calls++; return syntheticOutcome(spec); } });
    for (const name of ['maxFilesPerAgent', 'maxSourceTokensPerAgent']) {
      await expect(agent.run({ target, engagementDir, semgrepMode, [name]: value })).rejects.toThrow(/positive safe integer/);
    }
    expect(calls).toBe(0);
  });
});

describe('bounded agent orchestration', () => {
  it('drains 145 tasks across scheduling windows with at most 16 active, retaining failures', async () => {
    let active = 0, peak = 0; const visited: string[] = [];
    const units = Array.from({ length: 145 }, (_, index) => ({ unitKey: String(index) }));
    const results = await executePagedWork({ units, maxConcurrency: 16, maximumWorkUnits: 128,
      worker: async unit => {
        active++; peak = Math.max(peak, active); visited.push(unit.unitKey);
        try { await new Promise<void>(resolve => setImmediate(resolve)); if (unit.unitKey === '7') throw new Error('fixture failure'); return unit.unitKey; }
        finally { active--; }
      } });
    expect(peak).toBe(16); expect(active).toBe(0);
    expect(visited).toHaveLength(145); expect(new Set(visited).size).toBe(145);
    expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(144);
    expect(results[7]!.status).toBe('rejected'); expect(results[144]!.value).toBe('144');
  });

  it.each([
    { maxConcurrency: undefined, expected: 34, count: 33 },
    { maxConcurrency: 100, expected: 18, count: 17 },
    { maxConcurrency: 3, expected: 3, count: 7 },
  ])('runs the public API at $expected concurrent sessions and reviews only after every task finishes ($count files)', async ({ maxConcurrency, expected, count }) => {
    const { target, engagementDir, semgrepMode } = fixture(count);
    let active = 0, peak = 0, started = 0, finished = 0;
    let release!: () => void; const firstWave = new Promise<void>(resolve => { release = resolve; });
    const seen = new Set<string>();
    const agent = createOffsecAgent({ scheduler: { controlIntervalMs: 1, resourceCapacity: () => 100 }, defaults: { maxFilesPerAgent: 1, maxSourceTokensPerAgent: 1_000 }, astBuilder: async () => ({ ok: false }),
      sessionRunner: async spec => {
        if (spec.phase === 'recon') return syntheticOutcome(spec);
        if (!spec.workUnit) { expect(active).toBe(0); expect(finished).toBe(count + 1); return syntheticOutcome(spec); }
        spec.onProgress?.({ kind: 'tool', from: 'main', detail: 'Read' });
        active++; started++; peak = Math.max(peak, active);
        try {
          expect(spec.workUnit.ownedSourceFiles).toHaveLength(1);
          expect(spec.prompt).toContain('dependencyFiles'); expect(spec.allowedReadFiles).toContain(join(spec.target, 'package.json'));
          for (const file of spec.workUnit.ownedSourceFiles) { expect(seen.has(file)).toBe(false); seen.add(file); }
          if (started === expected) release(); await firstWave;
          await new Promise<void>(resolve => setImmediate(resolve));
          return syntheticOutcome(spec);
        } finally { active--; finished++; }
      } });
    const result = await agent.run({ target, engagementDir, semgrepMode, maxConcurrency });
    expect(result.status).toBe('published'); expect(peak).toBe(expected); expect(seen.size).toBe(count + 1);
    const plan = JSON.parse(readFileSync(join(engagementDir, '00_work_plan.json'), 'utf8')) as OffsecWorkPlanV2;
    expect(plan.units).toHaveLength(count + 1);
    expect(plan.planningPolicy).toMatchObject({ maxOwnedFilesPerUnit: 1, maxOwnedEstimatedTokensPerUnit: 1_000 });
    expect(result.coverage.sourceReadCoverage?.filesWithDeliveryGaps).toHaveLength(0);
    expect(result.coverage.sourceReadCoverage?.allAssignedFilesDelivered).toBe(true);
    expect(readFileSync(result.finalReport, 'utf8')).toContain('Read 요청 미관측: 0개 파일');
    const sealedBytes = readFileSync(join(engagementDir, '00_work_plan.json'));
    const resumed = await agent.resume(engagementDir);
    expect(resumed.coverage.sourceReadCoverage).toEqual(result.coverage.sourceReadCoverage);
    expect(readFileSync(join(engagementDir, '00_work_plan.json'))).toEqual(sealedBytes);
    expect(started).toBe(count + 1);
  }, 30_000);

  it('uses default file capacity and limits budget slots to the actual number of tasks', async () => {
    const { target, engagementDir, semgrepMode } = fixture(25);
    const allocations: number[] = []; const counts: number[] = [];
    let release!: () => void; const barrier = new Promise<void>(resolve => { release = resolve; });
    const agent = createOffsecAgent({ scheduler: { controlIntervalMs: 1, resourceCapacity: () => 100 }, astBuilder: async () => ({ ok: false }), sessionRunner: async spec => {
      if (spec.workUnit) {
        spec.onProgress?.({ kind: 'tool', from: 'main', detail: 'Read' });
        counts.push(spec.workUnit.ownedSourceFiles.length); allocations.push(spec.maxBudgetUsd!);
        if (counts.length === 2) release(); await barrier;
      }
      return syntheticOutcome(spec);
    } });
    const result = await agent.run({ target, engagementDir, semgrepMode, costPolicy: 'enforce', maxBudgetUsd: 10 });
    expect(result.status).toBe('published'); expect(counts.sort((a, b) => a - b)).toEqual([2, DEFAULT_V2_AGENT_CAPACITY.maxFilesPerAgent]);
    expect(allocations).toHaveLength(2); expect(allocations.reduce((a, b) => a + b, 0)).toBeLessThan(7);
    const summary = JSON.parse(readFileSync(join(engagementDir, '01_analysis_plan.json'), 'utf8'));
    expect(summary.maxConcurrency).toBe(2);
    expect(summary.planningPolicy).toMatchObject({ maxOwnedEstimatedTokensPerUnit: 24_000, maxContextEstimatedTokensPerUnit: 16_000 });
  });
});
