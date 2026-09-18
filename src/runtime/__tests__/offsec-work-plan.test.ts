import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { executeBoundedWork } from '../workflow/bounded-work-executor.js';
import {
  assertOffsecWorkPlanComplete,
  assertOffsecWorkPlanIntact,
  assertOffsecWorkUnitIntact,
  assertPlanGraphIntegrity,
  createOffsecWorkPlan,
  createOffsecWorkPlanV2,
  getUnitTypedEdges,
  type OffsecWorkPlanV2,
} from '../workflow/offsec-work-plan.js';
import {
  createDependencyGraph,
} from '../workflow/offsec-dependency-graph.js';

// production의 stableJson/digest와 동일한 알고리즘 — 레거시(사전-P0-A) sealed plan 고정물을
// 재구성해 hash를 재계산하기 위함(assess.test.ts의 checkpoint hash 고정물과 동일한 패턴).
function testStableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(testStableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) =>
      `${JSON.stringify(key)}:${testStableJson(record[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}
function testDigest(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function fixture() {
  const target = mkdtempSync(join(tmpdir(), 'nunchi-work-plan-'));
  mkdirSync(join(target, 'packages', 'api'), { recursive: true });
  mkdirSync(join(target, 'packages', 'common'), { recursive: true });
  writeFileSync(
    join(target, 'packages', 'api', 'app.ts'),
    "import { authorize } from '../common/auth';\nexport const handler = authorize;\n",
  );
  writeFileSync(join(target, 'packages', 'common', 'auth.ts'), 'export const authorize = true;\n');
  return {
    target,
    manifest: {
      target_realpath: realpathSync(target),
      hash: 'a'.repeat(64),
      source_files: ['packages/api/app.ts', 'packages/common/auth.ts'],
      units: [
        { id: 'packages/api', files: ['packages/api/app.ts'] },
        { id: 'packages/common', files: ['packages/common/auth.ts'] },
      ],
    },
  };
}

describe('OffSec sealed work plan', () => {
  it('uses safe unit keys, sealed assignment receipts, and bounded cross-unit dependency context', () => {
    const { target, manifest } = fixture();
    const plan = createOffsecWorkPlan({ target, sourceManifest: manifest });
    expect(plan.units).toHaveLength(2);
    expect(plan.units.every((unit) => /^unit-[a-f0-9]{16}$/.test(unit.unitKey))).toBe(true);
    const api = plan.units.find((unit) => unit.sourceUnitId === 'packages/api')!;
    expect(api.contextFiles.map((file) => file.path)).toEqual(['packages/common/auth.ts']);
    expect(() => assertOffsecWorkPlanComplete(plan, [api.unitKey])).toThrow(/barrier/);
    expect(() => assertOffsecWorkPlanComplete(plan, plan.units.map((unit) => unit.unitKey))).not.toThrow();

    writeFileSync(join(target, 'packages', 'api', 'app.ts'), '// same plan, changed bytes\n');
    expect(() => assertOffsecWorkPlanIntact(plan)).not.toThrow();
  });

  it('rejects duplicate source ownership', () => {
    const { target, manifest } = fixture();
    manifest.units[1]!.files.push('packages/api/app.ts');
    expect(() => createOffsecWorkPlan({ target, sourceManifest: manifest })).toThrow(/여러 unit/);
  });

  it('binds new work plans to the portable source content hash', () => {
    const { target, manifest } = fixture();
    const contentHash = 'b'.repeat(64);
    const plan = createOffsecWorkPlan({
      target,
      sourceManifest: { ...manifest, content_hash: contentHash },
    });
    expect(plan.sourceManifestSha256).toBe(contentHash);
  });

  it('does not emit a cap record for a repeated reference to an already-included context file', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-work-plan-cap-'));
    mkdirSync(join(target, 'packages', 'api'), { recursive: true });
    mkdirSync(join(target, 'packages', 'common'), { recursive: true });
    writeFileSync(
      join(target, 'packages', 'api', 'app.ts'),
      "import { authorize } from '../common/auth';\nimport { authorize as again } from '../common/auth';\nexport const handler = authorize;\n",
    );
    writeFileSync(join(target, 'packages', 'common', 'auth.ts'), 'export const authorize = true;\n');
    const plan = createOffsecWorkPlan({
      target,
      sourceManifest: {
        target_realpath: realpathSync(target),
        hash: 'a'.repeat(64),
        source_files: ['packages/api/app.ts', 'packages/common/auth.ts'],
        units: [
          { id: 'packages/api', files: ['packages/api/app.ts'] },
          { id: 'packages/common', files: ['packages/common/auth.ts'] },
        ],
      },
      maxContextFilesPerUnit: 1,
    });
    const api = plan.units.find((unit) => unit.sourceUnitId === 'packages/api')!;
    expect(api.contextFiles.map((file) => file.path)).toEqual(['packages/common/auth.ts']);
    expect(api.unresolvedEdges).toEqual([]);
  });

  it('emits resolvedTarget for a truly omitted resolved file once the cap is reached', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-work-plan-cap-omit-'));
    mkdirSync(join(target, 'packages', 'api'), { recursive: true });
    mkdirSync(join(target, 'packages', 'common'), { recursive: true });
    mkdirSync(join(target, 'packages', 'other'), { recursive: true });
    writeFileSync(
      join(target, 'packages', 'api', 'app.ts'),
      "import { authorize } from '../common/auth';\nimport { helper } from '../other/helper';\n",
    );
    writeFileSync(join(target, 'packages', 'common', 'auth.ts'), 'export const authorize = true;\n');
    writeFileSync(join(target, 'packages', 'other', 'helper.ts'), 'export const helper = true;\n');
    const plan = createOffsecWorkPlan({
      target,
      sourceManifest: {
        target_realpath: realpathSync(target),
        hash: 'a'.repeat(64),
        source_files: ['packages/api/app.ts', 'packages/common/auth.ts', 'packages/other/helper.ts'],
        units: [
          { id: 'packages/api', files: ['packages/api/app.ts'] },
          { id: 'packages/common', files: ['packages/common/auth.ts'] },
          { id: 'packages/other', files: ['packages/other/helper.ts'] },
        ],
      },
      maxContextFilesPerUnit: 1,
    });
    const api = plan.units.find((unit) => unit.sourceUnitId === 'packages/api')!;
    expect(api.contextFiles.map((file) => file.path)).toEqual(['packages/common/auth.ts']);
    expect(api.unresolvedEdges).toEqual([{
      from: 'packages/api/app.ts',
      specifier: '../other/helper',
      reason: 'context-cap',
      resolvedTarget: 'packages/other/helper.ts',
    }]);
  });

  it('validates a legacy sealed plan whose context-cap record has no resolvedTarget', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-work-plan-legacy-cap-'));
    mkdirSync(join(target, 'packages', 'api'), { recursive: true });
    mkdirSync(join(target, 'packages', 'common'), { recursive: true });
    mkdirSync(join(target, 'packages', 'other'), { recursive: true });
    writeFileSync(
      join(target, 'packages', 'api', 'app.ts'),
      "import { authorize } from '../common/auth';\nimport { helper } from '../other/helper';\n",
    );
    writeFileSync(join(target, 'packages', 'common', 'auth.ts'), 'export const authorize = true;\n');
    writeFileSync(join(target, 'packages', 'other', 'helper.ts'), 'export const helper = true;\n');
    const plan = createOffsecWorkPlan({
      target,
      sourceManifest: {
        target_realpath: realpathSync(target),
        hash: 'a'.repeat(64),
        source_files: ['packages/api/app.ts', 'packages/common/auth.ts', 'packages/other/helper.ts'],
        units: [
          { id: 'packages/api', files: ['packages/api/app.ts'] },
          { id: 'packages/common', files: ['packages/common/auth.ts'] },
          { id: 'packages/other', files: ['packages/other/helper.ts'] },
        ],
      },
      maxContextFilesPerUnit: 1,
    });
    const api = plan.units.find((unit) => unit.sourceUnitId === 'packages/api')!;
    expect(api.unresolvedEdges).toHaveLength(1);
    expect(api.unresolvedEdges[0]!.resolvedTarget).toBe('packages/other/helper.ts');

    // 사전-P0-A 스키마는 resolvedTarget 필드 자체가 없었다 — 필드를 제거하고 그 시절 해시 알고리즘으로
    // workPlanSha256을 재계산해 실제 레거시 sealed plan 고정물을 재구성한다.
    const legacyUnits = plan.units.map((unit) => unit.unitKey === api.unitKey
      ? {
          ...unit,
          unresolvedEdges: unit.unresolvedEdges.map(({ resolvedTarget: _resolvedTarget, ...edge }) => edge),
        }
      : unit);
    const legacyCore = {
      schemaVersion: plan.schemaVersion,
      targetRealpath: plan.targetRealpath,
      sourceManifestSha256: plan.sourceManifestSha256,
      maxContextFilesPerUnit: plan.maxContextFilesPerUnit,
      units: legacyUnits,
    };
    const legacyPlan = {
      ...legacyCore,
      workPlanSha256: testDigest(testStableJson(legacyCore)),
      generatedAt: plan.generatedAt,
    };
    const parsed = assertOffsecWorkPlanIntact(legacyPlan);
    const legacyApi = parsed.units.find((unit) => unit.unitKey === api.unitKey)!;
    expect(legacyApi.unresolvedEdges[0]).toEqual({
      from: 'packages/api/app.ts', specifier: '../other/helper', reason: 'context-cap',
    });
    expect('resolvedTarget' in legacyApi.unresolvedEdges[0]!).toBe(false);
  });

  it('rejects an interior ../ traversal segment in a parsed source manifest file path', () => {
    const { target, manifest } = fixture();
    const traversal = {
      ...manifest,
      source_files: [...manifest.source_files, 'packages/api/../../../etc/passwd'],
      units: [
        ...manifest.units,
        { id: 'packages/api', files: ['packages/api/../../../etc/passwd'] },
      ],
    };
    expect(() => createOffsecWorkPlan({ target, sourceManifest: traversal })).toThrow();
  });

  it('rejects an interior ../ traversal segment in a sealed work plan file field on parse', () => {
    const { target, manifest } = fixture();
    const plan = createOffsecWorkPlan({ target, sourceManifest: manifest });
    const api = plan.units.find((unit) => unit.sourceUnitId === 'packages/api')!;
    const tamperedUnits = plan.units.map((unit) => unit.unitKey === api.unitKey
      ? { ...unit, ownedFiles: [{ ...unit.ownedFiles[0]!, path: 'packages/api/../../../etc/passwd' }] }
      : unit);
    const tamperedPlan = { ...plan, units: tamperedUnits };
    expect(() => assertOffsecWorkPlanIntact(tamperedPlan)).toThrow();
  });

  it('still accepts normal generated relative paths after the traversal-free tightening', () => {
    const { target, manifest } = fixture();
    const plan = createOffsecWorkPlan({ target, sourceManifest: manifest });
    expect(() => assertOffsecWorkPlanIntact(plan)).not.toThrow();
    expect(plan.units.flatMap((unit) => unit.ownedFiles.map((file) => file.path))).toEqual(
      expect.arrayContaining(['packages/api/app.ts', 'packages/common/auth.ts']),
    );
  });

  it('preserves Python cross-unit imports and unsupported package edges', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-work-plan-python-'));
    mkdirSync(join(target, 'services', 'api'), { recursive: true });
    mkdirSync(join(target, 'services', 'common'), { recursive: true });
    writeFileSync(join(target, 'services', 'api', 'handler.py'),
      'from ..common.auth import authorize\nimport flask\n');
    writeFileSync(join(target, 'services', 'common', 'auth.py'), 'authorize = True\n');
    const plan = createOffsecWorkPlan({
      target,
      sourceManifest: {
        target_realpath: realpathSync(target),
        hash: 'b'.repeat(64),
        source_files: ['services/api/handler.py', 'services/common/auth.py'],
        units: [
          { id: 'services/api', files: ['services/api/handler.py'] },
          { id: 'services/common', files: ['services/common/auth.py'] },
        ],
      },
    });
    const api = plan.units.find((unit) => unit.sourceUnitId === 'services/api')!;
    expect(api.contextFiles.map((file) => file.path)).toContain('services/common/auth.py');
    expect(api.unresolvedEdges).toContainEqual({
      from: 'services/api/handler.py', specifier: 'flask', reason: 'unresolved',
    });
  });
});

function v2Fixture(options?: { fileCount?: number; maxContextFiles?: number }) {
  const target = mkdtempSync(join(tmpdir(), 'nunchi-work-plan-v2-'));
  const fileCount = options?.fileCount ?? 5;
  mkdirSync(join(target, 'unit-a'), { recursive: true });
  mkdirSync(join(target, 'unit-b'), { recursive: true });
  mkdirSync(join(target, 'unit-c'), { recursive: true });

  writeFileSync(join(target, 'unit-a', 'main.ts'),
    Array.from({ length: fileCount - 1 }, (_, i) =>
      `import { dep${i} } from '../unit-b/dep${i}';\nimport { dep${i} } from '../unit-c/dep${i}';\n`).join(''));
  const unitAFiles = ['unit-a/main.ts'];
  const unitBFiles: string[] = [];
  const unitCFiles: string[] = [];
  for (let i = 0; i < fileCount - 1; i++) {
    const bFile = `unit-b/dep${i}.ts`;
    const cFile = `unit-c/dep${i}.ts`;
    writeFileSync(join(target, 'unit-b', `dep${i}.ts`), `export const dep${i} = ${i};\n`);
    writeFileSync(join(target, 'unit-c', `dep${i}.ts`), `export const dep${i} = ${i};\n`);
    unitBFiles.push(bFile);
    unitCFiles.push(cFile);
  }
  const allFiles = [...unitAFiles, ...unitBFiles, ...unitCFiles].sort();
  return {
    target,
    manifest: {
      target_realpath: realpathSync(target),
      hash: 'ba'.repeat(32),
      source_files: allFiles,
      units: [
        { id: 'unit-a', files: unitAFiles },
        { id: 'unit-b', files: unitBFiles },
        { id: 'unit-c', files: unitCFiles },
      ],
    },
    maxContextFiles: options?.maxContextFiles ?? 50,
  };
}

describe('OffSec work plan v2 — P2', () => {
  it('high-reference candidates rank first', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-v2-rank-'));
    mkdirSync(join(target, 'a'), { recursive: true });
    mkdirSync(join(target, 'b'), { recursive: true });
    writeFileSync(join(target, 'a', 'main.ts'),
      "import { x } from '../b/low';\nimport { y } from '../b/high';\nimport { z } from '../b/high';\n");
    writeFileSync(join(target, 'a', 'other.ts'),
      "import { y } from '../b/high';\n");
    writeFileSync(join(target, 'b', 'low.ts'), 'export const x = 1;\n');
    writeFileSync(join(target, 'b', 'high.ts'), 'export const y = 1;\n');
    const manifest = {
      target_realpath: realpathSync(target),
      hash: 'aa'.repeat(32),
      source_files: ['a/main.ts', 'a/other.ts', 'b/high.ts', 'b/low.ts'],
      units: [
        { id: 'a', files: ['a/main.ts', 'a/other.ts'] },
        { id: 'b', files: ['b/high.ts', 'b/low.ts'] },
      ],
    };
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const plan = createOffsecWorkPlanV2({
      target,
      sourceManifest: manifest,
      dependencyGraph: graph,
      maxContextFilesPerUnit: 50,
    }) as OffsecWorkPlanV2;
    const unitA = plan.units.find((u) => u.sourceUnitId === 'a')!;
    expect(unitA.contextFiles[0]!.path).toBe('b/high.ts');
  });

  it('tie-breaks deterministically by estimated tokens then path', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-v2-tie-'));
    mkdirSync(join(target, 'a'), { recursive: true });
    mkdirSync(join(target, 'b'), { recursive: true });
    writeFileSync(join(target, 'a', 'main.ts'),
      "import { x } from '../b/alpha';\nimport { y } from '../b/beta';\n");
    writeFileSync(join(target, 'b', 'alpha.ts'), 'export const x = 1;\n');
    writeFileSync(join(target, 'b', 'beta.ts'), 'export const y = 1;\n');
    const manifest = {
      target_realpath: realpathSync(target),
      hash: 'ab'.repeat(32),
      source_files: ['a/main.ts', 'b/alpha.ts', 'b/beta.ts'],
      units: [
        { id: 'a', files: ['a/main.ts'] },
        { id: 'b', files: ['b/alpha.ts', 'b/beta.ts'] },
      ],
    };
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const plan = createOffsecWorkPlanV2({
      target,
      sourceManifest: manifest,
      dependencyGraph: graph,
      maxContextFilesPerUnit: 50,
    }) as OffsecWorkPlanV2;
    const unitA = plan.units.find((u) => u.sourceUnitId === 'a')!;
    const contextPaths = unitA.contextFiles.map((f) => f.path);
    expect(contextPaths).toEqual(['b/alpha.ts', 'b/beta.ts']);
  });

  it('omits too-large candidate but still selects later fitting candidate', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-v2-skip-'));
    mkdirSync(join(target, 'a'), { recursive: true });
    mkdirSync(join(target, 'b'), { recursive: true });
    writeFileSync(join(target, 'a', 'main.ts'),
      "import { x } from '../b/big';\nimport { y } from '../b/small';\n");
    writeFileSync(join(target, 'b', 'big.ts'), 'x'.repeat(300_000));
    writeFileSync(join(target, 'b', 'small.ts'), 'export const y = 1;\n');
    const manifest = {
      target_realpath: realpathSync(target),
      hash: 'ac'.repeat(32),
      source_files: ['a/main.ts', 'b/big.ts', 'b/small.ts'],
      units: [
        { id: 'a', files: ['a/main.ts'] },
        { id: 'b', files: ['b/big.ts', 'b/small.ts'] },
      ],
    };
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const plan = createOffsecWorkPlanV2({
      target,
      sourceManifest: manifest,
      dependencyGraph: graph,
      maxContextFilesPerUnit: 50,
      maxContextEstimatedTokensPerUnit: 65_536,
    }) as OffsecWorkPlanV2;
    const unitA = plan.units.find((u) => u.sourceUnitId === 'a')!;
    expect(unitA.contextFiles.map((f) => f.path)).toContain('b/small.ts');
    expect(unitA.contextFiles.map((f) => f.path)).not.toContain('b/big.ts');
    const receipt = unitA.contextSelectionReceipt;
    expect(receipt.omitted.some((o) => o.target === 'b/big.ts' && o.reason === 'token-cap')).toBe(true);
  });

  it('distinguishes file-cap and token-cap omissions', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-v2-caps-'));
    mkdirSync(join(target, 'a'), { recursive: true });
    mkdirSync(join(target, 'b'), { recursive: true });
    mkdirSync(join(target, 'c'), { recursive: true });
    writeFileSync(join(target, 'a', 'main.ts'),
      "import { x } from '../b/dep';\nimport { y } from '../c/dep';\n");
    writeFileSync(join(target, 'b', 'dep.ts'), 'export const x = 1;\n');
    writeFileSync(join(target, 'c', 'dep.ts'), 'export const y = 1;\n');
    const manifest = {
      target_realpath: realpathSync(target),
      hash: 'ad'.repeat(32),
      source_files: ['a/main.ts', 'b/dep.ts', 'c/dep.ts'],
      units: [
        { id: 'a', files: ['a/main.ts'] },
        { id: 'b', files: ['b/dep.ts'] },
        { id: 'c', files: ['c/dep.ts'] },
      ],
    };
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const plan = createOffsecWorkPlanV2({
      target,
      sourceManifest: manifest,
      dependencyGraph: graph,
      maxContextFilesPerUnit: 1,
    }) as OffsecWorkPlanV2;
    const unitA = plan.units.find((u) => u.sourceUnitId === 'a')!;
    expect(unitA.contextFiles).toHaveLength(1);
    expect(unitA.contextSelectionReceipt.omitted).toHaveLength(1);
    expect(unitA.contextSelectionReceipt.omitted[0]!.reason).toBe('file-cap');
    expect(unitA.unresolvedEdges.some((e) => e.reason === 'context-cap')).toBe(true);
  });

  it('deduplicates repeated edges to one target into one candidate/disposition', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-v2-dedup-'));
    mkdirSync(join(target, 'a'), { recursive: true });
    mkdirSync(join(target, 'b'), { recursive: true });
    writeFileSync(join(target, 'a', 'main.ts'),
      "import { x } from '../b/dep';\nimport { y } from '../b/dep';\nexport { x };\n");
    writeFileSync(join(target, 'b', 'dep.ts'), 'export const x = 1;\nexport const y = 2;\n');
    const manifest = {
      target_realpath: realpathSync(target),
      hash: 'ae'.repeat(32),
      source_files: ['a/main.ts', 'b/dep.ts'],
      units: [
        { id: 'a', files: ['a/main.ts'] },
        { id: 'b', files: ['b/dep.ts'] },
      ],
    };
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const plan = createOffsecWorkPlanV2({
      target,
      sourceManifest: manifest,
      dependencyGraph: graph,
      maxContextFilesPerUnit: 50,
    }) as OffsecWorkPlanV2;
    const unitA = plan.units.find((u) => u.sourceUnitId === 'a')!;
    const contextPaths = unitA.contextFiles.map((f) => f.path);
    expect(contextPaths.filter((p) => p === 'b/dep.ts')).toHaveLength(1);
    expect(unitA.contextSelectionReceipt.candidateCount).toBe(1);
  });

  it('external edges do not consume context budget or inflate unresolved counts', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-v2-ext-'));
    mkdirSync(join(target, 'a'), { recursive: true });
    mkdirSync(join(target, 'b'), { recursive: true });
    writeFileSync(join(target, 'a', 'main.ts'),
      "import express from 'express';\nimport lodash from 'lodash';\nimport { x } from '../b/dep';\n");
    writeFileSync(join(target, 'b', 'dep.ts'), 'export const x = 1;\n');
    const manifest = {
      target_realpath: realpathSync(target),
      hash: 'af'.repeat(32),
      source_files: ['a/main.ts', 'b/dep.ts'],
      units: [
        { id: 'a', files: ['a/main.ts'] },
        { id: 'b', files: ['b/dep.ts'] },
      ],
    };
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const plan = createOffsecWorkPlanV2({
      target,
      sourceManifest: manifest,
      dependencyGraph: graph,
      maxContextFilesPerUnit: 50,
    }) as OffsecWorkPlanV2;
    const unitA = plan.units.find((u) => u.sourceUnitId === 'a')!;
    expect(unitA.unresolvedEdges.every((e) => e.reason !== 'unresolved' || !['express', 'lodash'].includes(e.specifier))).toBe(true);
    expect(unitA.contextFiles.map((f) => f.path)).toEqual(['b/dep.ts']);
    expect(unitA.contextSelectionReceipt.selectedContextFiles).toBe(1);
  });

  it('v2 plan tampering fails closed', () => {
    const { target, manifest } = fixture();
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const plan = createOffsecWorkPlanV2({
      target,
      sourceManifest: manifest,
      dependencyGraph: graph,
      maxContextFilesPerUnit: 50,
    }) as OffsecWorkPlanV2;
    expect(() => assertOffsecWorkPlanIntact(plan)).not.toThrow();
    const tampered = { ...plan, sourceManifestSha256: 'b'.repeat(64) };
    expect(() => assertOffsecWorkPlanIntact(tampered)).toThrow(/hash/);
  });

  it('v1 plan parsing/hash remains unchanged after v2 addition', () => {
    const { target, manifest } = fixture();
    const plan = createOffsecWorkPlan({ target, sourceManifest: manifest });
    expect(plan.schemaVersion).toBe('1.0.0');
    expect(() => assertOffsecWorkPlanIntact(plan)).not.toThrow();
    const api = plan.units.find((u) => u.sourceUnitId === 'packages/api')!;
    expect(api.contextFiles.map((f) => f.path)).toEqual(['packages/common/auth.ts']);
  });

  it('v2 work-unit VA inputs contain typed edges and planning receipt', () => {
    const { target, manifest } = fixture();
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const plan = createOffsecWorkPlanV2({
      target,
      sourceManifest: manifest,
      dependencyGraph: graph,
      maxContextFilesPerUnit: 50,
    }) as OffsecWorkPlanV2;
    const api = plan.units.find((u) => u.sourceUnitId === 'packages/api')!;
    expect(api.contextSelectionReceipt).toBeDefined();
    expect(api.contextSelectionReceipt.rankingPolicy).toBe('ref-count-desc/tokens-asc/path-asc');
    const typedEdges = getUnitTypedEdges(graph, api);
    expect(typedEdges.length).toBeGreaterThan(0);
    expect(typedEdges.every((e) => e.from === 'packages/api/app.ts')).toBe(true);
    expect(api.estimatedTokens).toBeGreaterThan(0);
  });

  it('source file count and unit ownership remain unchanged between v1 and v2', () => {
    const { target, manifest } = fixture();
    const v1 = createOffsecWorkPlan({ target, sourceManifest: manifest });
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const v2 = createOffsecWorkPlanV2({
      target,
      sourceManifest: manifest,
      dependencyGraph: graph,
      maxContextFilesPerUnit: 50,
    }) as OffsecWorkPlanV2;
    expect(v2.units.length).toBe(v1.units.length);
    for (const v1Unit of v1.units) {
      const v2Unit = v2.units.find((u) => u.unitKey === v1Unit.unitKey)!;
      expect(v2Unit).toBeDefined();
      expect(v2Unit.sourceUnitId).toBe(v1Unit.sourceUnitId);
      expect(v2Unit.ownedFiles.map((f) => f.path).sort()).toEqual(
        v1Unit.ownedFiles.map((f) => f.path).sort());
    }
  });

  it('v2 plan has deterministic hash across regeneration', () => {
    const { target, manifest } = fixture();
    const g1 = createDependencyGraph({ target, sourceManifest: manifest });
    const g2 = createDependencyGraph({ target, sourceManifest: manifest });
    const p1 = createOffsecWorkPlanV2({ target, sourceManifest: manifest, dependencyGraph: g1, maxContextFilesPerUnit: 50 });
    const p2 = createOffsecWorkPlanV2({ target, sourceManifest: manifest, dependencyGraph: g2, maxContextFilesPerUnit: 50 });
    expect(p1.workPlanSha256).toBe(p2.workPlanSha256);
  });
});

describe('bounded host work executor', () => {
  it('bounds concurrency, keeps sealed order, and settles partial failures', async () => {
    const units = Array.from({ length: 5 }, (_, index) => ({ unitKey: `unit-${String(index).padStart(16, '0')}` }));
    let active = 0;
    let observedMaximum = 0;
    const results = await executeBoundedWork({
      units,
      maxConcurrency: 2,
      maximumWorkUnits: 5,
      worker: async (unit) => {
        active += 1;
        observedMaximum = Math.max(observedMaximum, active);
        await new Promise((resolve) => setTimeout(resolve, unit === units[0] ? 5 : 1));
        active -= 1;
        if (unit === units[2]) throw new Error('fixture failure');
        return unit.unitKey;
      },
    });
    expect(observedMaximum).toBe(2);
    expect(results.map((result) => result.unit.unitKey)).toEqual(units.map((unit) => unit.unitKey));
    expect(results.map((result) => result.status)).toEqual([
      'fulfilled', 'fulfilled', 'rejected', 'fulfilled', 'fulfilled',
    ]);
  });

  it('rejects model-expandable or duplicate work sets before execution', async () => {
    const units = [{ unitKey: 'unit-0000000000000000' }, { unitKey: 'unit-0000000000000000' }];
    await expect(executeBoundedWork({
      units,
      maxConcurrency: 1,
      maximumWorkUnits: 2,
      worker: async () => undefined,
    })).rejects.toThrow(/중복/);
    await expect(executeBoundedWork({
      units: [...units, { unitKey: 'unit-1111111111111111' }],
      maxConcurrency: 1,
      maximumWorkUnits: 2,
      worker: async () => undefined,
    })).rejects.toThrow(/상한/);
  });

  it('retries rejected units once and sequentially after the bounded wave', async () => {
    const units = Array.from({ length: 3 }, (_, index) => ({ unitKey: `unit-${String(index).padStart(16, '0')}` }));
    const attempts = new Map<string, number>();
    let retryActive = 0;
    let maximumRetryActive = 0;
    const results = await executeBoundedWork({
      units,
      maxConcurrency: 3,
      maximumWorkUnits: 3,
      retryRejectedOnce: true,
      worker: async (unit, retryAttempt) => {
        const observedAttempt = (attempts.get(unit.unitKey) ?? 0) + 1;
        attempts.set(unit.unitKey, observedAttempt);
        expect(retryAttempt).toBe(observedAttempt);
        if (observedAttempt === 2) {
          retryActive += 1;
          maximumRetryActive = Math.max(maximumRetryActive, retryActive);
          await new Promise((resolve) => setTimeout(resolve, 1));
          retryActive -= 1;
        }
        if (unit !== units[0] && observedAttempt === 1) throw new Error('transient fixture failure');
        if (unit === units[2]) throw new Error('persistent fixture failure');
        return unit.unitKey;
      },
    });
    expect(results.map((result) => result.status)).toEqual(['fulfilled', 'fulfilled', 'rejected']);
    expect(attempts.get(units[0]!.unitKey)).toBe(1);
    expect(attempts.get(units[1]!.unitKey)).toBe(2);
    expect(attempts.get(units[2]!.unitKey)).toBe(2);
    expect(maximumRetryActive).toBe(1);
  });
});

describe('OffSec work plan v2 — F3/F4 structural cross-validation', () => {
  it('assertPlanGraphIntegrity passes for a valid v2 plan+graph pair', () => {
    const { target, manifest } = fixture();
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const plan = createOffsecWorkPlanV2({
      target,
      sourceManifest: manifest,
      dependencyGraph: graph,
      maxContextFilesPerUnit: 50,
    }) as OffsecWorkPlanV2;
    expect(() => assertPlanGraphIntegrity(plan, graph)).not.toThrow();
  });

  it('F4: fails closed when plan.dependencyGraphSha256 does not match graph', () => {
    const { target, manifest } = fixture();
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const plan = createOffsecWorkPlanV2({
      target,
      sourceManifest: manifest,
      dependencyGraph: graph,
      maxContextFilesPerUnit: 50,
    }) as OffsecWorkPlanV2;
    // Tamper graph hash to simulate mismatch
    const tamperedGraph = { ...graph, dependencyGraphSha256: 'b'.repeat(64) };
    expect(() => assertPlanGraphIntegrity(plan, tamperedGraph)).toThrow(/graph hash|다르다/);
  });

  it('F3: rejects plan with tampered context selection', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-v2-f3-'));
    mkdirSync(join(target, 'a'), { recursive: true });
    mkdirSync(join(target, 'b'), { recursive: true });
    writeFileSync(join(target, 'a', 'main.ts'),
      "import { x } from '../b/dep';\n");
    writeFileSync(join(target, 'b', 'dep.ts'), 'export const x = 1;\n');
    const manifest = {
      target_realpath: realpathSync(target),
      hash: 'f3'.repeat(32),
      source_files: ['a/main.ts', 'b/dep.ts'],
      units: [
        { id: 'a', files: ['a/main.ts'] },
        { id: 'b', files: ['b/dep.ts'] },
      ],
    };
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const plan = createOffsecWorkPlanV2({
      target,
      sourceManifest: manifest,
      dependencyGraph: graph,
      maxContextFilesPerUnit: 50,
    }) as OffsecWorkPlanV2;
    // Tamper a unit's receipt to claim more candidates than actually exist
    const tampered = JSON.parse(JSON.stringify(plan)) as OffsecWorkPlanV2;
    const unitA = tampered.units.find((u) => u.sourceUnitId === 'a')!;
    unitA.contextSelectionReceipt.candidateCount = 99;
    // Rehash plan
    const { workPlanSha256: _, generatedAt: __, ...core } = tampered;
    tampered.workPlanSha256 = testDigest(testStableJson(core));
    // Should fail because candidate count doesn't match re-derived value
    expect(() => assertPlanGraphIntegrity(tampered, graph)).toThrow(/candidate count|불일치/);
  });

  it('F3: plan-only validation rejects internally-invalid V2 receipt without graph', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-v2-f3-internal-'));
    mkdirSync(join(target, 'a'), { recursive: true });
    mkdirSync(join(target, 'b'), { recursive: true });
    writeFileSync(join(target, 'a', 'main.ts'),
      "import { x } from '../b/dep';\n");
    writeFileSync(join(target, 'b', 'dep.ts'), 'export const x = 1;\n');
    const manifest = {
      target_realpath: realpathSync(target),
      hash: 'ab'.repeat(32),
      source_files: ['a/main.ts', 'b/dep.ts'],
      units: [
        { id: 'a', files: ['a/main.ts'] },
        { id: 'b', files: ['b/dep.ts'] },
      ],
    };
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const plan = createOffsecWorkPlanV2({
      target,
      sourceManifest: manifest,
      dependencyGraph: graph,
      maxContextFilesPerUnit: 50,
    }) as OffsecWorkPlanV2;
    // Tamper: make candidateCount inconsistent with selected + omitted
    const tampered = JSON.parse(JSON.stringify(plan)) as OffsecWorkPlanV2;
    const unitA = tampered.units.find((u) => u.sourceUnitId === 'a')!;
    unitA.contextSelectionReceipt.candidateCount = 99;
    const { workPlanSha256: _, generatedAt: __, ...core } = tampered;
    tampered.workPlanSha256 = testDigest(testStableJson(core));
    // Plan-only validation should catch this without needing graph
    expect(() => assertOffsecWorkPlanIntact(tampered)).toThrow(/candidate count|불일치/);
  });

  it('omission records preserve truthful source/specifier provenance', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-v2-prov-'));
    mkdirSync(join(target, 'a'), { recursive: true });
    mkdirSync(join(target, 'b'), { recursive: true });
    mkdirSync(join(target, 'c'), { recursive: true });
    writeFileSync(join(target, 'a', 'main.ts'),
      "import { x } from '../b/dep';\nimport { y } from '../c/dep';\n");
    writeFileSync(join(target, 'b', 'dep.ts'), 'export const x = 1;\n');
    writeFileSync(join(target, 'c', 'dep.ts'), 'export const y = 1;\n');
    const manifest = {
      target_realpath: realpathSync(target),
      hash: 'ab'.repeat(32),
      source_files: ['a/main.ts', 'b/dep.ts', 'c/dep.ts'],
      units: [
        { id: 'a', files: ['a/main.ts'] },
        { id: 'b', files: ['b/dep.ts'] },
        { id: 'c', files: ['c/dep.ts'] },
      ],
    };
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const plan = createOffsecWorkPlanV2({
      target,
      sourceManifest: manifest,
      dependencyGraph: graph,
      maxContextFilesPerUnit: 1,
    }) as OffsecWorkPlanV2;
    const unitA = plan.units.find((u) => u.sourceUnitId === 'a')!;
    // The omitted unresolvedEdge should have truthful `from` and `specifier`
    const capEdge = unitA.unresolvedEdges.find((e) => e.reason === 'context-cap');
    expect(capEdge).toBeDefined();
    expect(capEdge!.from).toBe('a/main.ts'); // actual referencing file
    // specifier should be the real import specifier, not the target path
    expect(capEdge!.specifier).toMatch(/\.\.\/[bc]\/dep/);
    expect(capEdge!.resolvedTarget).toBeDefined();
  });

  it('assertPlanGraphIntegrity verifies planningPolicy.estimatedCharsPerToken matches graph', () => {
    const { target, manifest } = fixture();
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const plan = createOffsecWorkPlanV2({
      target,
      sourceManifest: manifest,
      dependencyGraph: graph,
      maxContextFilesPerUnit: 50,
    }) as OffsecWorkPlanV2;
    // Tamper: make policy charsPerToken differ from graph
    const tampered = JSON.parse(JSON.stringify(plan)) as OffsecWorkPlanV2;
    tampered.planningPolicy.estimatedCharsPerToken = 8;
    const { workPlanSha256: _, generatedAt: __, ...core } = tampered;
    tampered.workPlanSha256 = testDigest(testStableJson(core));
    expect(() => assertPlanGraphIntegrity(tampered, graph)).toThrow(/estimatedCharsPerToken/);
  });

  it('assertPlanGraphIntegrity verifies maxContextFilesPerUnit matches planningPolicy', () => {
    const { target, manifest } = fixture();
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const plan = createOffsecWorkPlanV2({
      target,
      sourceManifest: manifest,
      dependencyGraph: graph,
      maxContextFilesPerUnit: 50,
    }) as OffsecWorkPlanV2;
    // Tamper: make top-level maxContextFilesPerUnit differ from planningPolicy
    const tampered = JSON.parse(JSON.stringify(plan)) as OffsecWorkPlanV2;
    tampered.maxContextFilesPerUnit = 99;
    const { workPlanSha256: _, generatedAt: __, ...core } = tampered;
    tampered.workPlanSha256 = testDigest(testStableJson(core));
    expect(() => assertPlanGraphIntegrity(tampered, graph)).toThrow(/maxContextFilesPerUnit/);
  });

  it('assertPlanGraphIntegrity verifies unit.estimatedTokens = owned + selected context', () => {
    const { target, manifest, maxContextFiles } = v2Fixture();
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const plan = createOffsecWorkPlanV2({
      target,
      sourceManifest: manifest,
      dependencyGraph: graph,
      maxContextFilesPerUnit: maxContextFiles,
    }) as OffsecWorkPlanV2;
    // Tamper unit estimatedTokens
    const tampered = JSON.parse(JSON.stringify(plan)) as OffsecWorkPlanV2;
    tampered.units[0]!.estimatedTokens = 999999;
    const { workPlanSha256: _, generatedAt: __, ...core } = tampered;
    tampered.workPlanSha256 = testDigest(testStableJson(core));
    expect(() => assertPlanGraphIntegrity(tampered, graph)).toThrow(/estimatedTokens 불일치/);
  });

  it('assertPlanGraphIntegrity rejects tampered omission order', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-v2-omit-order-'));
    mkdirSync(join(target, 'a'), { recursive: true });
    mkdirSync(join(target, 'b'), { recursive: true });
    mkdirSync(join(target, 'c'), { recursive: true });
    mkdirSync(join(target, 'd'), { recursive: true });
    writeFileSync(join(target, 'a', 'main.ts'),
      "import { x } from '../b/dep';\nimport { y } from '../c/dep';\nimport { z } from '../d/dep';\n");
    writeFileSync(join(target, 'b', 'dep.ts'), 'export const x = 1;\n');
    writeFileSync(join(target, 'c', 'dep.ts'), 'export const y = 1;\n');
    writeFileSync(join(target, 'd', 'dep.ts'), 'export const z = 1;\n');
    const manifest = {
      target_realpath: realpathSync(target),
      hash: '00'.repeat(32),
      source_files: ['a/main.ts', 'b/dep.ts', 'c/dep.ts', 'd/dep.ts'],
      units: [
        { id: 'a', files: ['a/main.ts'] },
        { id: 'b', files: ['b/dep.ts'] },
        { id: 'c', files: ['c/dep.ts'] },
        { id: 'd', files: ['d/dep.ts'] },
      ],
    };
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const plan = createOffsecWorkPlanV2({
      target,
      sourceManifest: manifest,
      dependencyGraph: graph,
      maxContextFilesPerUnit: 1, // only 1 selected, 2 omitted
    }) as OffsecWorkPlanV2;
    const unitA = plan.units.find((u) => u.sourceUnitId === 'a')!;
    expect(unitA.contextSelectionReceipt.omitted.length).toBeGreaterThanOrEqual(2);
    // Tamper: reverse omitted order
    const tampered = JSON.parse(JSON.stringify(plan)) as OffsecWorkPlanV2;
    const tamperedUnitA = tampered.units.find((u) => u.sourceUnitId === 'a')!;
    tamperedUnitA.contextSelectionReceipt.omitted.reverse();
    const { workPlanSha256: _, generatedAt: __, ...core } = tampered;
    tampered.workPlanSha256 = testDigest(testStableJson(core));
    expect(() => assertPlanGraphIntegrity(tampered, graph)).toThrow(/omitted\[0\].*target 불일치/);
  });

  it('assertPlanGraphIntegrity rejects extra unresolvedEdge entries', () => {
    const { target, manifest } = fixture();
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const plan = createOffsecWorkPlanV2({
      target,
      sourceManifest: manifest,
      dependencyGraph: graph,
      maxContextFilesPerUnit: 50,
    }) as OffsecWorkPlanV2;
    // Tamper: add an extra unresolved edge to a unit
    const tampered = JSON.parse(JSON.stringify(plan)) as OffsecWorkPlanV2;
    tampered.units[0]!.unresolvedEdges.push({
      from: tampered.units[0]!.ownedFiles[0]!.path,
      specifier: './fake',
      reason: 'unresolved',
    });
    const { workPlanSha256: _, generatedAt: __, ...core } = tampered;
    tampered.workPlanSha256 = testDigest(testStableJson(core));
    expect(() => assertPlanGraphIntegrity(tampered, graph)).toThrow(/unresolvedEdges count 불일치/);
  });
});

describe('OffSec V2 publication-gate fixture', () => {
  it('correctly self-hashed V2 work-plan fixture passes assertOffsecWorkPlanIntact', () => {
    const { target, manifest } = fixture();
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const plan = createOffsecWorkPlanV2({
      target,
      sourceManifest: manifest,
      dependencyGraph: graph,
      maxContextFilesPerUnit: 50,
    }) as OffsecWorkPlanV2;

    // Verify the plan passes full integrity as a plain-JS fixture (simulating publication gate)
    const serialized = JSON.parse(JSON.stringify(plan));
    expect(() => assertOffsecWorkPlanIntact(serialized)).not.toThrow();

    // Verify self-hash is correct using test stableJson
    const { workPlanSha256: hash, generatedAt: _ts, ...core } = serialized as OffsecWorkPlanV2;
    expect(testDigest(testStableJson(core))).toBe(hash);
  });

  it('V2 self-hash tamper rejection: modified field invalidates workPlanSha256', () => {
    const { target, manifest } = fixture();
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const plan = createOffsecWorkPlanV2({
      target,
      sourceManifest: manifest,
      dependencyGraph: graph,
      maxContextFilesPerUnit: 50,
    }) as OffsecWorkPlanV2;

    // Tamper a field without rehashing
    const tampered = JSON.parse(JSON.stringify(plan)) as OffsecWorkPlanV2;
    tampered.sourceManifestSha256 = 'c'.repeat(64);
    expect(() => assertOffsecWorkPlanIntact(tampered)).toThrow(/hash/);
  });

  it('V2 plan+graph round-trip as serialized JSON passes assertPlanGraphIntegrity', () => {
    const { target, manifest } = fixture();
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const plan = createOffsecWorkPlanV2({
      target,
      sourceManifest: manifest,
      dependencyGraph: graph,
      maxContextFilesPerUnit: 50,
    }) as OffsecWorkPlanV2;

    // Simulate serialization round-trip (as on disk at publication)
    const planJson = JSON.parse(JSON.stringify(plan));
    const graphJson = JSON.parse(JSON.stringify(graph));
    expect(() => assertPlanGraphIntegrity(planJson, graphJson)).not.toThrow();
  });
});
