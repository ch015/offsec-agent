import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import type { ProviderRuntimeEvent } from '../providers/provider-runtime.js';
import { createOffsecWorkPlan, type OffsecWorkPlan } from '../workflow/offsec-work-plan.js';
import {
  assertScopeAssuranceComplete,
  assertScopeAssuranceIntact,
  createScopeAssurance,
  SCOPE_ASSURANCE_DISCLOSURE,
} from '../workflow/scope-assurance.js';

function fixture(): { target: string; workPlan: OffsecWorkPlan } {
  const target = mkdtempSync(join(tmpdir(), 'nunchi-scope-assurance-'));
  mkdirSync(join(target, 'packages', 'api'), { recursive: true });
  mkdirSync(join(target, 'packages', 'common'), { recursive: true });
  writeFileSync(
    join(target, 'packages', 'api', 'app.ts'),
    "import { authorize } from '../common/auth';\nexport const handler = authorize;\n",
  );
  writeFileSync(join(target, 'packages', 'common', 'auth.ts'), 'export const authorize = true;\n');
  const workPlan = createOffsecWorkPlan({
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
  });
  return { target, workPlan };
}

function readEvent(resource: string, overrides: Partial<ProviderRuntimeEvent> = {}): ProviderRuntimeEvent {
  return { at: new Date(0).toISOString(), event: 'PreToolUse', tool: 'Read', decision: 'allow', resource, ...overrides };
}

describe('OffSec host-owned scope assurance', () => {
  it('binds to the sealed work plan and records VA/Verifier read observations separately', () => {
    const { target, workPlan } = fixture();
    const api = workPlan.units.find((unit) => unit.sourceUnitId === 'packages/api')!;
    const common = workPlan.units.find((unit) => unit.sourceUnitId === 'packages/common')!;
    const completedUnitKeys = workPlan.units.map((unit) => unit.unitKey);
    const observations = new Map([
      [api.unitKey, {
        vaEvents: [
          readEvent(join(target, 'packages/api/app.ts')),
          readEvent(join(target, 'packages/api/app.ts')), // 중복 — dedupe되어야 한다
          readEvent(join(target, 'packages/common/auth.ts')),
          readEvent('/etc/hosts'), // scope 밖 — 카운트되지 않는다
        ],
        verifierEvents: [
          readEvent(join(target, 'packages/api/app.ts')),
        ],
        autonomousVerifierSealed: true,
      }],
      [common.unitKey, {
        vaEvents: [readEvent(join(target, 'packages/common/auth.ts'))],
        verifierEvents: [],
        autonomousVerifierSealed: true,
      }],
    ]);

    const assurance = createScopeAssurance({ target, workPlan, completedUnitKeys, observations });
    expect(assurance.disclosure).toBe(SCOPE_ASSURANCE_DISCLOSURE);
    expect(assurance.sourceManifestSha256).toBe(workPlan.sourceManifestSha256);
    expect(assurance.workPlanSha256).toBe(workPlan.workPlanSha256);

    const apiRecord = assurance.units.find((unit) => unit.unitKey === api.unitKey)!;
    expect(apiRecord.va).toEqual({ uniqueAllowedReadResources: 2, ownedFilesRead: 1, contextFilesRead: 1 });
    expect(apiRecord.verifier).toEqual({ uniqueAllowedReadResources: 1, ownedFilesRead: 1, contextFilesRead: 0 });
    expect(apiRecord.ownedFileCount).toBe(1);
    expect(apiRecord.contextFileCount).toBe(1);
    expect(apiRecord.unresolvedEdgeCount).toBe(0);
    expect(apiRecord.contextCappedEdgeCount).toBe(0);
    expect(apiRecord.autonomousVerifierSealed).toBe(true);

    expect(() => assertScopeAssuranceIntact(assurance)).not.toThrow();
    expect(() => assertScopeAssuranceComplete(assurance, workPlan, completedUnitKeys)).not.toThrow();
  });

  it('does not count denied reads or out-of-scope resources toward the assurance receipt', () => {
    const { target, workPlan } = fixture();
    const completedUnitKeys = workPlan.units.map((unit) => unit.unitKey);
    const observations = new Map(workPlan.units.map((unit) => [unit.unitKey, {
      vaEvents: [
        readEvent(join(target, unit.ownedFiles[0]!.path), { decision: 'deny' }),
        readEvent(join(target, unit.ownedFiles[0]!.path)),
      ],
      verifierEvents: [],
      autonomousVerifierSealed: true,
    }]));
    const assurance = createScopeAssurance({ target, workPlan, completedUnitKeys, observations });
    for (const unit of assurance.units) {
      expect(unit.va.uniqueAllowedReadResources).toBe(1);
      expect(unit.va.ownedFilesRead).toBe(1);
    }
  });

  it('fails closed when the receipt is tampered', () => {
    const { target, workPlan } = fixture();
    const completedUnitKeys = workPlan.units.map((unit) => unit.unitKey);
    const observations = new Map(workPlan.units.map((unit) => [unit.unitKey, {
      vaEvents: [], verifierEvents: [], autonomousVerifierSealed: true,
    }]));
    const assurance = createScopeAssurance({ target, workPlan, completedUnitKeys, observations });
    const tampered = { ...assurance, completedUnitKeys: [...assurance.completedUnitKeys].reverse().concat('extra') };
    expect(() => assertScopeAssuranceIntact(tampered)).toThrow(/hash/);
  });

  it('fails closed on a workPlanSha256 mismatch even when the receipt is internally self-consistent', () => {
    const { target, workPlan } = fixture();
    const other = fixture();
    const completedUnitKeys = workPlan.units.map((unit) => unit.unitKey);
    const observations = new Map(workPlan.units.map((unit) => [unit.unitKey, {
      vaEvents: [], verifierEvents: [], autonomousVerifierSealed: true,
    }]));
    const assurance = createScopeAssurance({ target, workPlan, completedUnitKeys, observations });
    expect(() => assertScopeAssuranceComplete(assurance, other.workPlan, completedUnitKeys))
      .toThrow(/work plan hash/);
  });

  it('allows partial unit completion (Quarantine + Proceed)', () => {
    const { target, workPlan } = fixture();
    const [first, second] = workPlan.units;
    const observations = new Map([[first!.unitKey, {
      vaEvents: [], verifierEvents: [], autonomousVerifierSealed: true,
    }]]);
    // Partial completion: 1/2 units — createScopeAssurance는 더 이상 throw하지 않음
    expect(() => createScopeAssurance({
      target, workPlan, completedUnitKeys: [first!.unitKey], observations,
    })).not.toThrow();

    // 완전한 receipt를 만든 뒤, assertScopeAssuranceComplete는 completed 목록 일치만 확인
    const fullObservations = new Map(workPlan.units.map((unit) => [unit.unitKey, {
      vaEvents: [], verifierEvents: [], autonomousVerifierSealed: true,
    }]));
    const assurance = createScopeAssurance({
      target, workPlan, completedUnitKeys: workPlan.units.map((unit) => unit.unitKey), observations: fullObservations,
    });
    // assertScopeAssuranceComplete: completed 목록이 다르면 여전히 throw
    expect(() => assertScopeAssuranceComplete(assurance, workPlan, [first!.unitKey]))
      .toThrow(/completed unit 목록이 다르다/);
    void second;
  });

  it('does not enforce any read-ratio or finding-density threshold', () => {
    const { target, workPlan } = fixture();
    const completedUnitKeys = workPlan.units.map((unit) => unit.unitKey);
    const observations = new Map(workPlan.units.map((unit) => [unit.unitKey, {
      vaEvents: [], verifierEvents: [], autonomousVerifierSealed: true,
    }]));
    // 실제 읽은 파일이 0개여도(허용된 Read 이벤트가 전혀 없어도) 구조적으로는 그대로 통과한다 —
    // 이 모듈은 read-ratio/finding-density gate를 두지 않는다(publication routing이 별도로 처리).
    expect(() => createScopeAssurance({ target, workPlan, completedUnitKeys, observations })).not.toThrow();
  });
});
