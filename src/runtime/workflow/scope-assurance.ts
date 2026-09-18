import { createHash } from 'node:crypto';
import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { z } from 'zod';

import type { ProviderRuntimeEvent } from '../providers/provider-runtime.js';
import { assertOffsecWorkPlanComplete, type OffsecWorkPlanAny } from './offsec-work-plan.js';

// 발행 시 신뢰 경계를 명확히 하기 위한 고정 문구 — Read 카운트는 최소 검토 신호일 뿐 의미론적
// 보안 분석의 증명이 아니다(coordinator/reviewer가 "얼마나 읽었는가"를 "얼마나 분석했는가"로
// 오독하지 않도록 receipt 자체에 박아 둔다).
export const SCOPE_ASSURANCE_DISCLOSURE =
  'Read/allowed-resource counts are a minimum-examination signal only. ' +
  'They do not prove semantic security analysis was performed for any file.';

const Sha256Schema = z.string().regex(/^[a-f0-9]{64}$/);

const UnitObservationSchema = z.object({
  uniqueAllowedReadResources: z.number().int().nonnegative(),
  ownedFilesRead: z.number().int().nonnegative(),
  contextFilesRead: z.number().int().nonnegative(),
}).strict();

const ScopeAssuranceUnitSchema = z.object({
  unitKey: z.string().regex(/^unit-[a-f0-9]{16}$/),
  sourceUnitId: z.string().min(1),
  ownedFileCount: z.number().int().positive(),
  contextFileCount: z.number().int().nonnegative(),
  unresolvedEdgeCount: z.number().int().nonnegative(),
  contextCappedEdgeCount: z.number().int().nonnegative(),
  va: UnitObservationSchema,
  verifier: UnitObservationSchema.optional(),
  autonomousVerifierSealed: z.boolean().optional(),
}).strict();

export const ScopeAssuranceSchema = z.object({
  schemaVersion: z.literal('1.0.0'),
  analysisMode: z.literal('v2').optional(),
  sourceManifestSha256: Sha256Schema,
  workPlanSha256: Sha256Schema,
  completedUnitKeys: z.array(z.string()).min(1),
  units: z.array(ScopeAssuranceUnitSchema).min(1),
  disclosure: z.literal(SCOPE_ASSURANCE_DISCLOSURE),
  generatedAt: z.string().datetime(),
  scopeAssuranceSha256: Sha256Schema,
}).strict();

export type ScopeAssurance = z.infer<typeof ScopeAssuranceSchema>;
export type ScopeAssuranceUnit = z.infer<typeof ScopeAssuranceUnitSchema>;
export type ScopeAssuranceUnitObservation = z.infer<typeof UnitObservationSchema>;

// 단일 진실 소스 — assess.ts(resume 검증)와 domains/offsec/lib/ch015/scope-assurance-gate.js(발행
// 게이트, plain CommonJS라 이 상수를 import할 수 없어 리터럴로 그대로 복제해야 한다)가 참조하는
// scope assurance 파일명. `00_work_unit_results.json`의 assurancePath 필드는 반드시 이 값과
// "정확히" 일치해야 한다(경로 traversal/절대경로 거부 — P0 correction §3).
export const SCOPE_ASSURANCE_FILE_NAME = '00_scope_assurance.json';

export type UnitScopeObservationInput = {
  vaEvents: readonly ProviderRuntimeEvent[];
  verifierEvents?: readonly ProviderRuntimeEvent[];
  autonomousVerifierSealed?: boolean;
};

export function createScopeAssurance(input: {
  target: string;
  analysisMode?: 'v2';
  workPlan: OffsecWorkPlanAny;
  completedUnitKeys: readonly string[];
  observations: ReadonlyMap<string, UnitScopeObservationInput>;
}): ScopeAssurance {
  // Quarantine + Proceed: partial completion 허용 — 완료된 unit만으로 assurance 생성
  // assertOffsecWorkPlanComplete(input.workPlan, input.completedUnitKeys);
  const units = [...input.completedUnitKeys].sort().map((unitKey) => {
    const unit = input.workPlan.units.find((candidate) => candidate.unitKey === unitKey);
    if (!unit) throw new Error(`OffSec scope assurance unit이 sealed work plan에 없다: ${unitKey}`);
    const observation = input.observations.get(unitKey);
    if (!observation) throw new Error(`OffSec scope assurance observation이 없다: ${unitKey}`);
    const ownedPaths = new Set(unit.ownedFiles.map((file) => resolve(input.target, file.path)));
    const contextPaths = new Set(unit.contextFiles.map((file) => resolve(input.target, file.path)));
    return {
      unitKey: unit.unitKey,
      sourceUnitId: unit.sourceUnitId,
      ownedFileCount: unit.ownedFiles.length,
      contextFileCount: unit.contextFiles.length,
      unresolvedEdgeCount: unit.unresolvedEdges.filter((edge) => edge.reason === 'unresolved').length,
      contextCappedEdgeCount: unit.unresolvedEdges.filter((edge) => edge.reason === 'context-cap').length,
      va: observeAllowedReads(observation.vaEvents, input.target, ownedPaths, contextPaths),
      // v2에는 verifier phase가 없다 — verifier events가 있을 때만 관측치를 기록하고, 없으면 필드를 생략한다.
      ...(observation.verifierEvents !== undefined
        ? { verifier: observeAllowedReads(observation.verifierEvents, input.target, ownedPaths, contextPaths) }
        : {}),
      ...(observation.autonomousVerifierSealed !== undefined
        ? { autonomousVerifierSealed: observation.autonomousVerifierSealed } : {}),
    };
  });
  const core = {
    schemaVersion: '1.0.0' as const,
    ...(input.analysisMode ? { analysisMode: input.analysisMode } : {}),
    sourceManifestSha256: input.workPlan.sourceManifestSha256,
    workPlanSha256: input.workPlan.workPlanSha256,
    completedUnitKeys: [...input.completedUnitKeys].sort(),
    units,
    disclosure: SCOPE_ASSURANCE_DISCLOSURE,
  };
  return ScopeAssuranceSchema.parse({
    ...core,
    generatedAt: new Date().toISOString(),
    scopeAssuranceSha256: digest(stableJson(core)),
  });
}

export function writeScopeAssurance(engagementDir: string, assurance: ScopeAssurance): string {
  const parsed = assertScopeAssuranceIntact(assurance);
  const path = join(engagementDir, SCOPE_ASSURANCE_FILE_NAME);
  const temporary = `${path}.${process.pid}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(parsed, null, 2)}\n`, { mode: 0o600 });
  renameSync(temporary, path);
  return path;
}

/** 자기 해시(scopeAssuranceSha256) 무결성만 확인 — 상위 work plan/results와의 정합은 별도로 검증한다. */
export function assertScopeAssuranceIntact(value: unknown): ScopeAssurance {
  const assurance = ScopeAssuranceSchema.parse(value);
  const { scopeAssuranceSha256: _sealed, generatedAt: _generatedAt, ...core } = assurance;
  if (digest(stableJson(core)) !== assurance.scopeAssuranceSha256) {
    throw new Error('OffSec scope assurance hash가 다르다');
  }
  return assurance;
}

/**
 * hash-bound scope assurance를 sealed work plan/완료 unit 목록과 교차 검증한다.
 * 새 실행이 assurance를 선언했는데 누락/변조/불완전하면 fail closed(throw)해야 한다.
 */
export function assertScopeAssuranceComplete(
  value: unknown,
  workPlan: OffsecWorkPlanAny,
  completedUnitKeys: readonly string[],
): ScopeAssurance {
  const assurance = assertScopeAssuranceIntact(value);
  if (assurance.workPlanSha256 !== workPlan.workPlanSha256) {
    throw new Error('OffSec scope assurance work plan hash가 다르다');
  }
  if (assurance.sourceManifestSha256 !== workPlan.sourceManifestSha256) {
    throw new Error('OffSec scope assurance source manifest hash가 다르다');
  }
  // Quarantine + Proceed: partial completion 허용
  // assertOffsecWorkPlanComplete(workPlan, completedUnitKeys);
  const expected = [...completedUnitKeys].sort();
  const declared = [...assurance.completedUnitKeys].sort();
  if (JSON.stringify(expected) !== JSON.stringify(declared)) {
    throw new Error('OffSec scope assurance completed unit 목록이 다르다');
  }
  if (assurance.units.length !== completedUnitKeys.length) {
    throw new Error(
      `OffSec scope assurance unit 수(${assurance.units.length})가 completed unit 수(${completedUnitKeys.length})와 다르다`,
    );
  }
  const planUnitsByKey = new Map(workPlan.units.map((unit) => [unit.unitKey, unit]));
  for (const unit of assurance.units) {
    const planUnit = planUnitsByKey.get(unit.unitKey);
    if (!planUnit) throw new Error(`OffSec scope assurance unit이 sealed work plan에 없다: ${unit.unitKey}`);
    if (
      unit.sourceUnitId !== planUnit.sourceUnitId ||
      unit.ownedFileCount !== planUnit.ownedFiles.length ||
      unit.contextFileCount !== planUnit.contextFiles.length ||
      unit.unresolvedEdgeCount !== planUnit.unresolvedEdges.filter((edge) => edge.reason === 'unresolved').length ||
      unit.contextCappedEdgeCount !== planUnit.unresolvedEdges.filter((edge) => edge.reason === 'context-cap').length
    ) {
      throw new Error(`OffSec scope assurance unit 관측치가 sealed work plan과 다르다: ${unit.unitKey}`);
    }
  }
  return assurance;
}

function observeAllowedReads(
  events: readonly ProviderRuntimeEvent[],
  target: string,
  ownedPaths: ReadonlySet<string>,
  contextPaths: ReadonlySet<string>,
): ScopeAssuranceUnitObservation {
  // 실제 허용된(allow) Read 이벤트만 "읽음"으로 집계한다 — 광범위 Grep/Glob 매칭이나 deny는
  // "파일을 조사했다"로 승격하지 않는다(호스트 concrete match receipt가 없는 한).
  const allowedReads = new Set(
    events
      .filter((event) => event.tool === 'Read' && event.decision === 'allow' && typeof event.resource === 'string')
      .map((event) => resolve(target, event.resource!)),
  );
  let ownedFilesRead = 0;
  let contextFilesRead = 0;
  let uniqueAllowedReadResources = 0;
  for (const path of allowedReads) {
    const inOwned = ownedPaths.has(path);
    const inContext = contextPaths.has(path);
    if (inOwned) ownedFilesRead += 1;
    if (inContext) contextFilesRead += 1;
    if (inOwned || inContext) uniqueAllowedReadResources += 1;
  }
  return { uniqueAllowedReadResources, ownedFilesRead, contextFilesRead };
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function digest(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}

export function readScopeAssurance(engagementDir: string): unknown {
  return JSON.parse(readFileSync(join(engagementDir, SCOPE_ASSURANCE_FILE_NAME), 'utf8'));
}
