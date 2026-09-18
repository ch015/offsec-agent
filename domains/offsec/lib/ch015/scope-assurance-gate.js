'use strict';

/**
 * 호스트 소유 work-unit scope assurance — 발행(publication) 시 검증하는 순수 JS 게이트.
 *
 * src/runtime/workflow/scope-assurance.ts(zod, TypeScript)가 assurance receipt의 생성/저장을
 * 담당하고, 이 모듈은 report-gate-hook.js(plain Node 훅 프로세스 — tsx 런타임 밖에서도 실행됨)에서
 * 같은 해시 스킴(정렬-키 stableJson + sha256)을 재구현해 구조/해시/식별자/완결 계정만 검증한다.
 * coverage-gate.js의 read-ratio류 임계값은 여기서 재사용하지 않는다(P0-C: 새 read-ratio gate 금지).
 *
 * host-bounded work-unit engagement 감지는 fanout_decision.flow가 아니라 sealed work plan/results
 * 산출물(00_work_plan.json + 00_work_unit_results.json) 존재 여부로 한다 — 두 산출물이 존재하는
 * engagement는 large-scale coverage_units.yaml 게이트(레거시 대규모 fanout)와 무관하게 독립 검증된다.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// src/runtime/workflow/scope-assurance.ts와 값이 반드시 동일해야 하는 리터럴들. plain CommonJS 훅
// 프로세스에서는 그 TS 모듈을 require할 수 없어 그대로 복제한다(docs/018에 이미 문서화된 패턴).
const SCOPE_ASSURANCE_FILE_NAME = '00_scope_assurance.json';
const SCOPE_ASSURANCE_SCHEMA_VERSION = '1.0.0';
const SCOPE_ASSURANCE_DISCLOSURE =
  'Read/allowed-resource counts are a minimum-examination signal only. ' +
  'They do not prove semantic security analysis was performed for any file.';
// `00_work_unit_results.json`의 schemaVersion. 진짜 레거시(P0-C 이전, assurance 개념 자체가 없던
// 산출물)만 이 리터럴을 갖는다 — legacy 판정은 필드 부재가 아니라 이 값으로만 한다(P0 correction §2:
// assurancePath/assuranceSha256을 지운다고 신규 결과가 legacy로 강등되지 않는다).
const WORK_UNIT_RESULTS_LEGACY_SCHEMA_VERSION = '1.0.0';
const WORK_UNIT_RESULTS_ACCEPTED_SCHEMA_VERSIONS = new Set(['1.0.0', '1.1.0']);

function isNonNegativeInt(value) {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0;
}

function isPositiveInt(value) {
  return typeof value === 'number' && Number.isInteger(value) && value > 0;
}

function hasDuplicates(list) {
  return new Set(list).size !== list.length;
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function readJson(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

// fanout_decision.flow와 무관하게, sealed work plan/results 산출물 존재만으로 판단한다.
function isHostWorkUnitEngagement(engagementDir) {
  return (
    fs.existsSync(path.join(engagementDir, '00_work_plan.json')) &&
    fs.existsSync(path.join(engagementDir, '00_work_unit_results.json'))
  );
}

function sortedJson(list) {
  return JSON.stringify((list || []).slice().sort());
}

/**
 * 반환 { ok, legacy, violations }.
 *   legacy=true  : results가 v1(assurance 미선언) — 하위 호환으로 통과.
 *   ok=false     : 구조/해시/식별자/완결 계정 위반 하나 이상.
 */
function evaluateScopeAssurance(engagementDir) {
  const plan = readJson(path.join(engagementDir, '00_work_plan.json'));
  const results = readJson(path.join(engagementDir, '00_work_unit_results.json'));
  if (!plan || !Array.isArray(plan.units)) {
    return { ok: false, violations: [{ code: 'WORK_PLAN_MISSING', message: '00_work_plan.json을 읽을 수 없습니다.' }] };
  }
  const { workPlanSha256: storedPlanHash, generatedAt: _planGeneratedAt, ...planCore } = plan;
  if (typeof storedPlanHash !== 'string' || sha256(stableJson(planCore)) !== storedPlanHash) {
    return {
      ok: false,
      violations: [{
        code: 'WORK_PLAN_HASH_MISMATCH',
        message: 'sealed work plan의 workPlanSha256이 재계산 값과 다릅니다(변조 의심).',
      }],
    };
  }
  if (!results) {
    return { ok: false, violations: [{ code: 'WORK_UNIT_RESULTS_MISSING', message: '00_work_unit_results.json을 읽을 수 없습니다.' }] };
  }
  if (!results.schemaVersion || !WORK_UNIT_RESULTS_ACCEPTED_SCHEMA_VERSIONS.has(results.schemaVersion)) {
    return {
      ok: false,
      violations: [{
        code: 'WORK_UNIT_RESULTS_SCHEMA_VERSION_INVALID',
        message: `work unit results schemaVersion이 허용 목록(1.0.0, 1.1.0)에 없습니다: ${results.schemaVersion ?? '(missing)'}`,
      }],
    };
  }

  const isTrueLegacyResults = results.schemaVersion === WORK_UNIT_RESULTS_LEGACY_SCHEMA_VERSION;
  const hasAssuranceReference = results.assurancePath !== undefined || results.assuranceSha256 !== undefined;
  if (isTrueLegacyResults && !hasAssuranceReference) {
    return { ok: true, legacy: true, violations: [] };
  }
  const violations = [];
  if (!hasAssuranceReference) {
    // 신규 schema(진짜 legacy 1.0.0이 아님) 결과에 assurance 참조 자체가 없다 — 참조를 지워
    // legacy로 강등시키려는 시도(또는 손상)를 fail closed로 거부한다.
    return {
      ok: false,
      violations: [{
        code: 'SCOPE_ASSURANCE_REFERENCE_MISSING',
        message: '신규 schema의 work unit results에 scope assurance 참조(assurancePath/assuranceSha256)가 없습니다.',
      }],
    };
  }
  if (!results.assurancePath || !results.assuranceSha256) {
    return {
      ok: false,
      violations: [{ code: 'SCOPE_ASSURANCE_REFERENCE_INCOMPLETE', message: 'assurancePath/assuranceSha256 중 하나만 선언되어 있습니다.' }],
    };
  }
  if (results.assurancePath !== SCOPE_ASSURANCE_FILE_NAME) {
    // 정확히 고정 파일명과 일치해야 한다 — 문자열 비교 자체로 상대/절대 경로 traversal을 차단한다
    // (engagement 디렉터리 밖 경로를 resolve하지 않는다).
    return {
      ok: false,
      violations: [{
        code: 'SCOPE_ASSURANCE_PATH_INVALID',
        message: `assurancePath는 반드시 ${SCOPE_ASSURANCE_FILE_NAME}이어야 합니다: ${results.assurancePath}`,
      }],
    };
  }
  if (hasDuplicates(Array.isArray(results.completedUnitKeys) ? results.completedUnitKeys : [])) {
    violations.push({
      code: 'SCOPE_ASSURANCE_RESULT_DUPLICATE_UNIT_KEY',
      message: 'work unit results의 completedUnitKeys에 중복 항목이 있습니다.',
    });
  }
  const resultsUnits = Array.isArray(results.units) ? results.units : [];
  if (resultsUnits.length > plan.units.length) {
    violations.push({
      code: 'SCOPE_ASSURANCE_RESULT_UNIT_COUNT_MISMATCH',
      message: `work unit results의 unit 레코드 수(${resultsUnits.length})가 sealed work plan(${plan.units.length})보다 큽니다.`,
    });
  }
  if (hasDuplicates(resultsUnits.map((u) => u.unitKey).filter(Boolean))) {
    violations.push({
      code: 'SCOPE_ASSURANCE_RESULT_DUPLICATE_UNIT_RECORD',
      message: 'work unit results의 units에 동일한 unitKey를 가진 중복 레코드가 있습니다.',
    });
  }
  const planUnitMap = new Map(plan.units.map((u) => [u.unitKey, u]));
  for (const resultUnit of resultsUnits) {
    const planUnit = planUnitMap.get(resultUnit.unitKey);
    if (!planUnit) {
      violations.push({
        code: 'SCOPE_ASSURANCE_RESULT_UNKNOWN_UNIT',
        message: `work unit results에 sealed work plan에 없는 unit이 있습니다: ${resultUnit.unitKey ?? '(none)'}`,
      });
    } else if (resultUnit.sourceUnitId !== undefined && resultUnit.sourceUnitId !== planUnit.sourceUnitId) {
      violations.push({
        code: 'SCOPE_ASSURANCE_RESULT_SOURCE_UNIT_ID_MISMATCH',
        message: `work unit results의 unit ${resultUnit.unitKey} sourceUnitId가 sealed work plan과 다릅니다.`,
      });
    }
  }
  if (results.workPlanSha256 !== undefined && results.workPlanSha256 !== storedPlanHash) {
    violations.push({
      code: 'SCOPE_ASSURANCE_RESULTS_WORK_PLAN_DIRECT_MISMATCH',
      message: 'work unit results의 workPlanSha256이 sealed work plan의 workPlanSha256과 다릅니다.',
    });
  }
  const assurancePath = path.join(engagementDir, SCOPE_ASSURANCE_FILE_NAME);
  let raw;
  try {
    raw = fs.readFileSync(assurancePath);
  } catch {
    return {
      ok: false,
      violations: [...violations, { code: 'SCOPE_ASSURANCE_MISSING', message: `참조된 scope assurance 파일을 읽을 수 없습니다: ${results.assurancePath}` }],
    };
  }
  if (sha256(raw) !== results.assuranceSha256) {
    violations.push({
      code: 'SCOPE_ASSURANCE_HASH_MISMATCH',
      message: '00_work_unit_results.json이 참조하는 assuranceSha256과 실제 파일 해시가 다릅니다(변조 의심).',
    });
  }
  let assurance;
  try {
    assurance = JSON.parse(raw.toString('utf8'));
  } catch {
    return {
      ok: false,
      violations: [...violations, { code: 'SCOPE_ASSURANCE_INVALID_JSON', message: 'scope assurance 파일이 유효한 JSON이 아닙니다.' }],
    };
  }
  const { scopeAssuranceSha256, generatedAt, ...core } = assurance;
  if (typeof scopeAssuranceSha256 !== 'string' || sha256(stableJson(core)) !== scopeAssuranceSha256) {
    violations.push({ code: 'SCOPE_ASSURANCE_SELF_HASH_MISMATCH', message: 'scope assurance 문서의 자기 해시가 내용과 다릅니다(변조 의심).' });
  }
  void generatedAt;
  // TS zod schema(ScopeAssuranceSchema)가 강제하는 literal 값 — 자기해시로만 묶여 있으면 완전히
  // self-consistent하게 위조된 문서가 임의의 schemaVersion/disclosure를 주장해도 통과할 수 있다.
  if (assurance.schemaVersion !== SCOPE_ASSURANCE_SCHEMA_VERSION) {
    violations.push({
      code: 'SCOPE_ASSURANCE_SCHEMA_VERSION_INVALID',
      message: `scope assurance schemaVersion이 ${SCOPE_ASSURANCE_SCHEMA_VERSION}이 아닙니다: ${assurance.schemaVersion}`,
    });
  }
  if (assurance.disclosure !== SCOPE_ASSURANCE_DISCLOSURE) {
    violations.push({ code: 'SCOPE_ASSURANCE_DISCLOSURE_INVALID', message: 'scope assurance disclosure 문구가 고정 문구와 다릅니다.' });
  }
  if (assurance.analysisMode !== undefined && assurance.analysisMode !== 'v2') {
    violations.push({ code: 'SCOPE_ASSURANCE_ANALYSIS_MODE_INVALID', message: 'Unknown scope assurance analysis mode.' });
  }
  if (assurance.workPlanSha256 !== plan.workPlanSha256) {
    violations.push({ code: 'SCOPE_ASSURANCE_WORK_PLAN_MISMATCH', message: 'scope assurance의 workPlanSha256이 sealed work plan과 다릅니다.' });
  }
  if (results.workPlanSha256 !== undefined && assurance.workPlanSha256 !== results.workPlanSha256) {
    violations.push({ code: 'SCOPE_ASSURANCE_RESULTS_WORK_PLAN_MISMATCH', message: 'scope assurance의 workPlanSha256이 work unit results와 다릅니다.' });
  }
  if (typeof plan.sourceManifestSha256 !== 'string' || assurance.sourceManifestSha256 !== plan.sourceManifestSha256) {
    violations.push({ code: 'SCOPE_ASSURANCE_SOURCE_MANIFEST_MISMATCH', message: 'scope assurance의 sourceManifestSha256이 sealed work plan과 다릅니다.' });
  }
  const planUnitKeys = plan.units.map((unit) => unit.unitKey).filter((key) => typeof key === 'string');
  const resultUnitKeys = Array.isArray(results.completedUnitKeys) ? results.completedUnitKeys : null;
  const assuranceUnitKeys = Array.isArray(assurance.completedUnitKeys) ? assurance.completedUnitKeys : null;
  if (!resultUnitKeys || !resultUnitKeys.every((key) => planUnitKeys.includes(key))) {
    violations.push({ code: 'SCOPE_ASSURANCE_RESULT_UNIT_KEY_MISMATCH', message: 'work unit results의 completedUnitKeys에 sealed work plan에 없는 unit이 포함되어 있습니다.' });
  }
  if (!assuranceUnitKeys || hasDuplicates(assuranceUnitKeys) || !assuranceUnitKeys.every((key) => planUnitKeys.includes(key))) {
    violations.push({
      code: 'SCOPE_ASSURANCE_UNIT_KEY_MISMATCH',
      message: 'scope assurance의 completedUnitKeys가 sealed work plan 유닛과 정확히 일치하지 않습니다(중복 포함).',
    });
  }
  // P0 advisory: results.completedUnitKeys와 assurance.completedUnitKeys가 동일한지 교차검증
  if (resultUnitKeys && assuranceUnitKeys && sortedJson(resultUnitKeys) !== sortedJson(assuranceUnitKeys)) {
    violations.push({
      code: 'SCOPE_ASSURANCE_COMPLETED_KEYS_DIVERGENCE',
      message: 'work unit results의 completedUnitKeys와 scope assurance의 completedUnitKeys가 다릅니다.',
    });
  }
  if (!Array.isArray(assurance.units) || assurance.units.length > plan.units.length) {
    violations.push({ code: 'SCOPE_ASSURANCE_UNIT_COUNT_MISMATCH', message: 'scope assurance unit 레코드 수가 sealed work plan보다 큽니다.' });
  } else if (hasDuplicates(assurance.units.map((unit) => unit.unitKey))) {
    // 동일 unitKey 레코드를 중복시켜 실제로 빠진 unit을 가리는 대체(substitution) 공격 —
    // 배열 길이 일치만으로는 이 패턴을 잡지 못한다.
    violations.push({
      code: 'SCOPE_ASSURANCE_DUPLICATE_UNIT_RECORD',
      message: 'scope assurance units에 동일한 unitKey를 가진 중복 레코드가 있습니다.',
    });
  } else {
    const planByKey = new Map(plan.units.map((unit) => [unit.unitKey, unit]));
    for (const unit of assurance.units) {
      const planUnit = planByKey.get(unit.unitKey);
      if (!planUnit) {
        violations.push({ code: 'SCOPE_ASSURANCE_UNKNOWN_UNIT', unit: unit.unitKey, message: `scope assurance에 sealed work plan에 없는 unit이 있습니다: ${unit.unitKey}` });
        continue;
      }
      const ownedFileCount = Array.isArray(planUnit.ownedFiles) ? planUnit.ownedFiles.length : undefined;
      const contextFileCount = Array.isArray(planUnit.contextFiles) ? planUnit.contextFiles.length : undefined;
      const unresolvedEdges = Array.isArray(planUnit.unresolvedEdges) ? planUnit.unresolvedEdges : [];
      const unresolvedEdgeCount = unresolvedEdges.filter((edge) => edge && edge.reason === 'unresolved').length;
      const contextCappedEdgeCount = unresolvedEdges.filter((edge) => edge && edge.reason === 'context-cap').length;
      if (unit.ownedFileCount !== ownedFileCount || unit.contextFileCount !== contextFileCount) {
        violations.push({ code: 'SCOPE_ASSURANCE_UNIT_SCOPE_MISMATCH', unit: unit.unitKey, message: `unit ${unit.unitKey}의 owned/context file count가 sealed work plan과 다릅니다.` });
      }
      if (unit.sourceUnitId !== planUnit.sourceUnitId) {
        violations.push({ code: 'SCOPE_ASSURANCE_UNIT_SOURCE_ID_MISMATCH', unit: unit.unitKey, message: `unit ${unit.unitKey}의 sourceUnitId가 sealed work plan과 다릅니다.` });
      }
      if (unit.unresolvedEdgeCount !== unresolvedEdgeCount || unit.contextCappedEdgeCount !== contextCappedEdgeCount) {
        violations.push({
          code: 'SCOPE_ASSURANCE_UNIT_EDGE_COUNT_MISMATCH',
          unit: unit.unitKey,
          message: `unit ${unit.unitKey}의 unresolved/context-cap edge count가 sealed work plan과 다릅니다.`,
        });
      }
      // seal 시스템 제거 — autonomousVerifierSealed 검증 불필요
      // TS zod schema가 강제하는 구조 제약(ownedFileCount는 양의 정수, 나머지 count는 비음수 정수) —
      // 새 read-ratio/finding-density 임계값이 아니라 타입/범위 구조만 확인한다.
      if (
        !isPositiveInt(unit.ownedFileCount) ||
        !isNonNegativeInt(unit.contextFileCount) ||
        !isNonNegativeInt(unit.unresolvedEdgeCount) ||
        !isNonNegativeInt(unit.contextCappedEdgeCount)
      ) {
        violations.push({
          code: 'SCOPE_ASSURANCE_UNIT_COUNT_STRUCTURE_INVALID',
          unit: unit.unitKey,
          message: `unit ${unit.unitKey}의 count 필드가 구조적으로 유효하지 않습니다(양의 정수/비음수 정수 요구).`,
        });
      }
      for (const role of ['va', 'verifier']) {
        // v2 performs independent review at the root rather than per-unit verification.
        if (role === 'verifier' && assurance.analysisMode === 'v2' && unit.verifier === undefined) continue;
        const observation = unit[role];
        if (
          !observation ||
          !isNonNegativeInt(observation.uniqueAllowedReadResources) ||
          !isNonNegativeInt(observation.ownedFilesRead) ||
          !isNonNegativeInt(observation.contextFilesRead)
        ) {
          violations.push({
            code: 'SCOPE_ASSURANCE_UNIT_OBSERVATION_STRUCTURE_INVALID',
            unit: unit.unitKey,
            message: `unit ${unit.unitKey}의 ${role} observation 필드가 구조적으로 유효하지 않습니다.`,
          });
        }
      }
    }
  }
  return { ok: violations.length === 0, legacy: false, violations };
}

module.exports = {
  isHostWorkUnitEngagement,
  evaluateScopeAssurance,
};
