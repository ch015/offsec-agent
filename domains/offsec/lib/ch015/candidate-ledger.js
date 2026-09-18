'use strict';

const FINAL_STATUSES = new Set([
  'CANDIDATE',
  'CONFIRMED',
  'DOWNGRADED',
  'FOLDED_INTO',
  'BACKLOG',
  'EXCLUDED',
  'PENDING_PENTEST',
  'PENDING_EXTERNAL',
  'FALSE_POSITIVE',
  'OUT_OF_SCOPE',
  'DISPUTED',
  'UNCLASSIFIED',
]);

const SCORE_INCLUDED_STATUSES = new Set(['CONFIRMED', 'DOWNGRADED']);
const PENDING_STATUSES = new Set(['PENDING_PENTEST', 'PENDING_EXTERNAL', 'DISPUTED']);
const EXCLUDED_STATUSES = new Set(['EXCLUDED', 'FALSE_POSITIVE', 'OUT_OF_SCOPE']);

const SEVERITY_KEYS = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info',
  STRUCTURAL_WEAKNESS: 'structural_weakness',
};

function normalizeToken(value) {
  return String(value || '')
    .trim()
    .toUpperCase()
    .replace(/[\s-]+/g, '_');
}

function normalizeStatus(status) {
  const normalized = normalizeToken(status);
  return normalized || 'UNCLASSIFIED';
}

function normalizeSeverity(severity) {
  const normalized = normalizeToken(severity);
  if (normalized === 'STRUCTURAL' || normalized === 'STRUCTURAL_WEAKNESS') {
    return 'STRUCTURAL_WEAKNESS';
  }
  if (Object.prototype.hasOwnProperty.call(SEVERITY_KEYS, normalized)) {
    return normalized;
  }
  return 'INFO';
}

function getCandidateId(candidate) {
  return String(
    candidate?.candidate_id ||
    candidate?.candidateId ||
    candidate?.finding_id ||
    candidate?.id ||
    'UNKNOWN'
  );
}

function getPathValue(object, path) {
  if (!object || typeof object !== 'object') return undefined;
  return path.split('.').reduce((current, key) => {
    if (current == null || typeof current !== 'object') return undefined;
    return current[key];
  }, object);
}

function hasContent(value) {
  if (value == null) return false;
  if (typeof value === 'string') return value.trim().length > 0;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === 'object') return Object.keys(value).length > 0;
  return true;
}

function hasAnyField(candidate, paths) {
  return paths.some((fieldPath) => hasContent(getPathValue(candidate, fieldPath)));
}

function getCandidates(input) {
  if (Array.isArray(input)) return input;
  if (!input || typeof input !== 'object') return [];

  const candidateKeys = [
    'candidates',
    'raw_candidates',
    'candidate_classifications',
    'classifications',
    'final_classification',
    'findings',
  ];

  for (const key of candidateKeys) {
    if (Array.isArray(input[key])) return input[key];
  }

  return [];
}

function getFinalStatus(candidate) {
  return normalizeStatus(
    candidate?.final_status ||
    candidate?.status ||
    candidate?.final_mapping?.status
  );
}

function getFinalSeverity(candidate) {
  return normalizeSeverity(
    candidate?.final_severity ||
    candidate?.severity_current ||
    candidate?.severity ||
    candidate?.va_severity
  );
}

function hasEvidence(candidate) {
  return hasAnyField(candidate, [
    'evidence.locations',
    'evidence.file_lines',
    'evidence.data_flow',
    'evidence.live_evidence',
    'evidence.repro_steps',
    'evidence_ref',
    'evidence_refs',
    'file',
    'location',
    'locations',
  ]);
}

function hasPentestRoute(candidate) {
  return hasAnyField(candidate, [
    'routing.pentest_route',
    'pentest_route',
    'verification.pentest_route',
  ]);
}

function hasPentestScenario(candidate) {
  return hasAnyField(candidate, [
    'routing.scenario_id',
    'routing.required_scenario',
    'routing.pentest_plan_id',
    'pentest_scenario',
    'scenario_id',
    'test_objective',
  ]);
}

// 후보가 pentest plan 시나리오를 가리키는 참조 ID 목록 (routing.pentest_plan_id 등).
function getPentestScenarioRefs(candidate) {
  return [
    getPathValue(candidate, 'routing.pentest_plan_id'),
    getPathValue(candidate, 'routing.scenario_id'),
    getPathValue(candidate, 'routing.required_scenario'),
    candidate?.scenario_id,
  ]
    .filter((ref) => ref != null && String(ref).trim())
    .map((ref) => String(ref).trim());
}

function hasExternalContext(candidate) {
  return hasAnyField(candidate, [
    'required_access',
    'external_system',
    'routing.required_access',
    'routing.external_system',
    'final_mapping.required_access',
    'final_mapping.external_system',
  ]);
}

function isScoreIncludedCandidate(candidate) {
  const status = getFinalStatus(candidate);
  if (!SCORE_INCLUDED_STATUSES.has(status)) return false;
  if (getFinalSeverity(candidate) === 'STRUCTURAL_WEAKNESS') return false;
  return candidate?.score_included !== false;
}

const VALIDITY_FIELDS = ['reachable', 'business_relevance', 'exploit_path'];

/**
 * Self-Verify validity 검사 (fail-soft).
 * CONFIRMED 후보의 validity.reachable / business_relevance / exploit_path를 점검한다.
 *   - CRITICAL/HIGH: 셋 다 부재 → error (Self-Verify 미수행으로 간주), 일부만 부재 → warning
 *   - MEDIUM 이하(SW 포함): 부재는 warning만 — 명백 결함만 차단하고 나머지는 보고만 한다.
 * @returns {{ errors: Array, warnings: Array }}
 */
function appraiseValidity(candidate) {
  const issues = { errors: [], warnings: [] };
  if (getFinalStatus(candidate) !== 'CONFIRMED') return issues;

  const missing = VALIDITY_FIELDS.filter(
    (field) => !hasContent(getPathValue(candidate, `validity.${field}`))
  );
  if (missing.length === 0) return issues;

  const severity = getFinalSeverity(candidate);
  const highStakes = severity === 'CRITICAL' || severity === 'HIGH';
  const allMissing = missing.length === VALIDITY_FIELDS.length;
  const entry = {
    candidate_id: getCandidateId(candidate),
    code: allMissing ? 'CONFIRMED_VALIDITY_MISSING' : 'CONFIRMED_VALIDITY_PARTIAL',
    message: `Confirmed ${severity} candidate is missing Self-Verify validity field(s): ${missing.join(', ')}.`,
  };

  if (highStakes && allMissing) {
    issues.errors.push(entry);
  } else {
    issues.warnings.push(entry);
  }
  return issues;
}

function validateCandidate(candidate) {
  const errors = [];
  const candidateId = getCandidateId(candidate);
  const status = getFinalStatus(candidate);

  function add(code, message) {
    errors.push({ candidate_id: candidateId, code, message });
  }

  if (!FINAL_STATUSES.has(status)) {
    add('INVALID_STATUS', `Unknown final status: ${status}`);
  }

  if (status === 'UNCLASSIFIED' || status === 'CANDIDATE') {
    add('CANDIDATE_UNCLASSIFIED', 'Candidate must be assigned a final status before report publication.');
  }

  if (SCORE_INCLUDED_STATUSES.has(status) && !hasEvidence(candidate)) {
    add('MISSING_EVIDENCE', 'Confirmed or downgraded candidate requires file-line, data-flow, or live evidence.');
  }

  if (status === 'DOWNGRADED' && !hasAnyField(candidate, [
    'downgrade_reason',
    'final_mapping.downgrade_reason',
    'final_mapping.severity_rationale',
  ])) {
    add('DOWNGRADE_REASON_MISSING', 'Downgraded candidate requires downgrade_reason or severity_rationale.');
  }

  if (status === 'BACKLOG' && !hasAnyField(candidate, [
    'backlog_reason',
    'next_step',
    'final_mapping.backlog_reason',
    'final_mapping.rationale',
    'final_mapping.next_step',
  ])) {
    add('BACKLOG_REASON_MISSING', 'Backlog candidate requires backlog_reason, rationale, or next_step.');
  }

  if (status === 'EXCLUDED' && !hasAnyField(candidate, [
    'exclusion_reason',
    'excluded_category',
    'final_mapping.exclusion_reason',
    'final_mapping.rationale',
    'reason',
  ])) {
    add('EXCLUSION_REASON_MISSING', 'Excluded candidate requires exclusion_reason, excluded_category, reason, or rationale.');
  }

  if (status === 'PENDING_EXTERNAL' && !hasExternalContext(candidate)) {
    add('PENDING_EXTERNAL_CONTEXT_MISSING', 'Pending external candidate requires required_access or external_system context.');
  }

  if (status === 'PENDING_PENTEST' && !hasPentestRoute(candidate)) {
    add('PENDING_PENTEST_ROUTE_MISSING', 'Pending pentest candidate requires a pentest_route.');
  }

  if (status === 'FOLDED_INTO' && !hasAnyField(candidate, ['folded_into', 'final_mapping.folded_into'])) {
    add('FOLDED_TARGET_MISSING', 'Folded candidate requires folded_into reference.');
  }

  if (status === 'FALSE_POSITIVE' && !hasAnyField(candidate, [
    'counter_evidence',
    'exclusion_reason',
    'final_mapping.counter_evidence',
    'final_mapping.exclusion_reason',
  ])) {
    add('FALSE_POSITIVE_COUNTER_EVIDENCE_MISSING', 'False positive classification requires counter-evidence or exclusion_reason.');
  }

  if (status === 'OUT_OF_SCOPE' && !hasAnyField(candidate, [
    'scope_reason',
    'exclusion_reason',
    'final_mapping.scope_reason',
    'final_mapping.exclusion_reason',
  ])) {
    add('OUT_OF_SCOPE_REASON_MISSING', 'Out-of-scope classification requires scope_reason or exclusion_reason.');
  }

  if (status === 'DISPUTED' && !hasAnyField(candidate, [
    'dispute_reason',
    'decision_needed',
    'final_mapping.dispute_reason',
    'final_mapping.decision_needed',
  ])) {
    add('DISPUTE_REASON_MISSING', 'Disputed classification requires dispute_reason or decision_needed.');
  }

  errors.push(...appraiseValidity(candidate).errors);

  return errors;
}

function emptySeverityCounts() {
  return {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    structural_weakness: 0,
  };
}

function summarizeCandidates(input) {
  const candidates = getCandidates(input);
  const byStatus = {};
  const bySeverity = emptySeverityCounts();
  const scoreIncludedCounts = emptySeverityCounts();

  for (const candidate of candidates) {
    const status = getFinalStatus(candidate);
    const severity = getFinalSeverity(candidate);
    const severityKey = SEVERITY_KEYS[severity] || 'info';

    byStatus[status] = (byStatus[status] || 0) + 1;
    bySeverity[severityKey] += 1;

    if (isScoreIncludedCandidate(candidate)) {
      scoreIncludedCounts[severityKey] += 1;
    }
  }

  const unclassified = (byStatus.UNCLASSIFIED || 0) + (byStatus.CANDIDATE || 0);
  const pending = Array.from(PENDING_STATUSES).reduce((sum, status) => sum + (byStatus[status] || 0), 0);
  const excluded = Array.from(EXCLUDED_STATUSES).reduce((sum, status) => sum + (byStatus[status] || 0), 0);

  return {
    total: candidates.length,
    by_status: byStatus,
    by_severity: bySeverity,
    score_included_counts: scoreIncludedCounts,
    unclassified,
    pending,
    backlog: byStatus.BACKLOG || 0,
    excluded,
    publish_allowed: unclassified === 0,
  };
}

function validateLedger(input) {
  const candidates = getCandidates(input);
  const errors = [];
  const warnings = [];

  for (const candidate of candidates) {
    errors.push(...validateCandidate(candidate));
    warnings.push(...appraiseValidity(candidate).warnings);
  }

  const summary = summarizeCandidates(candidates);
  return {
    valid: errors.length === 0,
    errors,
    warnings,
    summary,
  };
}

const SEVERITY_WEIGHT = { CRITICAL: 25, HIGH: 10, MEDIUM: 3, LOW: 1, INFO: 0, STRUCTURAL_WEAKNESS: 0 };

function getRootCauseLocation(candidate) {
  return String(
    candidate?.root_cause_location ||
    getPathValue(candidate, 'evidence.locations.0') ||
    candidate?.location ||
    ''
  ).trim();
}

function getRemediationKey(candidate) {
  return String(candidate?.remediation_key || '').trim();
}

function normalizeAffectedInstance(value) {
  if (value == null) return [];
  if (Array.isArray(value)) return value.flatMap(normalizeAffectedInstance);
  if (typeof value === 'string') return value.trim() ? [value.trim()] : [];
  if (typeof value === 'object') {
    const clone = {};
    for (const [key, val] of Object.entries(value)) {
      if (val != null && String(val).trim()) clone[key] = val;
    }
    return Object.keys(clone).length ? [clone] : [];
  }
  return [String(value)];
}

function getAffectedInstances(candidate) {
  return [
    ...normalizeAffectedInstance(candidate?.affected_instance),
    ...normalizeAffectedInstance(candidate?.affected_instances),
    ...normalizeAffectedInstance(getPathValue(candidate, 'final_mapping.affected_instances')),
  ];
}

function mergeAffectedInstances(candidates) {
  const seen = new Set();
  const merged = [];
  for (const candidate of candidates) {
    for (const instance of getAffectedInstances(candidate)) {
      const key = typeof instance === 'string' ? instance : JSON.stringify(instance);
      if (seen.has(key)) continue;
      seen.add(key);
      merged.push(instance);
    }
  }
  return merged;
}

function groupByRootCause(candidates) {
  const groups = new Map();
  for (const c of candidates) {
    const rcl = getRootCauseLocation(c);
    const rk = getRemediationKey(c);
    const key = rk || rcl || getCandidateId(c);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(c);
  }
  return groups;
}

// 그룹 내 대표 후보 선정: severity 최고 → 동률 시 evidence 보유 우선.
// deduplicateByRootCause(자동 fold)와 suggestEquivalenceClusters(LLM 제안)가 공유한다.
function selectRepresentative(group) {
  return group.reduce((best, c) => {
    const bw = SEVERITY_WEIGHT[getFinalSeverity(best)] || 0;
    const cw = SEVERITY_WEIGHT[getFinalSeverity(c)] || 0;
    if (cw > bw) return c;
    if (cw === bw && hasEvidence(c) && !hasEvidence(best)) return c;
    return best;
  });
}

function deduplicateByRootCause(input) {
  const candidates = getCandidates(input);
  const groups = groupByRootCause(candidates);
  const result = [];

  for (const [, group] of groups) {
    if (group.length === 1) {
      result.push(group[0]);
      continue;
    }
    const primary = selectRepresentative(group);
    const primaryId = getCandidateId(primary);
    const affectedInstances = mergeAffectedInstances(group);
    for (const c of group) {
      if (getCandidateId(c) === primaryId) {
        result.push({
          ...c,
          affected_instances: affectedInstances.length ? affectedInstances : c.affected_instances,
          final_mapping: {
            ...(c.final_mapping || {}),
            ...(affectedInstances.length ? { affected_instances: affectedInstances } : {}),
          },
        });
      } else {
        result.push({
          ...c,
          final_status: 'FOLDED_INTO',
          score_included: false,
          final_mapping: {
            ...(c.final_mapping || {}),
            folded_into: primaryId,
            exclusion_reason: `Same root cause or remediation as ${primaryId}: ${getRootCauseLocation(c) || getRemediationKey(c)}`,
          },
        });
      }
    }
  }
  return result;
}

// 후보의 root-cause 그룹 키(groupByRootCause와 동일 규칙). tier2에서 "같은 대상이지만
// root_cause 문자열은 다른가"를 판정하는 데 쓴다.
function candidateRootCauseKey(candidate) {
  return getRemediationKey(candidate) || getRootCauseLocation(candidate) || getCandidateId(candidate);
}

function normalizeTargetToken(value) {
  return String(value || '').trim().toLowerCase().replace(/\s+/g, ' ');
}

// tier2가 클러스터링에 쓰는 영향 대상 type — 구체적 공격 표면만. file/config는 입자가 너무
// 거칠어(같은 파일에 별개 취약점 다수) 같은 취약점 신호로 부적합 → 제외해 과제안을 줄인다.
const SPECIFIC_INSTANCE_TYPES = new Set(['route', 'function', 'endpoint', 'asset', 'flow']);
const COARSE_INSTANCE_TYPES = new Set(['file', 'config']);

// 후보가 영향을 주는 구체적 대상(route/function/endpoint/asset/flow)의 정규화 토큰 집합.
// differing-string 중복 탐지의 핵심 신호 — 같은 엔드포인트를 다른 file:line으로 보고한 경우.
function getInstanceTargets(candidate) {
  const targets = new Set();
  for (const inst of getAffectedInstances(candidate)) {
    if (typeof inst === 'string') {
      const t = normalizeTargetToken(inst);
      if (t) targets.add(t);
      continue;
    }
    // type이 명시된 거친 입자(file/config)는 스킵.
    const type = normalizeTargetToken(inst.type);
    if (type && COARSE_INSTANCE_TYPES.has(type)) continue;
    if (type && !SPECIFIC_INSTANCE_TYPES.has(type)) continue; // 알 수 없는 type도 보수적으로 스킵
    for (const field of ['target', 'route', 'endpoint', 'function', 'path', 'asset', 'flow']) {
      if (inst[field]) {
        const t = normalizeTargetToken(inst[field]);
        if (t) targets.add(t);
      }
    }
  }
  return targets;
}

function buildClusterRecord(group, key, basis, confidence) {
  const repId = getCandidateId(selectRepresentative(group));
  const ids = group.map(getCandidateId);
  return {
    cluster_key: key,
    basis,
    confidence, // 'high' = 동일 root/remediation 문자열 / 'review' = 의미적 표면 중복(같은 대상)
    candidate_ids: ids,
    suggested_representative: repId,
    suggested_folded: ids.filter((id) => id !== repId),
    score_included_ids: group.filter(isScoreIncludedCandidate).map(getCandidateId),
    merged_affected_instances: mergeAffectedInstances(group),
  };
}

function isSuperset(big, small) {
  for (const v of small) if (!big.has(v)) return false;
  return true;
}

// GAP-1 recall 보강: raw ledger 전체 후보를 2계층으로 기계 클러스터링해 "같은 취약점일 수
// 있는" 후보 그룹을 제안한다. ★ 제안 전용 — final_status를 절대 변경하지 않는다. MERGE/SPLIT/
// KEEP 최종 판정은 수렴 LLM이 folding_rules로 수행한다(offsec-lead.md:763 자동판정 금지 준수).
//   tier1(high)  — 동일 remediation_key/root_cause_location 문자열 공유(높은 정밀도).
//   tier2(review)— 같은 영향 대상(route/function/asset/flow)을 공유하나 root_cause 문자열은
//                  서로 다른 후보. cross-agent가 같은 결함을 다른 file:line으로 보고한
//                  differing-string 중복(GAP-1의 핵심)을 표면화한다.
// ⚠️ tier2는 같은 대상에 별개 취약점이 공존할 수 있어 게이트 차단 근거로 쓰지 않는다(제안만).
function suggestEquivalenceClusters(input) {
  const candidates = getCandidates(input);
  const clusters = [];

  // tier1
  const tier1MemberSets = [];
  for (const [key, group] of groupByRootCause(candidates)) {
    if (group.length < 2) continue;
    tier1MemberSets.push(new Set(group.map(getCandidateId)));
    const basis = getRemediationKey(selectRepresentative(group))
      ? 'shared remediation_key'
      : 'shared root_cause_location';
    clusters.push(buildClusterRecord(group, key, basis, 'high'));
  }

  // tier2
  const byTarget = new Map();
  for (const c of candidates) {
    for (const t of getInstanceTargets(c)) {
      if (!byTarget.has(t)) byTarget.set(t, []);
      byTarget.get(t).push(c);
    }
  }
  for (const [target, group] of byTarget) {
    if (group.length < 2) continue;
    // root_cause 키가 모두 같으면 tier1이 이미 잡음 → 스킵(중복 제안 방지).
    if (new Set(group.map(candidateRootCauseKey)).size < 2) continue;
    // tier1 클러스터에 완전 포함되면 스킵.
    const idSet = new Set(group.map(getCandidateId));
    if (tier1MemberSets.some((s) => isSuperset(s, idSet))) continue;
    clusters.push(buildClusterRecord(group, `target:${target}`, 'shared affected-instance target', 'review'));
  }

  return {
    schema_version: 1,
    generated_by: 'candidate-ledger.suggestEquivalenceClusters',
    note:
      'SUGGESTIONS ONLY. tier1(confidence:high)=shared root_cause/remediation string; ' +
      'tier2(confidence:review)=shared affected target but differing root-cause string ' +
      '(catches cross-agent same-vuln-different-line). Convergence LLM must judge each ' +
      'cluster MERGE/SPLIT/KEEP per folding_rules; final_status is NOT modified here. ' +
      'tier2 is advisory only and never a gate-blocking basis. Duplicates with neither a ' +
      'shared string nor a shared target still require LLM contextual search.',
    cluster_count: clusters.length,
    clusters,
  };
}

function scenarioCandidateIds(scenarios) {
  const ids = new Set();
  for (const scenario of Array.isArray(scenarios) ? scenarios : []) {
    const refs = []
      .concat(scenario?.candidate_id || [])
      .concat(scenario?.candidate_ref || [])
      .concat(scenario?.candidate_refs || [])
      .concat(scenario?.candidate_ids || []);
    for (const ref of refs) {
      if (ref != null && String(ref).trim()) ids.add(String(ref));
    }
  }
  return ids;
}

// plan 파일의 시나리오 자체 ID 집합 (scenario_id/id) — 후보의
// routing.pentest_plan_id ↔ plan 시나리오 연결 매칭에 사용한다.
function scenarioSelfIds(scenarios) {
  const ids = new Set();
  for (const scenario of Array.isArray(scenarios) ? scenarios : []) {
    for (const ref of [scenario?.scenario_id, scenario?.id]) {
      if (ref != null && String(ref).trim()) ids.add(String(ref).trim());
    }
  }
  return ids;
}

function calculatePentestRouteCoverage(input, scenarios = []) {
  const candidates = getCandidates(input);
  const scenarioIds = scenarioCandidateIds(scenarios);
  const planScenarioIds = scenarioSelfIds(scenarios);
  const requiringPentest = candidates.filter((candidate) => {
    return getFinalStatus(candidate) === 'PENDING_PENTEST' ||
      getPathValue(candidate, 'routing.pentest_required') === true;
  });

  const missing = [];
  for (const candidate of requiringPentest) {
    const candidateId = getCandidateId(candidate);
    const coveredByScenario = hasPentestScenario(candidate) ||
      scenarioIds.has(candidateId) ||
      getPentestScenarioRefs(candidate).some((ref) => planScenarioIds.has(ref));
    if (!hasPentestRoute(candidate) || !coveredByScenario) {
      missing.push(candidateId);
    }
  }

  const total = requiringPentest.length;
  const routed = total - missing.length;
  return {
    total,
    routed,
    missing,
    coverage: total === 0 ? 1 : routed / total,
  };
}

module.exports = {
  FINAL_STATUSES,
  SCORE_INCLUDED_STATUSES,
  PENDING_STATUSES,
  EXCLUDED_STATUSES,
  SEVERITY_KEYS,
  SEVERITY_WEIGHT,
  normalizeStatus,
  normalizeSeverity,
  getCandidateId,
  getCandidates,
  getFinalStatus,
  getFinalSeverity,
  getRootCauseLocation,
  getRemediationKey,
  getAffectedInstances,
  mergeAffectedInstances,
  groupByRootCause,
  selectRepresentative,
  deduplicateByRootCause,
  suggestEquivalenceClusters,
  hasEvidence,
  hasPentestRoute,
  hasPentestScenario,
  getPentestScenarioRefs,
  hasExternalContext,
  isScoreIncludedCandidate,
  appraiseValidity,
  validateCandidate,
  validateLedger,
  summarizeCandidates,
  calculatePentestRouteCoverage,
};

// ---------------------------------------------------------------------------
// CLI 진입점 (오케스트레이터가 `node lib/ch015/candidate-ledger.js validate ...`).
// exit code 계약: 0=통과(경고 포함), 2=차단(errors), 1=사용오류.
// 기존 validateLedger를 그대로 호출만 한다.
// ---------------------------------------------------------------------------
function parseLedgerArgs(argv) {
  const opts = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--ledger') opts.ledger = argv[++i];
    else if (a === '--classification') opts.classification = argv[++i];
    else if (!a.startsWith('--') && !opts.command) opts.command = a;
  }
  return opts;
}

function runLedgerCli(argv) {
  const fs = require('fs');
  const yaml = require('js-yaml');
  const opts = parseLedgerArgs(argv);

  if (!['validate', 'cluster'].includes(opts.command) || !opts.ledger) {
    process.stderr.write(
      'USAGE: candidate-ledger.js <validate|cluster> --ledger <yaml> [--classification <yaml>]\n'
    );
    return 1;
  }

  let doc;
  try {
    doc = yaml.load(fs.readFileSync(opts.ledger, 'utf8'));
  } catch (e) {
    process.stderr.write(`USAGE_ERROR: cannot read/parse ${opts.ledger}: ${e.message}\n`);
    return 1;
  }

  // cluster: 기계적 중복 후보 클러스터를 stdout(JSON)으로 출력. 제안 전용 — 절대 차단하지 않음(항상 0).
  // 수렴 단계가 이 출력을 folding_rules 입력(MERGE 후보)으로 LLM에 주입한다.
  if (opts.command === 'cluster') {
    process.stdout.write(JSON.stringify(suggestEquivalenceClusters(doc)) + '\n');
    return 0;
  }

  const result = validateLedger(doc);

  if (result.errors.length > 0) {
    for (const err of result.errors) {
      process.stderr.write(`${err.code}: ${err.candidate_id} — ${err.message}\n`);
    }
    return 2;
  }

  if (result.warnings.length > 0) {
    for (const warn of result.warnings) {
      process.stderr.write(`WARN ${warn.code}: ${warn.candidate_id} — ${warn.message}\n`);
    }
  }

  process.stdout.write(JSON.stringify({ valid: true, summary: result.summary }) + '\n');
  return 0;
}

if (require.main === module) {
  process.exit(runLedgerCli(process.argv.slice(2)));
}
