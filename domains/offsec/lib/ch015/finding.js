'use strict';

const { getSeverityWeight } = require('./scoring');

const VALID_SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);

let _findingCounter = 0;

/**
 * 발견 사항(Finding) ID 포맷
 * @param {number} num - 일련번호
 * @returns {string} "F-001" 형태
 */
function formatFindingId(num) {
  return `F-${String(num).padStart(3, '0')}`;
}

/**
 * 발견 사항 객체 생성
 * @param {Object} opts
 * @param {string} opts.title - 취약점 제목
 * @param {string} opts.severity - CRITICAL|HIGH|MEDIUM|LOW|INFO
 * @param {string} opts.category - 카테고리 (auth-bypass, data-manipulation 등)
 * @param {string} opts.dimension - 아키텍처 차원 (A1-A8, M9, M10, AS1-AS5)
 * @param {string} opts.rootCause - 근본 원인 (ARCHITECTURE, CONFIGURATION, CODE, PROCESS)
 * @param {string} opts.location - 파일:라인 위치
 * @param {string} opts.description - 상세 설명
 * @param {string} opts.cwe - CWE ID (필수, "CWE-NNN" 형식. 복수 시 쉼표 구분)
 * @param {string} opts.owaspTop10 - OWASP Top 10 항목 (필수, "A01"~"A10" 또는 "N/A")
 * @param {string} [opts.owaspApiTop10] - OWASP API Top 10 항목 (API 도메인 활성 시 필수)
 * @param {string} [opts.standards] - 추가 표준 매핑 ["NIST 800-53", "Secure Coding"]
 * @param {string} [opts.poc] - POC 코드/명령
 * @param {string} [opts.remediation] - 수정 가이드
 * @param {string} [opts.liveStatus] - CONFIRMED|BLOCKED|MITIGATED|INCONCLUSIVE|NOT_TESTED
 * @param {Object} [opts.impactAnalysis] - 6-step 영향도 분석
 * @param {Object} [opts.prerequisites] - 공격 전제 조건 분석
 * @param {string} [opts.prerequisites.direct] - 직접 전제 (예: "Route53 DNS 조작")
 * @param {string} [opts.prerequisites.category] - 전제 카테고리 (cloud_provider|supply_chain|internal_network|config_file|single_service|blockchain_rpc|user_action|none)
 * @param {string} [opts.prerequisites.scope_if_compromised] - 전제 침해 시 영향 범위
 * @param {boolean} [opts.prerequisites.defense_survives] - 전제 침해 시 이 방어선의 독립 유효성
 * @param {string} [opts.prerequisites.adjusted_feasibility] - 전제 반영 실전 Feasibility (H|M|L|T)
 * @param {string} [opts.prerequisites.rationale] - 판정 근거
 * @param {string} [opts.classification] - Confirmed_Vulnerability | Structural_Weakness
 * @param {string} [opts.originalSeverity] - Step 1.8 재분류 전 원래 심각도 (Structural_Weakness 시 보존)
 * @param {Object} [opts.impactProof] - { what, so_what, how, gate_result, failed_proofs }
 * @returns {Object} finding 객체
 */
function createFinding(opts) {
  // CWE 필수 검증 — 쉼표 구분 복수 허용, 각 토큰이 정확히 "CWE-NNN" 형식이어야 함 (끝 앵커 포함)
  const cweTokens = String(opts.cwe || '').split(',').map(s => s.trim()).filter(Boolean);
  if (cweTokens.length === 0 || !cweTokens.every(t => /^CWE-\d+$/.test(t))) {
    throw new Error(`Finding requires a valid CWE field (CWE-NNN format, comma-separated allowed). Received: "${opts.cwe || ''}"`);
  }
  // OWASP Top 10 필수 검증 — 모든 쉼표 구분 토큰이 A01~A10 또는 N/A 여야 함
  const owaspTokens = String(opts.owaspTop10 || '').split(',').map(s => s.trim()).filter(Boolean);
  if (owaspTokens.length === 0 || !owaspTokens.every(t => /^(A0[1-9]|A10|N\/A)$/.test(t))) {
    throw new Error(`Finding requires a valid owaspTop10 field (A01~A10 or N/A). Received: "${opts.owaspTop10 || ''}"`);
  }
  // Severity enum 검증 — 무검증 통과 시 점수/집계에서 조용히 누락되는 FN 경로 차단
  const severity = (opts.severity || 'INFO').toUpperCase();
  if (!VALID_SEVERITIES.has(severity)) {
    throw new Error(`Finding requires a valid severity (one of ${[...VALID_SEVERITIES].join(', ')}). Received: "${opts.severity}"`);
  }

  _findingCounter++;
  return {
    id: formatFindingId(_findingCounter),
    title: opts.title,
    severity,
    category: opts.category || 'uncategorized',
    dimension: opts.dimension || null,
    rootCause: opts.rootCause || null,
    location: opts.location || 'unknown',
    description: opts.description || '',
    cwe: opts.cwe,
    owaspTop10: opts.owaspTop10,
    owaspApiTop10: opts.owaspApiTop10 || null,
    standards: opts.standards || [],
    poc: opts.poc || null,
    remediation: opts.remediation || null,
    liveStatus: opts.liveStatus || null,
    impactAnalysis: opts.impactAnalysis || null,
    prerequisites: opts.prerequisites || null,
    classification: opts.classification || 'Confirmed_Vulnerability',
    originalSeverity: opts.originalSeverity || null,
    impactProof: opts.impactProof || null,
    evidences: opts.evidences || [],
    selfVerifyResult: opts.selfVerifyResult || null,
    timestamp: new Date().toISOString()
  };
}

/**
 * 심각도 기준 정렬 (CRITICAL → INFO)
 */
function sortFindings(findings) {
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  return [...findings].sort((a, b) => {
    const diff = (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
    if (diff !== 0) return diff;
    return a.id.localeCompare(b.id);
  });
}

/**
 * 카테고리별 그룹화
 */
function groupByCategory(findings) {
  const groups = {};
  for (const f of findings) {
    const cat = f.category || 'uncategorized';
    if (!groups[cat]) groups[cat] = [];
    groups[cat].push(f);
  }
  return groups;
}

/**
 * 심각도별 그룹화
 */
function groupBySeverity(findings) {
  const groups = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [], INFO: [] };
  for (const f of findings) {
    const sev = f.severity || 'INFO';
    if (!groups[sev]) groups[sev] = [];
    groups[sev].push(f);
  }
  return groups;
}

/**
 * Structural Weakness 판정 — classification 필드와 severity 문자열 중
 * 어느 쪽 신호가 와도 SW로 일관 판정한다 (scoring.js normalizeFindingSeverity와 동일 기준).
 */
function isStructuralWeakness(finding) {
  const classification = String(finding?.classification || '')
    .trim().toUpperCase().replace(/[\s-]+/g, '_');
  if (classification === 'STRUCTURAL_WEAKNESS') return true;
  const severity = String(finding?.severity || '')
    .trim().toUpperCase().replace(/[\s-]+/g, '_');
  return severity === 'STRUCTURAL_WEAKNESS' || severity === 'STRUCTURAL';
}

/**
 * 심각도별 카운트 집계
 */
function countBySeverity(findings) {
  // 서술적 severity 히스토그램. Structural_Weakness는 별도 버킷으로만 집계한다 —
  // nominal severity 버킷에 중복 증가시키면 SW가 severity 합계에 이중 노출된다.
  // (점수 산정은 scoring.countScoreIncludedFindings가 담당)
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, structural_weakness: 0 };
  for (const f of findings) {
    if (isStructuralWeakness(f)) {
      counts.structural_weakness++;
      continue;
    }
    // 필드 폴백: scoring.js와 동일한 필드 집합(severity/severity_current/final_severity)을
    // 인식한다 — YAML ledger 스키마(severity_current) finding이 히스토그램에서 누락되지 않게.
    const key = String(f.severity || f.severity_current || f.final_severity || 'INFO').toLowerCase();
    if (counts[key] !== undefined) counts[key]++;
  }
  return counts;
}

/**
 * 아키텍처 차원별 그룹화
 */
function groupByDimension(findings) {
  const groups = {};
  for (const f of findings) {
    const dim = f.dimension || 'unclassified';
    if (!groups[dim]) groups[dim] = [];
    groups[dim].push(f);
  }
  return groups;
}

/**
 * 근본 원인별 그룹화
 */
function groupByRootCause(findings) {
  const groups = { ARCHITECTURE: [], CONFIGURATION: [], CODE: [], PROCESS: [] };
  for (const f of findings) {
    const rc = f.rootCause || 'CODE';
    if (!groups[rc]) groups[rc] = [];
    groups[rc].push(f);
  }
  return groups;
}

/**
 * Finding 카운터 리셋 (테스트용)
 */
function resetCounter() {
  _findingCounter = 0;
}

module.exports = {
  formatFindingId,
  createFinding,
  sortFindings,
  groupByCategory,
  groupBySeverity,
  groupByDimension,
  groupByRootCause,
  countBySeverity,
  isStructuralWeakness,
  resetCounter
};
