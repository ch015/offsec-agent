'use strict';

const { getConfig } = require('../core/config');

// 하드코딩 fallback — 단일 소스는 config(scoring.securityScore.weights).
// config 로드 실패/키 부재 시에만 이 값이 쓰인다 (getSeverityWeights 참조).
// scoring.securityScore.formula 문자열은 표시용 — 실제 산식은 weights가 결정한다.
const SEVERITY_WEIGHTS = {
  CRITICAL: 25,
  HIGH: 10,
  MEDIUM: 3,
  LOW: 1,
  INFO: 0
};

/**
 * 심각도 가중치 테이블 — config(scoring.securityScore.weights, 소문자 키) 우선,
 * 하드코딩(SEVERITY_WEIGHTS)은 fallback. fail-soft: config 값이 숫자가 아니거나
 * 음수이거나 알 수 없는 severity 키면 해당 키만 fallback을 유지한다.
 */
function getSeverityWeights() {
  const merged = { ...SEVERITY_WEIGHTS };
  const configured = getConfig('scoring.securityScore.weights', null);
  if (configured && typeof configured === 'object' && !Array.isArray(configured)) {
    for (const [severity, weight] of Object.entries(configured)) {
      const key = String(severity).toUpperCase();
      const n = Number(weight);
      if (Object.prototype.hasOwnProperty.call(merged, key) && Number.isFinite(n) && n >= 0) {
        merged[key] = n;
      }
    }
  }
  return merged;
}

const SCORE_INCLUDED_STATUSES = new Set(['CONFIRMED', 'DOWNGRADED']);
const SCORE_EXCLUDED_STATUSES = new Set([
  'CANDIDATE',
  'BACKLOG',
  'EXCLUDED',
  'PENDING_PENTEST',
  'PENDING_EXTERNAL',
  'FOLDED_INTO',
  'FALSE_POSITIVE',
  'OUT_OF_SCOPE',
  'DISPUTED',
  'UNCLASSIFIED',
]);

function normalizeScoreToken(value) {
  return String(value || '')
    .trim()
    .toUpperCase()
    .replace(/[\s-]+/g, '_');
}

function emptyFindingCounts() {
  return {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    structural_weakness: 0,
  };
}

function normalizeFindingSeverity(finding) {
  // Structural Weakness 판정 신호 단일화: classification(SKILL 분류 필드)과
  // severity 문자열 중 어느 쪽이 와도 SW로 일관 판정한다 (finding.js countBySeverity와 동일 기준).
  const classification = normalizeScoreToken(finding?.classification);
  if (classification === 'STRUCTURAL_WEAKNESS') {
    return 'STRUCTURAL_WEAKNESS';
  }
  const severity = normalizeScoreToken(
    finding?.final_severity ||
    finding?.severity_current ||
    finding?.severity ||
    finding?.va_severity ||
    'INFO'
  );
  if (severity === 'STRUCTURAL' || severity === 'STRUCTURAL_WEAKNESS') {
    return 'STRUCTURAL_WEAKNESS';
  }
  return Object.prototype.hasOwnProperty.call(SEVERITY_WEIGHTS, severity) ? severity : 'INFO';
}

function shouldIncludeFindingInScore(finding) {
  const explicitStatus = finding?.final_status || finding?.status || finding?.final_mapping?.status;
  const status = explicitStatus ? normalizeScoreToken(explicitStatus) : 'CONFIRMED';

  if (SCORE_EXCLUDED_STATUSES.has(status)) return false;
  if (!SCORE_INCLUDED_STATUSES.has(status)) return false;
  return finding?.score_included !== false;
}

/**
 * 심각도별 가중치 반환
 */
function getSeverityWeight(severity) {
  return getSeverityWeights()[String(severity || '').toUpperCase()] || 0;
}

/**
 * 점수 합격 임계값 — config 단일 출처에서 로드.
 * scoring.securityScore.passThreshold(스펙 블록)를 우선하고, 레거시 ch015.securityScoreThreshold로 폴백한다.
 */
function getPassThreshold() {
  const spec = getConfig('scoring.securityScore.passThreshold', undefined);
  if (typeof spec === 'number') return spec;
  return getConfig('ch015.securityScoreThreshold', 85);
}

/**
 * 보안 점수 계산
 * Score = 100 - (CRITICAL × 25 + HIGH × 10 + MEDIUM × 3 + LOW × 1)
 * 
 * @param {Object} counts - { critical: N, high: N, medium: N, low: N, info: N }
 * @returns {number} 0-100 사이 보안 점수
 */
function calculateSecurityScore(counts) {
  const weights = getSeverityWeights();
  const deduction =
    (counts.critical || 0) * weights.CRITICAL +
    (counts.high || 0) * weights.HIGH +
    (counts.medium || 0) * weights.MEDIUM +
    (counts.low || 0) * weights.LOW;

  return Math.max(0, 100 - deduction);
}

/**
 * 최종 분류된 후보/취약점 목록에서 점수 산정 대상만 카운트한다.
 * CONFIRMED/DOWNGRADED만 점수에 반영하고, pending/backlog/folded/FP는 제외한다.
 * Structural Weakness는 별도 카운트하되 점수 차감에는 반영하지 않는다.
 */
function countScoreIncludedFindings(findings) {
  const counts = emptyFindingCounts();

  for (const finding of Array.isArray(findings) ? findings : []) {
    const explicitStatus = finding?.final_status || finding?.status || finding?.final_mapping?.status;
    const status = explicitStatus ? normalizeScoreToken(explicitStatus) : 'CONFIRMED';
    const severity = normalizeFindingSeverity(finding);

    if (severity === 'STRUCTURAL_WEAKNESS') {
      if (!SCORE_EXCLUDED_STATUSES.has(status)) counts.structural_weakness += 1;
      continue;
    }

    if (!shouldIncludeFindingInScore(finding)) continue;

    switch (severity) {
      case 'CRITICAL':
        counts.critical += 1;
        break;
      case 'HIGH':
        counts.high += 1;
        break;
      case 'MEDIUM':
        counts.medium += 1;
        break;
      case 'LOW':
        counts.low += 1;
        break;
      default:
        counts.info += 1;
        break;
    }
  }

  return counts;
}

function calculateScoreFromClassifiedFindings(findings) {
  return calculateSecurityScore(countScoreIncludedFindings(findings));
}

function validateScoreConsistency(countsOrFindings, reportedScore) {
  const counts = Array.isArray(countsOrFindings)
    ? countScoreIncludedFindings(countsOrFindings)
    : Object.assign(emptyFindingCounts(), countsOrFindings || {});
  const expected = calculateSecurityScore(counts);
  const reported = Number(reportedScore);

  return {
    valid: Number.isFinite(reported) && reported === expected,
    expected,
    reported,
    counts,
  };
}

/**
 * 점수 포맷 출력
 */
function formatScore(score, counts) {
  const threshold = getPassThreshold();
  const passed = isPassingScore(score, counts);
  const icon = passed ? '✅' : '❌';
  const swCount = counts.structural_weakness || 0;
  const swNote = swCount > 0
    ? `\n   STRUCTURAL_WEAKNESS: ${swCount} (Score에서 제외)`
    : '';

  return [
    `${icon} Security Score: ${score}/100 (기준: ${threshold})`,
    `   CRITICAL: ${counts.critical || 0} | HIGH: ${counts.high || 0} | MEDIUM: ${counts.medium || 0} | LOW: ${counts.low || 0} | INFO: ${counts.info || 0}${swNote}`,
    passed ? '   → PASS' : '   → FAIL — 즉시 조치 필요'
  ].join('\n');
}

/**
 * 합격 여부 판정 (복합 조건)
 * - Security Score ≥ threshold
 * - zeroToleranceSeverities(기본 ['critical']) 0건 필수
 * - HIGH ≤ maxHigh 건
 * - CVSS ≥ cvssGate 인 Finding 0건
 *
 * @param {number} score
 * @param {Object} counts - { critical, high, medium, low, info }
 * @param {Object} [options] - { maxCvss, zeroToleranceSeverities }
 */
function isPassingScore(score, counts, options = {}) {
  const threshold = getPassThreshold();
  const maxHigh = getConfig('scoring.securityScore.maxHighFindings', 2);
  const cvssGate = getConfig('scoring.securityScore.cvssGate', 9.0);
  const configuredZeroTolerance = getConfig('scoring.securityScore.zeroToleranceSeverities', ['critical']);
  const zeroTolerance = Array.isArray(options.zeroToleranceSeverities)
    ? options.zeroToleranceSeverities
    : (Array.isArray(configuredZeroTolerance) ? configuredZeroTolerance : ['critical']);

  for (const sev of zeroTolerance) {
    if ((counts[String(sev).toLowerCase()] || 0) > 0) return false;
  }
  if ((counts.high || 0) > maxHigh) return false;
  if (typeof options.maxCvss === 'number' && options.maxCvss >= cvssGate) return false;
  return score >= threshold;
}

/**
 * Precision = TP / (TP + FP)
 * @param {Array} labeledFindings - [{ label: 'TP'|'FP'|'Disputed' }]
 * @returns {number} 0-1
 */
function calculatePrecision(labeledFindings) {
  const tp = labeledFindings.filter(f => f.label === 'TP').length;
  const fp = labeledFindings.filter(f => f.label === 'FP').length;
  if (tp + fp === 0) return null;
  return tp / (tp + fp);
}

/**
 * Recall = TP / (TP + FN)
 * FN = golden findings not present in assessed findings
 * @param {Array} assessedIds - Finding IDs from assessment
 * @param {Array} goldenIds - Ground truth Finding IDs (all known TPs)
 * @returns {number} 0-1
 */
function calculateRecall(assessedIds, goldenIds) {
  const assessedSet = new Set(assessedIds);
  const tp = goldenIds.filter(id => assessedSet.has(id)).length;
  const fn = goldenIds.length - tp;
  if (tp + fn === 0) return null;
  return tp / (tp + fn);
}

/**
 * Severity accuracy = findings where va_severity === final_severity
 * @param {Array} labeledFindings - [{ va_severity, final_severity }]
 * @returns {{ accuracy: number, inaccurate: Array }}
 */
function calculateSeverityAccuracy(labeledFindings) {
  const withVaSeverity = labeledFindings.filter(f => f.va_severity != null);
  const accurate = withVaSeverity.filter(f => f.va_severity === f.final_severity);
  const inaccurate = withVaSeverity
    .filter(f => f.va_severity !== f.final_severity)
    .map(f => {
      const vaOrder = SEVERITY_ORDER[f.va_severity];
      const finalOrder = SEVERITY_ORDER[f.final_severity];
      let direction;
      if (typeof vaOrder !== 'number' || typeof finalOrder !== 'number') {
        direction = 'unknown';
      } else {
        // SEVERITY_ORDER: CRITICAL=0 … INFO=4 (낮을수록 심각). va가 더 심각하게 봤으면 overstatement
        direction = vaOrder < finalOrder ? 'overstatement' : 'understatement';
      }
      return {
        id: f.id,
        va_severity: f.va_severity,
        final_severity: f.final_severity,
        direction
      };
    });
  return {
    accuracy: withVaSeverity.length === 0 ? null : accurate.length / withVaSeverity.length,
    total: withVaSeverity.length,
    accurate_count: accurate.length,
    inaccurate_count: inaccurate.length,
    inaccurate
  };
}

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

/**
 * Full eval metrics from a labeled dataset
 * @param {Array} labeledFindings - labeled finding array from golden dataset
 * @returns {Object} comprehensive metrics
 */
function calculateEvalMetrics(labeledFindings) {
  const precision = calculatePrecision(labeledFindings);
  const severityResult = calculateSeverityAccuracy(labeledFindings);
  const tp = labeledFindings.filter(f => f.label === 'TP').length;
  const fp = labeledFindings.filter(f => f.label === 'FP').length;
  const disputed = labeledFindings.filter(f => f.label === 'Disputed').length;

  return {
    total: labeledFindings.length,
    tp,
    fp,
    disputed,
    precision,
    severity_accuracy: severityResult.accuracy,
    severity_detail: severityResult,
    overstatements: severityResult.inaccurate.filter(f => f.direction === 'overstatement').length,
    understatements: severityResult.inaccurate.filter(f => f.direction === 'understatement').length
  };
}

module.exports = {
  SEVERITY_WEIGHTS,
  SEVERITY_ORDER,
  getSeverityWeights,
  getSeverityWeight,
  calculateSecurityScore,
  countScoreIncludedFindings,
  calculateScoreFromClassifiedFindings,
  validateScoreConsistency,
  formatScore,
  isPassingScore,
  calculatePrecision,
  calculateRecall,
  calculateSeverityAccuracy,
  calculateEvalMetrics
};

// ---------------------------------------------------------------------------
// CLI 진입점 (오케스트레이터가 `node lib/ch015/scoring.js ...`로 능동 호출).
// exit code 계약: 0=통과, 2=차단(점수 불일치), 1=사용오류(파싱/파일).
// 위 export·로직은 변경하지 않는다 — 기존 함수를 그대로 노출만 한다.
// ---------------------------------------------------------------------------
function parseScoringArgs(argv) {
  const opts = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--classification') opts.classification = argv[++i];
    else if (a === '--ledger') opts.ledger = argv[++i];
    else if (a === '--reported') opts.reported = argv[++i];
  }
  return opts;
}

function runScoringCli(argv) {
  const fs = require('fs');
  const yaml = require('js-yaml');
  const opts = parseScoringArgs(argv);
  const source = opts.classification || opts.ledger;

  if (!source) {
    process.stderr.write('USAGE: scoring.js --classification <yaml>|--ledger <yaml> [--reported <score>]\n');
    return 1;
  }

  let doc;
  try {
    doc = yaml.load(fs.readFileSync(source, 'utf8'));
  } catch (e) {
    process.stderr.write(`USAGE_ERROR: cannot read/parse ${source}: ${e.message}\n`);
    return 1;
  }

  // findings 배열 추출 — ledger/classification 양쪽 스키마 대응.
  let findings = [];
  if (Array.isArray(doc)) {
    findings = doc;
  } else if (doc && typeof doc === 'object') {
    const keys = ['findings', 'candidates', 'raw_candidates', 'classifications',
      'candidate_classifications', 'final_classification'];
    for (const k of keys) {
      if (Array.isArray(doc[k])) { findings = doc[k]; break; }
    }
  }

  const counts = countScoreIncludedFindings(findings);
  const computed = calculateSecurityScore(counts);

  if (opts.reported !== undefined) {
    const reported = Number(opts.reported);
    if (!Number.isFinite(reported) || reported !== computed) {
      process.stderr.write(`SCORE_FORMULA_MISMATCH: computed=${computed} reported=${opts.reported}\n`);
      return 2;
    }
  }

  process.stdout.write(JSON.stringify({ score: computed, counts }) + '\n');
  return 0;
}

if (require.main === module) {
  process.exit(runScoringCli(process.argv.slice(2)));
}
