'use strict';

const { getConfig } = require('../core/config');

// 하드코딩 fallback — 단일 소스는 config(feedbackLoop.objection_weights).
// config 로드 실패/키 부재 시에만 이 값이 쓰인다 (getObjectionWeights 참조).
const OBJECTION_WEIGHTS = {
  // FP급 기각 (Finding 자체를 기각/무력화)
  false_positive: 3,
  not_proxy_pattern: 3,
  response_mitigated: 3,
  // 심각도/분류 재조정
  severity_dispute: 2,
  severity_overstatement: 2,
  severity_understatement: 2,
  asset_value_mismatch: 2,
  asset_inflation: 2,
  impact_gate_overclassified: 2,
  impact_gate_underclassified: 2,
  excessive_structural_weakness: 2,
  quantitative_correction: 2,
  // 증거 보완
  evidence_insufficient: 2,
  evidence_gap: 2,
  reference_missing: 2,
  dependency_issue: 2,
  // 누락
  missing_finding: 1
};

/**
 * objection 가중치 테이블 — config(feedbackLoop.objection_weights) 우선,
 * 하드코딩(OBJECTION_WEIGHTS)은 fallback. fail-soft: config 값이 숫자가
 * 아니거나 음수면 해당 키만 fallback을 유지한다.
 */
function getObjectionWeights() {
  const merged = { ...OBJECTION_WEIGHTS };
  const configured = getConfig('feedbackLoop.objection_weights', null);
  if (configured && typeof configured === 'object' && !Array.isArray(configured)) {
    for (const [type, weight] of Object.entries(configured)) {
      const n = Number(weight);
      if (Number.isFinite(n) && n >= 0) merged[type] = n;
    }
  }
  return merged;
}

const DEFAULT_CONVERGENCE_THRESHOLD = 5;
const MAX_ITERATIONS = 2;

/**
 * Calculate weighted objection score
 * @param {Array} objections - [{ type: 'false_positive'|'severity_dispute'|... }]
 * @returns {{ totalWeight: number, breakdown: Object, convergent: boolean }}
 */
function calculateObjectionWeight(objections, threshold = DEFAULT_CONVERGENCE_THRESHOLD) {
  const breakdown = {};
  let totalWeight = 0;
  const weights = getObjectionWeights();

  for (const obj of objections) {
    const type = obj.type || 'missing_finding';
    const weight = weights[type] || 1;
    totalWeight += weight;
    breakdown[type] = (breakdown[type] || 0) + weight;
  }

  return {
    totalWeight,
    breakdown,
    convergent: totalWeight < threshold,
    threshold
  };
}

/**
 * Determine if feedback loop should continue or converge
 * @param {Object} currentRound - { objections: [], iteration: N }
 * @param {Object} opts - { threshold, maxIterations }
 * @returns {{ action: 'CONVERGE'|'CONTINUE', reason: string, metrics: Object }}
 */
function evaluateConvergence(currentRound, opts = {}) {
  // 단일 출처: config.feedbackLoop. opts override 우선, 그다음 config, 그다음 하드 기본값.
  // 주의: config.ch015.limits.max_feedback_iterations(budget abort 하드 ceiling)와는 별개 개념 —
  //       여기서는 수렴(convergence) 소프트 바운드를 쓴다.
  const threshold = opts.threshold ?? getConfig('feedbackLoop.convergence_threshold', DEFAULT_CONVERGENCE_THRESHOLD);
  const maxIter = opts.maxIterations ?? getConfig('feedbackLoop.max_iterations', MAX_ITERATIONS);
  const objections = currentRound.objections || [];
  const iteration = currentRound.iteration || 1;

  const weightResult = calculateObjectionWeight(objections, threshold);

  if (objections.length === 0) {
    return {
      action: 'CONVERGE',
      reason: 'No objections raised',
      metrics: { ...weightResult, iteration }
    };
  }

  if (iteration >= maxIter) {
    return {
      action: 'CONVERGE',
      reason: `Max iterations (${maxIter}) reached`,
      metrics: { ...weightResult, iteration }
    };
  }

  if (weightResult.convergent) {
    return {
      action: 'CONVERGE',
      reason: `Weighted objection score (${weightResult.totalWeight}) below threshold (${threshold})`,
      metrics: { ...weightResult, iteration }
    };
  }

  return {
    action: 'CONTINUE',
    reason: `Weighted objection score (${weightResult.totalWeight}) >= threshold (${threshold})`,
    metrics: { ...weightResult, iteration }
  };
}

/**
 * Generate finding digest from VA findings for Verify handoff
 * Compact representation that allows Verifier to triage before full read
 * @param {Array} findings - finding objects from createFinding
 * @returns {Array} digest entries
 */
function generateFindingDigest(findings) {
  return findings.map(f => ({
    id: f.id,
    severity: f.severity,
    dimension: f.dimension,
    location: f.location,
    title: f.title,
    evidence_count: (f.evidences || []).length,
    self_verify_result: f.selfVerifyResult || 'NOT_PERFORMED',
    root_cause: f.rootCause || 'UNKNOWN'
  }));
}

/**
 * Format finding digest as YAML-ready structure
 * @param {Array} findings
 * @param {Object} metadata - { engagement_id, service, phase, timestamp }
 * @returns {Object} complete digest document
 */
function formatDigestDocument(findings, metadata = {}) {
  const digest = generateFindingDigest(findings);
  const { countBySeverity } = require('./finding');
  const counts = countBySeverity(findings);

  return {
    metadata: {
      engagement_id: metadata.engagement_id || 'unknown',
      service: metadata.service || 'unknown',
      phase: metadata.phase || 'VA',
      generated_at: new Date().toISOString(),
      finding_count: findings.length
    },
    summary: {
      severity_counts: counts,
      dimensions_covered: [...new Set(findings.map(f => f.dimension).filter(Boolean))].sort(),
      root_cause_distribution: findings.reduce((acc, f) => {
        const rc = f.rootCause || 'UNKNOWN';
        acc[rc] = (acc[rc] || 0) + 1;
        return acc;
      }, {})
    },
    findings: digest
  };
}

module.exports = {
  OBJECTION_WEIGHTS,
  getObjectionWeights,
  calculateObjectionWeight,
  evaluateConvergence,
  generateFindingDigest,
  formatDigestDocument
};
