'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const yaml = require('js-yaml');

const {
  OBJECTION_WEIGHTS,
  calculateObjectionWeight,
  evaluateConvergence,
  generateFindingDigest,
  formatDigestDocument
} = require('../feedback');

// --- OBJECTION_WEIGHTS ---

test('OBJECTION_WEIGHTS: false_positive is heaviest at 3', () => {
  assert.equal(OBJECTION_WEIGHTS.false_positive, 3);
});

test('OBJECTION_WEIGHTS: includes all 17 types', () => {
  const expected = ['false_positive', 'not_proxy_pattern', 'response_mitigated',
    'severity_dispute', 'severity_overstatement', 'severity_understatement',
    'asset_value_mismatch', 'asset_inflation', 'impact_gate_overclassified',
    'impact_gate_underclassified', 'excessive_structural_weakness',
    'quantitative_correction',
    'evidence_insufficient', 'evidence_gap', 'reference_missing',
    'dependency_issue', 'missing_finding'];
  for (const key of expected) {
    assert.ok(OBJECTION_WEIGHTS[key] !== undefined, `missing: ${key}`);
  }
  assert.equal(Object.keys(OBJECTION_WEIGHTS).length, expected.length);
});

test('OBJECTION_WEIGHTS: FP급 기각=3, 재조정/보완류=2, 누락=1', () => {
  assert.equal(OBJECTION_WEIGHTS.not_proxy_pattern, 3);
  assert.equal(OBJECTION_WEIGHTS.response_mitigated, 3);
  assert.equal(OBJECTION_WEIGHTS.asset_value_mismatch, 2);
  assert.equal(OBJECTION_WEIGHTS.asset_inflation, 2);
  assert.equal(OBJECTION_WEIGHTS.impact_gate_overclassified, 2);
  assert.equal(OBJECTION_WEIGHTS.impact_gate_underclassified, 2);
  assert.equal(OBJECTION_WEIGHTS.excessive_structural_weakness, 2);
  assert.equal(OBJECTION_WEIGHTS.quantitative_correction, 2);
  assert.equal(OBJECTION_WEIGHTS.reference_missing, 2);
  assert.equal(OBJECTION_WEIGHTS.missing_finding, 1);
});

test('OBJECTION_WEIGHTS: config files use the same taxonomy', () => {
  const root = path.resolve(__dirname, '..', '..', '..');
  const expected = Object.keys(OBJECTION_WEIGHTS).sort();

  const ch015Config = JSON.parse(fs.readFileSync(path.join(root, 'ch015.config.json'), 'utf8'));
  assert.deepEqual(Object.keys(ch015Config.feedbackLoop.objection_weights).sort(), expected);

  const harnessConfig = yaml.load(fs.readFileSync(path.join(root, 'harness', 'config.yaml'), 'utf8'));
  assert.deepEqual(Object.keys(harnessConfig.feedback.objection_weights).sort(), expected);
});

// --- calculateObjectionWeight ---

test('calculateObjectionWeight: empty objections = weight 0, convergent', () => {
  const result = calculateObjectionWeight([]);
  assert.equal(result.totalWeight, 0);
  assert.equal(result.convergent, true);
});

test('calculateObjectionWeight: single false_positive = weight 3', () => {
  const result = calculateObjectionWeight([{ type: 'false_positive' }]);
  assert.equal(result.totalWeight, 3);
  assert.equal(result.breakdown.false_positive, 3);
});

test('calculateObjectionWeight: mixed objections sum correctly', () => {
  const objections = [
    { type: 'false_positive' },     // 3
    { type: 'severity_dispute' },    // 2
    { type: 'missing_finding' }      // 1
  ];
  const result = calculateObjectionWeight(objections);
  assert.equal(result.totalWeight, 6);
});

test('calculateObjectionWeight: convergent when below threshold', () => {
  const result = calculateObjectionWeight([{ type: 'missing_finding' }], 5);
  assert.equal(result.convergent, true);
});

test('calculateObjectionWeight: not convergent when at threshold', () => {
  const objections = [
    { type: 'false_positive' },  // 3
    { type: 'severity_dispute' } // 2 → total = 5
  ];
  const result = calculateObjectionWeight(objections, 5);
  assert.equal(result.convergent, false);
});

test('calculateObjectionWeight: unknown type defaults to weight 1', () => {
  const result = calculateObjectionWeight([{ type: 'unknown_type' }]);
  assert.equal(result.totalWeight, 1);
});

// --- evaluateConvergence ---

test('evaluateConvergence: CONVERGE on empty objections', () => {
  const result = evaluateConvergence({ objections: [], iteration: 1 });
  assert.equal(result.action, 'CONVERGE');
  assert.match(result.reason, /No objections/);
});

test('evaluateConvergence: CONVERGE at max iterations', () => {
  const objections = [{ type: 'false_positive' }, { type: 'false_positive' }]; // weight=6
  const result = evaluateConvergence(
    { objections, iteration: 2 },
    { maxIterations: 2, threshold: 5 }
  );
  assert.equal(result.action, 'CONVERGE');
  assert.match(result.reason, /Max iterations/);
});

test('evaluateConvergence: CONVERGE when weight below threshold', () => {
  const result = evaluateConvergence(
    { objections: [{ type: 'missing_finding' }], iteration: 1 },
    { threshold: 5, maxIterations: 3 }
  );
  assert.equal(result.action, 'CONVERGE');
  assert.match(result.reason, /below threshold/);
});

test('evaluateConvergence: CONTINUE when weight >= threshold and iterations remain', () => {
  const objections = [
    { type: 'false_positive' },  // 3
    { type: 'severity_dispute' } // 2 → total = 5
  ];
  const result = evaluateConvergence(
    { objections, iteration: 1 },
    { threshold: 5, maxIterations: 3 }
  );
  assert.equal(result.action, 'CONTINUE');
});

test('evaluateConvergence: uses default threshold=5 and maxIterations=2', () => {
  const objections = [{ type: 'false_positive' }, { type: 'false_positive' }]; // weight=6
  const result = evaluateConvergence({ objections, iteration: 1 });
  assert.equal(result.action, 'CONTINUE');
  assert.equal(result.metrics.threshold, 5);
});

test('evaluateConvergence: includes iteration in metrics', () => {
  const result = evaluateConvergence({ objections: [], iteration: 2 });
  assert.equal(result.metrics.iteration, 2);
});

// --- generateFindingDigest ---

test('generateFindingDigest: extracts key fields', () => {
  const findings = [{
    id: 'F-001',
    severity: 'HIGH',
    dimension: 'A1',
    location: 'auth.js:10',
    title: 'Hardcoded JWT secret',
    evidences: [{ ref: 'auth.js:10' }, { ref: 'auth.js:20' }],
    selfVerifyResult: 'CONFIRMED',
    rootCause: 'CODE'
  }];
  const digest = generateFindingDigest(findings);
  assert.equal(digest.length, 1);
  assert.equal(digest[0].id, 'F-001');
  assert.equal(digest[0].evidence_count, 2);
  assert.equal(digest[0].self_verify_result, 'CONFIRMED');
});

test('generateFindingDigest: defaults for missing fields', () => {
  const findings = [{ id: 'F-001', severity: 'LOW', title: 'test' }];
  const digest = generateFindingDigest(findings);
  assert.equal(digest[0].evidence_count, 0);
  assert.equal(digest[0].self_verify_result, 'NOT_PERFORMED');
  assert.equal(digest[0].root_cause, 'UNKNOWN');
});

// --- formatDigestDocument ---

test('formatDigestDocument: generates complete document structure', () => {
  const findings = [{
    id: 'F-001', severity: 'HIGH', dimension: 'A1',
    location: 'auth.js:10', title: 'test',
    evidences: [], rootCause: 'CODE',
    category: 'auth-bypass'
  }];
  const doc = formatDigestDocument(findings, {
    engagement_id: 'TEST-001',
    service: 'va'
  });
  assert.equal(doc.metadata.engagement_id, 'TEST-001');
  assert.equal(doc.metadata.finding_count, 1);
  assert.ok(doc.summary.severity_counts);
  assert.ok(doc.summary.dimensions_covered.includes('A1'));
  assert.equal(doc.findings.length, 1);
});
