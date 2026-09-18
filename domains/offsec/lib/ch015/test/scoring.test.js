'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  SEVERITY_WEIGHTS,
  SEVERITY_ORDER,
  getSeverityWeights,
  getSeverityWeight,
  calculateSecurityScore,
  countScoreIncludedFindings,
  calculateScoreFromClassifiedFindings,
  validateScoreConsistency,
  isPassingScore,
  calculatePrecision,
  calculateRecall,
  calculateSeverityAccuracy,
  calculateEvalMetrics
} = require('../scoring');

// --- getSeverityWeight ---

test('getSeverityWeight: returns correct weights for each severity', () => {
  assert.equal(getSeverityWeight('CRITICAL'), 25);
  assert.equal(getSeverityWeight('HIGH'), 10);
  assert.equal(getSeverityWeight('MEDIUM'), 3);
  assert.equal(getSeverityWeight('LOW'), 1);
  assert.equal(getSeverityWeight('INFO'), 0);
});

test('getSeverityWeight: case-insensitive', () => {
  assert.equal(getSeverityWeight('critical'), 25);
  assert.equal(getSeverityWeight('High'), 10);
});

test('getSeverityWeight: unknown severity returns 0', () => {
  assert.equal(getSeverityWeight('UNKNOWN'), 0);
  assert.equal(getSeverityWeight(''), 0);
});

test('getSeverityWeights: repo config(scoring.securityScore.weights)와 하드코딩 fallback이 일치', () => {
  // 단일 소스(config)와 fallback이 어긋나면 점수 산정이 환경에 따라 달라진다
  assert.deepEqual(getSeverityWeights(), SEVERITY_WEIGHTS);
});

// --- calculateSecurityScore ---

test('calculateSecurityScore: perfect score with no findings', () => {
  assert.equal(calculateSecurityScore({ critical: 0, high: 0, medium: 0, low: 0 }), 100);
});

test('calculateSecurityScore: single CRITICAL = 75', () => {
  assert.equal(calculateSecurityScore({ critical: 1, high: 0, medium: 0, low: 0 }), 75);
});

test('calculateSecurityScore: boundary at 85 (1H + 1M + 2L)', () => {
  assert.equal(calculateSecurityScore({ critical: 0, high: 1, medium: 1, low: 2 }), 85);
});

test('calculateSecurityScore: floor at 0 (no negative scores)', () => {
  assert.equal(calculateSecurityScore({ critical: 5, high: 0, medium: 0, low: 0 }), 0);
});

test('calculateSecurityScore: handles missing keys with defaults', () => {
  assert.equal(calculateSecurityScore({}), 100);
  assert.equal(calculateSecurityScore({ critical: 1 }), 75);
});

test('calculateSecurityScore: mixed severity deduction', () => {
  // 2C(50) + 3H(30) + 5M(15) + 10L(10) = 105 → clamped to 0
  assert.equal(calculateSecurityScore({ critical: 2, high: 3, medium: 5, low: 10 }), 0);
});

test('countScoreIncludedFindings: counts only confirmed and downgraded findings', () => {
  const counts = countScoreIncludedFindings([
    { id: 'F-001', final_status: 'CONFIRMED', severity: 'CRITICAL' },
    { id: 'F-002', final_status: 'DOWNGRADED', severity: 'HIGH' },
    { id: 'F-003', final_status: 'BACKLOG', severity: 'MEDIUM' },
    { id: 'F-004', final_status: 'PENDING_PENTEST', severity: 'MEDIUM' },
    { id: 'F-005', final_status: 'FALSE_POSITIVE', severity: 'HIGH' },
    { id: 'F-006', final_status: 'CONFIRMED', severity: 'STRUCTURAL_WEAKNESS' },
    { id: 'F-007', final_status: 'EXCLUDED', severity: 'MEDIUM' },
  ]);

  assert.deepEqual(counts, {
    critical: 1,
    high: 1,
    medium: 0,
    low: 0,
    info: 0,
    structural_weakness: 1,
  });
});

test('countScoreIncludedFindings: classification=Structural_Weakness with nominal HIGH is SW, not deducted', () => {
  const counts = countScoreIncludedFindings([
    { id: 'F-001', final_status: 'CONFIRMED', severity: 'HIGH', classification: 'Structural_Weakness' },
    { id: 'F-002', final_status: 'CONFIRMED', severity: 'HIGH' },
  ]);

  assert.deepEqual(counts, {
    critical: 0,
    high: 1,
    medium: 0,
    low: 0,
    info: 0,
    structural_weakness: 1,
  });
  // SW가 HIGH 버킷으로 새어 점수를 차감하지 않는다
  assert.equal(calculateSecurityScore(counts), 90);
});

test('calculateScoreFromClassifiedFindings: applies CH015 formula to score-included findings', () => {
  const score = calculateScoreFromClassifiedFindings([
    { id: 'F-001', final_status: 'CONFIRMED', severity: 'HIGH' },
    { id: 'F-002', final_status: 'CONFIRMED', severity: 'MEDIUM' },
    { id: 'F-003', final_status: 'BACKLOG', severity: 'MEDIUM' },
  ]);

  assert.equal(score, 87);
});

test('validateScoreConsistency: detects reported score mismatch', () => {
  const result = validateScoreConsistency([
    { id: 'F-001', final_status: 'CONFIRMED', severity: 'HIGH' },
    { id: 'F-002', final_status: 'CONFIRMED', severity: 'MEDIUM' },
    { id: 'F-003', final_status: 'CONFIRMED', severity: 'LOW' },
  ], 90);

  assert.equal(result.valid, false);
  assert.equal(result.expected, 86);
  assert.equal(result.reported, 90);
});

// --- isPassingScore ---

test('isPassingScore: passes with score=85, no critical, high≤2', () => {
  assert.equal(isPassingScore(85, { critical: 0, high: 2 }), true);
});

test('isPassingScore: fails with any CRITICAL', () => {
  assert.equal(isPassingScore(90, { critical: 1, high: 0 }), false);
});

test('isPassingScore: fails with HIGH > 2', () => {
  assert.equal(isPassingScore(90, { critical: 0, high: 3 }), false);
});

test('isPassingScore: fails with score below threshold', () => {
  assert.equal(isPassingScore(84, { critical: 0, high: 0 }), false);
});

test('isPassingScore: fails with CVSS gate breach', () => {
  assert.equal(isPassingScore(90, { critical: 0, high: 0 }, { maxCvss: 9.0 }), false);
});

test('isPassingScore: passes when CVSS below gate', () => {
  assert.equal(isPassingScore(90, { critical: 0, high: 0 }, { maxCvss: 8.9 }), true);
});

test('isPassingScore: zeroToleranceSeverities option overrides default critical-only gate', () => {
  // 기본(config: ['critical'])에서는 HIGH 1건이 zero-tolerance에 걸리지 않는다
  assert.equal(isPassingScore(90, { critical: 0, high: 1 }), true);
  // 옵션으로 high를 zero-tolerance에 추가하면 HIGH 1건으로 fail
  assert.equal(isPassingScore(90, { critical: 0, high: 1 }, { zeroToleranceSeverities: ['critical', 'high'] }), false);
  // 옵션이 critical을 빼면 CRITICAL은 zero-tolerance에서 빠지지만 점수 차감으로는 여전히 작동
  assert.equal(isPassingScore(90, { critical: 1, high: 0 }, { zeroToleranceSeverities: [] }), true);
});

test('isPassingScore: zeroToleranceSeverities matching is case-insensitive', () => {
  assert.equal(isPassingScore(90, { critical: 1 }, { zeroToleranceSeverities: ['CRITICAL'] }), false);
});

// --- calculatePrecision ---

test('calculatePrecision: all TP = 1.0', () => {
  const findings = [{ label: 'TP' }, { label: 'TP' }, { label: 'TP' }];
  assert.equal(calculatePrecision(findings), 1);
});

test('calculatePrecision: all FP = 0.0', () => {
  const findings = [{ label: 'FP' }, { label: 'FP' }];
  assert.equal(calculatePrecision(findings), 0);
});

test('calculatePrecision: mixed TP/FP', () => {
  const findings = [{ label: 'TP' }, { label: 'TP' }, { label: 'FP' }];
  assert.ok(Math.abs(calculatePrecision(findings) - 2/3) < 0.001);
});

test('calculatePrecision: Disputed not counted', () => {
  const findings = [{ label: 'TP' }, { label: 'Disputed' }];
  assert.equal(calculatePrecision(findings), 1);
});

test('calculatePrecision: empty = null (no data)', () => {
  assert.equal(calculatePrecision([]), null);
});

// --- calculateRecall ---

test('calculateRecall: all found = 1.0', () => {
  assert.equal(calculateRecall(['F-001', 'F-002'], ['F-001', 'F-002']), 1);
});

test('calculateRecall: none found = 0.0', () => {
  assert.equal(calculateRecall([], ['F-001', 'F-002']), 0);
});

test('calculateRecall: partial = 0.5', () => {
  assert.equal(calculateRecall(['F-001'], ['F-001', 'F-002']), 0.5);
});

test('calculateRecall: empty golden = null (no oracle)', () => {
  assert.equal(calculateRecall(['F-001'], []), null);
});

test('calculateSeverityAccuracy: empty = null (no data)', () => {
  const result = calculateSeverityAccuracy([]);
  assert.equal(result.accuracy, null);
  assert.equal(result.total, 0);
});

// --- calculateSeverityAccuracy ---

test('calculateSeverityAccuracy: all match = 1.0', () => {
  const findings = [
    { va_severity: 'HIGH', final_severity: 'HIGH' },
    { va_severity: 'MEDIUM', final_severity: 'MEDIUM' }
  ];
  const result = calculateSeverityAccuracy(findings);
  assert.equal(result.accuracy, 1);
  assert.equal(result.inaccurate_count, 0);
});

test('calculateSeverityAccuracy: overstatement detection', () => {
  const findings = [
    { id: 'F-001', va_severity: 'CRITICAL', final_severity: 'HIGH' }
  ];
  const result = calculateSeverityAccuracy(findings);
  assert.equal(result.accuracy, 0);
  assert.equal(result.inaccurate[0].direction, 'overstatement');
});

test('calculateSeverityAccuracy: understatement detection', () => {
  const findings = [
    { id: 'F-001', va_severity: 'LOW', final_severity: 'HIGH' }
  ];
  const result = calculateSeverityAccuracy(findings);
  assert.equal(result.accuracy, 0);
  assert.equal(result.inaccurate[0].direction, 'understatement');
});

test('calculateSeverityAccuracy: skips entries without va_severity', () => {
  const findings = [
    { va_severity: 'HIGH', final_severity: 'HIGH' },
    { final_severity: 'MEDIUM' }
  ];
  const result = calculateSeverityAccuracy(findings);
  assert.equal(result.total, 1);
  assert.equal(result.accuracy, 1);
});

// --- calculateEvalMetrics ---

test('calculateEvalMetrics: comprehensive aggregation', () => {
  const findings = [
    { label: 'TP', va_severity: 'HIGH', final_severity: 'HIGH' },
    { label: 'TP', va_severity: 'CRITICAL', final_severity: 'HIGH' },
    { label: 'FP', va_severity: 'MEDIUM', final_severity: 'MEDIUM' },
    { label: 'Disputed', va_severity: 'LOW', final_severity: 'LOW' }
  ];
  const result = calculateEvalMetrics(findings);
  assert.equal(result.total, 4);
  assert.equal(result.tp, 2);
  assert.equal(result.fp, 1);
  assert.equal(result.disputed, 1);
  assert.ok(Math.abs(result.precision - 2/3) < 0.001);
  assert.equal(result.overstatements, 1);
  assert.equal(result.understatements, 0);
});

// --- Constants ---

test('SEVERITY_ORDER: CRITICAL < HIGH < MEDIUM < LOW < INFO', () => {
  assert.ok(SEVERITY_ORDER.CRITICAL < SEVERITY_ORDER.HIGH);
  assert.ok(SEVERITY_ORDER.HIGH < SEVERITY_ORDER.MEDIUM);
  assert.ok(SEVERITY_ORDER.MEDIUM < SEVERITY_ORDER.LOW);
  assert.ok(SEVERITY_ORDER.LOW < SEVERITY_ORDER.INFO);
});

// --- CLI 진입점 (require.main === module) ---
{
  const { spawnSync } = require('node:child_process');
  const fs = require('node:fs');
  const os = require('node:os');
  const path = require('node:path');
  const yaml = require('js-yaml');
  const SCORING_CLI = path.resolve(__dirname, '..', 'scoring.js');

  const runCli = (args) => {
    const r = spawnSync('node', [SCORING_CLI, ...args], { encoding: 'utf8', timeout: 10_000 });
    return { code: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
  };
  const writeYaml = (obj) => {
    const p = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-score-cli-')), 'ledger.yaml');
    fs.writeFileSync(p, yaml.dump(obj));
    return p;
  };

  // 1 CONFIRMED HIGH → score = 100 - 10 = 90
  const ledger = { findings: [{ candidate_id: 'C-1', final_status: 'CONFIRMED', severity: 'HIGH' }] };

  test('CLI scoring: prints score and exits 0 without --reported', () => {
    const p = writeYaml(ledger);
    const r = runCli(['--ledger', p]);
    assert.equal(r.code, 0, r.stderr);
    assert.equal(JSON.parse(r.stdout).score, 90);
  });

  test('CLI scoring: --reported matching computed exits 0', () => {
    const p = writeYaml(ledger);
    const r = runCli(['--classification', p, '--reported', '90']);
    assert.equal(r.code, 0, r.stderr);
  });

  test('CLI scoring: --reported mismatch exits 2 with SCORE_FORMULA_MISMATCH', () => {
    const p = writeYaml(ledger);
    const r = runCli(['--ledger', p, '--reported', '85']);
    assert.equal(r.code, 2);
    assert.match(r.stderr, /SCORE_FORMULA_MISMATCH: computed=90 reported=85/);
  });

  test('CLI scoring: missing file exits 1 (usage error)', () => {
    const r = runCli(['--ledger', '/nonexistent/path.yaml', '--reported', '90']);
    assert.equal(r.code, 1);
  });

  test('CLI scoring: no source arg exits 1', () => {
    const r = runCli(['--reported', '90']);
    assert.equal(r.code, 1);
  });
}
