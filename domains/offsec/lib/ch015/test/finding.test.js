'use strict';

const { test, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

const {
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
} = require('../finding');

beforeEach(() => {
  resetCounter();
});

// --- formatFindingId ---

test('formatFindingId: pads to 3 digits', () => {
  assert.equal(formatFindingId(1), 'F-001');
  assert.equal(formatFindingId(42), 'F-042');
  assert.equal(formatFindingId(100), 'F-100');
  assert.equal(formatFindingId(999), 'F-999');
});

// --- createFinding ---

const VALID_OPTS = {
  title: 'SQL Injection in login',
  severity: 'HIGH',
  category: 'injection',
  dimension: 'A4',
  rootCause: 'CODE',
  location: 'src/auth.js:42',
  description: 'Unsanitized user input in SQL query',
  cwe: 'CWE-89',
  owaspTop10: 'A03'
};

test('createFinding: returns finding with auto-increment ID', () => {
  const f1 = createFinding(VALID_OPTS);
  const f2 = createFinding(VALID_OPTS);
  assert.equal(f1.id, 'F-001');
  assert.equal(f2.id, 'F-002');
});

test('createFinding: includes all required fields', () => {
  const f = createFinding(VALID_OPTS);
  assert.equal(f.title, 'SQL Injection in login');
  assert.equal(f.severity, 'HIGH');
  assert.equal(f.category, 'injection');
  assert.equal(f.dimension, 'A4');
  assert.equal(f.rootCause, 'CODE');
  assert.equal(f.cwe, 'CWE-89');
  assert.equal(f.owaspTop10, 'A03');
  assert.ok(f.timestamp);
});

test('createFinding: severity is uppercased', () => {
  const f = createFinding({ ...VALID_OPTS, severity: 'high' });
  assert.equal(f.severity, 'HIGH');
});

test('createFinding: defaults optional fields to null', () => {
  const f = createFinding(VALID_OPTS);
  assert.equal(f.poc, null);
  assert.equal(f.remediation, null);
  assert.equal(f.liveStatus, null);
  assert.equal(f.impactAnalysis, null);
  assert.equal(f.prerequisites, null);
  assert.equal(f.originalSeverity, null);
});

test('createFinding: preserves originalSeverity for Structural_Weakness', () => {
  const f = createFinding({
    ...VALID_OPTS,
    severity: 'INFO',
    classification: 'Structural_Weakness',
    originalSeverity: 'HIGH',
    impactProof: { what: 'N/A', so_what: 'N/A', how: 'N/A', gate_result: 'FAIL', failed_proofs: ['So_What'] }
  });
  assert.equal(f.classification, 'Structural_Weakness');
  assert.equal(f.severity, 'INFO');
  assert.equal(f.originalSeverity, 'HIGH');
  assert.deepEqual(f.impactProof.failed_proofs, ['So_What']);
});

test('createFinding: throws on missing CWE', () => {
  assert.throws(
    () => createFinding({ ...VALID_OPTS, cwe: '' }),
    /requires a valid CWE field/
  );
});

test('createFinding: throws on invalid CWE format', () => {
  assert.throws(
    () => createFinding({ ...VALID_OPTS, cwe: 'CVE-2024-1234' }),
    /requires a valid CWE field/
  );
});

test('createFinding: throws on missing owaspTop10', () => {
  assert.throws(
    () => createFinding({ ...VALID_OPTS, owaspTop10: '' }),
    /requires a valid owaspTop10 field/
  );
});

test('createFinding: accepts N/A for owaspTop10', () => {
  const f = createFinding({ ...VALID_OPTS, owaspTop10: 'N/A' });
  assert.equal(f.owaspTop10, 'N/A');
});

test('createFinding: throws on invalid severity token', () => {
  assert.throws(
    () => createFinding({ ...VALID_OPTS, severity: 'CRIT' }),
    /requires a valid severity/
  );
});

test('createFinding: throws on garbage severity', () => {
  assert.throws(
    () => createFinding({ ...VALID_OPTS, severity: 'Critical!' }),
    /requires a valid severity/
  );
});

test('createFinding: accepts comma-separated CWE tokens', () => {
  const f = createFinding({ ...VALID_OPTS, cwe: 'CWE-89, CWE-79' });
  assert.equal(f.cwe, 'CWE-89, CWE-79');
});

test('createFinding: throws when any CWE token is malformed', () => {
  assert.throws(
    () => createFinding({ ...VALID_OPTS, cwe: 'CWE-89, junk' }),
    /requires a valid CWE field/
  );
});

test('createFinding: throws when any owasp token is malformed', () => {
  assert.throws(
    () => createFinding({ ...VALID_OPTS, owaspTop10: 'A01, GARBAGE' }),
    /requires a valid owaspTop10 field/
  );
});

// --- sortFindings ---

test('sortFindings: sorts CRITICAL > HIGH > MEDIUM > LOW > INFO', () => {
  const findings = [
    { id: 'F-001', severity: 'LOW' },
    { id: 'F-002', severity: 'CRITICAL' },
    { id: 'F-003', severity: 'HIGH' },
    { id: 'F-004', severity: 'INFO' },
    { id: 'F-005', severity: 'MEDIUM' }
  ];
  const sorted = sortFindings(findings);
  assert.deepEqual(sorted.map(f => f.severity), ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
});

test('sortFindings: same severity sorted by ID', () => {
  const findings = [
    { id: 'F-003', severity: 'HIGH' },
    { id: 'F-001', severity: 'HIGH' }
  ];
  const sorted = sortFindings(findings);
  assert.deepEqual(sorted.map(f => f.id), ['F-001', 'F-003']);
});

test('sortFindings: does not mutate original', () => {
  const findings = [{ id: 'F-002', severity: 'LOW' }, { id: 'F-001', severity: 'HIGH' }];
  sortFindings(findings);
  assert.equal(findings[0].id, 'F-002');
});

// --- groupByCategory ---

test('groupByCategory: groups correctly', () => {
  const findings = [
    { category: 'injection' },
    { category: 'injection' },
    { category: 'auth-bypass' }
  ];
  const groups = groupByCategory(findings);
  assert.equal(groups['injection'].length, 2);
  assert.equal(groups['auth-bypass'].length, 1);
});

test('groupByCategory: handles missing category as uncategorized', () => {
  const findings = [{ category: null }, {}];
  const groups = groupByCategory(findings);
  assert.equal(groups['uncategorized'].length, 2);
});

// --- groupBySeverity ---

test('groupBySeverity: creates all severity buckets', () => {
  const groups = groupBySeverity([]);
  assert.deepEqual(Object.keys(groups).sort(), ['CRITICAL', 'HIGH', 'INFO', 'LOW', 'MEDIUM']);
});

test('groupBySeverity: distributes correctly', () => {
  const findings = [
    { severity: 'HIGH' },
    { severity: 'HIGH' },
    { severity: 'LOW' }
  ];
  const groups = groupBySeverity(findings);
  assert.equal(groups.HIGH.length, 2);
  assert.equal(groups.LOW.length, 1);
  assert.equal(groups.CRITICAL.length, 0);
});

// --- countBySeverity ---

test('countBySeverity: counts correctly', () => {
  const findings = [
    { severity: 'CRITICAL' },
    { severity: 'HIGH' },
    { severity: 'HIGH' },
    { severity: 'MEDIUM' },
    { severity: 'LOW' },
    { severity: 'LOW' },
    { severity: 'LOW' },
    { severity: 'INFO' }
  ];
  const counts = countBySeverity(findings);
  assert.deepEqual(counts, { critical: 1, high: 2, medium: 1, low: 3, info: 1, structural_weakness: 0 });
});

test('countBySeverity: empty array', () => {
  assert.deepEqual(countBySeverity([]), { critical: 0, high: 0, medium: 0, low: 0, info: 0, structural_weakness: 0 });
});

test('countBySeverity: falls back to severity_current / final_severity (YAML ledger schema)', () => {
  const counts = countBySeverity([
    { severity: 'HIGH' },                                   // 1순위 severity
    { severity_current: 'MEDIUM' },                         // 2순위 severity_current
    { final_severity: 'LOW' },                              // 3순위 final_severity
    { severity: 'HIGH', severity_current: 'LOW' },          // severity가 우선
    { severity_current: 'CRITICAL', final_severity: 'LOW' } // severity_current가 final보다 우선
  ]);
  assert.deepEqual(counts, { critical: 1, high: 2, medium: 1, low: 1, info: 0, structural_weakness: 0 });
});

test('countBySeverity: empty-string severity falls through to next field', () => {
  const counts = countBySeverity([
    { severity: '', severity_current: 'MEDIUM' },
    { severity: '', severity_current: '', final_severity: '' } // 전부 빈 값 → INFO
  ]);
  assert.equal(counts.medium, 1);
  assert.equal(counts.info, 1);
});

test('countBySeverity: counts structural weakness in its own bucket only (no double count)', () => {
  const findings = [
    { severity: 'INFO', classification: 'Structural_Weakness' },
    { severity: 'INFO', classification: 'Structural_Weakness' },
    { severity: 'HIGH' }
  ];
  const counts = countBySeverity(findings);
  assert.equal(counts.structural_weakness, 2);
  // SW는 nominal severity 버킷에 이중 증가하지 않는다
  assert.equal(counts.info, 0);
  assert.equal(counts.high, 1);
});

test('countBySeverity: SW judged by classification even with nominal HIGH severity', () => {
  const counts = countBySeverity([
    { severity: 'HIGH', classification: 'Structural_Weakness' }
  ]);
  assert.equal(counts.structural_weakness, 1);
  assert.equal(counts.high, 0);
});

test('countBySeverity: SW judged by severity string without classification', () => {
  const counts = countBySeverity([
    { severity: 'STRUCTURAL_WEAKNESS' },
    { severity: 'STRUCTURAL' }
  ]);
  assert.equal(counts.structural_weakness, 2);
  assert.equal(counts.info, 0);
});

// --- isStructuralWeakness ---

test('isStructuralWeakness: accepts classification or severity signal, case/separator-insensitive', () => {
  assert.equal(isStructuralWeakness({ classification: 'Structural_Weakness', severity: 'HIGH' }), true);
  assert.equal(isStructuralWeakness({ classification: 'structural-weakness' }), true);
  assert.equal(isStructuralWeakness({ severity: 'STRUCTURAL_WEAKNESS' }), true);
  assert.equal(isStructuralWeakness({ severity: 'Structural Weakness' }), true);
  assert.equal(isStructuralWeakness({ classification: 'Confirmed_Vulnerability', severity: 'HIGH' }), false);
  assert.equal(isStructuralWeakness({}), false);
});

// --- groupByDimension ---

test('groupByDimension: groups by A1-A8', () => {
  const findings = [
    { dimension: 'A1' },
    { dimension: 'A1' },
    { dimension: 'A4' }
  ];
  const groups = groupByDimension(findings);
  assert.equal(groups['A1'].length, 2);
  assert.equal(groups['A4'].length, 1);
});

test('groupByDimension: null dimension as unclassified', () => {
  const findings = [{ dimension: null }];
  const groups = groupByDimension(findings);
  assert.equal(groups['unclassified'].length, 1);
});

// --- groupByRootCause ---

test('groupByRootCause: groups correctly', () => {
  const findings = [
    { rootCause: 'ARCHITECTURE' },
    { rootCause: 'CODE' },
    { rootCause: 'CODE' }
  ];
  const groups = groupByRootCause(findings);
  assert.equal(groups.ARCHITECTURE.length, 1);
  assert.equal(groups.CODE.length, 2);
});

test('groupByRootCause: defaults to CODE', () => {
  const findings = [{ rootCause: null }, {}];
  const groups = groupByRootCause(findings);
  assert.equal(groups.CODE.length, 2);
});
