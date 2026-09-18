'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  deduplicateByRootCause,
  suggestEquivalenceClusters,
  getFinalStatus,
  isScoreIncludedCandidate,
  appraiseValidity,
  validateLedger,
  summarizeCandidates,
  calculatePentestRouteCoverage,
} = require('../candidate-ledger');

test('getFinalStatus: defaults unclassified when no status exists', () => {
  assert.equal(getFinalStatus({ candidate_id: 'C-001' }), 'UNCLASSIFIED');
});

test('validateLedger: blocks unclassified candidates before publication', () => {
  const result = validateLedger([
    { candidate_id: 'C-001', status: 'CANDIDATE', severity: 'MEDIUM' },
  ]);

  assert.equal(result.valid, false);
  assert.equal(result.summary.publish_allowed, false);
  assert.equal(result.errors[0].code, 'CANDIDATE_UNCLASSIFIED');
});

test('validateLedger: confirmed candidates require evidence', () => {
  const result = validateLedger([
    { candidate_id: 'F-001', final_status: 'CONFIRMED', severity: 'HIGH' },
  ]);

  assert.equal(result.valid, false);
  assert.equal(result.errors[0].code, 'MISSING_EVIDENCE');
});

test('validateLedger: pending external candidates require external context', () => {
  const result = validateLedger([
    { candidate_id: 'F-008', final_status: 'PENDING_EXTERNAL', severity: 'MEDIUM' },
  ]);

  assert.equal(result.valid, false);
  assert.equal(result.errors[0].code, 'PENDING_EXTERNAL_CONTEXT_MISSING');
});

test('validateLedger: folded and false-positive classifications need traceable reasons', () => {
  const result = validateLedger([
    { candidate_id: 'F-010', final_status: 'FOLDED_INTO', severity: 'LOW' },
    { candidate_id: 'F-011', final_status: 'FALSE_POSITIVE', severity: 'LOW' },
  ]);

  assert.equal(result.valid, false);
  assert.deepEqual(result.errors.map((e) => e.code), [
    'FOLDED_TARGET_MISSING',
    'FALSE_POSITIVE_COUNTER_EVIDENCE_MISSING',
  ]);
});

test('validateLedger: backlog and downgraded classifications need rationale', () => {
  const result = validateLedger([
    {
      candidate_id: 'F-007',
      final_status: 'BACKLOG',
      severity: 'MEDIUM',
      evidence: { locations: ['src/dto.ts:21'] },
    },
    {
      candidate_id: 'F-009',
      final_status: 'DOWNGRADED',
      severity: 'LOW',
      evidence: { locations: ['src/session.ts:11'] },
    },
  ]);

  assert.equal(result.valid, false);
  assert.deepEqual(result.errors.map((e) => e.code), [
    'BACKLOG_REASON_MISSING',
    'DOWNGRADE_REASON_MISSING',
  ]);
});

test('summarizeCandidates: pending and backlog remain preserved but excluded from score', () => {
  const candidates = [
    {
      candidate_id: 'F-001',
      final_status: 'CONFIRMED',
      severity: 'HIGH',
      evidence: { locations: ['src/auth.ts:10'] },
    },
    {
      candidate_id: 'F-007',
      final_status: 'BACKLOG',
      severity: 'MEDIUM',
      evidence: { locations: ['src/dto.ts:21'] },
      final_mapping: { rationale: 'Valid but deferred' },
    },
    {
      candidate_id: 'F-008',
      final_status: 'PENDING_EXTERNAL',
      severity: 'MEDIUM',
      required_access: 'external callback receiver',
    },
  ];

  const summary = summarizeCandidates(candidates);
  assert.equal(summary.total, 3);
  assert.equal(summary.backlog, 1);
  assert.equal(summary.pending, 1);
  assert.equal(summary.score_included_counts.high, 1);
  assert.equal(summary.score_included_counts.medium, 0);
  assert.equal(isScoreIncludedCandidate(candidates[1]), false);
});

test('deduplicateByRootCause: folds repeated instances of one vulnerability', () => {
  const result = deduplicateByRootCause([
    {
      candidate_id: 'F-001',
      remediation_key: 'add-auth-to-testbed-routes',
      final_status: 'CONFIRMED',
      severity: 'HIGH',
      evidence: { locations: ['routes/testbed.go:10'] },
      affected_instances: [
        { route: 'GET /testbed/payments', evidence: 'routes/testbed.go:10' },
      ],
    },
    {
      candidate_id: 'F-002',
      remediation_key: 'add-auth-to-testbed-routes',
      final_status: 'CONFIRMED',
      severity: 'MEDIUM',
      evidence: { locations: ['routes/testbed.go:22'] },
      affected_instances: [
        { route: 'POST /testbed/checkout', evidence: 'routes/testbed.go:22' },
      ],
    },
  ]);

  const primary = result.find((candidate) => candidate.candidate_id === 'F-001');
  const folded = result.find((candidate) => candidate.candidate_id === 'F-002');

  assert.equal(folded.final_status, 'FOLDED_INTO');
  assert.equal(folded.score_included, false);
  assert.equal(folded.final_mapping.folded_into, 'F-001');
  assert.deepEqual(primary.affected_instances, [
    { route: 'GET /testbed/payments', evidence: 'routes/testbed.go:10' },
    { route: 'POST /testbed/checkout', evidence: 'routes/testbed.go:22' },
  ]);
});

test('suggestEquivalenceClusters: clusters shared root-cause candidates without mutating status', () => {
  const input = [
    {
      candidate_id: 'F-001',
      remediation_key: 'add-auth-to-testbed-routes',
      final_status: 'CONFIRMED',
      severity: 'HIGH',
      evidence: { locations: ['routes/testbed.go:10'] },
      affected_instances: [{ route: 'GET /testbed/payments' }],
    },
    {
      candidate_id: 'F-002',
      remediation_key: 'add-auth-to-testbed-routes',
      final_status: 'CONFIRMED',
      severity: 'MEDIUM',
      evidence: { locations: ['routes/testbed.go:22'] },
      affected_instances: [{ route: 'POST /testbed/checkout' }],
    },
    {
      candidate_id: 'F-003',
      remediation_key: 'sanitize-search-query',
      final_status: 'CONFIRMED',
      severity: 'HIGH',
      evidence: { locations: ['search.go:5'] },
    },
  ];

  const out = suggestEquivalenceClusters(input);

  // 단독 후보(F-003)는 클러스터 아님; 공유 그룹(F-001/F-002)만 제안.
  assert.equal(out.cluster_count, 1);
  const cluster = out.clusters[0];
  assert.deepEqual(cluster.candidate_ids.sort(), ['F-001', 'F-002']);
  assert.equal(cluster.suggested_representative, 'F-001'); // HIGH > MEDIUM
  assert.deepEqual(cluster.suggested_folded, ['F-002']);
  assert.deepEqual(cluster.score_included_ids.sort(), ['F-001', 'F-002']);

  // ★ 제안 전용 — 입력 후보의 final_status를 변경하지 않는다.
  assert.equal(input[0].final_status, 'CONFIRMED');
  assert.equal(input[1].final_status, 'CONFIRMED');
  assert.equal(input[1].score_included, undefined);
});

test('suggestEquivalenceClusters: distinct root causes and targets yield no clusters', () => {
  const out = suggestEquivalenceClusters([
    { candidate_id: 'F-001', root_cause_location: 'a.go:1', final_status: 'CONFIRMED', severity: 'HIGH', evidence: { locations: ['a.go:1'] } },
    { candidate_id: 'F-002', root_cause_location: 'b.go:9', final_status: 'CONFIRMED', severity: 'LOW', evidence: { locations: ['b.go:9'] } },
  ]);
  assert.equal(out.cluster_count, 0);
});

test('suggestEquivalenceClusters: tier2 surfaces shared-target duplicates with differing root cause', () => {
  const out = suggestEquivalenceClusters([
    {
      candidate_id: 'F-010', remediation_key: 'add-auth-middleware', root_cause_location: 'auth.go:40',
      final_status: 'CONFIRMED', severity: 'HIGH', evidence: { locations: ['auth.go:40'] },
      affected_instances: [{ type: 'route', target: 'GET /metrics' }],
    },
    {
      candidate_id: 'F-011', remediation_key: 'guard-metrics-route', root_cause_location: 'routes/api.go:12',
      final_status: 'CONFIRMED', severity: 'MEDIUM', evidence: { locations: ['routes/api.go:12'] },
      affected_instances: [{ type: 'route', target: 'GET /metrics' }],
    },
  ]);

  // 서로 다른 root_cause 문자열 → tier1 0건; 같은 영향 대상 → tier2 'review' 1건.
  assert.equal(out.cluster_count, 1);
  assert.equal(out.clusters[0].confidence, 'review');
  assert.equal(out.clusters[0].basis, 'shared affected-instance target');
  assert.deepEqual(out.clusters[0].candidate_ids.sort(), ['F-010', 'F-011']);
  assert.equal(out.clusters[0].suggested_representative, 'F-010'); // HIGH > MEDIUM
});

test('suggestEquivalenceClusters: coarse file-type instances do not create tier2 clusters', () => {
  const out = suggestEquivalenceClusters([
    {
      candidate_id: 'F-030', root_cause_location: 'a.go:1', final_status: 'CONFIRMED', severity: 'HIGH',
      evidence: { locations: ['a.go:1'] }, affected_instances: [{ type: 'file', target: 'utils.go' }],
    },
    {
      candidate_id: 'F-031', root_cause_location: 'b.go:2', final_status: 'CONFIRMED', severity: 'LOW',
      evidence: { locations: ['b.go:2'] }, affected_instances: [{ type: 'file', target: 'utils.go' }],
    },
  ]);
  // 서로 다른 root cause + 같은 파일(거친 입자 type:file) → tier1 0, tier2도 0(file 제외).
  assert.equal(out.cluster_count, 0);
});

test('suggestEquivalenceClusters: tier2 does not double-emit what tier1 already grouped', () => {
  const out = suggestEquivalenceClusters([
    {
      candidate_id: 'F-020', remediation_key: 'shared-fix', final_status: 'CONFIRMED', severity: 'HIGH',
      evidence: { locations: ['x.go:1'] }, affected_instances: [{ type: 'route', target: '/a' }],
    },
    {
      candidate_id: 'F-021', remediation_key: 'shared-fix', final_status: 'CONFIRMED', severity: 'LOW',
      evidence: { locations: ['x.go:9'] }, affected_instances: [{ type: 'route', target: '/a' }],
    },
  ]);

  // 같은 remediation_key(tier1) + 같은 target(tier2 후보) → tier1 1건만, tier2 중복 제안 없음.
  assert.equal(out.cluster_count, 1);
  assert.equal(out.clusters[0].confidence, 'high');
});

test('validateLedger: excluded candidates require an exclusion reason', () => {
  const result = validateLedger([
    { candidate_id: 'F-014', final_status: 'EXCLUDED', severity: 'LOW' },
  ]);

  assert.equal(result.valid, false);
  assert.equal(result.errors[0].code, 'EXCLUSION_REASON_MISSING');
});

test('summarizeCandidates: EXCLUDED is preserved and excluded from score', () => {
  const candidates = [
    {
      candidate_id: 'F-014',
      final_status: 'EXCLUDED',
      severity: 'MEDIUM',
      exclusion_reason: 'Pure DoS item filtered by engagement policy',
    },
  ];

  const result = validateLedger(candidates);
  const summary = summarizeCandidates(candidates);

  assert.equal(result.valid, true);
  assert.equal(summary.excluded, 1);
  assert.equal(summary.by_status.EXCLUDED, 1);
  assert.equal(summary.score_included_counts.medium, 0);
  assert.equal(isScoreIncludedCandidate(candidates[0]), false);
});

test('calculatePentestRouteCoverage: requires route plus scenario for pending pentest', () => {
  const candidates = [
    {
      candidate_id: 'F-008',
      final_status: 'PENDING_PENTEST',
      severity: 'MEDIUM',
      routing: { pentest_route: 'LIVE_BUSINESS_FLOW' },
    },
    {
      candidate_id: 'F-010',
      final_status: 'PENDING_PENTEST',
      severity: 'LOW',
    },
  ];

  const result = calculatePentestRouteCoverage(candidates, [
    { scenario_id: 'S-008', candidate_id: 'F-008' },
  ]);

  assert.equal(result.total, 2);
  assert.equal(result.routed, 1);
  assert.deepEqual(result.missing, ['F-010']);
  assert.equal(result.coverage, 0.5);
});

// ─── 게이트 ↔ 템플릿 계약: raw-findings-ledger.template.yaml 스키마 그대로 채운
//     후보가 validator를 통과해야 한다 (A1 계약 결렬 회귀 방지) ───────────────

// 템플릿 렌더 결과를 모사: 미사용 placeholder는 빈 문자열로 남는다.
function templateShapedCandidate(overrides) {
  return {
    candidate_id: 'CAND-000',
    proposed_finding_id: '',
    final_finding_id: '',
    title: 'template-shaped candidate',
    source_phase: 'va',
    source_agent: 'va-auditor',
    dimension: 'A1',
    root_cause_location: 'src/auth.ts:10',
    remediation_key: 'fix-auth',
    affected_instances: [],
    severity_initial: 'MEDIUM',
    severity_current: 'MEDIUM',
    final_status: 'CANDIDATE',
    score_included: false,
    evidence: { class: 'Observed', locations: ['src/auth.ts:10'], live_evidence: [] },
    validity: { code_exists: 'true', reachable: 'likely', business_relevance: 'high', exploit_path: 'unverified' },
    prerequisites: { auth: 'unauth', data: 'none', environment: 'local' },
    routing: {
      verify_required: true,
      verify_reason: '',
      pentest_route: '',
      pentest_plan_id: '',
      required_access: '',
      external_system: '',
    },
    final_mapping: {
      folded_into: '',
      exclusion_reason: '',
      downgrade_reason: '',
      dispute_reason: '',
      ciso_decision: { method: '', final_severity: '', rationale: '' },
      next_step: '',
    },
    ...overrides,
  };
}

test('validateLedger: template-shaped PENDING_PENTEST/DOWNGRADED/DISPUTED/PENDING_EXTERNAL candidates pass', () => {
  const pendingPentest = templateShapedCandidate({
    candidate_id: 'CAND-001',
    final_status: 'PENDING_PENTEST',
    routing: {
      verify_required: true,
      verify_reason: '',
      pentest_route: 'LIVE_BUSINESS_FLOW',
      pentest_plan_id: 'S-001',
      required_access: '',
      external_system: '',
    },
  });
  const downgraded = templateShapedCandidate({
    candidate_id: 'CAND-002',
    final_status: 'DOWNGRADED',
    severity_current: 'LOW',
    final_mapping: {
      folded_into: '',
      exclusion_reason: '',
      downgrade_reason: 'Compensating control caps impact to LOW',
      dispute_reason: '',
      ciso_decision: { method: '', final_severity: '', rationale: '' },
      next_step: '',
    },
  });
  const disputed = templateShapedCandidate({
    candidate_id: 'CAND-003',
    final_status: 'DISPUTED',
    final_mapping: {
      folded_into: '',
      exclusion_reason: '',
      downgrade_reason: '',
      dispute_reason: 'VA claims HIGH, Verifier claims MEDIUM',
      ciso_decision: { method: '', final_severity: '', rationale: '' },
      next_step: '',
    },
  });
  const pendingExternal = templateShapedCandidate({
    candidate_id: 'CAND-004',
    final_status: 'PENDING_EXTERNAL',
    routing: {
      verify_required: false,
      verify_reason: '',
      pentest_route: 'EXTERNAL_SYSTEM_REQUIRED',
      pentest_plan_id: '',
      required_access: 'PG admin console',
      external_system: 'payment-gateway',
    },
  });

  const result = validateLedger([pendingPentest, downgraded, disputed, pendingExternal]);
  assert.deepEqual(result.errors, []);
  assert.equal(result.valid, true);

  const coverage = calculatePentestRouteCoverage(
    [pendingPentest],
    [{ scenario_id: 'S-001', candidate_id: 'CAND-001' }]
  );
  assert.equal(coverage.coverage, 1);
});

test('calculatePentestRouteCoverage: routing.pentest_plan_id links candidate to plan scenario', () => {
  const candidate = {
    candidate_id: 'CAND-010',
    final_status: 'PENDING_PENTEST',
    severity_current: 'MEDIUM',
    routing: { pentest_route: 'LIVE_UNAUTH', pentest_plan_id: 'S-010' },
  };

  // plan scenario가 candidate_id 역참조 없이 scenario_id만 노출해도 매칭된다.
  const matched = calculatePentestRouteCoverage([candidate], [{ scenario_id: 'S-010' }]);
  assert.equal(matched.routed, 1);
  assert.equal(matched.coverage, 1);
});

test('validateLedger: template-shaped PENDING_PENTEST without pentest_route still errors', () => {
  const result = validateLedger([
    templateShapedCandidate({
      candidate_id: 'CAND-011',
      final_status: 'PENDING_PENTEST',
      // routing.pentest_route가 빈 문자열(미기록) — 게이트 강제력 유지 확인
    }),
  ]);

  assert.equal(result.valid, false);
  assert.equal(result.errors[0].code, 'PENDING_PENTEST_ROUTE_MISSING');
});

test('validateLedger: template-shaped DISPUTED without dispute_reason still errors', () => {
  const result = validateLedger([
    templateShapedCandidate({ candidate_id: 'CAND-012', final_status: 'DISPUTED' }),
  ]);

  assert.equal(result.valid, false);
  assert.equal(result.errors[0].code, 'DISPUTE_REASON_MISSING');
});

test('validateLedger: template-shaped DOWNGRADED without downgrade_reason still errors', () => {
  const result = validateLedger([
    templateShapedCandidate({
      candidate_id: 'CAND-013',
      final_status: 'DOWNGRADED',
      severity_current: 'LOW',
    }),
  ]);

  assert.equal(result.valid, false);
  assert.equal(result.errors[0].code, 'DOWNGRADE_REASON_MISSING');
});

test('validateLedger: template-shaped PENDING_EXTERNAL without access context still errors', () => {
  const result = validateLedger([
    templateShapedCandidate({ candidate_id: 'CAND-014', final_status: 'PENDING_EXTERNAL' }),
  ]);

  assert.equal(result.valid, false);
  assert.equal(result.errors[0].code, 'PENDING_EXTERNAL_CONTEXT_MISSING');
});

// ─── Self-Verify validity 검사 (P1-8, fail-soft) ───────────────────────────

test('validity: CONFIRMED CRITICAL/HIGH with all three validity fields absent is an error', () => {
  const result = validateLedger([
    {
      candidate_id: 'F-020',
      final_status: 'CONFIRMED',
      severity: 'HIGH',
      evidence: { locations: ['src/auth.ts:10'] },
      // validity 전체 부재 → Self-Verify 미수행으로 간주
    },
  ]);

  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.code === 'CONFIRMED_VALIDITY_MISSING'));
});

test('validity: CONFIRMED HIGH with partial validity is a warning, not an error', () => {
  const result = validateLedger([
    {
      candidate_id: 'F-021',
      final_status: 'CONFIRMED',
      severity: 'HIGH',
      evidence: { locations: ['src/auth.ts:10'] },
      validity: { reachable: 'confirmed' }, // business_relevance / exploit_path 부재
    },
  ]);

  assert.equal(result.valid, true);
  assert.equal(result.errors.length, 0);
  assert.ok(result.warnings.some((w) => w.code === 'CONFIRMED_VALIDITY_PARTIAL'));
});

test('validity: CONFIRMED MEDIUM with all validity fields absent is only a warning', () => {
  const result = validateLedger([
    {
      candidate_id: 'F-022',
      final_status: 'CONFIRMED',
      severity: 'MEDIUM',
      evidence: { locations: ['src/dto.ts:21'] },
    },
  ]);

  assert.equal(result.valid, true);
  assert.equal(result.errors.length, 0);
  assert.ok(result.warnings.some((w) => w.code === 'CONFIRMED_VALIDITY_MISSING'));
});

test('validity: CONFIRMED HIGH with full validity passes with no warnings', () => {
  const result = validateLedger([
    {
      candidate_id: 'F-023',
      final_status: 'CONFIRMED',
      severity: 'HIGH',
      evidence: { locations: ['src/auth.ts:10'] },
      validity: { reachable: 'confirmed', business_relevance: 'high', exploit_path: 'confirmed' },
    },
  ]);

  assert.equal(result.valid, true);
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.warnings, []);
});

test('validity: non-CONFIRMED statuses are not subject to validity checks', () => {
  const issues = appraiseValidity({
    candidate_id: 'F-024',
    final_status: 'BACKLOG',
    severity: 'HIGH',
  });
  assert.deepEqual(issues, { errors: [], warnings: [] });
});

test('validity: empty-string template placeholders count as absent', () => {
  const issues = appraiseValidity({
    candidate_id: 'F-025',
    final_status: 'CONFIRMED',
    severity: 'CRITICAL',
    validity: { reachable: '', business_relevance: '', exploit_path: '' },
  });
  assert.equal(issues.errors.length, 1);
  assert.equal(issues.errors[0].code, 'CONFIRMED_VALIDITY_MISSING');
});

test('validateLedger: accepts a fully classified candidate ledger', () => {
  const result = validateLedger([
    {
      candidate_id: 'F-012',
      final_status: 'BACKLOG',
      severity: 'LOW',
      evidence: { locations: ['src/validation.ts:42'] },
      final_mapping: { rationale: 'Valid low-risk backlog item' },
    },
    {
      candidate_id: 'F-013',
      final_status: 'OUT_OF_SCOPE',
      severity: 'LOW',
      exclusion_reason: 'Dependency-owned endpoint',
    },
  ]);

  assert.equal(result.valid, true);
  assert.equal(result.summary.publish_allowed, true);
});

// --- CLI 진입점 (require.main === module) ---
{
  const { spawnSync } = require('node:child_process');
  const fs = require('node:fs');
  const os = require('node:os');
  const path = require('node:path');
  const yaml = require('js-yaml');
  const LEDGER_CLI = path.resolve(__dirname, '..', 'candidate-ledger.js');

  const runCli = (args) => {
    const r = spawnSync('node', [LEDGER_CLI, ...args], { encoding: 'utf8', timeout: 10_000 });
    return { code: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
  };
  const writeYaml = (obj) => {
    const p = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-ledger-cli-')), 'ledger.yaml');
    fs.writeFileSync(p, yaml.dump(obj));
    return p;
  };

  test('CLI ledger: valid ledger exits 0', () => {
    const p = writeYaml({ candidates: [
      { candidate_id: 'C-1', final_status: 'EXCLUDED', severity: 'LOW', exclusion_reason: 'test' },
    ] });
    const r = runCli(['validate', '--ledger', p]);
    assert.equal(r.code, 0, r.stderr);
    assert.equal(JSON.parse(r.stdout).valid, true);
  });

  test('CLI ledger: errors exit 2 with code listing', () => {
    const p = writeYaml({ candidates: [
      { candidate_id: 'C-1', status: 'CANDIDATE', severity: 'MEDIUM' },
    ] });
    const r = runCli(['validate', '--ledger', p]);
    assert.equal(r.code, 2);
    assert.match(r.stderr, /CANDIDATE_UNCLASSIFIED/);
  });

  test('CLI ledger: missing file exits 1', () => {
    const r = runCli(['validate', '--ledger', '/nonexistent/ledger.yaml']);
    assert.equal(r.code, 1);
  });

  test('CLI ledger: no command exits 1', () => {
    const p = writeYaml({ candidates: [] });
    const r = runCli(['--ledger', p]);
    assert.equal(r.code, 1);
  });
}
