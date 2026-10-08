'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  mergeCandidateClassifications,
  validateEquivalenceReview,
  applyDeterministicGates,
  validateReportGate,
} = require('../report-gate');

test('invalid equivalence decisions include actionable expected values for all callers', () => {
  for (const decision of ['REJECT', 'FOLD', 'FOLDED_INTO']) {
    const result = validateEquivalenceReview(completeReview(1, [{ group_id: 'G1', members: ['F-001'], decision }]), [], { requireEquivalenceReview: true });
    const error = result.errors.find(e => e.code === 'EQUIVALENCE_GROUP_DECISION_INVALID');
    assert.deepEqual(error.expected, ['MERGE', 'SPLIT', 'KEEP']);
    assert.equal(error.actual, decision);
    assert.equal(error.group_id, 'G1');
    assert.match(error.message, /Allowed decisions: MERGE, SPLIT, KEEP/);
  }
});

function completeReview(reviewedCandidateCount = 1, groups = []) {
  return {
    status: 'COMPLETE',
    reviewed_candidate_count: reviewedCandidateCount,
    groups,
    unresolved: [],
  };
}

test('mergeCandidateClassifications: overlays final status without losing evidence', () => {
  const merged = mergeCandidateClassifications(
    {
      candidates: [
        {
          candidate_id: 'F-007',
          status: 'CANDIDATE',
          severity: 'MEDIUM',
          evidence: { locations: ['src/dto.ts:10'] },
        },
      ],
    },
    {
      final_classification: [
        {
          candidate_id: 'F-007',
          final_status: 'BACKLOG',
          final_mapping: { rationale: 'Valid but deferred' },
        },
      ],
    }
  );

  assert.equal(merged.length, 1);
  assert.equal(merged[0].final_status, 'BACKLOG');
  assert.deepEqual(merged[0].evidence.locations, ['src/dto.ts:10']);
});

test('validateReportGate: fails when a raw candidate remains unclassified', () => {
  const result = validateReportGate({
    ledger: {
      candidates: [
        { candidate_id: 'F-007', status: 'CANDIDATE', severity: 'MEDIUM' },
      ],
    },
    classification: {
      equivalence_review: completeReview(0),
    },
    reportedScore: 100,
  });

  assert.equal(result.ok, false);
  assert.equal(result.errors.some((e) => e.code === 'CANDIDATE_UNCLASSIFIED'), true);
});

test('validateReportGate: empty findings require an explicit host allowance', () => {
  const input = {
    ledger: { candidates: [] },
    classification: { equivalence_review: completeReview(0) },
    reportedScore: 100,
  };
  const blocked = validateReportGate(input);
  assert.equal(blocked.errors.some((error) => error.code === 'RAW_LEDGER_MISSING'), true);

  const allowed = validateReportGate({ ...input, allowEmptyCandidates: true });
  assert.equal(allowed.errors.some((error) => error.code === 'RAW_LEDGER_MISSING'), false);
  assert.equal(allowed.ok, true, JSON.stringify(allowed.errors));
});

// 결과서 provenance(브랜치+커밋해시) 강제 — 추적성.
const cleanCand = [
  { candidate_id: 'F-200', final_status: 'CONFIRMED', severity: 'LOW', evidence: { locations: ['a.go:1'] } },
];

test('validateReportGate: requireProvenance blocks when branch/commit missing (PROVENANCE_MISSING)', () => {
  const r = validateReportGate({
    ledger: { candidates: cleanCand },
    classification: { equivalence_review: completeReview(1) },
    requireScore: false,
    requireProvenance: true,
  });
  assert.equal(r.ok, false);
  assert.equal(r.errors.some((e) => e.code === 'PROVENANCE_MISSING'), true);
});

test('validateReportGate: provenance from manifest satisfies requireProvenance', () => {
  const r = validateReportGate({
    ledger: { candidates: cleanCand },
    classification: { equivalence_review: completeReview(1) },
    manifest: { git_branch: 'main', git_head: 'a'.repeat(40) },
    requireScore: false,
    requireProvenance: true,
  });
  assert.equal(r.errors.some((e) => e.code === 'PROVENANCE_MISSING'), false);
  assert.equal(r.provenance.git_branch, 'main');
  assert.equal(r.provenance.git_commit, 'a'.repeat(40));
  assert.equal(r.ok, true);
});

test('validateReportGate: missing provenance is warning-only by default (backward compat)', () => {
  const r = validateReportGate({
    ledger: { candidates: cleanCand },
    classification: { equivalence_review: completeReview(1) },
    requireScore: false,
  });
  assert.equal(r.errors.some((e) => e.code === 'PROVENANCE_MISSING'), false);
  assert.equal(r.warnings.some((w) => w.code === 'PROVENANCE_MISSING'), true);
});

test('validateReportGate: provenance falls back field-by-field across sources (P4)', () => {
  const r = validateReportGate({
    ledger: { candidates: cleanCand },
    classification: {
      equivalence_review: completeReview(1),
      provenance: { git_branch: 'release/1.0', git_head: 'b'.repeat(40) },
    },
    // manifest 존재하나 git 필드가 비어 있음(비-git) → classification.provenance로 채워야 함.
    manifest: { git_branch: null, git_head: null },
    requireScore: false,
    requireProvenance: true,
  });
  assert.equal(r.errors.some((e) => e.code === 'PROVENANCE_MISSING'), false);
  assert.equal(r.provenance.git_branch, 'release/1.0');
  assert.equal(r.provenance.git_commit, 'b'.repeat(40));
});

// GAP-1 하드 backstop: 같은 root/remediation 클러스터의 score_included 2건↑가
// MERGE도 SPLIT/KEEP 선언도 없으면 발행 차단(과거 warning → error 승격).
const dupPair = [
  {
    candidate_id: 'F-101', remediation_key: 'add-auth-to-metrics', final_status: 'CONFIRMED',
    severity: 'MEDIUM', evidence: { locations: ['routes/metrics.go:5'] },
  },
  {
    candidate_id: 'F-102', remediation_key: 'add-auth-to-metrics', final_status: 'CONFIRMED',
    severity: 'MEDIUM', evidence: { locations: ['routes/metrics.go:5'] },
  },
];

test('validateReportGate: blocks unfolded duplicate cluster left as separate score-included findings', () => {
  const result = validateReportGate({
    ledger: { candidates: dupPair },
    classification: { equivalence_review: completeReview(2) }, // 그룹 선언 없음
    requireScore: false,
  });

  assert.equal(result.ok, false);
  const err = result.errors.find((e) => e.code === 'UNFOLDED_ROOT_CAUSE_GROUP');
  assert.ok(err, 'expected blocking UNFOLDED_ROOT_CAUSE_GROUP error');
  assert.deepEqual(err.candidates.sort(), ['F-101', 'F-102']);
});

test('validateReportGate: explicit SPLIT declaration overrides the unfolded-cluster block', () => {
  const result = validateReportGate({
    ledger: { candidates: dupPair },
    classification: {
      equivalence_review: completeReview(2, [
        {
          group_id: 'G-1', decision: 'SPLIT', members: ['F-101', 'F-102'],
          split_reason: 'Different trust boundaries despite shared remediation key',
        },
      ]),
    },
    requireScore: false,
  });

  assert.equal(result.errors.some((e) => e.code === 'UNFOLDED_ROOT_CAUSE_GROUP'), false);
  // F-C: 정상 선언된 그룹은 중복 warning도 남기지 않는다.
  assert.equal(result.warnings.some((w) => w.code === 'UNFOLDED_ROOT_CAUSE_GROUP'), false);
  assert.equal(result.ok, true);
});

test('validateReportGate: KEEP without rationale does not override the unfolded-cluster block (F-A)', () => {
  const result = validateReportGate({
    ledger: { candidates: dupPair },
    classification: {
      equivalence_review: completeReview(2, [
        { group_id: 'G-1', decision: 'KEEP', members: ['F-101', 'F-102'] }, // 사유 없음
      ]),
    },
    requireScore: false,
  });

  assert.equal(result.ok, false);
  assert.equal(result.errors.some((e) => e.code === 'UNFOLDED_ROOT_CAUSE_GROUP'), true);
  assert.equal(result.errors.some((e) => e.code === 'EQUIVALENCE_KEEP_REASON_MISSING'), true);
});

test('validateReportGate: KEEP with rationale overrides the unfolded-cluster block (F-A)', () => {
  const result = validateReportGate({
    ledger: { candidates: dupPair },
    classification: {
      equivalence_review: completeReview(2, [
        {
          group_id: 'G-1', decision: 'KEEP', members: ['F-101', 'F-102'],
          keep_reason: 'Same remediation slug but independent vulns on distinct trust boundaries',
        },
      ]),
    },
    requireScore: false,
  });

  assert.equal(result.errors.some((e) => e.code === 'UNFOLDED_ROOT_CAUSE_GROUP'), false);
  assert.equal(result.errors.some((e) => e.code === 'EQUIVALENCE_KEEP_REASON_MISSING'), false);
  assert.equal(result.ok, true);
});

test('validateReportGate: a FOLDED_INTO member clears the unfolded-cluster block', () => {
  const result = validateReportGate({
    ledger: {
      candidates: [
        dupPair[0],
        {
          candidate_id: 'F-102', remediation_key: 'add-auth-to-metrics', final_status: 'FOLDED_INTO',
          severity: 'MEDIUM', evidence: { locations: ['routes/metrics.go:5'] },
          final_mapping: { folded_into: 'F-101' },
        },
      ],
    },
    classification: { equivalence_review: completeReview(1) },
    requireScore: false,
  });

  assert.equal(result.errors.some((e) => e.code === 'UNFOLDED_ROOT_CAUSE_GROUP'), false);
  assert.equal(result.ok, true);
});

test('validateReportGate: blocks unresolved DISPUTED candidate at publish', () => {
  const result = validateReportGate({
    ledger: {
      candidates: [
        { candidate_id: 'F-009', final_status: 'DISPUTED', severity: 'CRITICAL', dispute_reason: 'severity 이견' },
      ],
    },
    classification: { equivalence_review: completeReview(0) },
    requireScore: false,
  });
  assert.equal(result.ok, false);
  assert.equal(result.errors.some((e) => e.code === 'DISPUTED_UNRESOLVED_AT_PUBLISH'), true);
});

test('validateReportGate: allows DISPUTED candidate with CISO decision', () => {
  const result = validateReportGate({
    ledger: {
      candidates: [
        {
          candidate_id: 'F-010',
          final_status: 'DISPUTED',
          severity: 'HIGH',
          dispute_reason: 'severity 이견',
          ciso_decision: 'accept-as-HIGH',
        },
      ],
    },
    classification: { equivalence_review: completeReview(0) },
    requireScore: false,
  });
  assert.equal(result.errors.some((e) => e.code === 'DISPUTED_UNRESOLVED_AT_PUBLISH'), false);
});

test('validateReportGate: empty template-rendered ciso_decision slot does not resolve DISPUTED', () => {
  const result = validateReportGate({
    ledger: {
      candidates: [
        {
          candidate_id: 'F-011',
          final_status: 'DISPUTED',
          severity: 'HIGH',
          final_mapping: {
            dispute_reason: 'VA HIGH vs Verifier MEDIUM',
            // 템플릿이 빈 placeholder로 렌더한 슬롯 — 해소로 오인 금지
            ciso_decision: { method: '', final_severity: '', rationale: '' },
          },
        },
      ],
    },
    classification: { equivalence_review: completeReview(0) },
    requireScore: false,
  });
  assert.equal(result.ok, false);
  assert.equal(result.errors.some((e) => e.code === 'DISPUTED_UNRESOLVED_AT_PUBLISH'), true);
});

test('validateReportGate: final_mapping.ciso_decision write-back resolves DISPUTED', () => {
  const result = validateReportGate({
    ledger: {
      candidates: [
        {
          candidate_id: 'F-012',
          final_status: 'DISPUTED',
          severity: 'HIGH',
          final_mapping: {
            dispute_reason: 'VA HIGH vs Verifier MEDIUM',
            ciso_decision: {
              method: 'conservative_default',
              final_severity: 'HIGH',
              rationale: '근거 대등 — 보수적 판단 채택',
            },
          },
        },
      ],
    },
    classification: { equivalence_review: completeReview(0) },
    requireScore: false,
  });
  assert.equal(result.errors.some((e) => e.code === 'DISPUTED_UNRESOLVED_AT_PUBLISH'), false);
});

test('validateReportGate: template-shaped PENDING_PENTEST with pentest_plan_id passes route coverage', () => {
  const result = validateReportGate({
    ledger: {
      candidates: [
        {
          candidate_id: 'CAND-001',
          final_status: 'PENDING_PENTEST',
          severity: 'MEDIUM',
          routing: {
            verify_required: true,
            verify_reason: '',
            pentest_route: 'LIVE_BUSINESS_FLOW',
            pentest_plan_id: 'S-001',
            required_access: '',
            external_system: '',
          },
        },
      ],
    },
    classification: { equivalence_review: completeReview(1) },
    pentestPlan: { scenarios: [{ scenario_id: 'S-001', candidate_id: 'CAND-001' }] },
    reportedScore: 100,
  });

  assert.equal(result.ok, true);
  assert.equal(result.route_coverage.coverage, 1);
});

test('validateReportGate: fails on score formula mismatch', () => {
  const result = validateReportGate({
    ledger: {
      candidates: [
        {
          candidate_id: 'F-001',
          final_status: 'CONFIRMED',
          severity: 'HIGH',
          evidence: { locations: ['src/auth.ts:10'] },
          validity: {
            reachable: 'yes — public route',
            business_relevance: 'auth bypass on payment flow',
            exploit_path: 'unauth request -> handler',
          },
        },
        {
          candidate_id: 'F-002',
          final_status: 'CONFIRMED',
          severity: 'MEDIUM',
          evidence: { locations: ['src/auth.ts:20'] },
        },
      ],
    },
    classification: {
      equivalence_review: completeReview(2),
    },
    reportedScore: 90,
  });

  assert.equal(result.ok, false);
  assert.equal(result.errors.some((e) => e.code === 'SCORE_FORMULA_MISMATCH'), true);
  assert.equal(result.score.expected, 87);
});

test('validateReportGate: fails when an equivalence merge still counts multiple findings', () => {
  const result = validateReportGate({
    ledger: {
      candidates: [
        {
          candidate_id: 'F-001',
          final_status: 'CONFIRMED',
          severity: 'HIGH',
          evidence: { locations: ['routes/testbed.go:10'] },
          affected_instances: [{ route: 'GET /testbed/payments' }],
        },
        {
          candidate_id: 'F-002',
          final_status: 'CONFIRMED',
          severity: 'MEDIUM',
          evidence: { locations: ['routes/testbed.go:22'] },
        },
      ],
    },
    classification: {
      equivalence_review: completeReview(2, [
        {
          group_id: 'DG-001',
          decision: 'MERGE',
          representative: 'F-001',
          members: ['F-001', 'F-002'],
          affected_instances: [{ route: 'GET /testbed/payments' }, { route: 'POST /testbed/checkout' }],
          rationale: 'Same missing auth control affects multiple routes.',
        },
      ]),
    },
    reportedScore: 87,
  });

  assert.equal(result.ok, false);
  assert.equal(result.errors.some((e) => e.code === 'MERGED_GROUP_MULTIPLE_SCORE_INCLUDED'), true);
});

test('validateReportGate: passes when equivalence merge folds repeated instances', () => {
  const result = validateReportGate({
    ledger: {
      candidates: [
        {
          candidate_id: 'F-001',
          final_status: 'CONFIRMED',
          severity: 'HIGH',
          evidence: { locations: ['routes/testbed.go:10'] },
          affected_instances: [
            { route: 'GET /testbed/payments', evidence: 'routes/testbed.go:10' },
            { route: 'POST /testbed/checkout', evidence: 'routes/testbed.go:22' },
          ],
          validity: {
            reachable: 'yes — public route',
            business_relevance: 'auth bypass on payment flow',
            exploit_path: 'unauth request -> handler',
          },
        },
        {
          candidate_id: 'F-002',
          final_status: 'FOLDED_INTO',
          severity: 'MEDIUM',
          evidence: { locations: ['routes/testbed.go:22'] },
          final_mapping: { folded_into: 'F-001' },
        },
      ],
    },
    classification: {
      equivalence_review: completeReview(2, [
        {
          group_id: 'DG-001',
          decision: 'MERGE',
          representative: 'F-001',
          members: ['F-001', 'F-002'],
          rationale: 'Same missing auth control affects multiple routes.',
        },
      ]),
    },
    reportedScore: 90,
  });

  assert.equal(result.ok, true);
  assert.equal(result.summary.score_included_counts.high, 1);
  assert.equal(result.summary.score_included_counts.medium, 0);
});

test('validateReportGate: fails when final equivalence review is missing', () => {
  const result = validateReportGate({
    ledger: {
      candidates: [
        {
          candidate_id: 'F-001',
          final_status: 'CONFIRMED',
          severity: 'HIGH',
          evidence: { locations: ['src/auth.ts:10'] },
          validity: {
            reachable: 'yes — public route',
            business_relevance: 'auth bypass on payment flow',
            exploit_path: 'unauth request -> handler',
          },
        },
      ],
    },
    reportedScore: 90,
  });

  assert.equal(result.ok, false);
  assert.equal(result.errors.some((e) => e.code === 'EQUIVALENCE_REVIEW_MISSING'), true);
});

test('validateReportGate: fails when split decision lacks reason', () => {
  const result = validateReportGate({
    ledger: {
      candidates: [
        {
          candidate_id: 'F-001',
          final_status: 'CONFIRMED',
          severity: 'HIGH',
          evidence: { locations: ['src/auth.ts:10'] },
          validity: {
            reachable: 'yes — public route',
            business_relevance: 'auth bypass on payment flow',
            exploit_path: 'unauth request -> handler',
          },
        },
        {
          candidate_id: 'F-002',
          final_status: 'CONFIRMED',
          severity: 'MEDIUM',
          evidence: { locations: ['src/auth.ts:30'] },
        },
      ],
    },
    classification: {
      equivalence_review: completeReview(2, [
        {
          group_id: 'DG-002',
          decision: 'SPLIT',
          members: ['F-001', 'F-002'],
        },
      ]),
    },
    reportedScore: 87,
  });

  assert.equal(result.ok, false);
  assert.equal(result.errors.some((e) => e.code === 'EQUIVALENCE_SPLIT_REASON_MISSING'), true);
});

test('validateReportGate: fails when final score is missing', () => {
  const result = validateReportGate({
    ledger: {
      candidates: [
        {
          candidate_id: 'F-001',
          final_status: 'CONFIRMED',
          severity: 'HIGH',
          evidence: { locations: ['src/auth.ts:10'] },
          validity: {
            reachable: 'yes — public route',
            business_relevance: 'auth bypass on payment flow',
            exploit_path: 'unauth request -> handler',
          },
        },
      ],
    },
    classification: {
      equivalence_review: completeReview(1),
    },
  });

  assert.equal(result.ok, false);
  assert.equal(result.errors.some((e) => e.code === 'SCORE_NOT_PROVIDED'), true);
});

// ─────────────────────────────────────────────────────────────
// [P1-7] Strict Formula Write-시점 검증 (fail-soft)
// classification의 숫자 security_score가 있으면 역산 대조, 부재 시 에러 없음
// ─────────────────────────────────────────────────────────────

function oneHighLedger() {
  return {
    candidates: [
      {
        candidate_id: 'F-001',
        final_status: 'CONFIRMED',
        severity: 'HIGH',
        evidence: { locations: ['src/auth.ts:10'] },
        validity: {
          reachable: 'yes — public route',
          business_relevance: 'auth bypass on payment flow',
          exploit_path: 'unauth request -> handler',
        },
      },
    ],
  };
}

test('P1-7: numeric security_score in classification matching formula passes', () => {
  const result = validateReportGate({
    ledger: oneHighLedger(),
    classification: { equivalence_review: completeReview(1), security_score: 90 },
    requireScore: false,
  });
  assert.equal(result.ok, true, JSON.stringify(result.errors));
  assert.equal(result.score.valid, true);
});

test('P1-7: numeric security_score mismatching formula blocks', () => {
  const result = validateReportGate({
    ledger: oneHighLedger(),
    classification: { equivalence_review: completeReview(1), security_score: 95 },
    requireScore: false,
  });
  assert.equal(result.ok, false);
  assert.equal(result.errors.some((e) => e.code === 'SCORE_FORMULA_MISMATCH'), true);
});

test('P1-7: numeric-string security_score is recognized and checked', () => {
  const result = validateReportGate({
    ledger: oneHighLedger(),
    classification: { equivalence_review: completeReview(1), security_score: '90' },
    requireScore: false,
  });
  assert.equal(result.ok, true, JSON.stringify(result.errors));
  assert.equal(result.score.valid, true);
});

test('P1-7: empty/non-numeric security_score placeholder is treated as absent (no error)', () => {
  for (const placeholder of ['', '   ', 'TBD', null]) {
    const result = validateReportGate({
      ledger: oneHighLedger(),
      classification: { equivalence_review: completeReview(1), security_score: placeholder },
      requireScore: false,
    });
    assert.equal(result.ok, true, `placeholder ${JSON.stringify(placeholder)}: ${JSON.stringify(result.errors)}`);
    assert.equal(result.warnings.some((e) => e.code === 'SCORE_NOT_PROVIDED'), true);
  }
});

test('validateReportGate: can warn on missing score in draft mode', () => {
  const result = validateReportGate({
    ledger: {
      candidates: [
        {
          candidate_id: 'F-001',
          final_status: 'CONFIRMED',
          severity: 'HIGH',
          evidence: { locations: ['src/auth.ts:10'] },
          validity: {
            reachable: 'yes — public route',
            business_relevance: 'auth bypass on payment flow',
            exploit_path: 'unauth request -> handler',
          },
        },
      ],
    },
    classification: {
      equivalence_review: completeReview(1),
    },
    requireScore: false,
  });

  assert.equal(result.ok, true);
  assert.equal(result.warnings.some((e) => e.code === 'SCORE_NOT_PROVIDED'), true);
});

test('validateReportGate: fails when pending pentest lacks route coverage', () => {
  const result = validateReportGate({
    ledger: {
      candidates: [
        {
          candidate_id: 'F-008',
          final_status: 'PENDING_PENTEST',
          severity: 'MEDIUM',
          routing: { pentest_route: 'LIVE_BUSINESS_FLOW' },
        },
      ],
    },
    classification: {
      equivalence_review: completeReview(1),
    },
    pentestPlan: { scenarios: [] },
    reportedScore: 100,
  });

  assert.equal(result.ok, false);
  assert.equal(result.errors.some((e) => e.code === 'PENTEST_ROUTE_COVERAGE_INCOMPLETE'), true);
});

test('validateReportGate: passes when backlog, pending, route, and score are coherent', () => {
  const result = validateReportGate({
    ledger: {
      candidates: [
        {
          candidate_id: 'F-001',
          final_status: 'CONFIRMED',
          severity: 'HIGH',
          evidence: { locations: ['src/auth.ts:10'] },
          validity: {
            reachable: 'yes — public route',
            business_relevance: 'auth bypass on payment flow',
            exploit_path: 'unauth request -> handler',
          },
        },
        {
          candidate_id: 'F-007',
          final_status: 'BACKLOG',
          severity: 'MEDIUM',
          evidence: { locations: ['src/dto.ts:20'] },
          final_mapping: { rationale: 'Valid but deferred' },
        },
        {
          candidate_id: 'F-008',
          final_status: 'PENDING_PENTEST',
          severity: 'MEDIUM',
          routing: { pentest_route: 'LIVE_BUSINESS_FLOW' },
          required_access: 'merchant callback receiver',
        },
        {
          candidate_id: 'F-009',
          final_status: 'EXCLUDED',
          severity: 'MEDIUM',
          exclusion_reason: 'Pure DoS item filtered by engagement policy',
        },
      ],
    },
    classification: {
      equivalence_review: completeReview(4),
    },
    pentestPlan: {
      scenarios: [
        { scenario_id: 'S-008', candidate_id: 'F-008' },
      ],
    },
    reportedScore: 90,
  });

  assert.equal(result.ok, true);
  assert.equal(result.summary.total, 4);
  assert.equal(result.summary.excluded, 1);
  assert.equal(result.summary.score_included_counts.medium, 0);
  assert.equal(result.route_coverage.coverage, 1);
});

// ---------------------------------------------------------------------------
// 결정론 게이트 배선 (로드맵 #2): cite-check(#3) + poc-gate(#4)
// ---------------------------------------------------------------------------

// --- poc-gate (#4) ---

test('poc-gate: default policy leaves CONFIRMED without poc_artifact intact (no over-block)', () => {
  const result = validateReportGate({
    ledger: {
      candidates: [
        { candidate_id: 'F-1', final_status: 'CONFIRMED', severity: 'LOW', evidence: { locations: ['a.go:1'] } },
      ],
    },
    classification: { equivalence_review: completeReview(1) },
    requireScore: false,
  });
  assert.equal(result.ok, true, JSON.stringify(result.errors));
  assert.equal(result.gate_summary.poc_gate.missing_artifact, 1);
  assert.equal(result.gate_summary.poc_gate.downgraded, 0);
});

test('poc-gate: verified binding earns gate-owned verifiedAt', () => {
  const gate = applyDeterministicGates(
    [
      {
        candidate_id: 'F-1',
        final_status: 'CONFIRMED',
        location: 'auth.go:42',
        poc_artifact: { observed: 'curl -> 200; sink reached at auth.go:42 with tainted input' },
      },
    ],
    { now: 'gate:TEST' }
  );
  assert.equal(gate.gateSummary.poc_gate.verified, 1);
  assert.equal(gate.candidates[0].verifiedAt, 'gate:TEST');
  assert.equal(gate.candidates[0].poc_gate.verified, true);
});

test('poc-gate: CONFIRMED with unobserved signature is downgraded and blocks publish', () => {
  const result = validateReportGate({
    ledger: {
      candidates: [
        {
          candidate_id: 'F-1',
          final_status: 'CONFIRMED',
          severity: 'HIGH',
          location: 'auth.go:42',
          evidence: { locations: ['auth.go:42'] },
          poc_artifact: { observed: 'curl -> 200 OK, nothing relevant observed' },
        },
      ],
    },
    classification: { equivalence_review: completeReview(1) },
    requireScore: false,
  });
  assert.equal(result.ok, false);
  assert.equal(result.errors.some((e) => e.code === 'CANDIDATE_UNCLASSIFIED'), true);
  assert.equal(result.gate_summary.poc_gate.downgraded, 1);
});

test('poc-gate: self-stamped verifiedAt is rejected and re-owned by the gate', () => {
  const gate = applyDeterministicGates(
    [
      {
        candidate_id: 'F-1',
        final_status: 'CONFIRMED',
        location: 'x.go:1',
        verifiedAt: 'agent:cheat',
        poc_artifact: { observed: 'reached x.go:1' },
      },
    ],
    { now: 'gate:TEST' }
  );
  assert.equal(gate.gateSummary.poc_gate.self_stamped, 1);
  assert.equal(gate.candidates[0].verifiedAt, 'gate:TEST');
  assert.equal(gate.gateWarnings.some((w) => w.code === 'POC_SELF_STAMP_REJECTED'), true);
});

test('poc-gate: requirePocBinding blocks CONFIRMED lacking a poc_artifact', () => {
  const result = validateReportGate({
    ledger: {
      candidates: [
        { candidate_id: 'F-1', final_status: 'CONFIRMED', severity: 'HIGH', evidence: { locations: ['a.go:1'] } },
      ],
    },
    classification: { equivalence_review: completeReview(1) },
    requireScore: false,
    requirePocBinding: true,
  });
  assert.equal(result.ok, false);
  assert.equal(result.gate_summary.poc_gate.downgraded, 1);
  assert.equal(result.errors.some((e) => e.code === 'CANDIDATE_UNCLASSIFIED'), true);
});

test('poc-gate: requirePocBinding keeps CONFIRMED WITH contract-compliant poc_artifact (gate-owned verifiedAt)', () => {
  // #3 활성화 회귀: poc_바인딩_방출 계약(poc_artifact.observed에 poc_signature 실재)을 준수한 CONFIRMED은
  // requirePocBinding=on(활성)에서도 강등되지 않고, 게이트가 verifiedAt을 부여한다(에이전트 self-stamp 아님).
  const gate = applyDeterministicGates(
    [
      {
        candidate_id: 'PT-1',
        final_status: 'CONFIRMED',
        severity: 'HIGH',
        location: 'multipart.py:219',
        poc_signature: 'multipart.py:219',
        poc_artifact: { observed: 'curl → measured N=40 time=11.0001s; catastrophic backtracking at multipart.py:219' },
      },
    ],
    { requirePocBinding: true, now: 'gate:TEST' }
  );
  assert.equal(gate.gateSummary.poc_gate.verified, 1);
  assert.equal(gate.gateSummary.poc_gate.downgraded, 0);
  assert.equal(gate.candidates[0].final_status, 'CONFIRMED');
  assert.equal(gate.candidates[0].verifiedAt, 'gate:TEST');
  assert.equal(gate.candidates[0].poc_gate.verified, true);
});

// --- cite-check (#3) ---

let citeRoot;
test('cite-check: setup source root', () => {
  citeRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-gate-'));
  fs.writeFileSync(path.join(citeRoot, 'auth.go'), 'func check() {\n  if !isAdmin(r) { return err } // guard\n}\n');
});

test('cite-check: real source guard keeps the FALSE_POSITIVE (passed)', () => {
  const gate = applyDeterministicGates(
    [
      {
        candidate_id: 'F-1',
        final_status: 'FALSE_POSITIVE',
        counter_evidence: 'refuted: `isAdmin(r)` guard at auth.go:2 blocks unauthorized access',
      },
    ],
    { sourceRoot: citeRoot }
  );
  assert.equal(gate.gateSummary.cite_check.passed, 1);
  assert.equal(gate.gateSummary.cite_check.downgraded, 0);
  assert.equal(gate.candidates[0].final_status, 'FALSE_POSITIVE');
});

test('cite-check: hallucinated guard downgrades FP to DISPUTED and blocks publish', () => {
  const result = validateReportGate({
    ledger: {
      candidates: [
        {
          candidate_id: 'F-1',
          final_status: 'FALSE_POSITIVE',
          counter_evidence: 'refuted: the `sanitizeInput(x)` guard at auth.go:2 neutralizes this',
        },
      ],
    },
    classification: { equivalence_review: completeReview(0) },
    requireScore: false,
    sourceRoot: citeRoot,
  });
  assert.equal(result.gate_summary.cite_check.downgraded, 1);
  assert.equal(result.ok, false);
  assert.equal(result.errors.some((e) => e.code === 'DISPUTED_UNRESOLVED_AT_PUBLISH'), true);
});

test('cite-check: without a source root the FALSE_POSITIVE is left untouched (skip)', () => {
  const gate = applyDeterministicGates(
    [
      {
        candidate_id: 'F-1',
        final_status: 'FALSE_POSITIVE',
        counter_evidence: 'refuted: the `sanitizeInput(x)` guard at auth.go:2 neutralizes this',
      },
    ],
    {}
  );
  assert.equal(gate.gateSummary.cite_check.checked, 0);
  assert.equal(gate.candidates[0].final_status, 'FALSE_POSITIVE');
});

test('cite-check: teardown source root', () => {
  if (citeRoot) fs.rmSync(citeRoot, { recursive: true, force: true });
});
