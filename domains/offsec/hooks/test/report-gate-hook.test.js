/**
 * report-gate-hook.runGate 단위 테스트
 * 실행: node --test hooks/test/report-gate-hook.test.js
 */

'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { prospectiveContent, runGate } = require('../report-gate-hook.js');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-rgh-'));
process.on('exit', () => { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch {} });

function mkEng(name) {
  const d = path.join(TMP, name);
  fs.mkdirSync(d, { recursive: true });
  return d;
}

// P1: 실제 플로우는 Phase 0에서 source_manifest.json을 항상 생성한다.
// 최종 결과서(strongFinal) 게이트는 provenance(브랜치+커밋)를 강제하므로 테스트도 이를 모델링한다.
function writeManifest(d, { git_branch = 'main', git_head = 'a'.repeat(40) } = {}) {
  fs.writeFileSync(path.join(d, 'source_manifest.json'), JSON.stringify({ git_branch, git_head }));
}

test('runGate: not activated outside an engagement dir', () => {
  const out = runGate({ filePath: '/tmp/whatever-report.md', env: {} });
  assert.equal(out.activated, false);
});

test('host draft can be written with zero findings while final publication remains gated', () => {
  const d = mkEng('host-managed-draft');
  const env = { AGENT_ENGAGEMENT_DIR: d, AGENT_CONTRACT_ID: 'nunchi.offsec.assessment', AGENT_CONTRACT_VERSION: '2.1.0', AGENT_PHASE: 'report', AGENT_REPORT_DRAFT_ARTIFACT: '07_security_report.draft.md' };
  assert.equal(runGate({ filePath: path.join(d, env.AGENT_REPORT_DRAFT_ARTIFACT), env, content: '# No confirmed findings' }).hostDraft, true);
  const final = runGate({ filePath: path.join(d, '07_security_report.md'), env, content: '# No confirmed findings' });
  assert.equal(final.activated, true); assert.equal(final.noArtifacts, true);
  const other = runGate({ filePath: path.join(d, 'other_security_report.draft.md'), env });
  assert.equal(other.hostDraft, undefined); assert.equal(other.activated, true);
});

test('prospectiveContent reconstructs Edit and MultiEdit final content', () => {
  const d = mkEng('prospective-edit');
  const report = path.join(d, 'security-report.md');
  fs.writeFileSync(report, '# Report\ncommit: old\nstatus: draft\n');
  assert.equal(prospectiveContent('Edit', {
    old_string: 'commit: old', new_string: 'commit: abc1234',
  }, report), '# Report\ncommit: abc1234\nstatus: draft\n');
  assert.equal(prospectiveContent('MultiEdit', { edits: [
    { old_string: 'commit: old', new_string: 'commit: abc1234' },
    { old_string: 'status: draft', new_string: 'status: final' },
  ] }, report), '# Report\ncommit: abc1234\nstatus: final\n');
  assert.equal(prospectiveContent('MultiEdit', { edits: [] }, report), fs.readFileSync(report, 'utf8'));
});

test('runGate: no artifacts on strong final-report name → flagged for fail-closed', () => {
  const d = mkEng('empty');
  const out = runGate({
    filePath: path.join(d, 'security-report.md'),
    env: { AGENT_ENGAGEMENT_DIR: d },
  });
  assert.equal(out.activated, true);
  assert.equal(out.noArtifacts, true);
  assert.equal(out.strongFinal, true);
});

test('runGate: weak report name (dev_report) no artifacts → not strongFinal', () => {
  const d = mkEng('empty-weak');
  const out = runGate({
    filePath: path.join(d, '08_dev_report-api.md'),
    env: { AGENT_ENGAGEMENT_DIR: d },
  });
  assert.equal(out.activated, true);
  assert.equal(out.noArtifacts, true);
  assert.equal(out.strongFinal, false);
});

test('runGate: not activated for report path outside engagement dir', () => {
  const d = mkEng('eng-outside');
  const out = runGate({
    filePath: '/var/tmp/reports/some-report.md',
    env: { AGENT_ENGAGEMENT_DIR: d },
  });
  assert.equal(out.activated, false);
});

test('runGate: blocks when ledger has unclassified candidate', () => {
  const d = mkEng('unclassified');
  writeManifest(d);
  fs.writeFileSync(
    path.join(d, '01_va_raw_findings_ledger-1st.yaml'),
    'candidates:\n  - id: F-001\n    final_status: UNCLASSIFIED\n'
  );
  const out = runGate({
    filePath: path.join(d, 'security-report.md'),
    env: { AGENT_ENGAGEMENT_DIR: d },
  });
  assert.equal(out.activated, true);
  assert.equal(out.result.ok, false);
  assert.ok(out.result.errors.some((e) => e.code === 'CANDIDATE_UNCLASSIFIED'));
});

test('runGate: exposes intermediate VA result errors without treating them as final publication', () => {
  const d = mkEng('unclassified-intermediate');
  writeManifest(d);
  fs.writeFileSync(
    path.join(d, '01_va_raw_findings_ledger-1st.yaml'),
    'candidates:\n  - id: F-001\n    final_status: UNCLASSIFIED\n'
  );
  const out = runGate({
    filePath: path.join(d, '01_va_result-1st.md'),
    env: { AGENT_ENGAGEMENT_DIR: d, CH015_REPORT_GATE: 'on' },
  });
  assert.equal(out.strongFinal, false);
  assert.equal(out.result.ok, false);
  assert.ok(out.result.errors.some((e) => e.code === 'CANDIDATE_UNCLASSIFIED'));
});

test('runGate: final report without git provenance retains a warning under the current publication policy', () => {
  const d = mkEng('prov-missing');
  // manifest 없음 — 브랜치+커밋 출처 부재.
  fs.writeFileSync(
    path.join(d, '01_va_raw_findings_ledger-1st.yaml'),
    'candidates:\n  - id: F-001\n    final_status: CONFIRMED\n    severity: HIGH\n    evidence:\n      locations:\n        - "src/app.js:10"\n    validity:\n      reachable: "yes"\n      business_relevance: "admin"\n      exploit_path: "unauth -> admin"\n'
  );
  const out = runGate({
    filePath: path.join(d, 'security-report.md'),
    env: { AGENT_ENGAGEMENT_DIR: d },
  });
  assert.equal(out.activated, true);
  assert.equal(out.result.ok, true);
  assert.ok(out.result.warnings.some((e) => e.code === 'PROVENANCE_MISSING'));
  assert.ok(!out.result.errors.some((e) => e.code === 'PROVENANCE_MISSING'));
});

test('runGate [P1]: weak (non-final) report name does not enforce provenance', () => {
  const d = mkEng('prov-weak');
  // manifest 없어도 strongFinal이 아니면 provenance는 경고만(비차단).
  fs.writeFileSync(
    path.join(d, '01_va_raw_findings_ledger-1st.yaml'),
    'candidates:\n  - id: F-001\n    final_status: CONFIRMED\n    severity: HIGH\n    evidence:\n      locations:\n        - "src/app.js:10"\n    validity:\n      reachable: "yes"\n      business_relevance: "admin"\n      exploit_path: "unauth -> admin"\n'
  );
  const out = runGate({
    filePath: path.join(d, '08_dev_report-api.md'), // weak → strongFinal=false
    env: { AGENT_ENGAGEMENT_DIR: d },
  });
  assert.equal(out.activated, true);
  assert.equal(out.result.errors.some((e) => e.code === 'PROVENANCE_MISSING'), false);
  assert.ok(out.result.warnings.some((w) => w.code === 'PROVENANCE_MISSING'));
});

const CLEAN_LEDGER =
  'candidates:\n  - id: F-001\n    final_status: CONFIRMED\n    severity: HIGH\n    evidence:\n      locations:\n        - "src/app.js:10"\n    validity:\n      reachable: "yes"\n      business_relevance: "admin"\n      exploit_path: "unauth -> admin"\n';

test('runGate [P1+]: final report body missing the commit hash is blocked (강제 기입)', () => {
  const d = mkEng('prov-body-missing');
  writeManifest(d); // git_head = 'a'*40
  fs.writeFileSync(path.join(d, '01_va_raw_findings_ledger-1st.yaml'), CLEAN_LEDGER);
  const out = runGate({
    filePath: path.join(d, 'security-report.md'),
    env: { AGENT_ENGAGEMENT_DIR: d },
    content: '# Security Report\n커밋 언급 없음.\n',
  });
  assert.equal(out.activated, true);
  assert.equal(out.result.ok, false);
  assert.ok(out.result.errors.some((e) => e.code === 'PROVENANCE_NOT_IN_REPORT'));
});

test('runGate [P1+]: final report body containing the commit passes', () => {
  const d = mkEng('prov-body-ok');
  writeManifest(d);
  fs.writeFileSync(path.join(d, '01_va_raw_findings_ledger-1st.yaml'), CLEAN_LEDGER);
  const out = runGate({
    filePath: path.join(d, 'security-report.md'),
    env: { AGENT_ENGAGEMENT_DIR: d },
    content: `# Security Report\n| 진단 브랜치 | main |\n| 진단 커밋 | ${'a'.repeat(40)} |\n`,
  });
  assert.equal(out.activated, true);
  assert.equal(out.result.errors.some((e) => e.code === 'PROVENANCE_NOT_IN_REPORT'), false);
  assert.equal(out.result.ok, true, JSON.stringify(out.result.errors));
});

test('runGate: passes for a clean confirmed ledger (no classification required)', () => {
  const d = mkEng('clean');
  writeManifest(d);
  fs.writeFileSync(
    path.join(d, '01_va_raw_findings_ledger-1st.yaml'),
    'candidates:\n  - id: F-001\n    final_status: CONFIRMED\n    severity: HIGH\n    evidence:\n      locations:\n        - "src/app.js:10"\n    validity:\n      reachable: "yes — public route GET /admin"\n      business_relevance: "admin takeover"\n      exploit_path: "unauth request -> admin handler"\n'
  );
  const out = runGate({
    filePath: path.join(d, 'security-report.md'),
    env: { AGENT_ENGAGEMENT_DIR: d },
  });
  assert.equal(out.activated, true);
  assert.equal(out.result.ok, true, JSON.stringify(out.result.errors));
});

// ─────────────────────────────────────────────────────────────
// #3 poc-binding 활성화 (pentest 스코프, 2026-07-09)
// pentestPlan 존재 = pentest 수행 → CONFIRMED은 pentester poc_artifact로 기계검증돼야.
// VA-only(pentestPlan 부재)엔 미강제(위 clean confirmed 테스트가 그 경로를 커버).
// ─────────────────────────────────────────────────────────────
const LEDGER_CONFIRMED_NO_POC =
  'candidates:\n  - id: F-001\n    final_status: CONFIRMED\n    severity: HIGH\n    location: "src/app.js:10"\n    evidence:\n      locations:\n        - "src/app.js:10"\n    validity:\n      reachable: "yes — public route GET /admin"\n      business_relevance: "admin takeover"\n      exploit_path: "unauth request -> admin handler"\n';
const LEDGER_CONFIRMED_WITH_POC =
  'candidates:\n  - id: F-001\n    final_status: CONFIRMED\n    severity: HIGH\n    location: "src/app.js:10"\n    poc_signature: "src/app.js:10"\n    poc_artifact:\n      observed: "curl -> 200; tainted input reached sink at src/app.js:10"\n    evidence:\n      locations:\n        - "src/app.js:10"\n    validity:\n      reachable: "yes — public route GET /admin"\n      business_relevance: "admin takeover"\n      exploit_path: "unauth request -> admin handler"\n';

test('runGate: pentest engagement (pentestPlan present) downgrades CONFIRMED lacking poc_artifact', () => {
  const d = mkEng('pentest-nopoc');
  writeManifest(d);
  fs.writeFileSync(path.join(d, '01_va_raw_findings_ledger-1st.yaml'), LEDGER_CONFIRMED_NO_POC);
  fs.writeFileSync(path.join(d, '04_pentest_plan.yaml'), 'scenarios: []\n'); // pentest 수행 표식
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.activated, true);
  assert.equal(out.result.gate_summary.poc_gate.downgraded, 1);
  assert.equal(out.result.ok, false);
});

test('runGate: pentest engagement keeps CONFIRMED WITH contract-compliant poc_artifact (gate verifiedAt)', () => {
  const d = mkEng('pentest-poc');
  writeManifest(d);
  fs.writeFileSync(path.join(d, '01_va_raw_findings_ledger-1st.yaml'), LEDGER_CONFIRMED_WITH_POC);
  fs.writeFileSync(path.join(d, '04_pentest_plan.yaml'), 'scenarios: []\n');
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.activated, true);
  assert.equal(out.result.gate_summary.poc_gate.verified, 1);
  assert.equal(out.result.gate_summary.poc_gate.downgraded, 0);
  assert.equal(out.result.ok, true, JSON.stringify(out.result.errors));
});

test('runGate: CH015_REQUIRE_POC_BINDING=off disables enforcement even with pentestPlan', () => {
  const d = mkEng('pentest-off');
  writeManifest(d);
  fs.writeFileSync(path.join(d, '01_va_raw_findings_ledger-1st.yaml'), LEDGER_CONFIRMED_NO_POC);
  fs.writeFileSync(path.join(d, '04_pentest_plan.yaml'), 'scenarios: []\n');
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d, CH015_REQUIRE_POC_BINDING: 'off' } });
  assert.equal(out.result.gate_summary.poc_gate.downgraded, 0);
});

// ─────────────────────────────────────────────────────────────
// [P1-7] Write-시점 Strict Formula 검증 (fail-soft)
// ─────────────────────────────────────────────────────────────

const LEDGER_ONE_HIGH =
  'candidates:\n  - id: F-001\n    final_status: CONFIRMED\n    severity: HIGH\n    evidence:\n      locations:\n        - "src/app.js:10"\n    validity:\n      reachable: "yes — public route GET /admin"\n      business_relevance: "admin takeover"\n      exploit_path: "unauth request -> admin handler"\n';

function classificationYaml(scoreLine) {
  return [
    scoreLine,
    'equivalence_review:',
    '  status: COMPLETE',
    '  reviewed_candidate_count: 1',
    '  unresolved: []',
    '',
  ].filter(Boolean).join('\n');
}

test('runGate [P1-7]: matching numeric security_score in classification passes', () => {
  const d = mkEng('score-match');
  writeManifest(d);
  fs.writeFileSync(path.join(d, '01_va_raw_findings_ledger-1st.yaml'), LEDGER_ONE_HIGH);
  fs.writeFileSync(
    path.join(d, '05_convergence_classification-1st.yaml'),
    classificationYaml('security_score: 90') // 1 HIGH → 100 - 10 = 90
  );
  const out = runGate({
    filePath: path.join(d, 'security-report.md'),
    env: { AGENT_ENGAGEMENT_DIR: d },
  });
  assert.equal(out.activated, true);
  assert.equal(out.result.ok, true, JSON.stringify(out.result.errors));
  assert.equal(out.result.score && out.result.score.valid, true);
});

test('runGate [P1-7]: mismatching numeric security_score blocks at write time', () => {
  const d = mkEng('score-mismatch');
  writeManifest(d);
  fs.writeFileSync(path.join(d, '01_va_raw_findings_ledger-1st.yaml'), LEDGER_ONE_HIGH);
  fs.writeFileSync(
    path.join(d, '05_convergence_classification-1st.yaml'),
    classificationYaml('security_score: 98')
  );
  const out = runGate({
    filePath: path.join(d, 'security-report.md'),
    env: { AGENT_ENGAGEMENT_DIR: d },
  });
  assert.equal(out.activated, true);
  assert.equal(out.result.ok, false);
  assert.ok(out.result.errors.some((e) => e.code === 'SCORE_FORMULA_MISMATCH'));
});

test('runGate [P1-7]: absent/placeholder security_score does not error (fail-soft)', () => {
  const d = mkEng('score-absent');
  writeManifest(d);
  fs.writeFileSync(path.join(d, '01_va_raw_findings_ledger-1st.yaml'), LEDGER_ONE_HIGH);
  fs.writeFileSync(
    path.join(d, '05_convergence_classification-1st.yaml'),
    classificationYaml('security_score: ""')
  );
  const out = runGate({
    filePath: path.join(d, 'security-report.md'),
    env: { AGENT_ENGAGEMENT_DIR: d },
  });
  assert.equal(out.activated, true);
  assert.equal(out.result.ok, true, JSON.stringify(out.result.errors));
  assert.ok(out.result.warnings.some((w) => w.code === 'SCORE_NOT_PROVIDED'));
});

// ─────────────────────────────────────────────────────────────
// 커버리지 게이트 (대규모 전수 커버리지 강제, R1/R2/R3) — large-scale flow에서만
// ─────────────────────────────────────────────────────────────
function writeLargeScale(d, { manifestUnits, coverageYaml }) {
  fs.writeFileSync(path.join(d, 'source_manifest.json'), JSON.stringify({
    schema_version: 1, git_branch: 'main', git_head: 'a'.repeat(40),
    source_file_count: 999, loc_estimate: 999999, subproject_count: manifestUnits.length,
    units: manifestUnits,
  }));
  fs.writeFileSync(path.join(d, 'fanout_decision.json'), JSON.stringify({ flow: 'large-scale', analysis_mode: 'ast' }));
  fs.writeFileSync(path.join(d, '01_va_raw_findings_ledger-1st.yaml'), LEDGER_ONE_HIGH);
  if (coverageYaml != null) fs.writeFileSync(path.join(d, 'coverage_units.yaml'), coverageYaml);
}

test('coverage-gate: large-scale undecomposed big unit → COVERAGE_REQUIRE_SPLIT blocks', () => {
  const d = mkEng('cov-split');
  writeLargeScale(d, {
    manifestUnits: [{ id: 'src-tauri', loc: 71345 }, { id: 'account-pool-server', loc: 10000 }],
    coverageYaml: [
      'defined_units: [src-tauri, account-pool-server]',
      'audit_units:',
      '  - { id: src-tauri, path: src-tauri, files_in_scope: 200, files_examined: 200 }',
      '  - { id: account-pool-server, path: account-pool-server, files_in_scope: 20, files_examined: 20 }',
    ].join('\n'),
  });
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, false);
  assert.ok(out.result.errors.some((e) => e.code === 'COVERAGE_REQUIRE_SPLIT' && e.unit === 'src-tauri'));
});

test('coverage-gate: large-scale properly decomposed + full coverage → passes', () => {
  const d = mkEng('cov-ok');
  writeLargeScale(d, {
    manifestUnits: [{ id: 'src-tauri', loc: 71345 }, { id: 'account-pool-server', loc: 10000 }],
    coverageYaml: [
      'defined_units: [src-tauri/commands, src-tauri/cc, account-pool-server]',
      'audit_units:',
      '  - { id: src-tauri/commands, path: src-tauri/commands, files_in_scope: 50, files_examined: 50 }',
      '  - { id: src-tauri/cc, path: src-tauri/cc, files_in_scope: 50, files_examined: 50 }',
      '  - { id: account-pool-server, path: account-pool-server, files_in_scope: 20, files_examined: 20 }',
    ].join('\n'),
  });
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, true, JSON.stringify(out.result.errors));
});

test('coverage-gate: large-scale under-covered unit → COVERAGE_UNDER_COVERED blocks', () => {
  const d = mkEng('cov-ratio');
  writeLargeScale(d, {
    manifestUnits: [{ id: 'account-pool-server', loc: 10000 }],
    coverageYaml: [
      'defined_units: [account-pool-server]',
      'audit_units:',
      '  - { id: account-pool-server, path: account-pool-server, files_in_scope: 100, files_examined: 20 }',
    ].join('\n'),
  });
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, false);
  assert.ok(out.result.errors.some((e) => e.code === 'COVERAGE_UNDER_COVERED'));
});

test('coverage-gate: large-scale without coverage_units.yaml → COVERAGE_DATA_MISSING blocks', () => {
  const d = mkEng('cov-missing');
  writeLargeScale(d, { manifestUnits: [{ id: 'x', loc: 10000 }], coverageYaml: null });
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, false);
  assert.ok(out.result.errors.some((e) => e.code === 'COVERAGE_COVERAGE_DATA_MISSING'));
});

test('coverage-gate: CH015_COVERAGE_GATE=off disables even for large-scale', () => {
  const d = mkEng('cov-off');
  writeLargeScale(d, {
    manifestUnits: [{ id: 'src-tauri', loc: 71345 }],
    coverageYaml: 'defined_units: [src-tauri]\naudit_units:\n  - { id: src-tauri, path: src-tauri, files_in_scope: 200, files_examined: 200 }',
  });
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d, CH015_COVERAGE_GATE: 'off' } });
  assert.ok(!out.result.errors.some((e) => String(e.code).startsWith('COVERAGE_')));
});

test('coverage-gate: standard flow (not large-scale) is unaffected', () => {
  const d = mkEng('cov-standard');
  fs.writeFileSync(path.join(d, 'source_manifest.json'), JSON.stringify({
    git_branch: 'main', git_head: 'a'.repeat(40), units: [{ id: 'src-tauri', loc: 71345 }],
  }));
  fs.writeFileSync(path.join(d, 'fanout_decision.json'), JSON.stringify({ flow: 'grouped' }));
  fs.writeFileSync(path.join(d, '01_va_raw_findings_ledger-1st.yaml'), LEDGER_ONE_HIGH);
  fs.writeFileSync(path.join(d, 'coverage_units.yaml'), 'defined_units: [src-tauri]\naudit_units:\n  - { id: src-tauri, path: src-tauri, files_in_scope: 200, files_examined: 10 }');
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.ok(!out.result.errors.some((e) => String(e.code).startsWith('COVERAGE_')));
});

// ─────────────────────────────────────────────────────────────
// R3′ (scope를 manifest에서 계산) + R7 (제외 정당화) — 2차 실측 누락 정면 수정
// ─────────────────────────────────────────────────────────────
function writeLargeScaleSF(d, { units, sourceFiles, coverageYaml }) {
  fs.writeFileSync(path.join(d, 'source_manifest.json'), JSON.stringify({
    schema_version: 1, git_branch: 'main', git_head: 'a'.repeat(40),
    source_file_count: sourceFiles.length, loc_estimate: 999999, subproject_count: units.length,
    units, source_files: sourceFiles,
  }));
  fs.writeFileSync(path.join(d, 'fanout_decision.json'), JSON.stringify({ flow: 'large-scale' }));
  fs.writeFileSync(path.join(d, '01_va_raw_findings_ledger-1st.yaml'), LEDGER_ONE_HIGH);
  fs.writeFileSync(path.join(d, 'coverage_units.yaml'), coverageYaml);
}

test('R3prime: sampling hidden by self-reported scope is caught via manifest scope', () => {
  const d = mkEng('r3p-sample');
  const sf = Array.from({ length: 100 }, (_, i) => `aps/f${i}.go`);
  writeLargeScaleSF(d, {
    units: [{ id: 'aps', loc: 10000 }], sourceFiles: sf,
    // 자기신고 scope 20(거짓)이지만 manifest엔 100파일 → 게이트는 100으로 계산 → 20/100 UNDER_COVERED
    coverageYaml: 'defined_units: [aps]\naudit_units:\n  - { id: aps, path: aps, files_in_scope: 20, files_examined: 20 }',
  });
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, false);
  assert.ok(out.result.errors.some((e) => e.code === 'COVERAGE_UNDER_COVERED'));
});

test('R3prime: genuinely full coverage passes', () => {
  const d = mkEng('r3p-full');
  const sf = Array.from({ length: 100 }, (_, i) => `aps/f${i}.go`);
  writeLargeScaleSF(d, {
    units: [{ id: 'aps', loc: 10000 }], sourceFiles: sf,
    coverageYaml: 'defined_units: [aps]\naudit_units:\n  - { id: aps, path: aps, files_in_scope: 100, files_examined: 100 }',
  });
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, true, JSON.stringify(out.result.errors));
});

test('R7: excluding a unit with security code without justification is blocked', () => {
  const d = mkEng('r7-block');
  const sf = ['aps/main.go', 'packages/design-core/src/Button.jsx', 'packages/design-core/README.md'];
  writeLargeScaleSF(d, {
    units: [{ id: 'aps', loc: 10000 }], sourceFiles: sf,
    coverageYaml: [
      'excluded_units: [packages/design-core]',
      'defined_units: [aps]',
      'audit_units:',
      '  - { id: aps, path: aps, files_in_scope: 1, files_examined: 1 }',
    ].join('\n'),
  });
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, false);
  assert.ok(out.result.errors.some((e) => e.code === 'COVERAGE_EXCLUSION_UNJUSTIFIED' && e.unit === 'packages/design-core'));
});

test('R7: exclusion with explicit justification passes', () => {
  const d = mkEng('r7-justified');
  const sf = ['aps/main.go', 'packages/design-core/src/Button.jsx'];
  writeLargeScaleSF(d, {
    units: [{ id: 'aps', loc: 10000 }], sourceFiles: sf,
    coverageYaml: [
      'excluded_units:',
      '  - { path: packages/design-core, justification: "reviewed — pure design tokens, secret-scan 0" }',
      'defined_units: [aps]',
      'audit_units:',
      '  - { id: aps, path: aps, files_in_scope: 1, files_examined: 1 }',
    ].join('\n'),
  });
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.ok(!out.result.errors.some((e) => e.code === 'COVERAGE_EXCLUSION_UNJUSTIFIED'));
});

// ─────────────────────────────────────────────────────────────
// R8 (교차파일 패턴 반복) — 확인된 취약 패턴의 미분류 인스턴스 차단 (GD-01류)
// ─────────────────────────────────────────────────────────────
test('R8: confirmed sink pattern recurring in an unclassified file is blocked', () => {
  const d = mkEng('r8-block');
  // grep 대상 target 트리: 두 파일 모두 pool_server_url 포함
  const tgt = path.join(d, 'target');
  fs.mkdirSync(path.join(tgt, 'commands'), { recursive: true });
  fs.writeFileSync(path.join(tgt, 'commands', 'billing.rs'), 'let u = pool_server_url;\n');
  fs.writeFileSync(path.join(tgt, 'commands', 'account.rs'), 'let u = pool_server_url;\n');
  fs.writeFileSync(path.join(d, 'source_manifest.json'), JSON.stringify({
    schema_version: 1, git_branch: 'main', git_head: 'a'.repeat(40),
    target_realpath: tgt, units: [{ id: 'commands', loc: 100 }],
    source_files: ['commands/billing.rs', 'commands/account.rs'],
  }));
  fs.writeFileSync(path.join(d, 'fanout_decision.json'), JSON.stringify({ flow: 'large-scale' }));
  fs.writeFileSync(path.join(d, '01_va_raw_findings_ledger-1st.yaml'), LEDGER_ONE_HIGH);
  fs.writeFileSync(path.join(d, 'coverage_units.yaml'), [
    'defined_units: [commands]',
    'audit_units:',
    '  - { id: commands, path: commands, files_in_scope: 2, files_examined: 2 }',
    'sink_signatures:',
    '  - { pattern: "pool_server_url", classified_files: ["commands/billing.rs"] }', // account.rs 누락
  ].join('\n'));
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, false);
  assert.ok(out.result.errors.some((e) => e.code === 'COVERAGE_SYSTEMIC_RECURRENCE' && /account\.rs/.test(String(e.unit))));
});

test('R8: all instances classified passes', () => {
  const d = mkEng('r8-ok');
  const tgt = path.join(d, 'target');
  fs.mkdirSync(path.join(tgt, 'commands'), { recursive: true });
  fs.writeFileSync(path.join(tgt, 'commands', 'billing.rs'), 'let u = pool_server_url;\n');
  fs.writeFileSync(path.join(tgt, 'commands', 'account.rs'), 'let u = pool_server_url;\n');
  fs.writeFileSync(path.join(d, 'source_manifest.json'), JSON.stringify({
    schema_version: 1, git_branch: 'main', git_head: 'a'.repeat(40),
    target_realpath: tgt, units: [{ id: 'commands', loc: 100 }],
    source_files: ['commands/billing.rs', 'commands/account.rs'],
  }));
  fs.writeFileSync(path.join(d, 'fanout_decision.json'), JSON.stringify({ flow: 'large-scale' }));
  fs.writeFileSync(path.join(d, '01_va_raw_findings_ledger-1st.yaml'), LEDGER_ONE_HIGH);
  fs.writeFileSync(path.join(d, 'coverage_units.yaml'), [
    'defined_units: [commands]',
    'audit_units:',
    '  - { id: commands, path: commands, files_in_scope: 2, files_examined: 2 }',
    'sink_signatures:',
    '  - { pattern: "pool_server_url", classified_files: ["commands/billing.rs", "commands/account.rs"] }',
  ].join('\n'));
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.ok(!out.result.errors.some((e) => e.code === 'COVERAGE_SYSTEMIC_RECURRENCE'));
});

// ─────────────────────────────────────────────────────────────
// host-owned work-unit scope assurance 게이트(P0-C) — fanout_decision.flow와 무관, sealed work
// plan/results 산출물 존재만으로 감지한다. coverage_units.yaml(대규모 fanout) 게이트와는 독립.
// ─────────────────────────────────────────────────────────────
const crypto = require('node:crypto');

function stableJsonFixture(value) {
  if (Array.isArray(value)) return `[${value.map(stableJsonFixture).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${stableJsonFixture(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}
function sha256Fixture(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

// src/runtime/workflow/scope-assurance.ts의 SCOPE_ASSURANCE_DISCLOSURE와 값이 반드시 동일해야 한다.
const SCOPE_ASSURANCE_DISCLOSURE =
  'Read/allowed-resource counts are a minimum-examination signal only. ' +
  'They do not prove semantic security analysis was performed for any file.';

// 호스트가 실제로 생성하는 sealed work plan + results + scope assurance 3종 산출물을 그대로 흉내낸다.
function writeHostWorkUnitEngagement(d, {
  tamperAssurance, dropAssurance, mismatchUnitKeys,
  resultsSchemaVersion = '1.0.0',
  wrongAssurancePath,
  wrongSourceUnitId, wrongSourceManifestSha256, wrongUnresolvedCount,
  notSealed, wrongSchemaVersion, wrongDisclosure,
} = {}) {
  writeManifest(d);
  fs.writeFileSync(path.join(d, '01_va_raw_findings_ledger-1st.yaml'), LEDGER_ONE_HIGH);

  const unitKey = 'unit-0000000000000001';
  const workPlanCore = {
    schemaVersion: '1.0.0',
    targetRealpath: '/tmp/fixture-target',
    sourceManifestSha256: 'a'.repeat(64),
    maxContextFilesPerUnit: 50,
    units: [{
      unitKey,
      sourceUnitId: 'packages/api',
      ownedFiles: [{ path: 'packages/api/app.ts', bytes: 10, sha256: 'b'.repeat(64) }],
      contextFiles: [],
      unresolvedEdges: [],
      assignedSourceSha256: 'c'.repeat(64),
    }],
  };
  const workPlan = {
    ...workPlanCore,
    workPlanSha256: sha256Fixture(stableJsonFixture(workPlanCore)),
    generatedAt: new Date(0).toISOString(),
  };
  fs.writeFileSync(path.join(d, '00_work_plan.json'), JSON.stringify(workPlan, null, 2));

  const assuranceUnitKey = mismatchUnitKeys ? 'unit-9999999999999999' : unitKey;
  const assuranceCore = {
    schemaVersion: wrongSchemaVersion ? '9.9.9' : '1.0.0',
    sourceManifestSha256: wrongSourceManifestSha256 ? 'f'.repeat(64) : workPlan.sourceManifestSha256,
    workPlanSha256: workPlan.workPlanSha256,
    completedUnitKeys: [assuranceUnitKey],
    units: [{
      unitKey: assuranceUnitKey,
      sourceUnitId: wrongSourceUnitId ? 'packages/wrong' : 'packages/api',
      ownedFileCount: 1,
      contextFileCount: 0,
      unresolvedEdgeCount: wrongUnresolvedCount ? 1 : 0,
      contextCappedEdgeCount: 0,
      va: { uniqueAllowedReadResources: 1, ownedFilesRead: 1, contextFilesRead: 0 },
      verifier: { uniqueAllowedReadResources: 1, ownedFilesRead: 1, contextFilesRead: 0 },
      autonomousVerifierSealed: notSealed ? false : true,
    }],
    disclosure: wrongDisclosure ? 'fixture disclosure — wrong text' : SCOPE_ASSURANCE_DISCLOSURE,
  };
  // self-consistent 위조: 필드를 바꾼 뒤 자기 해시(scopeAssuranceSha256)를 다시 계산한다 —
  // 자기 해시만 맞으면 통과한다는 가정이 성립하지 않음을 보이기 위함(각 cross-check가 독립적으로
  // 막아야 한다). tamperAssurance만 예외적으로 해시를 계산한 "이후"에 값을 바꿔 self-hash mismatch를
  // 별도로 exercise한다(기존 테스트 의도 유지).
  const assurance = {
    ...assuranceCore,
    generatedAt: new Date(0).toISOString(),
    scopeAssuranceSha256: sha256Fixture(stableJsonFixture(assuranceCore)),
  };
  if (tamperAssurance) assurance.completedUnitKeys = [...assurance.completedUnitKeys, 'unit-1111111111111111'];
  const assuranceContent = `${JSON.stringify(assurance, null, 2)}\n`;
  fs.writeFileSync(path.join(d, '00_scope_assurance.json'), assuranceContent);

  const results = {
    schemaVersion: resultsSchemaVersion,
    workPlanSha256: workPlan.workPlanSha256,
    completedUnitKeys: [unitKey],
    ...(dropAssurance ? {} : {
      assurancePath: wrongAssurancePath !== undefined ? wrongAssurancePath : '00_scope_assurance.json',
      assuranceSha256: sha256Fixture(fs.readFileSync(path.join(d, '00_scope_assurance.json'))),
    }),
    units: [{ unitKey, sourceUnitId: 'packages/api' }],
  };
  fs.writeFileSync(path.join(d, '00_work_unit_results.json'), JSON.stringify(results, null, 2));
  return { workPlan, assurance };
}

// unitKey 중복 레코드로 실제 누락된 unit을 가리는 대체(substitution) 공격 전용 2-unit 고정물.
function writeHostWorkUnitEngagementDuplicateRecord(d) {
  writeManifest(d);
  fs.writeFileSync(path.join(d, '01_va_raw_findings_ledger-1st.yaml'), LEDGER_ONE_HIGH);

  const unitKeyA = 'unit-0000000000000001';
  const unitKeyB = 'unit-0000000000000002';
  const workPlanCore = {
    schemaVersion: '1.0.0',
    targetRealpath: '/tmp/fixture-target',
    sourceManifestSha256: 'a'.repeat(64),
    maxContextFilesPerUnit: 50,
    units: [
      {
        unitKey: unitKeyA, sourceUnitId: 'packages/api',
        ownedFiles: [{ path: 'packages/api/app.ts', bytes: 10, sha256: 'b'.repeat(64) }],
        contextFiles: [], unresolvedEdges: [], assignedSourceSha256: 'c'.repeat(64),
      },
      {
        unitKey: unitKeyB, sourceUnitId: 'packages/common',
        ownedFiles: [{ path: 'packages/common/auth.ts', bytes: 10, sha256: 'd'.repeat(64) }],
        contextFiles: [], unresolvedEdges: [], assignedSourceSha256: 'e'.repeat(64),
      },
    ],
  };
  const workPlan = {
    ...workPlanCore,
    workPlanSha256: sha256Fixture(stableJsonFixture(workPlanCore)),
    generatedAt: new Date(0).toISOString(),
  };
  fs.writeFileSync(path.join(d, '00_work_plan.json'), JSON.stringify(workPlan, null, 2));

  const unitRecordA = {
    unitKey: unitKeyA,
    sourceUnitId: 'packages/api',
    ownedFileCount: 1,
    contextFileCount: 0,
    unresolvedEdgeCount: 0,
    contextCappedEdgeCount: 0,
    va: { uniqueAllowedReadResources: 1, ownedFilesRead: 1, contextFilesRead: 0 },
    verifier: { uniqueAllowedReadResources: 1, ownedFilesRead: 1, contextFilesRead: 0 },
    autonomousVerifierSealed: true,
  };
  const assuranceCore = {
    schemaVersion: '1.0.0',
    sourceManifestSha256: workPlan.sourceManifestSha256,
    workPlanSha256: workPlan.workPlanSha256,
    completedUnitKeys: [unitKeyA, unitKeyB],
    // unit B의 실제 관측 레코드는 아예 없다 — unit A 레코드를 중복시켜 개수만 맞춘다.
    units: [unitRecordA, { ...unitRecordA }],
    disclosure: SCOPE_ASSURANCE_DISCLOSURE,
  };
  const assurance = {
    ...assuranceCore,
    generatedAt: new Date(0).toISOString(),
    scopeAssuranceSha256: sha256Fixture(stableJsonFixture(assuranceCore)),
  };
  fs.writeFileSync(path.join(d, '00_scope_assurance.json'), `${JSON.stringify(assurance, null, 2)}\n`);

  const results = {
    schemaVersion: '1.0.0',
    workPlanSha256: workPlan.workPlanSha256,
    completedUnitKeys: [unitKeyA, unitKeyB],
    assurancePath: '00_scope_assurance.json',
    assuranceSha256: sha256Fixture(fs.readFileSync(path.join(d, '00_scope_assurance.json'))),
    units: [
      { unitKey: unitKeyA, sourceUnitId: 'packages/api' },
      { unitKey: unitKeyB, sourceUnitId: 'packages/common' },
    ],
  };
  fs.writeFileSync(path.join(d, '00_work_unit_results.json'), JSON.stringify(results, null, 2));
}

test('scope-assurance-gate: valid host work-unit engagement passes without a fanout_decision.json at all', () => {
  const d = mkEng('assurance-ok');
  writeHostWorkUnitEngagement(d);
  assert.ok(!fs.existsSync(path.join(d, 'fanout_decision.json')));
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, true, JSON.stringify(out.result.errors));
  assert.ok(!out.result.errors.some((e) => String(e.code).startsWith('SCOPE_ASSURANCE_')));
});

test('scope-assurance-gate: tampered assurance receipt blocks publication (fail closed)', () => {
  const d = mkEng('assurance-tampered');
  writeHostWorkUnitEngagement(d, { tamperAssurance: true });
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, false);
  assert.ok(out.result.errors.some((e) => e.code === 'SCOPE_ASSURANCE_SELF_HASH_MISMATCH'));
});

test('scope-assurance-gate: a declared but physically missing assurance file blocks publication', () => {
  const d = mkEng('assurance-missing-file');
  writeHostWorkUnitEngagement(d);
  fs.rmSync(path.join(d, '00_scope_assurance.json'));
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, false);
  assert.ok(out.result.errors.some((e) => e.code === 'SCOPE_ASSURANCE_MISSING'));
});

test('scope-assurance-gate: unit key mismatch between plan and assurance blocks publication', () => {
  const d = mkEng('assurance-unit-mismatch');
  writeHostWorkUnitEngagement(d, { mismatchUnitKeys: true });
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, false);
  assert.ok(out.result.errors.some((e) => e.code === 'SCOPE_ASSURANCE_UNIT_KEY_MISMATCH'));
});

test('scope-assurance-gate: legacy v1 results without a declared assurance receipt remain backward compatible', () => {
  const d = mkEng('assurance-legacy');
  writeHostWorkUnitEngagement(d, { dropAssurance: true });
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, true, JSON.stringify(out.result.errors));
  assert.ok(!out.result.errors.some((e) => String(e.code).startsWith('SCOPE_ASSURANCE_')));
});

test('scope-assurance-gate: CH015_SCOPE_ASSURANCE_GATE=off disables even for a tampered receipt', () => {
  const d = mkEng('assurance-off');
  writeHostWorkUnitEngagement(d, { tamperAssurance: true });
  const out = runGate({
    filePath: path.join(d, 'security-report.md'),
    env: { AGENT_ENGAGEMENT_DIR: d, CH015_SCOPE_ASSURANCE_GATE: 'off' },
  });
  assert.ok(!out.result.errors.some((e) => String(e.code).startsWith('SCOPE_ASSURANCE_')));
});

// ── P0 correction pass: downgrade-attack fix + plain-JS parity strengthening ──────────────

test('scope-assurance-gate: dropping assurance references from a fresh (non-legacy) schemaVersion result is blocked, not downgraded to legacy', () => {
  const d = mkEng('assurance-downgrade-attack');
  writeHostWorkUnitEngagement(d, { resultsSchemaVersion: '1.1.0', dropAssurance: true });
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, false);
  assert.ok(!out.result.scope_assurance_gate || out.result.scope_assurance_gate.ok === false);
  assert.ok(out.result.errors.some((e) => e.code === 'SCOPE_ASSURANCE_REFERENCE_MISSING'));
});

test('scope-assurance-gate: assurancePath with an interior traversal segment is rejected', () => {
  const d = mkEng('assurance-path-traversal');
  writeHostWorkUnitEngagement(d, { wrongAssurancePath: '../../../etc/passwd' });
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, false);
  assert.ok(out.result.errors.some((e) => e.code === 'SCOPE_ASSURANCE_PATH_INVALID'));
});

test('scope-assurance-gate: an absolute assurancePath is rejected', () => {
  const d = mkEng('assurance-path-absolute');
  writeHostWorkUnitEngagement(d, { wrongAssurancePath: '/etc/passwd' });
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, false);
  assert.ok(out.result.errors.some((e) => e.code === 'SCOPE_ASSURANCE_PATH_INVALID'));
});

test('scope-assurance-gate: sourceUnitId mismatch against the sealed work plan is rejected', () => {
  const d = mkEng('assurance-source-unit-id-mismatch');
  writeHostWorkUnitEngagement(d, { wrongSourceUnitId: true });
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, false);
  assert.ok(out.result.errors.some((e) => e.code === 'SCOPE_ASSURANCE_UNIT_SOURCE_ID_MISMATCH'));
});

test('scope-assurance-gate: sourceManifestSha256 mismatch against the sealed work plan is rejected', () => {
  const d = mkEng('assurance-source-manifest-mismatch');
  writeHostWorkUnitEngagement(d, { wrongSourceManifestSha256: true });
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, false);
  assert.ok(out.result.errors.some((e) => e.code === 'SCOPE_ASSURANCE_SOURCE_MANIFEST_MISMATCH'));
});

test('scope-assurance-gate: unresolved/context-cap edge count mismatch against the sealed work plan is rejected', () => {
  const d = mkEng('assurance-edge-count-mismatch');
  writeHostWorkUnitEngagement(d, { wrongUnresolvedCount: true });
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, false);
  assert.ok(out.result.errors.some((e) => e.code === 'SCOPE_ASSURANCE_UNIT_EDGE_COUNT_MISMATCH'));
});

test('scope-assurance-gate: legacy autonomousVerifierSealed is optional after seal removal', () => {
  const d = mkEng('assurance-not-sealed');
  writeHostWorkUnitEngagement(d, { notSealed: true });
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, true);
  assert.ok(!out.result.errors.some((e) => e.code === 'SCOPE_ASSURANCE_UNIT_NOT_SEALED'));
});

test('scope-assurance-gate: a self-consistently-forged schemaVersion literal is still rejected', () => {
  const d = mkEng('assurance-wrong-schema-version');
  writeHostWorkUnitEngagement(d, { wrongSchemaVersion: true });
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, false);
  assert.ok(!out.result.errors.some((e) => e.code === 'SCOPE_ASSURANCE_SELF_HASH_MISMATCH'));
  assert.ok(out.result.errors.some((e) => e.code === 'SCOPE_ASSURANCE_SCHEMA_VERSION_INVALID'));
});

test('scope-assurance-gate: a self-consistently-forged disclosure literal is still rejected', () => {
  const d = mkEng('assurance-wrong-disclosure');
  writeHostWorkUnitEngagement(d, { wrongDisclosure: true });
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, false);
  assert.ok(!out.result.errors.some((e) => e.code === 'SCOPE_ASSURANCE_SELF_HASH_MISMATCH'));
  assert.ok(out.result.errors.some((e) => e.code === 'SCOPE_ASSURANCE_DISCLOSURE_INVALID'));
});

test('scope-assurance-gate: a duplicate unit record substituting for a genuinely missing unit is rejected', () => {
  const d = mkEng('assurance-duplicate-unit-record');
  writeHostWorkUnitEngagementDuplicateRecord(d);
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, false);
  assert.ok(out.result.errors.some((e) => e.code === 'SCOPE_ASSURANCE_DUPLICATE_UNIT_RECORD'));
});

test('scope-assurance-gate: a duplicate completedUnitKeys entry in work unit results is rejected', () => {
  const d = mkEng('assurance-duplicate-result-key');
  writeHostWorkUnitEngagement(d);
  const resultsPath = path.join(d, '00_work_unit_results.json');
  const results = JSON.parse(fs.readFileSync(resultsPath, 'utf8'));
  results.completedUnitKeys = [results.completedUnitKeys[0], results.completedUnitKeys[0]];
  fs.writeFileSync(resultsPath, JSON.stringify(results, null, 2));
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, false);
  assert.ok(out.result.errors.some((e) => e.code === 'SCOPE_ASSURANCE_RESULT_DUPLICATE_UNIT_KEY'));
});

test('scope-assurance-gate: does not activate without sealed work plan/results (non-work-unit engagement)', () => {
  const d = mkEng('assurance-not-applicable');
  writeManifest(d);
  fs.writeFileSync(path.join(d, '01_va_raw_findings_ledger-1st.yaml'), LEDGER_ONE_HIGH);
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, true, JSON.stringify(out.result.errors));
  assert.ok(!('scope_assurance_gate' in out.result));
});

// ── final hardening pass: schemaVersion allow-list, results.units accounting, workPlanSha256 recompute ──

test('scope-assurance-gate: an unknown results schemaVersion (e.g. 2.0.0) is fail-closed', () => {
  const d = mkEng('assurance-unknown-schema-version');
  writeHostWorkUnitEngagement(d, { resultsSchemaVersion: '2.0.0' });
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, false);
  assert.ok(out.result.errors.some((e) => e.code === 'WORK_UNIT_RESULTS_SCHEMA_VERSION_INVALID'));
});

test('scope-assurance-gate: a missing results schemaVersion is fail-closed', () => {
  const d = mkEng('assurance-missing-schema-version');
  writeHostWorkUnitEngagement(d);
  const resultsPath = path.join(d, '00_work_unit_results.json');
  const results = JSON.parse(fs.readFileSync(resultsPath, 'utf8'));
  delete results.schemaVersion;
  fs.writeFileSync(resultsPath, JSON.stringify(results, null, 2));
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, false);
  assert.ok(out.result.errors.some((e) => e.code === 'WORK_UNIT_RESULTS_SCHEMA_VERSION_INVALID'));
});

test('scope-assurance-gate: a duplicate result unit record substituting for a missing unit fails', () => {
  const d = mkEng('assurance-dup-result-unit');
  writeHostWorkUnitEngagementDuplicateRecord(d);
  // Replace results.units: duplicate unit A's record, dropping unit B
  const resultsPath = path.join(d, '00_work_unit_results.json');
  const results = JSON.parse(fs.readFileSync(resultsPath, 'utf8'));
  const unitA = results.units[0];
  results.units = [unitA, { ...unitA }];
  fs.writeFileSync(resultsPath, JSON.stringify(results, null, 2));
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, false);
  assert.ok(out.result.errors.some((e) => e.code === 'SCOPE_ASSURANCE_RESULT_DUPLICATE_UNIT_RECORD'));
});

test('scope-assurance-gate: a result unit with mismatched sourceUnitId against the plan is rejected', () => {
  const d = mkEng('assurance-result-source-unit-id');
  writeHostWorkUnitEngagement(d);
  const resultsPath = path.join(d, '00_work_unit_results.json');
  const results = JSON.parse(fs.readFileSync(resultsPath, 'utf8'));
  results.units[0].sourceUnitId = 'packages/attacker-replaced';
  fs.writeFileSync(resultsPath, JSON.stringify(results, null, 2));
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, false);
  assert.ok(out.result.errors.some((e) => e.code === 'SCOPE_ASSURANCE_RESULT_SOURCE_UNIT_ID_MISMATCH'));
});

test('scope-assurance-gate: a tampered workPlanSha256 (content hash recompute mismatch) blocks publication', () => {
  const d = mkEng('assurance-plan-tamper');
  const { workPlan } = writeHostWorkUnitEngagement(d);
  // Tamper the plan: change maxContextFilesPerUnit but keep the old hash
  const planPath = path.join(d, '00_work_plan.json');
  const tampered = JSON.parse(fs.readFileSync(planPath, 'utf8'));
  tampered.maxContextFilesPerUnit = 999;
  // Leave workPlanSha256 as the old value — recompute will not match
  fs.writeFileSync(planPath, JSON.stringify(tampered, null, 2));
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.result.ok, false);
  assert.ok(out.result.errors.some((e) => e.code === 'WORK_PLAN_HASH_MISMATCH'));
});

// ─────────────────────────────────────────────────────────────
// V2 work plan with dependencyGraphSha256, planningPolicy, estimatedTokens,
// and contextSelectionReceipt — exercises the real plain-JS scope-assurance
// publication gate with a correctly self-hashed V2 plan.
// ─────────────────────────────────────────────────────────────

function writeHostWorkUnitEngagementV2(d, { tamperPlanHash } = {}) {
  writeManifest(d);
  fs.writeFileSync(path.join(d, '01_va_raw_findings_ledger-1st.yaml'), LEDGER_ONE_HIGH);

  const unitKey = 'unit-0000000000000001';
  const planningPolicy = {
    estimatedCharsPerToken: 4,
    maxContextEstimatedTokensPerUnit: 65536,
    maxContextFilesPerUnit: 50,
  };
  const contextSelectionReceipt = {
    ownedEstimatedTokens: 3,
    candidateCount: 0,
    selectedContextFiles: 0,
    selectedContextEstimatedTokens: 0,
    omitted: [],
    rankingPolicy: 'ref-count-desc/tokens-asc/path-asc',
  };
  const workPlanCore = {
    schemaVersion: '2.0.0',
    targetRealpath: '/tmp/fixture-target-v2',
    sourceManifestSha256: 'a'.repeat(64),
    dependencyGraphSha256: 'd'.repeat(64),
    planningPolicy,
    maxContextFilesPerUnit: 50,
    units: [{
      unitKey,
      sourceUnitId: 'packages/api',
      ownedFiles: [{ path: 'packages/api/app.ts', bytes: 10, sha256: 'b'.repeat(64) }],
      contextFiles: [],
      unresolvedEdges: [],
      assignedSourceSha256: 'c'.repeat(64),
      estimatedTokens: 3,
      contextSelectionReceipt,
    }],
  };
  const correctHash = sha256Fixture(stableJsonFixture(workPlanCore));
  const workPlan = {
    ...workPlanCore,
    workPlanSha256: tamperPlanHash ? 'f'.repeat(64) : correctHash,
    generatedAt: new Date(0).toISOString(),
  };
  fs.writeFileSync(path.join(d, '00_work_plan.json'), JSON.stringify(workPlan, null, 2));

  const assuranceCore = {
    schemaVersion: '1.0.0',
    sourceManifestSha256: workPlanCore.sourceManifestSha256,
    workPlanSha256: tamperPlanHash ? 'f'.repeat(64) : correctHash,
    completedUnitKeys: [unitKey],
    units: [{
      unitKey,
      sourceUnitId: 'packages/api',
      ownedFileCount: 1,
      contextFileCount: 0,
      unresolvedEdgeCount: 0,
      contextCappedEdgeCount: 0,
      va: { uniqueAllowedReadResources: 1, ownedFilesRead: 1, contextFilesRead: 0 },
      verifier: { uniqueAllowedReadResources: 1, ownedFilesRead: 1, contextFilesRead: 0 },
      autonomousVerifierSealed: true,
    }],
    disclosure: SCOPE_ASSURANCE_DISCLOSURE,
  };
  const assurance = {
    ...assuranceCore,
    generatedAt: new Date(0).toISOString(),
    scopeAssuranceSha256: sha256Fixture(stableJsonFixture(assuranceCore)),
  };
  fs.writeFileSync(path.join(d, '00_scope_assurance.json'), `${JSON.stringify(assurance, null, 2)}\n`);

  const results = {
    schemaVersion: '1.0.0',
    workPlanSha256: workPlan.workPlanSha256,
    completedUnitKeys: [unitKey],
    assurancePath: '00_scope_assurance.json',
    assuranceSha256: sha256Fixture(fs.readFileSync(path.join(d, '00_scope_assurance.json'))),
    units: [{ unitKey, sourceUnitId: 'packages/api' }],
  };
  fs.writeFileSync(path.join(d, '00_work_unit_results.json'), JSON.stringify(results, null, 2));
  return { workPlan };
}

test('scope-assurance-gate [V2]: valid V2 work plan with dependencyGraphSha256/planningPolicy/estimatedTokens/contextSelectionReceipt passes publication gate', () => {
  const d = mkEng('assurance-v2-ok');
  writeHostWorkUnitEngagementV2(d);
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.activated, true);
  assert.equal(out.result.ok, true, JSON.stringify(out.result.errors));
  assert.ok(!out.result.errors.some((e) => String(e.code).startsWith('SCOPE_ASSURANCE_')));
  assert.ok(!out.result.errors.some((e) => e.code === 'WORK_PLAN_HASH_MISMATCH'));
});

test('scope-assurance-gate [V2]: tampered V2 work plan hash is rejected (hash tampering detection)', () => {
  const d = mkEng('assurance-v2-tampered');
  writeHostWorkUnitEngagementV2(d, { tamperPlanHash: true });
  const out = runGate({ filePath: path.join(d, 'security-report.md'), env: { AGENT_ENGAGEMENT_DIR: d } });
  assert.equal(out.activated, true);
  assert.equal(out.result.ok, false);
  assert.ok(out.result.errors.some((e) => e.code === 'WORK_PLAN_HASH_MISMATCH'));
});
