'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const {
  commitReservation,
  createFanoutDecision,
  initFanoutPlan,
  reconcileFanout,
  reserveAgents,
  validateManifestFreshness,
} = require('../agent-plan');
const { stableJson } = require('../source-manifest');

function manifest(overrides = {}) {
  return {
    schema_version: 1,
    target_realpath: overrides.target_realpath || fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-plan-target-')),
    source_file_count: overrides.source_file_count ?? 23,
    loc_estimate: overrides.loc_estimate ?? 1290,
    subproject_count: overrides.subproject_count ?? 1,
    git_head: null,
    policy: { codeExtensions: ['.go'], excludedDirs: [] },
    source_files: Array.from({ length: overrides.source_file_count ?? 23 }, (_, i) => `src/f${i}.go`),
    hash: overrides.hash || `hash-${overrides.source_file_count ?? 23}`,
  };
}

test('fanout decision: small AST project forces one VA and one verifier', () => {
  const decision = createFanoutDecision({
    manifest: manifest({ source_file_count: 23 }),
    analysisMode: 'ast',
    verificationMode: 'VA_ONLY',
    config: {
      ch015: { dimensionParallelism: { enabled: true, mode: 'grouped', min_source_files: 50 } },
      feedbackLoop: { max_iterations: 2 },
    },
  });

  assert.equal(decision.analysis_mode, 'ast');
  assert.equal(decision.ast_policy.run_once_before_fanout, true);
  assert.equal(decision.va.mode, 'sequential');
  assert.equal(decision.limits['va:va-auditor'], 1);
  assert.equal(decision.limits['verify:verifier'], 1);
});

test('fanout decision: grouped starts at configured source threshold', () => {
  const decision = createFanoutDecision({
    manifest: manifest({ source_file_count: 50 }),
    config: {
      ch015: { dimensionParallelism: { enabled: true, mode: 'grouped', min_source_files: 50 } },
      feedbackLoop: { max_iterations: 2 },
    },
  });

  assert.equal(decision.va.mode, 'grouped');
  assert.equal(decision.limits['va:va-auditor'], 4);
  // Verify는 VA 수에 맞춰 그룹으로 생성 → grouped면 verifier도 4.
  assert.equal(decision.limits['verify:verifier'], 4);
  assert.equal(decision.verify.initial_agents, 4);
  assert.deepEqual(decision.verify.allowed_groups, ['auth', 'data', 'config', 'availability']);
});

test('fanout decision: large-scale verify cap defaults to 16 (not unbounded)', () => {
  const decision = createFanoutDecision({
    manifest: manifest({ source_file_count: 500 }),
    verificationMode: 'VA_ONLY',
    config: { feedbackLoop: { max_iterations: 2 } },
  });

  assert.equal(decision.flow, 'large-scale');
  assert.equal(decision.limits['tier1-verify:verifier'], 16);
});

test('fanout decision: large-scale verify cap clamps caller override down to 16', () => {
  const decision = createFanoutDecision({
    manifest: manifest({ source_file_count: 500 }),
    maxTier1VerifyAgents: 50,
    verificationMode: 'VA_ONLY',
    config: { feedbackLoop: { max_iterations: 2 } },
  });

  assert.equal(decision.limits['tier1-verify:verifier'], 16);
});

test('fanout decision: explicit standard flow keeps a large repository on one host-sequential VA', () => {
  const decision = createFanoutDecision({
    manifest: manifest({ source_file_count: 500, loc_estimate: 100000, subproject_count: 5 }),
    flow: 'standard',
    vaMode: 'sequential',
    verificationMode: 'VA_ONLY',
    config: { feedbackLoop: { max_iterations: 2 } },
  });

  assert.equal(decision.flow, 'standard');
  assert.equal(decision.va.mode, 'sequential');
  assert.equal(decision.limits['va:va-auditor'], 1);
  assert.equal(decision.limits['verify:verifier'], 1);
  assert.equal(decision.limits['tier1-va:va-auditor'], undefined);
});

test('fanout decision: full mode gives 8 verifiers each with a distinct group id (A6)', () => {
  const decision = createFanoutDecision({
    manifest: manifest({ source_file_count: 80 }),
    verificationMode: 'VA_ONLY',
    config: {
      ch015: { dimensionParallelism: { enabled: true, mode: 'full', min_source_files: 50 } },
      feedbackLoop: { max_iterations: 2 },
    },
  });

  assert.equal(decision.va.mode, 'full');
  assert.equal(decision.limits['verify:verifier'], 8);
  assert.equal(decision.verify.initial_agents, 8);
  // 충돌 방지: verifier마다 고유 그룹 식별자(a1..a8)가 있어야 한다.
  assert.equal(decision.verify.allowed_groups.length, 8);
  assert.equal(new Set(decision.verify.allowed_groups).size, 8);
});

test('reserve blocks VA over-fanout for small projects', () => {
  const target = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-plan-small-'));
  fs.mkdirSync(path.join(target, 'src'), { recursive: true });
  fs.writeFileSync(path.join(target, 'src', 'main.go'), 'package main\n');
  const engagement = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-plan-eng-'));
  initFanoutPlan({
    target,
    engagementDir: engagement,
    analysisMode: 'ast',
    config: {
      ch015: { dimensionParallelism: { enabled: true, mode: 'grouped', min_source_files: 50 } },
      feedbackLoop: { max_iterations: 2 },
    },
  });

  assert.throws(
    () => reserveAgents(engagement, { phase: 'va', role: 'va-auditor', count: 8 }),
    /AGENT_FANOUT_LIMIT_EXCEEDED/
  );

  fs.rmSync(target, { recursive: true, force: true });
  fs.rmSync(engagement, { recursive: true, force: true });
});

test('reconcile detects artifact without active commit', () => {
  const target = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-plan-target-'));
  fs.mkdirSync(path.join(target, 'src'), { recursive: true });
  fs.writeFileSync(path.join(target, 'src', 'main.go'), 'package main\n');
  const engagement = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-plan-eng-'));
  initFanoutPlan({ target, engagementDir: engagement, analysisMode: 'llm' });
  fs.writeFileSync(path.join(engagement, '01_va_result-1st.md'), '# VA\n');

  const audit = reconcileFanout(engagement, { checkCurrentSource: false });
  assert.equal(audit.ok, false);
  assert.ok(audit.errors.some((e) => e.code === 'AGENT_ARTIFACT_WITHOUT_COMMIT'));

  fs.rmSync(target, { recursive: true, force: true });
  fs.rmSync(engagement, { recursive: true, force: true });
});

test('manifest freshness accepts a legacy path-bound hash when content is unchanged', () => {
  const target = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-plan-legacy-target-'));
  fs.mkdirSync(path.join(target, 'src'), { recursive: true });
  fs.writeFileSync(path.join(target, 'src', 'main.go'), 'package main\n');
  const engagement = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-plan-legacy-eng-'));
  initFanoutPlan({ target, engagementDir: engagement, analysisMode: 'llm' });

  const manifestPath = path.join(engagement, 'source_manifest.json');
  const decisionPath = path.join(engagement, 'fanout_decision.json');
  const stored = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const decision = JSON.parse(fs.readFileSync(decisionPath, 'utf8'));
  const { hash: _hash, content_hash: _contentHash, generated_at: _generatedAt, ...legacyCore } = stored;
  const legacyHash = crypto.createHash('sha256').update(stableJson(legacyCore)).digest('hex');
  delete stored.content_hash;
  stored.hash = legacyHash;
  delete decision.manifest_content_hash;
  decision.manifest_hash = legacyHash;
  fs.writeFileSync(manifestPath, JSON.stringify(stored, null, 2));

  assert.deepEqual(validateManifestFreshness(engagement, decision), []);
  fs.rmSync(target, { recursive: true, force: true });
  fs.rmSync(engagement, { recursive: true, force: true });
});

test('reconcile treats an expected artifact as pending until the host commits its reservation', () => {
  const target = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-plan-target-'));
  fs.mkdirSync(path.join(target, 'src'), { recursive: true });
  fs.writeFileSync(path.join(target, 'src', 'main.go'), 'package main\n');
  const engagement = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-plan-eng-'));
  initFanoutPlan({ target, engagementDir: engagement, analysisMode: 'llm' });
  reserveAgents(engagement, {
    phase: 'va',
    role: 'va-auditor',
    count: 1,
    expectedArtifacts: ['01_va_result-1st.md'],
  });
  fs.writeFileSync(path.join(engagement, '01_va_result-1st.md'), '# VA\n');

  const audit = reconcileFanout(engagement, {
    checkCurrentSource: false,
    allowPendingArtifacts: true,
  });
  assert.equal(audit.ok, true);
  assert.ok(audit.warnings.some((warning) => warning.code === 'AGENT_ARTIFACT_PENDING_COMMIT'));

  fs.rmSync(target, { recursive: true, force: true });
  fs.rmSync(engagement, { recursive: true, force: true });
});

test('reconcile passes when reservation, commit, and canonical artifact agree', () => {
  const target = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-plan-target-'));
  fs.mkdirSync(path.join(target, 'src'), { recursive: true });
  fs.writeFileSync(path.join(target, 'src', 'main.go'), 'package main\n');
  const engagement = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-plan-eng-'));
  initFanoutPlan({ target, engagementDir: engagement, analysisMode: 'llm' });
  const reservation = reserveAgents(engagement, { phase: 'va', role: 'va-auditor', count: 1 });
  fs.writeFileSync(path.join(engagement, '01_va_result-1st.md'), '# VA\n');
  commitReservation(engagement, {
    reservationId: reservation.id,
    artifacts: ['01_va_result-1st.md'],
  });

  const audit = reconcileFanout(engagement, { checkCurrentSource: false });
  assert.equal(audit.ok, true);

  fs.rmSync(target, { recursive: true, force: true });
  fs.rmSync(engagement, { recursive: true, force: true });
});
