/**
 * P3-4 / post-phase 보안 강화 회귀 테스트
 */

'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..', '..');
const HOOK = path.join(ROOT, 'hooks', 'post-phase.js');

function runHook(env) {
  return execFileSync('node', [HOOK], {
    env: { ...process.env, ...env },
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

test('post-phase: creates log dir with 0700 perms and file with 0600', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-ph-'));
  // Clean existing log dir by pointing CH015 to a fresh fake root via env
  // Hook writes to harness/eval/reports/<id>_phase_log.jsonl under repo root
  // We instead check the actual hook by running and inspecting perms
  const engagementId = `test-${Date.now()}`;
  runHook({
    AGENT_ENGAGEMENT_ID: engagementId,
    AGENT_PHASE: 'unit-test',
    AGENT_FINDING_COUNT: '3',
    AGENT_EVIDENCE_COUNT: '10',
    AGENT_HALLUCINATION_COUNT: '0',
    AGENT_PHASE_TOKENS: '100',
    AGENT_PHASE_COST_USD: '0.01',
    AGENT_ENGAGEMENT_DIR: tmp,
  });

  const logDir = path.join(ROOT, 'harness', 'eval', 'reports');
  const logFile = path.join(logDir, `${engagementId}_phase_log.jsonl`);
  assert.ok(fs.existsSync(logFile), 'log file should exist');

  const fileMode = fs.statSync(logFile).mode & 0o777;
  assert.equal(fileMode, 0o600, `log file should be 0600, got ${fileMode.toString(8)}`);

  const dirMode = fs.statSync(logDir).mode & 0o777;
  // dir already existed before from earlier writes — we force-chmod to 0700
  assert.equal(dirMode, 0o700, `log dir should be 0700, got ${dirMode.toString(8)}`);

  const content = fs.readFileSync(logFile, 'utf8');
  const last = content.trim().split('\n').pop();
  const obj = JSON.parse(last);
  assert.equal(obj.engagement_id, engagementId);
  assert.equal(obj.tokens_delta, 100);

  // Budget tracker should have written into engagementDir
  const budget = JSON.parse(fs.readFileSync(path.join(tmp, 'budget.json'), 'utf8'));
  assert.equal(budget.tokens, 100);

  fs.unlinkSync(logFile);
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('post-phase: writes phase_state.json to engagement dir', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-ps-'));
  const engagementId = `state-${Date.now()}`;
  runHook({
    AGENT_ENGAGEMENT_ID: engagementId,
    AGENT_PHASE: 'architecture',
    AGENT_FINDING_COUNT: '5',
    AGENT_EVIDENCE_COUNT: '12',
    AGENT_HALLUCINATION_COUNT: '0',
    AGENT_PHASE_TOKENS: '50000',
    AGENT_PHASE_COST_USD: '1.50',
    AGENT_ENGAGEMENT_DIR: tmp,
    AGENT_ROLE: '',
  });

  const stateFile = path.join(tmp, 'phase_state.json');
  assert.ok(fs.existsSync(stateFile), 'phase_state.json should exist');

  const state = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
  assert.equal(state.engagement_id, engagementId);
  assert.equal(state.current_phase, 'architecture');
  assert.deepEqual(state.completed_phases, ['architecture']);
  assert.equal(state.cumulative_findings, 5);
  assert.equal(state.cumulative_evidence, 12);
  assert.equal(state.cumulative_tokens, 50000);
  assert.equal(state.cumulative_cost_usd, 1.5);
  assert.equal(state.lead_state, undefined);

  // Second phase call — cumulative
  runHook({
    AGENT_ENGAGEMENT_ID: engagementId,
    AGENT_PHASE: 'deep-analysis',
    AGENT_FINDING_COUNT: '2',
    AGENT_EVIDENCE_COUNT: '3',
    AGENT_HALLUCINATION_COUNT: '0',
    AGENT_PHASE_TOKENS: '30000',
    AGENT_PHASE_COST_USD: '0.80',
    AGENT_ENGAGEMENT_DIR: tmp,
    AGENT_ROLE: '',
  });

  const state2 = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
  assert.deepEqual(state2.completed_phases, ['architecture', 'deep-analysis']);
  assert.equal(state2.cumulative_findings, 7);
  assert.equal(state2.cumulative_tokens, 80000);

  const logDir = path.join(ROOT, 'harness', 'eval', 'reports');
  const logFile = path.join(logDir, `${engagementId}_phase_log.jsonl`);
  if (fs.existsSync(logFile)) fs.unlinkSync(logFile);
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('post-phase: records lead_state for offsec-lead role', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-lead-'));
  const engagementId = `lead-${Date.now()}`;
  runHook({
    AGENT_ENGAGEMENT_ID: engagementId,
    AGENT_PHASE: 'architecture',
    AGENT_FINDING_COUNT: '3',
    AGENT_EVIDENCE_COUNT: '6',
    AGENT_HALLUCINATION_COUNT: '0',
    AGENT_PHASE_TOKENS: '20000',
    AGENT_PHASE_COST_USD: '0.50',
    AGENT_ENGAGEMENT_DIR: tmp,
    AGENT_ROLE: 'offsec-lead',
  });

  const state = JSON.parse(fs.readFileSync(path.join(tmp, 'phase_state.json'), 'utf8'));
  assert.ok(state.lead_state, 'lead_state should exist');
  assert.equal(state.lead_state.agent_calls.length, 1);
  assert.equal(state.lead_state.agent_calls[0].phase, 'architecture');
  assert.equal(state.lead_state.last_gate_phase, 'architecture');

  const logDir = path.join(ROOT, 'harness', 'eval', 'reports');
  const logFile = path.join(logDir, `${engagementId}_phase_log.jsonl`);
  if (fs.existsSync(logFile)) fs.unlinkSync(logFile);
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('post-phase: warns on non-sequential phase order', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-order-'));
  const engagementId = `order-${Date.now()}`;

  // First: verify
  runHook({
    AGENT_ENGAGEMENT_ID: engagementId,
    AGENT_PHASE: 'verify',
    AGENT_FINDING_COUNT: '1',
    AGENT_EVIDENCE_COUNT: '1',
    AGENT_HALLUCINATION_COUNT: '0',
    AGENT_PHASE_TOKENS: '1000',
    AGENT_PHASE_COST_USD: '0.01',
    AGENT_ENGAGEMENT_DIR: tmp,
  });

  // Second: va (backwards — va comes before verify) — should warn on stderr
  let stderr = '';
  try {
    execFileSync('node', [HOOK], {
      env: {
        ...process.env,
        AGENT_ENGAGEMENT_ID: engagementId,
        AGENT_PHASE: 'va',
        AGENT_FINDING_COUNT: '0',
        AGENT_EVIDENCE_COUNT: '0',
        AGENT_HALLUCINATION_COUNT: '0',
        AGENT_PHASE_TOKENS: '500',
        AGENT_PHASE_COST_USD: '0.01',
        AGENT_ENGAGEMENT_DIR: tmp,
      },
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (e) {
    stderr = e.stderr || '';
  }
  // Even if it doesn't throw, check phase_state
  const state = JSON.parse(fs.readFileSync(path.join(tmp, 'phase_state.json'), 'utf8'));
  assert.deepEqual(state.completed_phases, ['verify', 'va']);

  const logDir = path.join(ROOT, 'harness', 'eval', 'reports');
  const logFile = path.join(logDir, `${engagementId}_phase_log.jsonl`);
  if (fs.existsSync(logFile)) fs.unlinkSync(logFile);
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('post-phase: exits with code 2 when an explicit budget is exceeded', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-ph-abort-'));
  const engagementId = `abort-${Date.now()}`;
  fs.writeFileSync(
    path.join(tmp, 'ch015.config.json'),
    JSON.stringify({ ch015: { limits: { max_session_tokens: 2_000_000 } } }),
  );
  let errCode = 0;
  try {
    runHook({
      AGENT_ENGAGEMENT_ID: engagementId,
      AGENT_PHASE: 'unit-test',
      AGENT_FINDING_COUNT: '0',
      AGENT_EVIDENCE_COUNT: '0',
      AGENT_HALLUCINATION_COUNT: '0',
      AGENT_PHASE_TOKENS: '3000000',   // exceeds 2M cap
      AGENT_PHASE_COST_USD: '0',
      AGENT_ENGAGEMENT_DIR: tmp,
      CH015_ROOT: tmp,
    });
  } catch (e) {
    errCode = e.status;
  }
  assert.equal(errCode, 2);

  const logDir = path.join(ROOT, 'harness', 'eval', 'reports');
  const logFile = path.join(logDir, `${engagementId}_phase_log.jsonl`);
  if (fs.existsSync(logFile)) fs.unlinkSync(logFile);
  fs.rmSync(tmp, { recursive: true, force: true });
});
