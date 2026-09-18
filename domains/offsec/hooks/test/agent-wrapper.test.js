/**
 * P1-1 / Agent Wrapper 통합 테스트
 * hooks/agent-wrapper.js 를 child process로 실행하여
 * stdin JSON → post-phase → budget.json 반영을 검증한다.
 */

'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const WRAPPER = path.resolve(__dirname, '..', 'agent-wrapper.js');

function runWrapper(payload, extraEnv = {}) {
  const r = spawnSync('node', [WRAPPER], {
    input: payload == null ? '' : JSON.stringify(payload),
    env: { ...process.env, ...extraEnv },
    encoding: 'utf8',
    timeout: 15_000,
  });
  return { code: r.status, stderr: r.stderr || '', stdout: r.stdout || '' };
}

function mkEng() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-wrap-'));
}

test('agent-wrapper: rejects empty stdin', () => {
  const r = runWrapper(null);
  assert.equal(r.code, 1);
});

test('agent-wrapper: rejects missing engagement_dir by default', () => {
  const r = runWrapper({
    phase: 'va',
    agent_role: 'va-auditor',
    usage: { input_tokens: 1000, output_tokens: 500 },
  });
  assert.equal(r.code, 1);
  assert.match(r.stderr, /engagement_dir missing/);
});

test('agent-wrapper: can explicitly skip missing engagement_dir in debug mode', () => {
  const r = runWrapper({
    phase: 'va',
    agent_role: 'va-auditor',
    usage: { input_tokens: 1000, output_tokens: 500 },
  }, { CH015_AGENT_WRAPPER_ALLOW_MISSING_ENGAGEMENT: '1' });
  assert.equal(r.code, 0);
  assert.match(r.stderr, /engagement_dir missing/);
});

test('agent-wrapper: writes tokens to budget.json via post-phase', () => {
  const d = mkEng();
  const r = runWrapper({
    phase: 'va',
    agent_role: 'va-auditor',
    engagement_dir: d,
    engagement_id: 'test-eng-1',
    usage: { input_tokens: 50_000, output_tokens: 2_000 },
    findings: { count: 3, evidence: 8, hallucinations: 0 },
  });
  assert.equal(r.code, 0, `stderr: ${r.stderr}`);

  const budget = JSON.parse(fs.readFileSync(path.join(d, 'budget.json'), 'utf8'));
  assert.equal(budget.tokens, 52_000);
  assert.ok(budget.cost_usd > 0);

  const ledgerFile = path.join(d, 'agent_invocations.jsonl');
  const ledger = fs.readFileSync(ledgerFile, 'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(ledger.length, 1);
  assert.equal(ledger[0].agent_role, 'va-auditor');
  assert.equal(ledger[0].phase, 'va');
  if (process.platform !== 'win32') {
    assert.equal(fs.statSync(ledgerFile).mode & 0o777, 0o600);
  }

  // post-phase도 로그 남김 (harness/eval/reports)
  const logDir = path.resolve(__dirname, '..', '..', 'harness', 'eval', 'reports');
  const logFile = path.join(logDir, 'test-eng-1_phase_log.jsonl');
  assert.ok(fs.existsSync(logFile));
  const logContent = fs.readFileSync(logFile, 'utf8').trim().split('\n').pop();
  const logEntry = JSON.parse(logContent);
  assert.equal(logEntry.phase, 'va');
  assert.equal(logEntry.tokens_delta, 52_000);
  assert.equal(logEntry.finding_count, 3);

  fs.unlinkSync(logFile);
  fs.rmSync(d, { recursive: true, force: true });
});

test('agent-wrapper: propagates an explicitly configured budget ABORT exit=2', () => {
  const d = mkEng();
  fs.writeFileSync(
    path.join(d, 'ch015.config.json'),
    JSON.stringify({ ch015: { limits: { max_session_tokens: 2_000_000 } } }),
  );
  const r = runWrapper({
    phase: 'verify',
    agent_role: 'verifier',
    engagement_dir: d,
    engagement_id: 'test-abort',
    usage: { input_tokens: 3_000_000, output_tokens: 0 }, // exceeds 2M cap
  }, { CH015_ROOT: d });
  assert.equal(r.code, 2);

  const logDir = path.resolve(__dirname, '..', '..', 'harness', 'eval', 'reports');
  const logFile = path.join(logDir, 'test-abort_phase_log.jsonl');
  if (fs.existsSync(logFile)) fs.unlinkSync(logFile);
  fs.rmSync(d, { recursive: true, force: true });
});

test('agent-wrapper: post-phase spawn failure exits non-zero (no ABORT masking)', () => {
  const d = mkEng();
  // PATH를 빈 디렉터리로 비워 wrapper 내부의 spawnSync('node', [post-phase])가
  // ENOENT로 실패하게 만든다 → r.error 세트, r.status == null.
  // 종전 `process.exit(r.status || 0)`는 이를 exit 0으로 마스킹했다.
  const emptyBin = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-nobin-'));
  const r = spawnSync(process.execPath, [WRAPPER], {
    input: JSON.stringify({
      phase: 'va',
      agent_role: 'va-auditor',
      engagement_dir: d,
      engagement_id: 'test-spawnfail',
      usage: { input_tokens: 10, output_tokens: 5 },
    }),
    env: { ...process.env, PATH: emptyBin },
    encoding: 'utf8',
    timeout: 15_000,
  });
  assert.notEqual(r.status, 0, `expected non-zero exit; stderr: ${r.stderr}`);
  assert.match(r.stderr || '', /post-phase did not complete/);

  fs.rmSync(emptyBin, { recursive: true, force: true });
  fs.rmSync(d, { recursive: true, force: true });
});

test('agent-wrapper: accepts explicit cost_usd override', () => {
  const d = mkEng();
  runWrapper({
    phase: 'pentest',
    agent_role: 'pentester',
    engagement_dir: d,
    engagement_id: 'test-cost',
    usage: { input_tokens: 10, output_tokens: 5, cost_usd: 12.5 },
  });
  const budget = JSON.parse(fs.readFileSync(path.join(d, 'budget.json'), 'utf8'));
  assert.equal(budget.cost_usd, 12.5);

  const logDir = path.resolve(__dirname, '..', '..', 'harness', 'eval', 'reports');
  const logFile = path.join(logDir, 'test-cost_phase_log.jsonl');
  if (fs.existsSync(logFile)) fs.unlinkSync(logFile);
  fs.rmSync(d, { recursive: true, force: true });
});
