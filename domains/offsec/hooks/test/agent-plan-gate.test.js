'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..', '..');
const GATE = path.join(ROOT, 'hooks', 'agent-plan-gate.js');

function mkProject() {
  const target = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-gate-target-'));
  fs.mkdirSync(path.join(target, 'src'), { recursive: true });
  fs.writeFileSync(path.join(target, 'src', 'main.go'), 'package main\n');
  return target;
}

function runGate(args, env = {}) {
  return spawnSync(process.execPath, [GATE, ...args], {
    env: { ...process.env, ...env },
    encoding: 'utf8',
    timeout: 15000,
  });
}

test('agent-plan-gate CLI: init creates source manifest and fanout decision', () => {
  const target = mkProject();
  const engagement = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-gate-eng-'));

  const r = runGate(['init', '--engagement-dir', engagement, '--target', target, '--analysis-mode', 'ast']);

  assert.equal(r.status, 0, r.stderr);
  assert.ok(fs.existsSync(path.join(engagement, 'source_manifest.json')));
  assert.ok(fs.existsSync(path.join(engagement, 'fanout_decision.json')));
  const decision = JSON.parse(fs.readFileSync(path.join(engagement, 'fanout_decision.json'), 'utf8'));
  assert.equal(decision.va.initial_agents, 1);
  assert.equal(decision.ast_policy.run_once_before_fanout, true);

  fs.rmSync(target, { recursive: true, force: true });
  fs.rmSync(engagement, { recursive: true, force: true });
});

test('agent-plan-gate CLI: reserve exits 2 when small project requests 8 VA agents', () => {
  const target = mkProject();
  const engagement = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-gate-eng-'));
  assert.equal(runGate(['init', '--engagement-dir', engagement, '--target', target]).status, 0);

  const r = runGate([
    'reserve',
    '--engagement-dir', engagement,
    '--phase', 'va',
    '--role', 'va-auditor',
    '--count', '8',
  ]);

  assert.equal(r.status, 2);
  assert.match(r.stderr, /AGENT_FANOUT_LIMIT_EXCEEDED/);

  fs.rmSync(target, { recursive: true, force: true });
  fs.rmSync(engagement, { recursive: true, force: true });
});

test('agent-plan-gate CLI: reserve, commit, reconcile succeeds for canonical VA artifact', () => {
  const target = mkProject();
  const engagement = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-gate-eng-'));
  assert.equal(runGate(['init', '--engagement-dir', engagement, '--target', target]).status, 0);

  const reserve = runGate([
    'reserve',
    '--engagement-dir', engagement,
    '--phase', 'va',
    '--role', 'va-auditor',
    '--count', '1',
  ]);
  assert.equal(reserve.status, 0, reserve.stderr);
  const reservationId = JSON.parse(reserve.stdout).reservation_id;
  fs.writeFileSync(path.join(engagement, '01_va_result-1st.md'), '# VA\n');

  const commit = runGate([
    'commit',
    '--engagement-dir', engagement,
    '--reservation', reservationId,
    '--artifacts', '01_va_result-1st.md',
  ]);
  assert.equal(commit.status, 0, commit.stderr);

  const reconcile = runGate(['reconcile', '--engagement-dir', engagement, '--check-current-source', 'false']);
  assert.equal(reconcile.status, 0, reconcile.stderr);
  const audit = JSON.parse(reconcile.stdout);
  assert.equal(audit.ok, true);

  fs.rmSync(target, { recursive: true, force: true });
  fs.rmSync(engagement, { recursive: true, force: true });
});
