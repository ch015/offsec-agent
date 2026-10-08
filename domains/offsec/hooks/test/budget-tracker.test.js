/**
 * P2-7 / Budget Tracker 단위 테스트
 */

'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');

const { track, checkLimits, DEFAULTS } = require('../budget-tracker.js');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-budget-'));
process.on('exit', () => { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch {} });

function mkDir(name) {
  const d = path.join(TMP, name);
  fs.mkdirSync(d, { recursive: true });
  return d;
}

test('track: creates budget.json with initial update', () => {
  const d = mkDir('t1');
  const { state, alerts } = track({ tokens: 100 }, { AGENT_ENGAGEMENT_DIR: d });
  assert.equal(state.tokens, 100);
  assert.equal(alerts.length, 0);
  assert.ok(fs.existsSync(path.join(d, 'budget.json')));
});

test('track: accumulates tokens across calls', () => {
  const d = mkDir('t2');
  track({ tokens: 500_000 }, { AGENT_ENGAGEMENT_DIR: d });
  const { state } = track({ tokens: 500_000 }, { AGENT_ENGAGEMENT_DIR: d });
  assert.equal(state.tokens, 1_000_000);
});

test('track: records tokens without a default cap', () => {
  const d = mkDir('t3');
  const { state, alerts } = track({ tokens: 1_700_000 }, { AGENT_ENGAGEMENT_DIR: d });
  assert.equal(state.tokens, 1_700_000);
  assert.equal(alerts.filter((a) => a.name === 'tokens').length, 0);
});

test('checkLimits: honors an explicitly configured token cap', () => {
  const d = mkDir('t4');
  const state = track({ tokens: 2_000_000 }, { AGENT_ENGAGEMENT_DIR: d }).state;
  const alerts = checkLimits(state, { ...DEFAULTS, max_session_tokens: 2_000_000 });
  const aborts = alerts.filter((a) => a.level === 'ABORT' && a.name === 'tokens');
  assert.equal(aborts.length, 1);
});

test('track: records cost without a default cap', () => {
  const d = mkDir('t5');
  const { state, alerts } = track({ cost_usd: 30.5 }, { AGENT_ENGAGEMENT_DIR: d });
  assert.equal(state.cost_usd, 30.5);
  assert.equal(alerts.filter((a) => a.name === 'cost_usd').length, 0);
});

test('cost: old numeric limits do not enforce without explicit policy', () => {
  const state = { cost_usd: 100, tokens: 0, tool_calls: {} };
  assert.equal(checkLimits(state, { ...DEFAULTS, cost_limit_usd: 1 }).filter(a => a.name === 'cost_usd').length, 0);
  assert.equal(checkLimits(state, { ...DEFAULTS, cost_limit_usd: 1, cost_policy: 'enforce' }).filter(a => a.name === 'cost_usd').length, 1);
});

test('track: records tool calls without a default cap', () => {
  const d = mkDir('t6');
  let last;
  for (let i = 0; i < 501; i++) last = track({ tool: 'Read' }, { AGENT_ENGAGEMENT_DIR: d });
  assert.equal(last.state.tool_calls.Read, 501);
  assert.equal(last.alerts.filter((a) => a.name === 'tool_calls.Read').length, 0);
});

test('track: agent_depth limit', () => {
  const d = mkDir('t7');
  const { alerts } = track({ agent_depth: 5 }, { AGENT_ENGAGEMENT_DIR: d });
  const aborts = alerts.filter((a) => a.name === 'agent_depth' && a.level === 'ABORT');
  assert.equal(aborts.length, 1);
});

test('track: requires AGENT_ENGAGEMENT_DIR', () => {
  assert.throws(() => track({ tokens: 1 }, {}), /AGENT_ENGAGEMENT_DIR/);
});

test('track: atomic write (tmp + rename)', () => {
  const d = mkDir('t8');
  track({ tokens: 100 }, { AGENT_ENGAGEMENT_DIR: d });
  assert.ok(fs.existsSync(path.join(d, 'budget.json')));
  assert.ok(!fs.existsSync(path.join(d, 'budget.json.tmp')));
});

test('track: events log retained up to 200', () => {
  const d = mkDir('t9');
  for (let i = 0; i < 250; i++) track({ tokens: 1 }, { AGENT_ENGAGEMENT_DIR: d });
  const state = JSON.parse(fs.readFileSync(path.join(d, 'budget.json'), 'utf8'));
  assert.ok(state.events.length <= 200);
});

test('track: preserves all concurrent process updates', async () => {
  const d = mkDir('parallel');
  const script = path.resolve(__dirname, '..', 'budget-tracker.js');
  await Promise.all(Array.from({ length: 40 }, () => new Promise((resolve, reject) => {
    execFile('node', [script, '--tokens', '1'], {
      env: { ...process.env, AGENT_ENGAGEMENT_DIR: d },
    }, (error) => error ? reject(error) : resolve());
  })));
  const state = JSON.parse(fs.readFileSync(path.join(d, 'budget.json'), 'utf8'));
  assert.equal(state.tokens, 40);
  assert.equal(state.events.length, 40);
});
