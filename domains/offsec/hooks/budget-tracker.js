#!/usr/bin/env node
/**
 * CH015 Budget Tracker (P2-7)
 *
 * engagement 단위의 토큰/비용/tool 호출 예산을 누적 추적한다.
 * post-phase.js 또는 on-stop.js 에서 호출하여 한계 도달 시 abort 신호를 발생시킨다.
 *
 * 상태 파일: engagement_dir/budget.json
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { withFileLock } = require('../lib/core/io.js');

const DEFAULTS = {
  max_session_tokens: null,
  cost_limit_usd: null,
  cost_policy: 'record-only',
  max_agent_depth: 5,
  // F1: feedbackLoop.max_iterations(agent-plan fanout 게이트)와 단일 값으로 동기화 유지.
  // 두 게이트가 같은 feedback 루프를 통제하므로 값이 어긋나면 라운드 차단 기준이 모순된다.
  max_feedback_iterations: 2,
  max_objection_cycles: 2,
  per_tool_budget: {},
  warn_threshold_ratio: 0.8,
  abort_threshold_ratio: 1.0,
};

function loadConfig(ch015Root) {
  try {
    const raw = fs.readFileSync(path.join(ch015Root, 'ch015.config.json'), 'utf8');
    const cfg = JSON.parse(raw);
    return { ...DEFAULTS, ...(cfg?.ch015?.limits || {}) };
  } catch {
    return DEFAULTS;
  }
}

function loadState(engagementDir) {
  const p = path.join(engagementDir, 'budget.json');
  if (!fs.existsSync(p)) {
    return {
      tokens: 0,
      cost_usd: 0.0,
      tool_calls: {},
      agent_depth: 0,
      feedback_iterations: 0,
      objection_cycles: 0,
      events: [],
    };
  }
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch {
    return null;
  }
}

function saveState(engagementDir, state) {
  const p = path.join(engagementDir, 'budget.json');
  const tmp = `${p}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(state, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, p);
}

function checkLimits(state, limits) {
  const alerts = [];
  const warn = limits.warn_threshold_ratio;
  const abort = limits.abort_threshold_ratio;

  function evalRatio(name, current, max) {
    if (!max || max <= 0) return;
    const r = current / max;
    if (r >= abort) alerts.push({ level: 'ABORT', name, current, max, ratio: r });
    else if (r >= warn) alerts.push({ level: 'WARN', name, current, max, ratio: r });
  }

  evalRatio('tokens', state.tokens, limits.max_session_tokens);
  if (limits.cost_policy === 'enforce') evalRatio('cost_usd', state.cost_usd, limits.cost_limit_usd);
  evalRatio('agent_depth', state.agent_depth, limits.max_agent_depth);
  evalRatio('feedback_iterations', state.feedback_iterations, limits.max_feedback_iterations);
  evalRatio('objection_cycles', state.objection_cycles, limits.max_objection_cycles);

  for (const [tool, max] of Object.entries(limits.per_tool_budget || {})) {
    evalRatio(`tool_calls.${tool}`, state.tool_calls[tool] || 0, max);
  }

  return alerts;
}

/**
 * track(update) — CLI/programmatic entry.
 *   update: { tokens?, cost_usd?, tool?, agent_depth?, feedback_iterations?, objection_cycles? }
 *   env:
 *     AGENT_ENGAGEMENT_DIR (required)
 *     CH015_ROOT (optional — config 로드, 미지정 시 DEFAULTS 사용)
 */
function track(update, env = process.env) {
  const engagementDir = env.AGENT_ENGAGEMENT_DIR;
  if (!engagementDir) throw new Error('AGENT_ENGAGEMENT_DIR required');
  fs.mkdirSync(engagementDir, { recursive: true });

  const root = env.CH015_ROOT || path.resolve(__dirname, '..');
  const limits = { ...loadConfig(root) };
  if (env.CH015_COST_POLICY) limits.cost_policy = env.CH015_COST_POLICY;

  return withFileLock(path.join(engagementDir, 'budget.json'), () => {
    const state = loadState(engagementDir) || {
      tokens: 0, cost_usd: 0, tool_calls: {}, agent_depth: 0,
      feedback_iterations: 0, objection_cycles: 0, events: [],
    };

    if (update.tokens) state.tokens += Number(update.tokens);
    if (update.cost_usd) state.cost_usd += Number(update.cost_usd);
    if (update.agent_depth !== undefined) state.agent_depth = Number(update.agent_depth);
    if (update.feedback_iterations !== undefined) state.feedback_iterations = Number(update.feedback_iterations);
    if (update.objection_cycles !== undefined) state.objection_cycles = Number(update.objection_cycles);
    if (update.tool) state.tool_calls[update.tool] = (state.tool_calls[update.tool] || 0) + 1;

    const alerts = checkLimits(state, limits);
    state.events.push({ ts: new Date().toISOString(), update, alerts });
    if (state.events.length > 200) state.events = state.events.slice(-200);

    saveState(engagementDir, state);
    return { state, alerts };
  });
}

function cliMain(argv) {
  const [, , ...rest] = argv;
  const opts = {};
  for (let i = 0; i < rest.length; i += 2) {
    const k = rest[i].replace(/^--/, '');
    opts[k] = rest[i + 1];
  }
  const { alerts } = track(opts);
  for (const a of alerts) {
    console.error(`[CH015 BUDGET ${a.level}] ${a.name}: ${a.current}/${a.max} (${(a.ratio * 100).toFixed(1)}%)`);
  }
  const aborts = alerts.filter((a) => a.level === 'ABORT');
  if (aborts.length) process.exit(2);
}

if (require.main === module) {
  cliMain(process.argv);
}

module.exports = { track, checkLimits, loadState, saveState, DEFAULTS };
