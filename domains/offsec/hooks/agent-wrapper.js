#!/usr/bin/env node
/**
 * Agent Wrapper — Agent Tool 호출 결과에서 사용량(usage)을 추출해
 * AGENT_PHASE_TOKENS / AGENT_PHASE_COST_USD 환경변수를 채우고
 * post-phase.js 훅을 호출하여 예산 트래커에 반영한다.
 *
 * 사용처:
 *   OffSec Lead가 Agent(subagent_type=..., prompt=...) 호출 직후,
 *   반환된 결과 (usage.input_tokens, usage.output_tokens, usage.cost_usd)를
 *   JSON으로 stdin에 넘겨 이 스크립트를 실행한다.
 *
 * 입력 포맷 (stdin JSON):
 *   {
 *     "phase": "va" | "verify" | "pentest" | "redteam" | "convergence",
 *     "agent_role": "va-auditor" | "verifier" | ...,
 *     "usage": {
 *       "input_tokens": 123456,
 *       "output_tokens": 7890,
 *       "cost_usd": 0.45       // optional — 없으면 input+output 합으로 근사
 *     },
 *     "engagement_dir": "/path/to/engagement",
 *     "engagement_id": "eng-2026-04-17-proj-x",
 *     "findings": { "count": 3, "evidence": 12, "hallucinations": 0 } // optional
 *   }
 *
 * 출력: exit 0 (정상) | exit 2 (budget abort) | exit 1 (입력 오류)
 *
 * 테스트: hooks/test/agent-wrapper.test.js
 */

'use strict';

const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const HOOK_DIR = __dirname;
const POST_PHASE = path.join(HOOK_DIR, 'post-phase.js');

function readStdin() {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) return resolve('');
    let buf = '';
    const timeout = setTimeout(() => resolve(buf), 500);
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => { buf += c; });
    process.stdin.on('end', () => { clearTimeout(timeout); resolve(buf); });
    process.stdin.on('error', () => { clearTimeout(timeout); resolve(buf); });
  });
}

function parseInput(raw) {
  if (!raw || !raw.trim()) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

function computeTokens(usage) {
  if (!usage || typeof usage !== 'object') return 0;
  const inTok = Number(usage.input_tokens || 0);
  const outTok = Number(usage.output_tokens || 0);
  return Math.max(0, Math.round(inTok + outTok));
}

function computeCostUsd(usage, tokens) {
  if (usage && typeof usage.cost_usd === 'number') return usage.cost_usd;
  // 아주 대략적 근사: 100만 토큰당 $15 (mix 모델). 실제 세션에서 override 권장.
  // agent-wrapper가 정확한 cost를 알 수 없으므로 usage.cost_usd를 주는 것이 이상적.
  return tokens > 0 ? (tokens / 1_000_000) * 15 : 0;
}

async function main() {
  const raw = await readStdin();
  const input = parseInput(raw);

  if (!input || typeof input !== 'object') {
    console.error('[CH015][agent-wrapper] invalid/empty stdin JSON');
    process.exit(1);
  }

  const phase = input.phase || process.env.AGENT_PHASE || 'unknown';
  const role = input.agent_role || process.env.AGENT_ROLE || 'unknown';
  const engagementDir =
    input.engagement_dir || process.env.AGENT_ENGAGEMENT_DIR || '';
  const engagementId =
    input.engagement_id || process.env.AGENT_ENGAGEMENT_ID || 'unknown';

  if (!engagementDir) {
    console.error('[CH015][agent-wrapper] engagement_dir missing — skipping');
    process.exit(process.env.CH015_AGENT_WRAPPER_ALLOW_MISSING_ENGAGEMENT === '1' ? 0 : 1);
  }

  const tokens = computeTokens(input.usage);
  const cost = computeCostUsd(input.usage, tokens);

  const findings = input.findings || {};
  const invocationLog = path.join(engagementDir, 'agent_invocations.jsonl');
  fs.appendFileSync(invocationLog, JSON.stringify({
    timestamp: new Date().toISOString(),
    engagement_id: engagementId,
    phase,
    agent_role: role,
    subagent_type: input.subagent_type || input.agent?.name || '',
    status: input.status || 'completed',
    usage: input.usage || {},
    tokens,
    cost_usd: cost,
    findings,
    artifacts: input.artifacts || input.storage_paths || [],
  }) + '\n', { encoding: 'utf8', mode: 0o600 });

  const childEnv = {
    ...process.env,
    AGENT_PHASE: phase,
    AGENT_ROLE: role,
    AGENT_ENGAGEMENT_DIR: engagementDir,
    AGENT_ENGAGEMENT_ID: engagementId,
    AGENT_PHASE_TOKENS: String(tokens),
    AGENT_PHASE_COST_USD: String(cost.toFixed(6)),
    AGENT_FINDING_COUNT: String(findings.count || 0),
    AGENT_EVIDENCE_COUNT: String(findings.evidence || 0),
    AGENT_HALLUCINATION_COUNT: String(findings.hallucinations || 0),
  };

  const r = spawnSync('node', [POST_PHASE], {
    env: childEnv,
    stdio: ['ignore', 'inherit', 'inherit'],
    timeout: 15_000,
  });

  // spawn 실패(r.error) / 타임아웃·시그널 종료(r.status == null)는 budget ABORT
  // 판정 자체가 수행되지 않은 것이므로 0으로 마스킹하지 않고 비-0으로 전파한다.
  if (r.error || r.status == null) {
    const detail = r.error
      ? r.error.message
      : `no exit status (signal=${r.signal || 'unknown'})`;
    console.error(`[CH015][agent-wrapper] post-phase did not complete: ${detail}`);
    process.exit(1);
  }

  // post-phase.js가 abort(2)를 내면 상위로 그대로 전달
  process.exit(r.status);
}

main().catch((e) => {
  console.error(`[CH015][agent-wrapper] unexpected: ${e.message}`);
  process.exit(1);
});
