#!/usr/bin/env node
/**
 * PreToolUse Hook — CH015 Invariant Runtime Enforcer
 *
 * Claude Code harness가 Tool 호출 직전에 stdin으로 JSON 컨텍스트를 넘기면
 * (`{ tool, args, session_id, agent: {...}, env: {...} }`) verify-invariants
 * 모듈의 preToolUseCheck 에게 위임하여 Verifier Phase 순서(Invariants I1/I2)
 * 위반을 런타임에 차단한다.
 *
 * 차단 시:
 *   - stderr 에 사유 기록
 *   - engagement_dir/audit.log 에 ANCHORING_VIOLATION 기록 (verify-invariants 내부)
 *   - exit 2 로 Tool 실행 중단
 *
 * 허용 시:
 *   - exit 0, 정상 Tool 실행 흐름
 *
 * 미적용 조건 (조용히 통과):
 *   - AGENT_ROLE 이 verifier 가 아니면 스킵
 *   - stdin 이 비어있고 verifier role도 식별되지 않으면 스킵
 *
 * 테스트: hooks/test/pre-tool-use.test.js
 */

'use strict';

const { preToolUseCheck } = require('./verify-invariants.js');

function readStdin() {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) return resolve('');
    let buf = '';
    const timeout = setTimeout(() => resolve(buf), 500);
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => { buf += chunk; });
    process.stdin.on('end', () => { clearTimeout(timeout); resolve(buf); });
    process.stdin.on('error', () => { clearTimeout(timeout); resolve(buf); });
  });
}

function parsePayload(raw) {
  if (!raw || !raw.trim()) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function normalizeAgentRole(value) {
  if (typeof value !== 'string') return '';
  if (/(\b|:|\/)verifier(\b|:|\/)/i.test(value)) return 'verifier';
  if (/(\b|:|\/)va-auditor(\b|:|\/)/i.test(value)) return 'va-auditor';
  if (/(\b|:|\/)pentester(\b|:|\/)/i.test(value)) return 'pentester';
  if (/(\b|:|\/)redteam(\b|:|\/)/i.test(value)) return 'redteam';
  return value;
}

function pickAgentRole(payload) {
  const candidates = [
    // Claude Code PreToolUse 페이로드는 서브에이전트 신원을 top-level
    // agent_type/agent_id로 싣는다. 세션 공통 env보다 실제 호출 신원을 우선한다.
    payload && payload.agent_type,
    payload && payload.agent_id,
    payload && payload.subagent_type,
    payload && payload.agent && payload.agent.name,
    payload && payload.agent && payload.agent.role,
    payload && payload.agent && payload.agent.type,
    payload && payload.env && payload.env.AGENT_ROLE,
    payload && payload.AGENT_ROLE,
    payload && payload.agent_role,
    process.env.AGENT_ROLE,
  ];
  for (const candidate of candidates) {
    const role = normalizeAgentRole(candidate);
    if (role) return role;
  }
  return '';
}

function pickEnv(payload) {
  // 우선순위: payload.env > process.env
  return {
    AGENT_ROLE: pickAgentRole(payload),
    AGENT_ENGAGEMENT_DIR:
      (payload && payload.env && payload.env.AGENT_ENGAGEMENT_DIR) ||
      (payload && payload.AGENT_ENGAGEMENT_DIR) ||
      (payload && payload.engagement_dir) ||
      process.env.AGENT_ENGAGEMENT_DIR ||
      '',
    AGENT_VERIFY_ROUND:
      (payload && payload.env && payload.env.AGENT_VERIFY_ROUND) ||
      (payload && payload.AGENT_VERIFY_ROUND) ||
      (payload && payload.verify_round) ||
      process.env.AGENT_VERIFY_ROUND ||
      '',
    AGENT_VERIFY_GROUP:
      (payload && payload.env && payload.env.AGENT_VERIFY_GROUP) ||
      (payload && payload.AGENT_VERIFY_GROUP) ||
      (payload && payload.verify_group) ||
      (payload && payload.group_id) ||
      process.env.AGENT_VERIFY_GROUP ||
      '',
  };
}

function isVerifierEnv(env) {
  return normalizeAgentRole(env && env.AGENT_ROLE) === 'verifier';
}

function evaluateHookPayload(raw, checkFn = preToolUseCheck) {
  const payload = parsePayload(raw);

  if (!payload) {
    const role = normalizeAgentRole(process.env.AGENT_ROLE);
    if (role === 'verifier') {
      return {
        exitCode: 2,
        stderr: '[CH015][PreToolUse] malformed or empty hook payload for verifier role',
      };
    }
    return { exitCode: 0 };
  }

  const tool = (payload && (payload.tool || payload.tool_name)) || '';
  const args = (payload && (payload.args || payload.tool_input)) || {};
  const env = pickEnv(payload);

  if (!tool) {
    return { exitCode: 0 };
  }

  let result;
  try {
    result = checkFn({ tool, args, env });
  } catch (e) {
    return {
      exitCode: isVerifierEnv(env) ? 2 : 0,
      stderr: `[CH015][PreToolUse] invariant check error: ${e.message}`,
    };
  }

  if (result && result.allow === false) {
    return {
      exitCode: typeof result.exitCode === 'number' ? result.exitCode : 2,
      stderr: `[CH015][BLOCK] ${result.reason}`,
    };
  }
  return { exitCode: 0 };
}

async function main() {
  const raw = await readStdin();
  const decision = evaluateHookPayload(raw);
  if (decision.stderr) console.error(decision.stderr);
  process.exit(decision.exitCode);
}

if (require.main === module) {
  main().catch((e) => {
    console.error(`[CH015][PreToolUse] unexpected: ${e.message}`);
    process.exit(normalizeAgentRole(process.env.AGENT_ROLE) === 'verifier' ? 2 : 0);
  });
} else {
  module.exports = {
    evaluateHookPayload,
    normalizeAgentRole,
    pickAgentRole,
    pickEnv,
    isVerifierEnv,
  };
}
