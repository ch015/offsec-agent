/**
 * P0-rev-4 / PreToolUse 훅 통합 테스트
 *
 * 실제 hook 스크립트(hooks/pre-tool-use.js)를 child process로 실행하여
 * stdin JSON → exit code + stderr 동작을 검증한다.
 */

'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const HOOK = path.resolve(__dirname, '..', 'pre-tool-use.js');
const HOOKS_CONFIG = path.resolve(__dirname, '..', 'hooks.json');
const { evaluateHookPayload, pickAgentRole } = require('../pre-tool-use');

function runHook(payload, extraEnv = {}) {
  const r = spawnSync('node', [HOOK], {
    input: payload == null ? '' : JSON.stringify(payload),
    env: { ...process.env, ...extraEnv },
    encoding: 'utf8',
    timeout: 10_000,
  });
  return { code: r.status, stderr: r.stderr || '', stdout: r.stdout || '' };
}

function mkEngagement() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-pre-tool-'));
}

test('PreToolUse: fail-open on empty stdin', () => {
  const r = runHook(null);
  assert.equal(r.code, 0);
});

test('PreToolUse: fail-open on malformed JSON', () => {
  const r = spawnSync('node', [HOOK], {
    input: 'this is not json',
    env: process.env,
    encoding: 'utf8',
  });
  assert.equal(r.status, 0);
});

test('PreToolUse: fails closed on empty stdin for verifier role', () => {
  const r = runHook(null, { AGENT_ROLE: 'verifier' });
  assert.equal(r.code, 2);
  assert.match(r.stderr, /malformed or empty hook payload/i);
});

test('PreToolUse: fails closed on malformed JSON for verifier role', () => {
  const r = spawnSync('node', [HOOK], {
    input: 'this is not json',
    env: { ...process.env, AGENT_ROLE: 'verifier' },
    encoding: 'utf8',
  });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /malformed or empty hook payload/i);
});

test('PreToolUse: fails closed on invariant exception for verifier role', () => {
  const decision = evaluateHookPayload(JSON.stringify({
    tool: 'Read',
    args: { file_path: '/tmp/eng/01_va_result-1st.md' },
    env: {
      AGENT_ROLE: 'verifier',
      AGENT_ENGAGEMENT_DIR: '/tmp/eng',
      AGENT_VERIFY_ROUND: '1st',
    },
  }), () => {
    throw new Error('synthetic invariant failure');
  });

  assert.equal(decision.exitCode, 2);
  assert.match(decision.stderr, /synthetic invariant failure/);
});

test('PreToolUse: keeps non-verifier invariant exceptions fail-open', () => {
  const decision = evaluateHookPayload(JSON.stringify({
    tool: 'Read',
    args: { file_path: '/tmp/eng/01_va_result-1st.md' },
    env: {
      AGENT_ROLE: 'va-auditor',
      AGENT_ENGAGEMENT_DIR: '/tmp/eng',
    },
  }), () => {
    throw new Error('synthetic invariant failure');
  });

  assert.equal(decision.exitCode, 0);
  assert.match(decision.stderr, /synthetic invariant failure/);
});

test('PreToolUse config: covers Read and I3 protected edit tools', () => {
  const config = JSON.parse(fs.readFileSync(HOOKS_CONFIG, 'utf8'));
  const entries = config.hooks && config.hooks.PreToolUse;
  assert.ok(Array.isArray(entries));

  const matchers = new Set(entries.map((entry) => entry.matcher));
  for (const tool of ['Read', 'Edit', 'Write', 'MultiEdit', 'NotebookEdit', 'Bash']) {
    assert.ok(matchers.has(tool), `missing PreToolUse matcher for ${tool}`);
  }

  for (const entry of entries.filter((entry) => matchers.has(entry.matcher))) {
    const commands = (entry.hooks || []).map((hook) => hook.command);
    assert.ok(
      commands.includes('node ${CLAUDE_PLUGIN_ROOT}/hooks/pre-tool-use.js'),
      `matcher ${entry.matcher} must run pre-tool-use.js`
    );
  }
});

// Codex 플러그인 번들 패키징 테스트는 제거했다. 이 리포는 Codex 플러그인을
// 배포하지 않고 Claude Agent SDK 호스트만 사용한다 (plugins/ch015/.codex-plugin,
// install.sh 는 이식 대상이 아니다). 검증 대상이 없는 단정은 남기지 않는다.

test('PreToolUse: allows non-verifier roles reading VA report', () => {
  const d = mkEngagement();
  const r = runHook({
    tool: 'Read',
    args: { file_path: path.join(d, '01_va_result-1st.md') },
    env: {
      AGENT_ROLE: 'va-auditor',
      AGENT_ENGAGEMENT_DIR: d,
    },
  });
  assert.equal(r.code, 0);
  fs.rmSync(d, { recursive: true, force: true });
});

test('PreToolUse: BLOCKS verifier reading VA report before autonomous', () => {
  const d = mkEngagement();
  const r = runHook({
    tool: 'Read',
    args: { file_path: path.join(d, '01_va_result-1st.md') },
    env: {
      AGENT_ROLE: 'verifier',
      AGENT_ENGAGEMENT_DIR: d,
      AGENT_VERIFY_ROUND: '1st',
    },
  });
  assert.equal(r.code, 2, `expected exit 2, got ${r.code}: ${r.stderr}`);
  assert.match(r.stderr, /Invariant I1\/I2|ANCHORING/i);
  // audit.log written by verify-invariants
  const log = fs.readFileSync(path.join(d, 'audit.log'), 'utf8');
  assert.match(log, /ANCHORING_VIOLATION/);
  fs.rmSync(d, { recursive: true, force: true });
});

test('PreToolUse: BLOCKS verifier reading non-canonical engagement report before autonomous', () => {
  const d = mkEngagement();
  const r = runHook({
    tool: 'Read',
    args: { file_path: path.join(d, 'ch015-cross-pay-api-2026-06-01-v2.md') },
    env: {
      AGENT_ROLE: 'verifier',
      AGENT_ENGAGEMENT_DIR: d,
      AGENT_VERIFY_ROUND: '1st',
    },
  });
  assert.equal(r.code, 2, `expected exit 2, got ${r.code}: ${r.stderr}`);
  assert.match(r.stderr, /Invariant I1\/I2|ANCHORING/i);
  fs.rmSync(d, { recursive: true, force: true });
});

test('PreToolUse: BLOCKS sealed report read when role is missing', () => {
  const d = mkEngagement();
  const r = runHook({
    tool: 'Read',
    args: { file_path: path.join(d, 'final-security-report.md') },
    env: {
      AGENT_ENGAGEMENT_DIR: d,
      AGENT_VERIFY_ROUND: '1st',
    },
  });
  assert.equal(r.code, 2, `expected exit 2, got ${r.code}: ${r.stderr}`);
  assert.match(r.stderr, /AGENT_ROLE is required/i);
  fs.rmSync(d, { recursive: true, force: true });
});

test('PreToolUse: infers verifier role and engagement dir from hook payload', () => {
  const d = mkEngagement();
  const r = runHook({
    tool: 'Read',
    args: { file_path: path.join(d, '01_va_result-1st.md') },
    agent: { name: 'ch015:offsec:verifier' },
  });
  assert.equal(r.code, 2, `expected exit 2, got ${r.code}: ${r.stderr}`);
  assert.match(r.stderr, /Invariant I1\/I2|ANCHORING/i);
  fs.rmSync(d, { recursive: true, force: true });
});

test('PreToolUse: ALLOWS verifier Read AFTER autonomous output exists', () => {
  const d = mkEngagement();
  fs.writeFileSync(path.join(d, '02a_verify_autonomous-1st.md'), '# auto\n');
  const r = runHook({
    tool: 'Read',
    args: { file_path: path.join(d, '01_va_result-1st.md') },
    env: {
      AGENT_ROLE: 'verifier',
      AGENT_ENGAGEMENT_DIR: d,
      AGENT_VERIFY_ROUND: '1st',
    },
  });
  assert.equal(r.code, 0);
  fs.rmSync(d, { recursive: true, force: true });
});

test('PreToolUse: accepts tool_name / tool_input variant field names', () => {
  const d = mkEngagement();
  const r = runHook({
    tool_name: 'Read',
    tool_input: { file_path: path.join(d, '06_pentest_result.md') },
    env: {
      AGENT_ROLE: 'verifier',
      AGENT_ENGAGEMENT_DIR: d,
      AGENT_VERIFY_ROUND: '1st',
    },
  });
  assert.equal(r.code, 2);
  fs.rmSync(d, { recursive: true, force: true });
});

test('PreToolUse: blocks VA delta before autonomous', () => {
  const d = mkEngagement();
  const r = runHook({
    tool: 'Read',
    args: { file_path: path.join(d, '03_va_delta-2nd.yaml') },
    env: {
      AGENT_ROLE: 'verifier',
      AGENT_ENGAGEMENT_DIR: d,
      AGENT_VERIFY_ROUND: '2nd',
    },
  });
  assert.equal(r.code, 2);
  assert.match(r.stderr, /Invariant I1\/I2|ANCHORING/i);
  fs.rmSync(d, { recursive: true, force: true });
});

test('PreToolUse: blocks re-Write on EXISTING autonomous output', () => {
  const d = mkEngagement();
  fs.writeFileSync(path.join(d, '02a_verify_autonomous-1st.md'), '# auto');
  const r = runHook({
    tool: 'Write',
    args: { file_path: path.join(d, '02a_verify_autonomous-1st.md') },
    env: {
      AGENT_ROLE: 'verifier',
      AGENT_ENGAGEMENT_DIR: d,
      AGENT_VERIFY_ROUND: '1st',
    },
  });
  assert.equal(r.code, 2);
  assert.match(r.stderr, /Invariant I3/);
  fs.rmSync(d, { recursive: true, force: true });
});

test('PreToolUse [P0-B]: allows first Write creating autonomous output (R0.5)', () => {
  const d = mkEngagement();
  const r = runHook({
    tool: 'Write',
    args: { file_path: path.join(d, '02a_verify_autonomous-1st.md') },
    env: {
      AGENT_ROLE: 'verifier',
      AGENT_ENGAGEMENT_DIR: d,
      AGENT_VERIFY_ROUND: '1st',
    },
  });
  assert.equal(r.code, 0, `expected allow for 02a creation: ${r.stderr}`);
  fs.rmSync(d, { recursive: true, force: true });
});

test('PreToolUse [P0-A]: env-less session allows arbitrary Read (no global block)', () => {
  const d = mkEngagement();
  fs.writeFileSync(path.join(d, 'notes.md'), '# notes');
  const r = runHook({
    tool: 'Read',
    args: { file_path: path.join(d, 'notes.md') },
  });
  assert.equal(r.code, 0, `expected allow, got ${r.code}: ${r.stderr}`);
  fs.rmSync(d, { recursive: true, force: true });
});

test('PreToolUse [P0-A]: env-less session still requires role for canonical sealed names', () => {
  const d = mkEngagement();
  const r = runHook({
    tool: 'Read',
    args: { file_path: path.join(d, '01_va_result-1st.md') },
  });
  assert.equal(r.code, 2, `expected block, got ${r.code}: ${r.stderr}`);
  assert.match(r.stderr, /AGENT_ROLE is required/i);
  fs.rmSync(d, { recursive: true, force: true });
});

test('PreToolUse [P1-1]: blocks verifier Write on VA report (SoD)', () => {
  const d = mkEngagement();
  const r = runHook({
    tool: 'Write',
    args: { file_path: path.join(d, '01_va_result-1st.md') },
    env: {
      AGENT_ROLE: 'verifier',
      AGENT_ENGAGEMENT_DIR: d,
      AGENT_VERIFY_ROUND: '1st',
    },
  });
  assert.equal(r.code, 2, `expected SoD block, got ${r.code}: ${r.stderr}`);
  assert.match(r.stderr, /Separation of duties/i);
  fs.rmSync(d, { recursive: true, force: true });
});

test('PreToolUse: blocks path-less Grep by verifier before R0.5 (cwd scan can leak sealed report)', () => {
  const d = mkEngagement();
  const r = runHook({
    tool: 'Grep',
    args: { pattern: 'foo' },
    env: {
      AGENT_ROLE: 'verifier',
      AGENT_ENGAGEMENT_DIR: d,
      AGENT_VERIFY_ROUND: '1st',
    },
  });
  assert.equal(r.code, 2);
  fs.rmSync(d, { recursive: true, force: true });
});

test('PreToolUse: allows path-less Grep by verifier after R0.5', () => {
  const d = mkEngagement();
  fs.writeFileSync(path.join(d, '02a_verify_autonomous-1st.md'), '# auto');
  const r = runHook({
    tool: 'Grep',
    args: { pattern: 'foo' },
    env: {
      AGENT_ROLE: 'verifier',
      AGENT_ENGAGEMENT_DIR: d,
      AGENT_VERIFY_ROUND: '1st',
    },
  });
  assert.equal(r.code, 0);
  fs.rmSync(d, { recursive: true, force: true });
});

test('PreToolUse: blocks verifier Bash outside AST allowlist', () => {
  const d = mkEngagement();
  const r = runHook({
    tool: 'Bash',
    args: { command: 'curl https://example.com' },
    env: {
      AGENT_ROLE: 'verifier',
      AGENT_ENGAGEMENT_DIR: d,
    },
  });
  assert.equal(r.code, 2);
  assert.match(r.stderr, /Verifier Bash is restricted/i);
  const log = fs.readFileSync(path.join(d, 'audit.log'), 'utf8');
  assert.match(log, /VERIFIER_BASH_SCOPE_VIOLATION/);
  fs.rmSync(d, { recursive: true, force: true });
});

test('PreToolUse: allows verifier Bash for AST tooling only', () => {
  const d = mkEngagement();
  for (const command of [
    'node /repo/lib/ch015/ast/context-builder.js /target',
    'ast-grep --pattern "foo()" /target',
    'semgrep scan --config p/default /target',
  ]) {
    const r = runHook({
      tool: 'Bash',
      args: { command },
      env: {
        AGENT_ROLE: 'verifier',
        AGENT_ENGAGEMENT_DIR: d,
      },
    });
    assert.equal(r.code, 0, `expected allow for ${command}: ${r.stderr}`);
  }
  fs.rmSync(d, { recursive: true, force: true });
});

test('PreToolUse: blocks verifier AST Bash with shell control operators', () => {
  const d = mkEngagement();
  const r = runHook({
    tool: 'Bash',
    args: { command: 'semgrep scan --config p/default /target; rm -rf /tmp/x' },
    env: {
      AGENT_ROLE: 'verifier',
      AGENT_ENGAGEMENT_DIR: d,
    },
  });
  assert.equal(r.code, 2);
  fs.rmSync(d, { recursive: true, force: true });
});

test('PreToolUse: 2nd round requires 02a_verify_autonomous-2nd.md', () => {
  const d = mkEngagement();
  fs.writeFileSync(path.join(d, '02a_verify_autonomous-1st.md'), '# auto-1');
  // only 1st exists, but we invoke 2nd round → block
  const blocked = runHook({
    tool: 'Read',
    args: { file_path: path.join(d, '03_va_result-2nd.md') },
    env: {
      AGENT_ROLE: 'verifier',
      AGENT_ENGAGEMENT_DIR: d,
      AGENT_VERIFY_ROUND: '2nd',
    },
  });
  assert.equal(blocked.code, 2);
  fs.writeFileSync(path.join(d, '02a_verify_autonomous-2nd.md'), '# auto-2');
  const allowed = runHook({
    tool: 'Read',
    args: { file_path: path.join(d, '03_va_result-2nd.md') },
    env: {
      AGENT_ROLE: 'verifier',
      AGENT_ENGAGEMENT_DIR: d,
      AGENT_VERIFY_ROUND: '2nd',
    },
  });
  assert.equal(allowed.code, 0);
  fs.rmSync(d, { recursive: true, force: true });
});

test('PreToolUse: infers 2nd round from sealed report path when env round is absent', () => {
  const d = mkEngagement();
  fs.writeFileSync(path.join(d, '02a_verify_autonomous-1st.md'), '# auto-1');

  const blocked = runHook({
    tool: 'Read',
    args: { file_path: path.join(d, '03_va_result-2nd.md') },
    agent: { name: 'ch015:offsec:verifier' },
  });
  assert.equal(blocked.code, 2, `expected 2nd round block, got ${blocked.code}: ${blocked.stderr}`);
  assert.match(blocked.stderr, /02a_verify_autonomous-2nd\.md/);

  fs.writeFileSync(path.join(d, '02a_verify_autonomous-2nd.md'), '# auto-2');
  const allowed = runHook({
    tool: 'Read',
    args: { file_path: path.join(d, '03_va_result-2nd.md') },
    agent: { name: 'ch015:offsec:verifier' },
  });
  assert.equal(allowed.code, 0, `expected allow after 2nd autonomous file: ${allowed.stderr}`);
  fs.rmSync(d, { recursive: true, force: true });
});

test('PreToolUse: infers grouped report round before focus suffix', () => {
  const d = mkEngagement();
  fs.writeFileSync(path.join(d, '02a_verify_autonomous-1st.md'), '# auto-1');

  const allowed = runHook({
    tool: 'Read',
    args: { file_path: path.join(d, '01_va_result-1st-auth.md') },
    agent: { name: 'ch015:offsec:verifier' },
  });
  assert.equal(allowed.code, 0, `expected grouped 1st report to use 1st autonomous file: ${allowed.stderr}`);

  const indexAllowed = runHook({
    tool: 'Read',
    args: { file_path: path.join(d, '01_va_findings_index-1st-auth.yaml') },
    agent: { name: 'ch015:offsec:verifier' },
  });
  assert.equal(indexAllowed.code, 0, `expected grouped index to use 1st autonomous file: ${indexAllowed.stderr}`);
  fs.rmSync(d, { recursive: true, force: true });
});

// --- pickAgentRole: Claude Code top-level agent_type/agent_id 인식 ---

test('pickAgentRole: top-level agent_type identifies verifier', () => {
  assert.equal(pickAgentRole({ agent_type: 'verifier' }), 'verifier');
});

test('pickAgentRole: top-level agent_id identifies role', () => {
  assert.equal(pickAgentRole({ agent_id: 'ch015:offsec:verifier' }), 'verifier');
});

test('pickAgentRole: actual agent_type takes priority over inherited subagent hints', () => {
  assert.equal(pickAgentRole({ subagent_type: 'va-auditor', agent_type: 'verifier' }), 'verifier');
});
