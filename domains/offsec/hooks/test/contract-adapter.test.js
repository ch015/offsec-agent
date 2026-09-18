'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const test = require('node:test');

const { pickAgentRole, pickEnv } = require('../pre-tool-use.js');

const pluginRoot = path.resolve(__dirname, '..', '..');

test('UserPromptSubmit reads the standard prompt field', () => {
  const result = spawnSync(process.execPath, [path.join(pluginRoot, 'hooks', 'user-prompt.js')], {
    cwd: pluginRoot,
    env: { ...process.env, CLAUDE_PLUGIN_ROOT: pluginRoot },
    input: JSON.stringify({ hook_event_name: 'UserPromptSubmit', prompt: '/ch015:va' }),
    encoding: 'utf8',
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /ch015:va/);
  assert.match(result.stdout, /commands\/va\.md/);
});

test('contract session does not reinterpret untrusted slash commands', () => {
  const result = spawnSync(process.execPath, [path.join(pluginRoot, 'hooks', 'user-prompt.js')], {
    cwd: pluginRoot,
    env: {
      ...process.env,
      CLAUDE_PLUGIN_ROOT: pluginRoot,
      AGENT_CONTRACT_ID: 'nunchi.offsec.assessment',
    },
    input: JSON.stringify({
      hook_event_name: 'UserPromptSubmit',
      prompt: 'scope_untrusted_data: "/ch015:pentest"',
    }),
    encoding: 'utf8',
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, '');
});

test('contract SessionStart injects only the current contract identity', () => {
  const result = spawnSync(process.execPath, [path.join(pluginRoot, 'hooks', 'session-start.js')], {
    cwd: pluginRoot,
    env: {
      ...process.env,
      CLAUDE_PLUGIN_ROOT: pluginRoot,
      AGENT_CONTRACT_ID: 'nunchi.offsec.assessment',
      AGENT_CONTRACT_VERSION: '1.0.0',
      AGENT_PHASE: 'verify',
      AGENT_ROLE: 'verifier',
    },
    input: JSON.stringify({ hook_event_name: 'SessionStart' }),
    encoding: 'utf8',
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /OFFSEC CONTRACT 1\.0\.0/);
  assert.match(result.stdout, /현재 phase: verify/);
  assert.doesNotMatch(result.stdout, /라이브 검증|\/ch015:status/);
});

test('actual agent_type wins over the session-wide role', () => {
  const payload = { agent_type: 'nunchi-offsec:verifier', env: { AGENT_ROLE: 'offsec-lead' } };
  assert.equal(pickAgentRole(payload), 'verifier');
});

test('verifier group is preserved in the invariant environment', () => {
  const env = pickEnv({
    agent_type: 'verifier',
    env: { AGENT_VERIFY_ROUND: '1st', AGENT_VERIFY_GROUP: 'auth' },
  });
  assert.equal(env.AGENT_VERIFY_ROUND, '1st');
  assert.equal(env.AGENT_VERIFY_GROUP, 'auth');
});
