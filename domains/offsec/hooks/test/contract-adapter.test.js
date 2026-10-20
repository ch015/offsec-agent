'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const test = require('node:test');

const pluginRoot = path.resolve(__dirname, '..', '..');

test('contract SessionStart injects only the current contract identity', () => {
  const result = spawnSync(process.execPath, [path.join(pluginRoot, 'hooks', 'session-start.js')], {
    cwd: pluginRoot,
    env: {
      ...process.env,
      CLAUDE_PLUGIN_ROOT: pluginRoot,
      AGENT_CONTRACT_ID: 'nunchi.offsec.assessment',
      AGENT_CONTRACT_VERSION: '1.0.0',
      AGENT_PHASE: 'analyze',
      AGENT_ROLE: 'analyzer',
    },
    input: JSON.stringify({ hook_event_name: 'SessionStart' }),
    encoding: 'utf8',
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /OFFSEC CONTRACT 1\.0\.0/);
  assert.match(result.stdout, /현재 phase: analyze/);
  assert.doesNotMatch(result.stdout, /라이브 검증|\/ch015:status/);
});
