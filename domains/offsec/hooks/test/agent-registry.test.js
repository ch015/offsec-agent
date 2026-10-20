'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const ROOT = path.resolve(__dirname, '..', '..');

test('active role registry has no v1 roles or model-owned orchestration', () => {
  const contract = JSON.parse(fs.readFileSync(path.join(ROOT, 'contracts/offsec-contract.v2.json'), 'utf8'));
  assert.equal(fs.existsSync(path.join(ROOT, 'contracts/offsec-contract.v1.json')), false);
  for (const [name, role] of Object.entries(contract.roles)) {
    assert.ok(['host', 'scanner', 'analyzer', 'reviewer', 'evaluator', 'reporter'].includes(name));
    assert.ok(!role.tools?.includes('Agent'));
    assert.equal((role.allowedDelegates || []).length, 0);
  }
  for (const name of ['offsec-lead', 'va-auditor', 'verifier', 'pentester']) assert.equal(fs.existsSync(path.join(ROOT, 'agents', name + '.md')), false);
});
test('hooks.json covers every built-in tool a role can receive', () => {
  // hooks.json wires the report gate only to Write and output sanitizing only to Read/Grep/Glob.
  // Granting another built-in tool (Edit, Bash, ...) must fail here so the hooks are reviewed with it.
  const contract = JSON.parse(fs.readFileSync(path.join(ROOT, 'contracts/offsec-contract.v2.json'), 'utf8'));
  const builtin = new Set(['Read', 'Grep', 'Glob', 'Write']);
  assert.ok(Object.keys(contract.roles).length > 0);
  for (const [name, role] of Object.entries(contract.roles)) {
    for (const tool of [...(role.tools || []), ...(role.elevatedTools || [])]) {
      assert.ok(builtin.has(tool) || tool.startsWith('mcp__nunchi__'), `${name}: ${tool} needs a hooks.json review`);
    }
  }
  const { hooks } = JSON.parse(fs.readFileSync(path.join(ROOT, 'hooks/hooks.json'), 'utf8'));
  assert.deepEqual(Object.keys(hooks).sort(), ['PostToolUse', 'PreToolUse', 'SessionStart']);
  const commands = (event, matcher) =>
    hooks[event].filter((entry) => entry.matcher === matcher).flatMap((entry) => entry.hooks.map((hook) => hook.command));
  assert.ok(commands('PreToolUse', 'Write').some((command) => command.endsWith('/hooks/report-gate-hook.js')));
  for (const matcher of ['Read', 'Grep', 'Glob']) {
    assert.ok(commands('PostToolUse', matcher).some((command) => command.endsWith('/hooks/sanitize-tool-output.js')));
  }
  for (const entries of Object.values(hooks)) {
    for (const hook of entries.flatMap((entry) => entry.hooks)) {
      const script = hook.command.replace('node ${CLAUDE_PLUGIN_ROOT}/', '');
      assert.ok(fs.existsSync(path.join(ROOT, script)), `missing hook script: ${script}`);
    }
  }
});
