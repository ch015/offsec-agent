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
for (const file of ['large-scale-flow.md', 'parallel-analysis.md']) test(`${file} describes host scheduling without old delegation calls`, () => {
  const content = fs.readFileSync(path.join(ROOT, 'skills/ch015/common', file), 'utf8');
  assert.doesNotMatch(content, /subagent_type:|Agent\s*\(/);
  assert.match(content, /host/i); assert.match(content, /Scanner/); assert.match(content, /Analyzer/);
});
