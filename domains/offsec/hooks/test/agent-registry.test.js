'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..', '..');

// 이 리포의 표기 규약: subagent_type은 agents/ frontmatter name과 문자 그대로 일치시킨다.
//
// SDK 호스트에서 관측된 사실 (docs/002-plugin-contract-findings.md F2/F5):
//   - 등록된 정식 이름은 `<플러그인>:<하위경로>:<이름>` 이다. 여기서는
//     agents/ 를 평면으로 두었으므로 `nunchi-offsec:<name>` 이 된다.
//   - 그런데 위임 시 bare 이름(`va-auditor`)도 정식 이름으로 해석된다.
//     따라서 프롬프트의 bare 표기는 유효하며 수정하지 않는다.
// bare 표기를 유지하는 이유: 플러그인 이름이 바뀌어도 프롬프트가 깨지지 않는다.
const BUILTIN_TYPES = new Set(['general-purpose']);

const FILES_WITH_SUBAGENT_CALLS = [
  path.join('skills', 'ch015', 'common', 'large-scale-flow.md'),
  path.join('skills', 'ch015', 'common', 'parallel-analysis.md')
];

test('offsec-lead does not orchestrate subagents — the host owns phase transitions', () => {
  const content = fs.readFileSync(path.join(ROOT, 'agents', 'offsec-lead.md'), 'utf8');
  assert.doesNotMatch(content, /subagent_type:|Agent\s*\(/);
});

function readAgentNames() {
  const dir = path.join(ROOT, 'agents');
  const names = new Set();
  for (const file of fs.readdirSync(dir)) {
    if (!file.endsWith('.md')) continue;
    const content = fs.readFileSync(path.join(dir, file), 'utf8');
    const m = content.match(/^name:\s*([^\n\r]+)/m);
    if (m) names.add(m[1].trim());
  }
  return names;
}

for (const relPath of FILES_WITH_SUBAGENT_CALLS) {
  test(`subagent_type values in ${relPath} match agent frontmatter names verbatim`, () => {
    const content = fs.readFileSync(path.join(ROOT, relPath), 'utf8');
    const used = [...content.matchAll(/subagent_type:\s*"([^"]+)"/g)].map((m) => m[1]);
    const agentNames = readAgentNames();

    assert.ok(used.length > 0, `${relPath} should declare subagent_type calls`);
    for (const id of used) {
      assert.ok(
        BUILTIN_TYPES.has(id) || agentNames.has(id),
        `subagent_type "${id}" in ${relPath} must verbatim-match one of: ` +
          `${[...agentNames].sort().join(', ')} (or builtin: ${[...BUILTIN_TYPES].join(', ')})`
      );
      assert.ok(
        !id.includes(':'),
        `subagent_type "${id}" in ${relPath} must not use namespaced (colon) notation`
      );
    }
  });
}
