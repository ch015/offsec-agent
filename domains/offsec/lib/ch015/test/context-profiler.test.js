'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { estimateTokens, measureFile, profileSkillDirectory, buildPhaseMapping, findMdFiles } = require('../context-profiler');

const SKILLS_ROOT = path.resolve(__dirname, '..', '..', '..', 'skills', 'ch015');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-profiler-'));
process.on('exit', () => { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch {} });

// --- estimateTokens ---

test('estimateTokens: empty string = 0', () => {
  assert.equal(estimateTokens(''), 0);
});

test('estimateTokens: uses ~3.5 chars per token', () => {
  const text = 'a'.repeat(35);
  assert.equal(estimateTokens(text), 10);
});

test('estimateTokens: rounds up', () => {
  const text = 'a'.repeat(36);
  assert.equal(estimateTokens(text), 11);
});

test('estimateTokens: handles mixed content', () => {
  const text = '한글과 English mixed 코드 const x = 42;';
  const tokens = estimateTokens(text);
  assert.ok(tokens > 0);
  assert.ok(tokens === Math.ceil(text.length / 3.5));
});

// --- measureFile ---

test('measureFile: measures lines, chars, tokens', () => {
  const filepath = path.join(TMP, 'test.md');
  fs.writeFileSync(filepath, 'line1\nline2\nline3\n');

  const result = measureFile(filepath);
  assert.equal(result.lines, 4);
  assert.equal(result.chars, 18);
  assert.equal(result.estimated_tokens, Math.ceil(18 / 3.5));
  assert.equal(result.filename, 'test.md');
  assert.equal(result.path, filepath);
});

test('measureFile: empty file', () => {
  const filepath = path.join(TMP, 'empty.md');
  fs.writeFileSync(filepath, '');

  const result = measureFile(filepath);
  assert.equal(result.lines, 1);
  assert.equal(result.chars, 0);
  assert.equal(result.estimated_tokens, 0);
});

// --- buildPhaseMapping ---

test('buildPhaseMapping: every mapped file exists on disk (no stale paths)', () => {
  const mapping = buildPhaseMapping(SKILLS_ROOT);
  for (const relPath of Object.keys(mapping)) {
    const fullPath = path.join(SKILLS_ROOT, ...relPath.split('/'));
    assert.ok(fs.existsSync(fullPath), `mapped file does not exist: ${relPath}`);
  }
});

test('buildPhaseMapping: maps depth/, principles/, and analysis guides to actual tree', () => {
  const mapping = buildPhaseMapping(SKILLS_ROOT);

  // 존재하지 않는 dimensions/ 경로를 매핑하지 않는다
  assert.ok(
    !Object.keys(mapping).some(k => k.includes('offsec/va/dimensions/')),
    'should not map nonexistent dimensions/ files'
  );

  assert.equal(mapping['offsec/va/depth/injection.md'], 'phase_2_deep_analysis');
  assert.equal(mapping['offsec/va/principles/row-level-security.md'], 'phase_1_architecture');
  assert.equal(mapping['common/taint-analysis.md'], 'phase_2_deep_analysis');
  assert.equal(mapping['offsec/va/concurrency.md'], 'phase_2_deep_analysis');
  assert.equal(mapping['offsec/va/supply-chain.md'], 'phase_2_deep_analysis');
  assert.equal(mapping['review/feedback/SKILL.md'], 'review');
  assert.equal(mapping['SKILL.md'], 'phase_0_always');
});

test('profileSkillDirectory: no skill md file falls into unknown phase', () => {
  const results = profileSkillDirectory(SKILLS_ROOT);
  const unknown = results.files.filter(f => f.phase === 'unknown').map(f => f.relPath);
  assert.deepEqual(unknown, [], `unmapped skill files: ${unknown.join(', ')}`);
});

// --- findMdFiles ---

test('findMdFiles: respects max scan depth', () => {
  const root = path.join(TMP, 'md-depth');
  let deep = root;
  for (let i = 0; i < 8; i++) {
    deep = path.join(deep, `d${i}`);
  }
  fs.mkdirSync(deep, { recursive: true });
  fs.writeFileSync(path.join(root, 'shallow.md'), '# shallow');
  fs.writeFileSync(path.join(deep, 'too-deep.md'), '# deep');

  const found = findMdFiles(root);
  assert.ok(found.some(f => f.endsWith('shallow.md')), 'shallow file should be found');
  assert.ok(!found.some(f => f.endsWith('too-deep.md')), 'file beyond depth cap should be excluded');
});
