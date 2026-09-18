/**
 * on-finding 훅 단위 테스트
 * - 차원 화이트리스트 (A1-A8 + M9/M10 보조 축 + 레거시 별칭)
 * - known_findings.yaml 블록 매칭의 토큰 경계 (substring 오탐 봉합)
 * 실행: node --test hooks/test/on-finding.test.js
 */

'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const {
  isSupportedDimension,
  matchDimensionBlocks,
} = require('../on-finding.js');

const HOOK = path.resolve(__dirname, '..', 'on-finding.js');

// ─────────────────────────────────────────────────────────────
// 차원 화이트리스트
// ─────────────────────────────────────────────────────────────

test('isSupportedDimension: accepts A1-A8 core dimensions', () => {
  for (let i = 1; i <= 8; i++) {
    assert.equal(isSupportedDimension(`A${i}`), true, `A${i}`);
  }
});

test('isSupportedDimension: accepts M9/M10 auxiliary axes', () => {
  assert.equal(isSupportedDimension('M9'), true);
  assert.equal(isSupportedDimension('M10'), true);
  assert.equal(isSupportedDimension('m9'), true, 'case-insensitive');
});

test('isSupportedDimension: accepts legacy aliases', () => {
  for (const d of ['AUTH', 'DATA', 'INPUT', 'CONFIG', 'CRYPTO', 'STATE', 'APISEC', 'LEAK']) {
    assert.equal(isSupportedDimension(d), true, d);
  }
});

test('isSupportedDimension: rejects out-of-range and junk values', () => {
  for (const d of ['A0', 'A9', 'M1', 'M11', 'M90', 'metadata', 'DATAX', '', null, undefined]) {
    assert.equal(isSupportedDimension(d), false, String(d));
  }
});

// ─────────────────────────────────────────────────────────────
// 토큰 경계 매칭 — substring 오탐 봉합
// ─────────────────────────────────────────────────────────────

const FIXTURE = [
  'patterns:',
  '  - pattern_id: P-001',
  '    title: idor in order api',
  '    dimensions: [A1]',
  '  - pattern_id: P-002',
  '    title: pii in response payload',
  '    dimensions: [DATA, INPUT]',
  '  - pattern_id: P-003',
  '    title: stores metadata blob unencrypted',
  '    dimensions: [CONFIG]',
  '  - pattern_id: P-010',
  '    title: hypothetical extended dimension',
  '    dimensions: [A10]',
  '  - pattern_id: P-011',
  '    title: M90 firmware marker',
  '    dimensions: [M9]',
].join('\n');

test('matchDimensionBlocks: DATA matches dimension token, not "metadata" substring', () => {
  const blocks = matchDimensionBlocks(FIXTURE, 'DATA');
  assert.equal(blocks.length, 1, `expected only P-002; got ${blocks.length}`);
  assert.match(blocks[0], /P-002/);
});

test('matchDimensionBlocks: A1 does not match A10', () => {
  const blocks = matchDimensionBlocks(FIXTURE, 'A1');
  assert.equal(blocks.length, 1);
  assert.match(blocks[0], /P-001/);
});

test('matchDimensionBlocks: M9 matches [M9] but not M90', () => {
  const blocks = matchDimensionBlocks(FIXTURE, 'M9');
  assert.equal(blocks.length, 1);
  assert.match(blocks[0], /P-011/);
});

test('matchDimensionBlocks: matches dimension inside multi-value list', () => {
  const blocks = matchDimensionBlocks(FIXTURE, 'INPUT');
  assert.equal(blocks.length, 1);
  assert.match(blocks[0], /P-002/);
});

test('matchDimensionBlocks: returns [] for unsupported dimension or non-string content', () => {
  assert.deepEqual(matchDimensionBlocks(FIXTURE, 'metadata'), []);
  assert.deepEqual(matchDimensionBlocks(FIXTURE, 'A10'), []);
  assert.deepEqual(matchDimensionBlocks(null, 'A1'), []);
});

// ─────────────────────────────────────────────────────────────
// CLI 스모크 — 훅 직접 실행 시 비충돌/exit 0
// ─────────────────────────────────────────────────────────────

test('on-finding CLI: exits 0 for M9 dimension (whitelisted)', () => {
  const r = spawnSync(process.execPath, [HOOK], {
    env: {
      ...process.env,
      AGENT_FINDING_ID: 'F-001',
      AGENT_SEVERITY: 'HIGH',
      AGENT_DIMENSION: 'M9',
      AGENT_ENGAGEMENT_ID: 'test-eng',
    },
    encoding: 'utf8',
    timeout: 10_000,
  });
  assert.equal(r.status, 0, r.stderr);
});

test('on-finding CLI: exits 0 silently for unsupported dimension', () => {
  const r = spawnSync(process.execPath, [HOOK], {
    env: { ...process.env, AGENT_DIMENSION: 'metadata' },
    encoding: 'utf8',
    timeout: 10_000,
  });
  assert.equal(r.status, 0, r.stderr);
  assert.equal((r.stdout || '').trim(), '');
});
