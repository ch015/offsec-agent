'use strict';

const { test, beforeEach, mock } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-recon-'));
process.env.CH015_RECON_CACHE_DIR = path.join(TMP, 'cache', 'recon');
process.on('exit', () => { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch {} });

let counter = 0;
function mkDir(prefix) {
  const d = path.join(TMP, `${prefix}-${++counter}`);
  fs.mkdirSync(d, { recursive: true });
  return d;
}

const {
  computeProjectFingerprint,
  loadReconCache,
  saveReconCache,
  invalidateCache,
  listCache,
  pruneExpired,
  INVALIDATION_FILES
} = require('../recon-cache');

// --- computeProjectFingerprint ---

test('computeProjectFingerprint: returns hash and files map', () => {
  const projDir = mkDir('fp');
  fs.writeFileSync(path.join(projDir, 'package.json'), '{"name":"test"}');

  const result = computeProjectFingerprint(projDir);
  assert.ok(result.hash);
  assert.ok(result.hash.length === 24);
  assert.ok(result.files['package.json']);
});

test('computeProjectFingerprint: different content = different hash', () => {
  const d1 = mkDir('fp-diff1');
  const d2 = mkDir('fp-diff2');
  fs.writeFileSync(path.join(d1, 'package.json'), '{"name":"a"}');
  fs.writeFileSync(path.join(d2, 'package.json'), '{"name":"b"}');

  const h1 = computeProjectFingerprint(d1);
  const h2 = computeProjectFingerprint(d2);
  assert.notEqual(h1.hash, h2.hash);
});

test('computeProjectFingerprint: empty project = stable hash', () => {
  const d1 = mkDir('fp-empty1');
  const d2 = mkDir('fp-empty2');

  const h1 = computeProjectFingerprint(d1);
  const h2 = computeProjectFingerprint(d2);
  assert.equal(h1.hash, h2.hash);
});

test('computeProjectFingerprint: ignores non-invalidation files', () => {
  const d1 = mkDir('fp-ignore');
  fs.writeFileSync(path.join(d1, 'README.md'), 'hello');

  const result = computeProjectFingerprint(d1);
  assert.equal(Object.keys(result.files).length, 0);
});

// --- INVALIDATION_FILES ---

test('INVALIDATION_FILES: includes key dependency files', () => {
  assert.ok(INVALIDATION_FILES.includes('package.json'));
  assert.ok(INVALIDATION_FILES.includes('go.mod'));
  assert.ok(INVALIDATION_FILES.includes('requirements.txt'));
  assert.ok(INVALIDATION_FILES.includes('Dockerfile'));
});

// --- save + load round-trip ---

test('saveReconCache + loadReconCache: round-trip works', () => {
  const projDir = mkDir('cache-rt');
  fs.writeFileSync(path.join(projDir, 'package.json'), '{"test":"roundtrip"}');

  const reconData = { tech_stack: ['node'], files: 42 };
  saveReconCache(projDir, reconData);

  const cached = loadReconCache(projDir);
  assert.ok(cached);
  assert.equal(cached.hit, true);
  assert.deepEqual(cached.recon_result, reconData);
});

test('loadReconCache: returns null for uncached project', () => {
  const projDir = mkDir('cache-miss');
  const result = loadReconCache(projDir);
  assert.equal(result, null);
});

test('loadReconCache: returns null with forceRefresh', () => {
  const projDir = mkDir('cache-force');
  fs.writeFileSync(path.join(projDir, 'package.json'), '{"test":"force"}');
  saveReconCache(projDir, { data: true });

  const result = loadReconCache(projDir, { forceRefresh: true });
  assert.equal(result, null);
});

test('loadReconCache: returns null after content change (fingerprint invalidation)', () => {
  const projDir = mkDir('cache-invalidate');
  fs.writeFileSync(path.join(projDir, 'package.json'), '{"v":1}');
  saveReconCache(projDir, { data: 'v1' });

  fs.writeFileSync(path.join(projDir, 'package.json'), '{"v":2}');
  const result = loadReconCache(projDir);
  assert.equal(result, null);
});

test('saveReconCache(relative) + loadReconCache(resolved): path normalization HIT', () => {
  const projDir = mkDir('cache-relpath');
  fs.writeFileSync(path.join(projDir, 'package.json'), '{"test":"relpath"}');

  // 상대 경로로 저장 → 절대 경로로 로드해도 HIT여야 한다
  const relPath = path.relative(process.cwd(), projDir);
  saveReconCache(relPath, { data: 'rel' });

  const cached = loadReconCache(path.resolve(relPath));
  assert.ok(cached, 'expected cache HIT for resolved path after relative save');
  assert.equal(cached.hit, true);
  assert.deepEqual(cached.recon_result, { data: 'rel' });
});

test('saveReconCache(symlink alias) + loadReconCache(real path): realpath normalization HIT', () => {
  // /tmp ↔ /private/tmp 류의 OS 별칭 경로 재현 — 실 디렉터리를 가리키는 symlink로
  // 저장한 뒤 실경로로 조회해도 HIT여야 한다.
  const projDir = mkDir('cache-realpath');
  fs.writeFileSync(path.join(projDir, 'package.json'), '{"test":"realpath"}');

  const alias = path.join(TMP, `alias-${++counter}`);
  fs.symlinkSync(projDir, alias);

  saveReconCache(alias, { data: 'realpath' });

  const realProjDir = fs.realpathSync(projDir);
  const cached = loadReconCache(realProjDir);
  assert.ok(cached, 'expected cache HIT for real path after symlink-alias save');
  assert.deepEqual(cached.recon_result, { data: 'realpath' });
});

test('saveReconCache + loadReconCache: nonexistent path keeps lexical normalization (no throw)', () => {
  // 존재하지 않는 경로는 realpath 불가 — lexical 정규화 fallback으로 round-trip 유지
  const ghost = path.join(TMP, 'ghost-project-never-created');
  saveReconCache(ghost, { data: 'ghost' });

  const cached = loadReconCache(ghost);
  assert.ok(cached, 'expected cache HIT for nonexistent path round-trip');
  assert.deepEqual(cached.recon_result, { data: 'ghost' });

  // 빈 fingerprint(파일 없는 프로젝트) 캐시 슬롯은 빈 디렉터리 기반의 다른
  // 테스트와 공유된다 — 오염 방지를 위해 정리
  invalidateCache(ghost);
});

test('saveReconCache + loadReconCache: trailing slash normalized', () => {
  const projDir = mkDir('cache-trailing');
  fs.writeFileSync(path.join(projDir, 'package.json'), '{"test":"trailing"}');

  saveReconCache(`${projDir}${path.sep}`, { data: 'trail' });
  const cached = loadReconCache(projDir);
  assert.ok(cached, 'expected cache HIT despite trailing slash on save');
  assert.deepEqual(cached.recon_result, { data: 'trail' });
});

test('loadReconCache: corrupted cached_at treated as miss', () => {
  const projDir = mkDir('cache-badts');
  fs.writeFileSync(path.join(projDir, 'package.json'), '{"test":"badts"}');

  const { cachePath } = saveReconCache(projDir, { data: true });
  const entry = JSON.parse(fs.readFileSync(cachePath, 'utf8'));
  entry.cached_at = 'not-a-date';
  fs.writeFileSync(cachePath, JSON.stringify(entry), 'utf8');

  assert.equal(loadReconCache(projDir), null);
});

test('pruneExpired: removes entries with missing/corrupted cached_at', () => {
  const projDir = mkDir('cache-prune-badts');
  fs.writeFileSync(path.join(projDir, 'package.json'), '{"test":"prune-badts"}');

  const { cachePath } = saveReconCache(projDir, { data: true });
  const entry = JSON.parse(fs.readFileSync(cachePath, 'utf8'));
  delete entry.cached_at;
  fs.writeFileSync(cachePath, JSON.stringify(entry), 'utf8');

  const removed = pruneExpired();
  assert.ok(removed >= 1, 'corrupted entry should be pruned');
  assert.equal(fs.existsSync(cachePath), false);
});

test('saveReconCache: atomic write leaves no tmp files behind', () => {
  const projDir = mkDir('cache-atomic');
  fs.writeFileSync(path.join(projDir, 'package.json'), '{"test":"atomic"}');

  const { cachePath } = saveReconCache(projDir, { data: true });
  assert.ok(fs.existsSync(cachePath));

  const cacheDir = path.dirname(cachePath);
  const leftovers = fs.readdirSync(cacheDir).filter(f => f.includes('.tmp.'));
  assert.deepEqual(leftovers, []);
});

// --- invalidateCache ---

test('invalidateCache: removes cache entry', () => {
  const projDir = mkDir('cache-inv');
  fs.writeFileSync(path.join(projDir, 'package.json'), '{"test":"inv"}');
  saveReconCache(projDir, { data: true });

  const removed = invalidateCache(projDir);
  assert.equal(removed, true);
  assert.equal(loadReconCache(projDir), null);
});

test('invalidateCache: returns false if no cache exists', () => {
  const projDir = mkDir('cache-inv-miss');
  assert.equal(invalidateCache(projDir), false);
});

// --- listCache ---

test('listCache: lists saved entries', () => {
  const projDir = mkDir('cache-list');
  fs.writeFileSync(path.join(projDir, 'package.json'), '{"test":"list"}');
  saveReconCache(projDir, { data: true });

  const entries = listCache();
  assert.ok(entries.length >= 1);
  // project_root는 realpath 정규화되어 저장된다 (macOS: /var/... → /private/var/...)
  const found = entries.find(e => e.project_root === fs.realpathSync(projDir));
  assert.ok(found);
  assert.ok(found.age_days >= 0);
});
