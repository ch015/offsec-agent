'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { loadConfig } = require('../core/config');

const DEFAULT_CACHE_DIR = '.ch015/cache/recon';
const DEFAULT_TTL_DAYS = 7;

const INVALIDATION_FILES = [
  'package.json',
  'package-lock.json',
  'go.mod',
  'go.sum',
  'requirements.txt',
  'pyproject.toml',
  'Pipfile.lock',
  'Cargo.toml',
  'Cargo.lock',
  'Dockerfile',
  'docker-compose.yml',
  'docker-compose.yaml',
];

/**
 * Compute SHA256 hash of a file's content.
 * Returns null if file does not exist.
 */
function hashFile(filepath) {
  if (!fs.existsSync(filepath)) return null;
  try {
    const content = fs.readFileSync(filepath);
    return crypto.createHash('sha256').update(content).digest('hex').slice(0, 16);
  } catch {
    return null;
  }
}

/**
 * Normalize a project root for stable save/load comparison:
 * absolute path, trailing slashes removed (path.resolve handles both),
 * then symlink-resolved via realpath when the path exists — /tmp ↔ /private/tmp
 * 같은 OS 별칭 경로로 저장/조회가 갈려 MISS 나지 않게 한다.
 * 존재하지 않는 경로는 lexical 정규화만 유지 (fail-soft).
 */
function normalizeProjectRoot(projectRoot) {
  const resolved = path.resolve(String(projectRoot || ''));
  try {
    return fs.realpathSync(resolved);
  } catch {
    return resolved;
  }
}

/**
 * Build a composite fingerprint from dependency/build files in the target project.
 * Used as the cache key — if any of these files change, cache is invalidated.
 */
function computeProjectFingerprint(projectRoot) {
  const fingerprints = {};
  for (const file of INVALIDATION_FILES) {
    const fullPath = path.join(projectRoot, file);
    const h = hashFile(fullPath);
    if (h) fingerprints[file] = h;
  }
  const stableKey = JSON.stringify(fingerprints, Object.keys(fingerprints).sort());
  return {
    hash: crypto.createHash('sha256').update(stableKey).digest('hex').slice(0, 24),
    files: fingerprints
  };
}

/**
 * Resolve the cache directory.
 * 우선순위: CH015_RECON_CACHE_DIR 환경변수 > config(ch015.reconCache.cache_dir) > 기본값.
 * 상대 경로는 현재 작업 디렉터리(cwd) 기준으로 해석되므로, 기본 설정에서는
 * 실행 위치(per-cwd)마다 별도의 캐시 디렉터리가 생긴다 — 전역(plugin-level) 캐시가 아니다.
 */
function getCacheDir() {
  const config = loadConfig();
  const configured = config.ch015 && config.ch015.reconCache && config.ch015.reconCache.cache_dir;
  const dir = process.env.CH015_RECON_CACHE_DIR || configured || DEFAULT_CACHE_DIR;
  return path.isAbsolute(dir) ? dir : path.resolve(process.cwd(), dir);
}

/**
 * Build the cache file path from a fingerprint hash.
 */
function getCachePath(fingerprintHash) {
  return path.join(getCacheDir(), `${fingerprintHash}.json`);
}

/**
 * Load a cached Recon result if valid.
 * Returns null when:
 *   - cache disabled in config
 *   - cache file missing
 *   - cache expired (TTL exceeded)
 *   - forceRefresh flag passed
 *
 * @param {string} projectRoot
 * @param {Object} [opts] - { forceRefresh }
 * @returns {Object|null} cached recon result or null
 */
function loadReconCache(projectRoot, opts = {}) {
  const config = loadConfig();
  const cacheConfig = (config.ch015 && config.ch015.reconCache) || {};

  if (cacheConfig.enabled === false) return null;
  if (opts.forceRefresh) return null;

  const fingerprint = computeProjectFingerprint(projectRoot);
  const cachePath = getCachePath(fingerprint.hash);

  if (!fs.existsSync(cachePath)) return null;

  let entry;
  try {
    entry = JSON.parse(fs.readFileSync(cachePath, 'utf8'));
  } catch {
    return null;
  }

  const ttlDays = cacheConfig.ttl_days || DEFAULT_TTL_DAYS;
  const ageMs = Date.now() - new Date(entry.cached_at).getTime();
  const maxAgeMs = ttlDays * 24 * 60 * 60 * 1000;

  // cached_at 누락/손상 시 ageMs는 NaN — TTL 판정이 불가능하므로 miss 처리
  if (!Number.isFinite(ageMs) || ageMs > maxAgeMs) {
    return null;
  }

  // 경로는 정규화(절대경로 + trailing slash 제거) 후 비교 — 상대/절대 표기 차이로 miss 나지 않게
  if (normalizeProjectRoot(entry.project_root) !== normalizeProjectRoot(projectRoot)) {
    return null;
  }

  return {
    hit: true,
    cached_at: entry.cached_at,
    age_days: +(ageMs / (24 * 60 * 60 * 1000)).toFixed(2),
    fingerprint: fingerprint.hash,
    fingerprint_files: fingerprint.files,
    recon_result: entry.recon_result
  };
}

/**
 * Save a Recon result to the cache.
 * @param {string} projectRoot
 * @param {Object} reconResult - the Phase 0 output to cache
 */
function saveReconCache(projectRoot, reconResult) {
  const config = loadConfig();
  const cacheConfig = (config.ch015 && config.ch015.reconCache) || {};
  if (cacheConfig.enabled === false) return null;

  const fingerprint = computeProjectFingerprint(projectRoot);
  const cacheDir = getCacheDir();
  if (!fs.existsSync(cacheDir)) fs.mkdirSync(cacheDir, { recursive: true });

  const cachePath = getCachePath(fingerprint.hash);
  const entry = {
    version: '1.0',
    cached_at: new Date().toISOString(),
    project_root: normalizeProjectRoot(projectRoot),
    fingerprint: fingerprint.hash,
    fingerprint_files: fingerprint.files,
    recon_result: reconResult
  };

  // tmp + rename으로 atomic write — 동시 실행/중단 시 손상된 JSON이 남지 않게
  const tmpPath = `${cachePath}.tmp.${process.pid}`;
  fs.writeFileSync(tmpPath, JSON.stringify(entry, null, 2), 'utf8');
  fs.renameSync(tmpPath, cachePath);
  return { cachePath, fingerprint: fingerprint.hash };
}

/**
 * Invalidate (delete) a cache entry for a project.
 * Returns true if a cache was removed.
 */
function invalidateCache(projectRoot) {
  const fingerprint = computeProjectFingerprint(projectRoot);
  const cachePath = getCachePath(fingerprint.hash);
  if (fs.existsSync(cachePath)) {
    try {
      fs.unlinkSync(cachePath);
      return true;
    } catch {
      return false;
    }
  }
  return false;
}

/**
 * List all cached Recon entries with metadata.
 */
function listCache() {
  const cacheDir = getCacheDir();
  if (!fs.existsSync(cacheDir)) return [];

  const entries = [];
  for (const file of fs.readdirSync(cacheDir)) {
    if (!file.endsWith('.json')) continue;
    try {
      const entry = JSON.parse(fs.readFileSync(path.join(cacheDir, file), 'utf8'));
      const ageMs = Date.now() - new Date(entry.cached_at).getTime();
      entries.push({
        fingerprint: entry.fingerprint,
        project_root: entry.project_root,
        cached_at: entry.cached_at,
        age_days: +(ageMs / (24 * 60 * 60 * 1000)).toFixed(2),
        file: path.join(cacheDir, file)
      });
    } catch {
      // skip corrupted entries
    }
  }
  return entries.sort((a, b) => new Date(b.cached_at) - new Date(a.cached_at));
}

/**
 * Clear all expired cache entries (age > TTL).
 * Returns count of removed entries.
 */
function pruneExpired() {
  const config = loadConfig();
  const cacheConfig = (config.ch015 && config.ch015.reconCache) || {};
  const ttlDays = cacheConfig.ttl_days || DEFAULT_TTL_DAYS;
  const maxAgeMs = ttlDays * 24 * 60 * 60 * 1000;

  let removed = 0;
  for (const entry of listCache()) {
    const ageMs = Date.now() - new Date(entry.cached_at).getTime();
    // cached_at 누락/손상(NaN) 엔트리도 삭제 대상 — TTL 판정 불가 엔트리는 신뢰 불가
    if (!Number.isFinite(ageMs) || ageMs > maxAgeMs) {
      try {
        fs.unlinkSync(entry.file);
        removed++;
      } catch {
        // 이미 삭제됐거나 권한 문제 — 카운트하지 않고 계속
      }
    }
  }
  return removed;
}

if (require.main === module) {
  const args = process.argv.slice(2);
  const cmd = args[0];

  switch (cmd) {
    case 'list': {
      const entries = listCache();
      if (entries.length === 0) {
        console.log('No cached Recon entries.');
      } else {
        console.log(`Cached Recon entries (${entries.length}):\n`);
        for (const e of entries) {
          console.log(`  ${e.fingerprint}  ${e.age_days}d old`);
          console.log(`    ${e.project_root}`);
          console.log(`    cached: ${e.cached_at}\n`);
        }
      }
      break;
    }
    case 'prune': {
      const removed = pruneExpired();
      console.log(`Pruned ${removed} expired cache entries.`);
      break;
    }
    case 'invalidate': {
      const target = args[1];
      if (!target) {
        console.error('Usage: node recon-cache.js invalidate <project-root>');
        process.exit(1);
      }
      const ok = invalidateCache(path.resolve(target));
      console.log(ok ? 'Cache invalidated.' : 'No cache entry found.');
      break;
    }
    case 'check': {
      const target = args[1];
      if (!target) {
        console.error('Usage: node recon-cache.js check <project-root>');
        process.exit(1);
      }
      const result = loadReconCache(path.resolve(target));
      if (result) {
        console.log(`HIT — ${result.age_days}d old, fingerprint ${result.fingerprint}`);
      } else {
        console.log('MISS — no valid cache entry.');
      }
      break;
    }
    default:
      console.log('Usage:');
      console.log('  node recon-cache.js list                       # List all cached entries');
      console.log('  node recon-cache.js check <project-root>       # Check cache status for project');
      console.log('  node recon-cache.js invalidate <project-root>  # Remove cache for project');
      console.log('  node recon-cache.js prune                      # Remove expired entries');
  }
}

module.exports = {
  computeProjectFingerprint,
  loadReconCache,
  saveReconCache,
  invalidateCache,
  listCache,
  pruneExpired,
  INVALIDATION_FILES
};
