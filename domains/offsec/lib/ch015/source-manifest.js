'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const { loadConfig } = require('../core/config');

// basename 기준 제외 목록. 여기 이름이 들어가면 프로젝트 어디에 있든 스캔에서 빠지므로
// 소스 디렉터리명으로 쓰일 수 있는 이름은 넣지 않는다. nunchi 산출물은 `.nunchi`(dot-prefix)에
// 모으고, 레거시 `reports/` 경로는 호출부가 excludePaths로 명시 제외한다 —
// `reports`를 여기 두면 `src/features/reports/` 같은 실제 소스가 조용히 누락된다(false negative).
const DEFAULT_EXCLUDED_DIRS = new Set([
  '.git',
  '.hg',
  '.svn',
  'node_modules',
  'vendor',
  'dist',
  'build',
  'coverage',
  '.next',
  '.nuxt',
  '.cache',
  'target',
  '__pycache__',
  '.nunchi',
  '.asx',
  '.agents',
  '.claude',
  '.cursor',
]);
const DEFAULT_MAX_UNIT_FILES = 200;
const DEFAULT_MAX_UNIT_LOC = 20_000;

const DEFAULT_BUILD_MARKERS = [
  'package.json',
  'go.mod',
  'Cargo.toml',
  'pom.xml',
  'build.gradle',
  'settings.gradle',
  'pyproject.toml',
  'requirements.txt',
  'composer.json',
  'Gemfile',
  'mix.exs',
  '*.csproj',
  '*.sln',
];
const DEFAULT_DEPENDENCY_MANIFESTS = [
  ...DEFAULT_BUILD_MARKERS,
  'package-lock.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'bun.lock',
  'bun.lockb',
  'go.sum',
  'Cargo.lock',
  'gradle.lockfile',
  'poetry.lock',
  'Pipfile.lock',
  'composer.lock',
  'Gemfile.lock',
  'mix.lock',
  'packages.lock.json',
  'Directory.Packages.props',
];

function toPosix(p) {
  return p.split(path.sep).join('/');
}

function normalizeRoot(targetRoot) {
  const resolved = path.resolve(String(targetRoot || '.'));
  try {
    return fs.realpathSync(resolved);
  } catch {
    return resolved;
  }
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function sourceManifestContentProjection(manifest) {
  const projection = {
    schema_version: manifest.schema_version,
    source_file_count: manifest.source_file_count,
    loc_estimate: manifest.loc_estimate,
    subproject_count: manifest.subproject_count,
    subproject_roots: manifest.subproject_roots,
    units: manifest.units,
    git_head: manifest.git_head,
    policy: manifest.policy,
    source_files: manifest.source_files,
    source_receipts: manifest.source_receipts,
    dependency_files: manifest.dependency_files,
    dependency_receipts: manifest.dependency_receipts,
  };
  // 신규 필드는 존재할 때만 투영에 포함한다 — 구버전 매니페스트(필드 부재)를 재해시해도
  // 과거 저장된 hash를 그대로 재현해야 하기 때문(P0-B backward-compatible hashing).
  if (manifest.security_resource_files !== undefined) {
    projection.security_resource_files = manifest.security_resource_files;
    projection.security_resource_receipts = manifest.security_resource_receipts;
  }
  if (manifest.scope_inventory !== undefined) {
    // scope_inventory가 매니페스트에 임베딩된 경우, 저장된 scope_inventory_sha256 필드를 그대로
    // 믿지 않고 실제 배열 내용을 재해시해 투영에 바인딩한다 — scope_inventory 배열만 변조하고
    // scope_inventory_sha256 필드는 그대로 둔 채라도 content hash가 반드시 달라지게 한다.
    projection.scope_inventory_schema_version = manifest.scope_inventory_schema_version;
    projection.scope_inventory_sha256 = sha256(stableJson(manifest.scope_inventory));
  } else if (manifest.scope_inventory_sha256 !== undefined) {
    // scope_inventory가 별도 파일로 분리된 설계(§4 "separately written 00_scope_inventory.json")인
    // 경우 매니페스트 객체에는 참조 해시만 존재하므로 그대로 투영한다.
    projection.scope_inventory_schema_version = manifest.scope_inventory_schema_version;
    projection.scope_inventory_sha256 = manifest.scope_inventory_sha256;
  }
  if (manifest.source_errors !== undefined) projection.source_errors = manifest.source_errors;
  return projection;
}

function sourceManifestContentHash(manifest) {
  return sha256(stableJson(sourceManifestContentProjection(manifest)));
}

function loadSourcePolicy(config = loadConfig()) {
  const sourceDirectories = Array.isArray(config.sourceDirectories)
    ? config.sourceDirectories.map(String)
    : [];
  const codeExtensions = Array.isArray(config.codeExtensions)
    ? config.codeExtensions.map((ext) => String(ext).toLowerCase())
    : ['.js', '.ts', '.py', '.go', '.java'];

  return {
    sourceDirectories,
    codeExtensions,
    excludedDirs: [...DEFAULT_EXCLUDED_DIRS].sort(),
    excludedPaths: config.ch015?.reportOutputDir ? [String(config.ch015.reportOutputDir)] : [],
    maxUnitFiles: DEFAULT_MAX_UNIT_FILES,
    maxUnitLoc: DEFAULT_MAX_UNIT_LOC,
  };
}

function shouldSkipDir(name, excludedDirs) {
  return excludedDirs.has(name);
}

function hasCodeExtension(filePath, extensions) {
  return extensions.has(path.extname(filePath).toLowerCase());
}

/**
 * #12A: Inert file heuristic — 실행 가능한 로직이 없는 파일을 식별.
 * 첫 1KB를 읽어서 logic keyword가 하나도 없으면 inert로 판정.
 * 주 대상: Figma 직렬화 JSX (Frame/Text/Rectangle만 있고 logic 없음).
 * 보수적: keyword가 하나라도 있으면 포함 (false negative 방지).
 */
const LOGIC_KEYWORDS = /\b(import|require|export\s+(default\s+)?function|export\s+(default\s+)?class|useState|useEffect|useCallback|useMemo|useRef|fetch|axios|addEventListener|onClick|onChange|onSubmit|async|await|Promise|setTimeout|setInterval|new\s+\w+|try\s*\{|if\s*\(|switch\s*\(|for\s*\(|while\s*\(|throw\s+|process\.|window\.|document\.|crypto\.|fs\.|require\(|module\.exports)\b|dangerouslySetInnerHTML|innerHTML|eval\s*\(|Function\s*\(/;

function isInertFile(fullPath, fileName) {
  const ext = path.extname(fileName).toLowerCase();
  // .jsx/.tsx만 검사 (다른 확장자는 대부분 실행 코드)
  if (ext !== '.jsx' && ext !== '.tsx') return false;
  try {
    const fd = fs.openSync(fullPath, 'r');
    const buf = Buffer.alloc(1024);
    const bytesRead = fs.readSync(fd, buf, 0, 1024, 0);
    fs.closeSync(fd);
    if (bytesRead < 50) return false; // 너무 작은 파일은 판단 불가 — 보수적으로 포함
    const head = buf.toString('utf8', 0, bytesRead);
    return !LOGIC_KEYWORDS.test(head);
  } catch {
    return false; // 읽기 실패 시 보수적으로 포함
  }
}

function safeReadLineCount(filePath) {
  try {
    const text = fs.readFileSync(filePath, 'utf8');
    if (text.length === 0) return 0;
    return text.split(/\r\n|\r|\n/).length;
  } catch {
    return 0;
  }
}

function walkSourceFiles(root, policy, errors = []) {
  const extensions = new Set(policy.codeExtensions);
  const excludedDirs = new Set(policy.excludedDirs);
  const files = [];
  const excludedPaths = new Set((policy.excludedPaths || []).map((value) =>
    path.resolve(root, String(value))));

  const isExcluded = (candidate) => {
    const absolute = path.resolve(candidate);
    return [...excludedPaths].some((excluded) =>
      absolute === excluded || absolute.startsWith(`${excluded}${path.sep}`));
  };

  function walk(dir) {
    if (isExcluded(dir)) return;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (error) {
      errors.push({ path: toPosix(path.relative(root, dir)) || '.', code: error.code || 'SOURCE_DIRECTORY_UNREADABLE' });
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (!shouldSkipDir(entry.name, excludedDirs)) walk(fullPath);
        continue;
      }
      if (!entry.isFile()) continue;
      if (!hasCodeExtension(entry.name, extensions)) continue;
      // #12A: Content-based inert file filter — 실행 가능한 로직이 없는 파일 제외
      if (isInertFile(fullPath, entry.name)) continue;
      files.push(toPosix(path.relative(root, fullPath)));
    }
  }

  walk(root);
  return [...new Set(files)].sort();
}

function walkDependencyFiles(root, policy, errors = []) {
  const excludedDirs = new Set(policy.excludedDirs);
  const excludedPaths = new Set((policy.excludedPaths || []).map((value) =>
    path.resolve(root, String(value))));
  const files = [];
  const isExcluded = (candidate) => {
    const absolute = path.resolve(candidate);
    return [...excludedPaths].some((excluded) =>
      absolute === excluded || absolute.startsWith(`${excluded}${path.sep}`));
  };
  function walk(dir) {
    if (isExcluded(dir)) return;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (error) {
      errors.push({ path: toPosix(path.relative(root, dir)) || '.', code: error.code || 'SOURCE_DIRECTORY_UNREADABLE' });
      return;
    }
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (!shouldSkipDir(entry.name, excludedDirs)) walk(fullPath);
        continue;
      }
      if (entry.isFile() && DEFAULT_DEPENDENCY_MANIFESTS.some((marker) => markerMatches(entry.name, marker))) {
        files.push(toPosix(path.relative(root, fullPath)));
      }
    }
  }
  walk(root);
  return [...new Set(files)].sort();
}

function markerMatches(fileName, marker) {
  if (!marker.includes('*')) return fileName === marker;
  const escaped = marker
    .split('*')
    .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    .join('.*');
  return new RegExp(`^${escaped}$`).test(fileName);
}

// ── eligible-file inventory + security-resource classification (P0-B) ──────
// 대상 실행/코드가 아닌 배포·플랫폼 설정 자원 — "모든 JSON"이 아니라 아래 좁은 패턴만 분류한다.
const SHELL_SCRIPT_EXTENSIONS = new Set(['.sh', '.bash', '.zsh']);
const SECURITY_CONFIG_EXTENSIONS = new Set(['.toml', '.hcl', '.tf', '.tfvars']);
const DOC_EXTENSIONS = new Set(['.md', '.mdx', '.rst', '.adoc', '.txt']);
const ASSET_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp', '.avif',
  '.mp4', '.mov', '.webm', '.mp3', '.wav', '.ogg', '.flac',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.css', '.scss', '.sass', '.less',
]);
const DOCKER_NAME_RE = /^(dockerfile|containerfile)(\..+)?$/i;
const COMPOSE_NAME_RE = /^(docker-)?compose(\..+)?\.ya?ml$/i;
const ENV_EXAMPLE_RE = /\.env\.(example|sample)$/i;
const TEST_PATH_RE = /(^|\/)(__tests__|__mocks__|__fixtures__|__snapshots__|tests?|specs?)(\/|$)/i;
const TEST_NAME_RE = /\.(test|spec)\.[^./]+$|(^|[_-])test_[^/]+\.py$|_test\.(?:py|go)$/i;

function pathSegments(relPath) {
  return relPath.split('/');
}

// 디렉터리 세그먼트에 name이 포함되는가(basename 자체는 제외 — 확장자 없는 파일명과의 혼동 방지).
function hasDirSegment(relPath, name) {
  const segments = pathSegments(relPath);
  return segments.slice(0, -1).includes(name);
}

// Supabase 트리 아래 "모든 JSON"이 아니라, 프로젝트 설정/스토리지 정책류 좁은 경로만 인식한다.
// 예: supabase/config.json(프로젝트 설정), supabase/storage_buckets/**/*.json(버킷/스토리지 정책).
// src-tauri/supabase/functions/**/*.json(엣지 함수 빌드 설정 등)은 여기 해당하지 않는다 —
// 다른 명시 규칙이 적용되지 않으면 generic inventory-only(기타)로 남는다.
function classifySupabaseSecurityJson(relPath) {
  const segments = pathSegments(relPath);
  const supabaseIndex = segments.lastIndexOf('supabase');
  if (supabaseIndex === -1) return false;
  const afterSupabase = segments.slice(supabaseIndex + 1);
  if (afterSupabase.length === 0) return false;
  if (afterSupabase.length === 1 && afterSupabase[0] === 'config.json') return true;
  if (afterSupabase[0] === 'storage_buckets') return true;
  return false;
}

// 배포/플랫폼 보안관련 리소스 — 좁고 결정론적인 경로/이름 규칙만 인식한다("모든 JSON" 금지).
function classifySecurityResource(relPath) {
  const base = path.basename(relPath);
  const baseLower = base.toLowerCase();
  const ext = path.extname(base).toLowerCase();

  if (DOCKER_NAME_RE.test(base) || COMPOSE_NAME_RE.test(baseLower)) return 'security-resource';
  if (SHELL_SCRIPT_EXTENSIONS.has(ext)) return 'security-resource';
  if (SECURITY_CONFIG_EXTENSIONS.has(ext) || ENV_EXAMPLE_RE.test(baseLower)) return 'security-resource';
  if (ext === '.json') {
    if (baseLower === 'tauri.conf.json') return 'security-resource';
    if (hasDirSegment(relPath, 'src-tauri') && hasDirSegment(relPath, 'capabilities')) return 'security-resource';
    if (classifySupabaseSecurityJson(relPath)) return 'security-resource';
    if (baseLower === 'plugin.json' || baseLower === 'manifest.json' || hasDirSegment(relPath, '.claude-plugin')) {
      return 'security-resource';
    }
    if (baseLower === 'registry.json') return 'generated-runtime-resource';
  }
  if (
    (hasDirSegment(relPath, '.github') && hasDirSegment(relPath, 'workflows') && /\.ya?ml$/i.test(baseLower)) ||
    baseLower === '.gitlab-ci.yml' ||
    baseLower === 'jenkinsfile' ||
    baseLower === 'azure-pipelines.yml' ||
    (hasDirSegment(relPath, '.circleci') && baseLower === 'config.yml')
  ) {
    return 'security-resource';
  }
  if (ext === '.md' && ['agents', 'skills', 'commands', 'methods'].some((name) => hasDirSegment(relPath, name))) {
    return 'runtime-prompt';
  }
  return null;
}

// 최소 구분: source/dependency-manifest/security-resource류/test/documentation/asset/other.
// source_files·dependency_files 판정을 최우선 존중 — 인벤토리 추가가 기존 unit 소유권을 바꾸지 않는다.
function classifyInventoryEntry(relPath, isSource, isDependency) {
  if (isDependency) return { classification: 'dependency-manifest', disposition: 'analyze-dependency' };
  if (isSource) return { classification: 'source', disposition: 'analyze-source' };
  const security = classifySecurityResource(relPath);
  if (security) return { classification: security, disposition: 'analyze-security-resource' };
  const base = path.basename(relPath);
  if (TEST_PATH_RE.test(relPath) || TEST_NAME_RE.test(base)) {
    return { classification: 'test', disposition: 'inventory-only' };
  }
  const ext = path.extname(base).toLowerCase();
  if (DOC_EXTENSIONS.has(ext)) return { classification: 'documentation', disposition: 'inventory-only' };
  if (ASSET_EXTENSIONS.has(ext)) return { classification: 'asset', disposition: 'inventory-only' };
  return { classification: 'other', disposition: 'inventory-only' };
}

// 제외 디렉터리/경로 이후 도달 가능한 모든 일반 파일(심볼릭 링크 제외) — 확장자 제한 없음.
// "무시된 build/vendor 디렉터리를 조사했다"는 주장이 아니라 대상 파일의 전수 인벤토리다.
function walkEligibleFiles(root, policy, errors = []) {
  const excludedDirs = new Set(policy.excludedDirs);
  const excludedPaths = new Set((policy.excludedPaths || []).map((value) =>
    path.resolve(root, String(value))));
  const files = [];
  const isExcluded = (candidate) => {
    const absolute = path.resolve(candidate);
    return [...excludedPaths].some((excluded) =>
      absolute === excluded || absolute.startsWith(`${excluded}${path.sep}`));
  };
  function walk(dir) {
    if (isExcluded(dir)) return;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (error) {
      errors.push({ path: toPosix(path.relative(root, dir)) || '.', code: error.code || 'SOURCE_DIRECTORY_UNREADABLE' });
      return;
    }
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (!shouldSkipDir(entry.name, excludedDirs)) walk(fullPath);
        continue;
      }
      if (!entry.isFile()) continue;
      files.push(toPosix(path.relative(root, fullPath)));
    }
  }
  walk(root);
  return [...new Set(files)].sort();
}

// 서브프로젝트(독립 빌드 유닛) 루트를 relative-path로 반환(정렬). 루트 자체가 빌드 마커를 가지면 '.' 포함.
function findSubprojectRoots(root, policy = {}) {
  const dirs = new Set();
  const excludedDirs = new Set(policy.excludedDirs || DEFAULT_EXCLUDED_DIRS);
  const excludedPaths = new Set((policy.excludedPaths || []).map((value) =>
    path.resolve(root, String(value))));

  function walk(dir) {
    const absolute = path.resolve(dir);
    if ([...excludedPaths].some((excluded) =>
      absolute === excluded || absolute.startsWith(`${excluded}${path.sep}`))) return;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    let hasMarker = false;
    for (const entry of entries) {
      if (!entry.isFile()) continue;
      if (DEFAULT_BUILD_MARKERS.some((marker) => markerMatches(entry.name, marker))) {
        hasMarker = true;
        break;
      }
    }
    if (hasMarker) dirs.add(toPosix(path.relative(root, dir)) || '.');

    for (const entry of entries) {
      if (!entry.isDirectory() || shouldSkipDir(entry.name, excludedDirs)) continue;
      walk(path.join(dir, entry.name));
    }
  }

  walk(root);
  return [...dirs].sort();
}

function countSubprojects(root) {
  return findSubprojectRoots(root).length;
}

// 파일(relative posix)을 가장 깊은(최장 prefix) 서브프로젝트 루트에 배정. 어디에도 안 걸리면 '.'.
function assignUnit(relFile, sortedRoots) {
  let best = '.';
  let bestLen = -1;
  for (const r of sortedRoots) {
    if (r === '.') { if (bestLen < 0) { best = '.'; bestLen = 0; } continue; }
    const prefix = `${r}/`;
    if (relFile === r || relFile.startsWith(prefix)) {
      if (r.length > bestLen) { best = r; bestLen = r.length; }
    }
  }
  return best;
}

// 유닛(서브프로젝트)별 { id, path, file_count, loc, files } 집계. locByFile: {relFile: loc}.
// 빌드마커가 하나도 없으면 전체를 단일 '.' 유닛으로 처리.
function buildUnitBreakdown(sourceFiles, locByFile, subprojectRoots, limits = {}) {
  const roots = subprojectRoots && subprojectRoots.length ? subprojectRoots : ['.'];
  const units = new Map();
  const ensure = (id) => {
    if (!units.has(id)) units.set(id, { id, path: id, file_count: 0, loc: 0, files: [] });
    return units.get(id);
  };
  for (const r of roots) ensure(r); // 파일 없는 서브프로젝트도 유닛으로 남김
  for (const rel of sourceFiles) {
    const u = ensure(assignUnit(rel, roots));
    u.file_count += 1;
    u.loc += Number(locByFile[rel] || 0);
    u.files.push(rel);
  }
  const maxUnitFiles = Number(limits.maxUnitFiles || DEFAULT_MAX_UNIT_FILES);
  const maxUnitLoc = Number(limits.maxUnitLoc || DEFAULT_MAX_UNIT_LOC);
  const split = [...units.values()].flatMap((unit) => {
    const files = unit.files.sort();
    if (files.length <= maxUnitFiles && unit.loc <= maxUnitLoc) return [{ ...unit, files }];
    const chunks = [];
    let current = { files: [], loc: 0 };
    for (const file of files) {
      const loc = Number(locByFile[file] || 0);
      if (current.files.length > 0 && (
        current.files.length >= maxUnitFiles || current.loc + loc > maxUnitLoc
      )) {
        chunks.push(current);
        current = { files: [], loc: 0 };
      }
      current.files.push(file);
      current.loc += loc;
    }
    if (current.files.length > 0) chunks.push(current);
    return chunks.map((chunk, index) => ({
      id: `${unit.id}#${String(index + 1).padStart(3, '0')}`,
      path: unit.path,
      file_count: chunk.files.length,
      loc: chunk.loc,
      files: chunk.files,
    }));
  });
  return split
    .sort((a, b) => b.loc - a.loc || a.id.localeCompare(b.id));
}

function getGitHead(root) {
  try {
    return execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 3000,
    }).trim();
  } catch {
    return null;
  }
}

// 진단 대상의 현재 브랜치명.
// P2: detached HEAD(rev-parse가 'HEAD' 반환)는 브랜치가 없지만 커밋은 있으므로, null로 두어
// provenance 게이트에 영구 차단당하지 않도록 "detached@<short-sha>" 마커로 기록한다(CI 흔한 케이스).
// 비-git 대상만 null(기록할 브랜치·커밋 자체가 없음).
function getGitBranch(root) {
  try {
    const branch = execFileSync('git', ['-C', root, 'rev-parse', '--abbrev-ref', 'HEAD'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 3000,
    }).trim();
    if (branch && branch !== 'HEAD') return branch;
    // detached HEAD → 커밋 단축 해시로 상태를 명시 기록.
    const short = execFileSync('git', ['-C', root, 'rev-parse', '--short', 'HEAD'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 3000,
    }).trim();
    return short ? `detached@${short}` : null;
  } catch {
    return null;
  }
}

function createSourceManifest(targetRoot, opts = {}) {
  const root = normalizeRoot(targetRoot);
  const config = opts.config || loadConfig();
  const basePolicy = opts.policy || loadSourcePolicy(config);
  const excludedPaths = [...new Set([
    ...(basePolicy.excludedPaths || []),
    ...(opts.excludePaths || []),
  ].map((value) => {
    const absolute = normalizeRoot(path.resolve(root, String(value)));
    const relative = path.relative(root, absolute);
    return relative === '' ? '.' : toPosix(relative);
  }).filter((value) => value !== '.' && value !== '..' && !value.startsWith('../')))].sort();
  const policy = {
    ...basePolicy,
    excludedPaths,
    maxUnitFiles: Number(opts.maxUnitFiles ?? basePolicy.maxUnitFiles ?? DEFAULT_MAX_UNIT_FILES),
    maxUnitLoc: Number(opts.maxUnitLoc ?? basePolicy.maxUnitLoc ?? DEFAULT_MAX_UNIT_LOC),
  };
  if (!Number.isInteger(policy.maxUnitFiles) || policy.maxUnitFiles < 1 ||
      !Number.isInteger(policy.maxUnitLoc) || policy.maxUnitLoc < 1) {
    throw new Error('source manifest unit limits must be positive integers');
  }
  const sourceErrors = [];
  const sourceFiles = walkSourceFiles(root, policy, sourceErrors);
  const dependencyFiles = walkDependencyFiles(root, policy, sourceErrors);
  let locEstimate = 0;
  const locByFile = {};

  for (const rel of sourceFiles) {
    const loc = safeReadLineCount(path.join(root, rel));
    locByFile[rel] = loc;
    locEstimate += loc;
  }

  const subprojectRoots = findSubprojectRoots(root, policy);
  const units = buildUnitBreakdown(sourceFiles, locByFile, subprojectRoots, policy);
  const unreadable = new Map();
  const readReceipt = rel => {
    if (unreadable.has(rel)) return null;
    try {
      const content = fs.readFileSync(path.join(root, rel));
      return { path: rel, bytes: content.byteLength, sha256: sha256(content) };
    } catch (error) {
      const issue = { path: rel, code: error.code || 'SOURCE_FILE_UNREADABLE' };
      sourceErrors.push(issue); unreadable.set(rel, issue); return null;
    }
  };
  const sourceReceipts = sourceFiles.flatMap(rel => { const value = readReceipt(rel); return value ? [value] : []; });
  const dependencyReceipts = dependencyFiles.flatMap(rel => { const value = readReceipt(rel); return value ? [value] : []; });

  // 대상 하위 전체 적격 파일(제외 정책 적용 후) 인벤토리 — source_files/units는 바뀌지 않는다.
  const sourceFileSet = new Set(sourceFiles);
  const dependencyFileSet = new Set(dependencyFiles);
  const sourceReceiptByPath = new Map(sourceReceipts.map((receipt) => [receipt.path, receipt]));
  const dependencyReceiptByPath = new Map(dependencyReceipts.map((receipt) => [receipt.path, receipt]));
  const eligibleFiles = walkEligibleFiles(root, policy, sourceErrors);
  const scopeInventory = eligibleFiles.map((rel) => {
    const { classification, disposition } = classifyInventoryEntry(
      rel, sourceFileSet.has(rel), dependencyFileSet.has(rel));
    const reused = sourceReceiptByPath.get(rel) || dependencyReceiptByPath.get(rel);
    const receipt = reused || readReceipt(rel);
    return receipt ? { path: rel, classification, disposition, bytes: receipt.bytes, sha256: receipt.sha256 }
      : { path: rel, classification, disposition, read_error: unreadable.get(rel).code };

  });
  const securityResourceEntries = scopeInventory.filter((entry) =>
    entry.classification === 'security-resource' ||
    entry.classification === 'runtime-prompt' ||
    entry.classification === 'generated-runtime-resource');
  const securityResourceFiles = securityResourceEntries.map((entry) => entry.path);
  const securityResourceReceipts = securityResourceEntries.filter(entry => entry.sha256).map((entry) =>
    ({ path: entry.path, bytes: entry.bytes, sha256: entry.sha256 }));
  const scopeInventorySha256 = sha256(stableJson(scopeInventory));

  const core = {
    schema_version: 1,
    target_realpath: root,
    source_file_count: sourceFiles.length,
    loc_estimate: locEstimate,
    subproject_count: subprojectRoots.length,
    subproject_roots: subprojectRoots,
    // 유닛별 file-list + LOC — coverage-gate(분해/완결성/커버리지 비율)의 결정론 입력.
    units: units.map((u) => ({ id: u.id, path: u.path, file_count: u.file_count, loc: u.loc, files: u.files })),
    git_head: getGitHead(root),
    git_branch: getGitBranch(root),
    policy,
    source_files: sourceFiles,
    source_receipts: sourceReceipts,
    dependency_files: dependencyFiles,
    dependency_receipts: dependencyReceipts,
    // P0-B: 추가 필드 — source_files/units 소유권 의미는 바꾸지 않는 적격 파일 인벤토리.
    security_resource_files: securityResourceFiles,
    security_resource_receipts: securityResourceReceipts,
    scope_inventory_schema_version: '1.0.0',
    scope_inventory_sha256: scopeInventorySha256,
    scope_inventory: scopeInventory,
    ...(sourceErrors.length ? { source_errors: [...new Map(sourceErrors.map(issue => [issue.path + ":" + issue.code, issue])).values()] } : {}),
  };

  const contentHash = sourceManifestContentHash(core);
  return {
    ...core,
    // `hash` remains as a compatibility alias for existing consumers.
    hash: contentHash,
    content_hash: contentHash,
    generated_at: new Date().toISOString(),
  };
}

function writeSourceManifest(engagementDir, manifest) {
  fs.mkdirSync(engagementDir, { recursive: true, mode: 0o700 });
  const filePath = path.join(engagementDir, 'source_manifest.json');
  const tmp = `${filePath}.tmp.${process.pid}`;
  fs.writeFileSync(tmp, JSON.stringify(manifest, null, 2), { encoding: 'utf8', mode: 0o600 });
  fs.renameSync(tmp, filePath);
  return filePath;
}

function loadSourceManifest(engagementDir) {
  const filePath = path.join(engagementDir, 'source_manifest.json');
  if (!fs.existsSync(filePath)) return null;
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

module.exports = {
  createSourceManifest,
  loadSourceManifest,
  loadSourcePolicy,
  normalizeRoot,
  stableJson,
  sourceManifestContentHash,
  writeSourceManifest,
  findSubprojectRoots,
  countSubprojects,
  assignUnit,
  buildUnitBreakdown,
  classifySecurityResource,
  classifyInventoryEntry,
  walkEligibleFiles,
};
