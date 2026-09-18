'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { execFileSync } = require('child_process');
const crypto = require('crypto');

const { createSourceManifest, sourceManifestContentHash, stableJson } = require('../source-manifest');
const { getSupportedExtensions } = require('../ast/parser');

const projectConfig = require('../../../ch015.config.json');

function mkProject() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-srcman-'));
  fs.mkdirSync(path.join(root, 'src'), { recursive: true });
  fs.mkdirSync(path.join(root, 'node_modules', 'pkg'), { recursive: true });
  fs.writeFileSync(path.join(root, 'go.mod'), 'module example.com/app\n');
  fs.writeFileSync(path.join(root, 'src', 'main.go'), 'package main\nfunc main() {}\n');
  fs.writeFileSync(path.join(root, 'src', 'api.js'), 'export const ok = true;\n');
  fs.writeFileSync(path.join(root, 'node_modules', 'pkg', 'ignored.js'), 'ignored\n');
  return root;
}

test('source manifest counts configured source files and excludes generated dirs', () => {
  const root = mkProject();
  const manifest = createSourceManifest(root);

  assert.equal(manifest.source_file_count, 2);
  assert.deepEqual(manifest.source_files, ['src/api.js', 'src/main.go']);
  assert.deepEqual(manifest.dependency_files, ['go.mod']);
  assert.equal(manifest.subproject_count, 1);
  assert.ok(manifest.loc_estimate >= 3);
  assert.equal(typeof manifest.hash, 'string');
  assert.equal(manifest.content_hash, manifest.hash);
  assert.equal(sourceManifestContentHash(manifest), manifest.hash);

  fs.rmSync(root, { recursive: true, force: true });
});

test('source manifest content identity ignores locator path and branch label', () => {
  const firstRoot = mkProject();
  const secondRoot = mkProject();
  const first = createSourceManifest(firstRoot);
  const second = createSourceManifest(secondRoot);

  assert.notEqual(first.target_realpath, second.target_realpath);
  assert.deepEqual(first.source_receipts, second.source_receipts);
  assert.equal(first.hash, second.hash);
  assert.equal(sourceManifestContentHash({ ...first, git_branch: 'renamed-branch' }), first.hash);

  fs.rmSync(firstRoot, { recursive: true, force: true });
  fs.rmSync(secondRoot, { recursive: true, force: true });
});

test('source manifest seals dependency manifests and excludes generated dependency trees', () => {
  const root = mkProject();
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"root"}\n');
  fs.writeFileSync(path.join(root, 'package-lock.json'), '{"lockfileVersion":3}\n');
  fs.writeFileSync(path.join(root, 'node_modules', 'pkg', 'package.json'), '{"name":"ignored"}\n');
  const first = createSourceManifest(root);
  assert.deepEqual(first.dependency_files, ['go.mod', 'package-lock.json', 'package.json']);
  assert.equal(first.dependency_receipts.length, 3);
  fs.writeFileSync(path.join(root, 'package-lock.json'), '{"lockfileVersion":2}\n');
  assert.notEqual(createSourceManifest(root).hash, first.hash);
  fs.rmSync(root, { recursive: true, force: true });
});

test('source manifest includes every parser-supported source extension', () => {
  const configured = new Set(projectConfig.codeExtensions);
  assert.deepEqual(getSupportedExtensions().filter((extension) => !configured.has(extension)), []);

  const root = mkProject();
  for (const extension of getSupportedExtensions()) {
    fs.writeFileSync(path.join(root, 'src', `supported${extension}`), 'source\n');
  }
  const manifest = createSourceManifest(root);
  for (const extension of getSupportedExtensions()) {
    assert.ok(manifest.source_files.includes(`src/supported${extension}`), extension);
  }
  fs.rmSync(root, { recursive: true, force: true });
});

test('source manifest captures git_branch and git_head for a git repo', () => {
  const root = mkProject();
  const git = (...a) => execFileSync('git', ['-C', root, ...a], { stdio: ['ignore', 'pipe', 'ignore'] });
  git('init', '-q');
  git('checkout', '-q', '-b', 'feat/test-branch');
  git('config', 'user.email', 't@t.test');
  git('config', 'user.name', 'test');
  git('add', '-A');
  git('commit', '-q', '-m', 'init');

  const manifest = createSourceManifest(root);
  assert.equal(manifest.git_branch, 'feat/test-branch');
  assert.match(String(manifest.git_head), /^[0-9a-f]{40}$/);

  fs.rmSync(root, { recursive: true, force: true });
});

test('source manifest records detached HEAD as detached@<short> (P2, not null)', () => {
  const root = mkProject();
  const git = (...a) => execFileSync('git', ['-C', root, ...a], { stdio: ['ignore', 'pipe', 'ignore'] });
  git('init', '-q');
  git('config', 'user.email', 't@t.test');
  git('config', 'user.name', 'test');
  git('add', '-A');
  git('commit', '-q', '-m', 'init');
  const sha = execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  git('checkout', '-q', sha); // detached HEAD

  const manifest = createSourceManifest(root);
  assert.match(String(manifest.git_branch), /^detached@[0-9a-f]{7,}$/);
  assert.match(String(manifest.git_head), /^[0-9a-f]{40}$/);

  fs.rmSync(root, { recursive: true, force: true });
});

test('source manifest git fields are null outside a git repo', () => {
  const root = mkProject();
  const manifest = createSourceManifest(root);
  assert.equal(manifest.git_branch, null);
  assert.equal(manifest.git_head, null);
  fs.rmSync(root, { recursive: true, force: true });
});

test('source manifest hash changes when source list changes', () => {
  const root = mkProject();
  const first = createSourceManifest(root);
  fs.writeFileSync(path.join(root, 'src', 'extra.go'), 'package main\n');
  const second = createSourceManifest(root);

  assert.notEqual(first.hash, second.hash);
  assert.equal(second.source_file_count, 3);

  const beforeContentChange = createSourceManifest(root);
  fs.writeFileSync(path.join(root, 'src', 'api.js'), 'export const no = false;\n');
  const afterContentChange = createSourceManifest(root);
  assert.notEqual(beforeContentChange.hash, afterContentChange.hash);

  fs.rmSync(root, { recursive: true, force: true });
});

test('source manifest excludes prior report material from source and subprojects', () => {
  const root = mkProject();
  fs.mkdirSync(path.join(root, 'reports', 'old'), { recursive: true });
  fs.writeFileSync(path.join(root, 'reports', 'old', '01_va_ledger.yaml'), 'finding: anchored\n');
  fs.writeFileSync(path.join(root, 'reports', 'old', 'package.json'), '{}\n');
  const manifest = createSourceManifest(root, { excludePaths: [path.join(root, 'reports')] });
  assert.equal(manifest.source_files.some((file) => file.startsWith('reports/')), false);
  assert.equal(manifest.subproject_roots.some((unit) => unit.startsWith('reports/')), false);
  fs.rmSync(root, { recursive: true, force: true });
});

test('source manifest excludes reports when the target uses a symlink alias', () => {
  const root = mkProject();
  const aliasParent = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-srcman-alias-'));
  const alias = path.join(aliasParent, 'target');
  try {
    fs.symlinkSync(root, alias, 'dir');
    fs.mkdirSync(path.join(root, 'reports', 'old'), { recursive: true });
    fs.writeFileSync(path.join(root, 'reports', 'old', 'app.js'), 'const stale = true;\n');
    fs.writeFileSync(path.join(root, 'reports', 'old', 'package.json'), '{}\n');
    const manifest = createSourceManifest(alias, { excludePaths: [path.join(alias, 'reports')] });
    assert.equal(manifest.source_files.some((file) => file.startsWith('reports/')), false);
    assert.equal(manifest.dependency_files.some((file) => file.startsWith('reports/')), false);
    assert.equal(manifest.subproject_roots.some((unit) => unit.startsWith('reports/')), false);
    assert.ok(manifest.source_files.includes('src/api.js'));
  } finally {
    fs.rmSync(aliasParent, { recursive: true, force: true });
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('source manifest deterministically splits an oversized monolith with exact-once assignment', () => {
  const root = mkProject();
  for (let index = 0; index < 5; index += 1) {
    fs.writeFileSync(path.join(root, 'src', `part-${index}.js`), `export const p${index} = true;\n`);
  }
  const first = createSourceManifest(root, { maxUnitFiles: 2, maxUnitLoc: 1000 });
  const second = createSourceManifest(root, { maxUnitFiles: 2, maxUnitLoc: 1000 });
  const assigned = first.units.flatMap((unit) => unit.files);
  assert.ok(first.units.length > 1);
  assert.deepEqual(assigned.slice().sort(), first.source_files);
  assert.equal(new Set(assigned).size, first.source_files.length);
  assert.deepEqual(first.units, second.units);
  fs.rmSync(root, { recursive: true, force: true });
});

test('source manifest rejects invalid unit limits', () => {
  const root = mkProject();
  assert.throws(() => createSourceManifest(root, { maxUnitFiles: -1 }), /positive integers/);
  fs.rmSync(root, { recursive: true, force: true });
});

// ── P0-B: eligible-file inventory + narrow security-resource classification ─

test('scope inventory classifies narrow security-resource patterns without touching source_files', () => {
  const root = mkProject();
  fs.writeFileSync(path.join(root, 'Dockerfile'), 'FROM node:20\n');
  fs.writeFileSync(path.join(root, 'deploy.sh'), '#!/bin/sh\necho deploy\n');
  fs.mkdirSync(path.join(root, 'src-tauri', 'capabilities'), { recursive: true });
  fs.writeFileSync(path.join(root, 'src-tauri', 'tauri.conf.json'), '{"productName":"app"}\n');
  fs.writeFileSync(path.join(root, 'src-tauri', 'capabilities', 'default.json'), '{"permissions":[]}\n');
  fs.mkdirSync(path.join(root, 'supabase'), { recursive: true });
  fs.writeFileSync(path.join(root, 'supabase', 'config.json'), '{"project_id":"x"}\n');
  fs.mkdirSync(path.join(root, 'agents'), { recursive: true });
  fs.writeFileSync(path.join(root, 'agents', 'reviewer.md'), '# Reviewer prompt\n');
  fs.writeFileSync(path.join(root, 'registry.json'), '{"version":"1.0.0"}\n');
  fs.writeFileSync(path.join(root, 'notes.md'), '# just docs\n');
  fs.writeFileSync(path.join(root, 'logo.svg'), '<svg></svg>\n');
  fs.writeFileSync(path.join(root, 'data.json'), '{"generic":true}\n');

  const manifest = createSourceManifest(root);
  const byPath = new Map(manifest.scope_inventory.map((entry) => [entry.path, entry]));
  const expectSecurity = (p) => {
    const entry = byPath.get(p);
    assert.ok(entry, `${p} missing from scope_inventory`);
    assert.equal(entry.disposition, 'analyze-security-resource');
    return entry;
  };
  assert.equal(expectSecurity('Dockerfile').classification, 'security-resource');
  assert.equal(expectSecurity('deploy.sh').classification, 'security-resource');
  assert.equal(expectSecurity('src-tauri/tauri.conf.json').classification, 'security-resource');
  assert.equal(expectSecurity('src-tauri/capabilities/default.json').classification, 'security-resource');
  assert.equal(expectSecurity('supabase/config.json').classification, 'security-resource');
  assert.equal(expectSecurity('agents/reviewer.md').classification, 'runtime-prompt');
  assert.equal(expectSecurity('registry.json').classification, 'generated-runtime-resource');

  assert.equal(byPath.get('notes.md').classification, 'documentation');
  assert.equal(byPath.get('notes.md').disposition, 'inventory-only');
  assert.equal(byPath.get('logo.svg').classification, 'asset');
  assert.equal(byPath.get('logo.svg').disposition, 'inventory-only');
  assert.equal(byPath.get('data.json').classification, 'other');
  assert.equal(byPath.get('data.json').disposition, 'inventory-only');
  assert.equal(byPath.get('src/api.js').classification, 'source');
  assert.equal(byPath.get('src/api.js').disposition, 'analyze-source');
  assert.equal(byPath.get('go.mod').classification, 'dependency-manifest');
  assert.equal(byPath.get('go.mod').disposition, 'analyze-dependency');

  assert.deepEqual(manifest.security_resource_files, [...new Set([
    'Dockerfile', 'deploy.sh', 'src-tauri/tauri.conf.json', 'src-tauri/capabilities/default.json',
    'supabase/config.json', 'agents/reviewer.md', 'registry.json',
  ])].sort());
  assert.deepEqual(
    manifest.security_resource_receipts.map((receipt) => receipt.path).sort(),
    manifest.security_resource_files.slice().sort(),
  );
  assert.equal(typeof manifest.scope_inventory_sha256, 'string');
  assert.match(manifest.scope_inventory_sha256, /^[a-f0-9]{64}$/);
  assert.equal(manifest.scope_inventory_schema_version, '1.0.0');

  // 인벤토리 추가는 기존 source_files/dependency_files/unit 소유권을 바꾸지 않는다.
  assert.deepEqual(manifest.source_files, ['src/api.js', 'src/main.go']);
  assert.deepEqual(manifest.dependency_files, ['go.mod']);
  const totalUnitFiles = manifest.units.reduce((sum, unit) => sum + unit.files.length, 0);
  assert.equal(totalUnitFiles, manifest.source_files.length);

  fs.rmSync(root, { recursive: true, force: true });
});

test('scope inventory leaves generic JSON/assets as inventory-only without a supported rule', () => {
  const root = mkProject();
  fs.writeFileSync(path.join(root, 'config.json'), '{"unrelated":true}\n');
  fs.writeFileSync(path.join(root, 'image.png'), 'binary\n');
  const manifest = createSourceManifest(root);
  const byPath = new Map(manifest.scope_inventory.map((entry) => [entry.path, entry]));
  assert.equal(byPath.get('config.json').classification, 'other');
  assert.equal(byPath.get('config.json').disposition, 'inventory-only');
  assert.equal(byPath.get('image.png').classification, 'asset');
  assert.equal(byPath.get('image.png').disposition, 'inventory-only');
  assert.equal(manifest.security_resource_files.includes('config.json'), false);
  assert.equal(manifest.security_resource_files.includes('image.png'), false);
  fs.rmSync(root, { recursive: true, force: true });
});

test('scope inventory excludes generated output directories and symlinks', () => {
  const root = mkProject();
  fs.mkdirSync(path.join(root, 'dist'), { recursive: true });
  fs.writeFileSync(path.join(root, 'dist', 'bundle.js'), 'ignored\n');
  fs.writeFileSync(path.join(root, 'real.txt'), 'target\n');
  let symlinked = true;
  try {
    fs.symlinkSync(path.join(root, 'real.txt'), path.join(root, 'link.txt'));
  } catch {
    symlinked = false;
  }
  const manifest = createSourceManifest(root);
  const paths = manifest.scope_inventory.map((entry) => entry.path);
  assert.equal(paths.some((p) => p.startsWith('dist/')), false);
  assert.equal(paths.some((p) => p.startsWith('node_modules/')), false);
  if (symlinked) assert.equal(paths.includes('link.txt'), false);
  assert.equal(paths.includes('real.txt'), true);
  fs.rmSync(root, { recursive: true, force: true });
});

test('scope inventory content mutation changes the new-schema content hash while the legacy projection is unaffected', () => {
  const root = mkProject();
  const manifest = createSourceManifest(root);
  assert.ok(manifest.scope_inventory.length > 0);

  // scope_inventory 배열 내용만 변조하고 scope_inventory_sha256 필드는 그대로 둔다 — 변조를
  // 놓치기 쉬운 지점이다. 그래도 재계산한 content hash는 반드시 원본과 달라야 한다(§P0-B 무결성
  // 바인딩: 저장된 scope_inventory_sha256 필드를 신뢰하지 않고 실제 embedded 배열을 재해시한다).
  const tamperedInventory = manifest.scope_inventory.map((entry, index) =>
    index === 0 ? { ...entry, classification: 'tampered' } : entry);
  const tampered = { ...manifest, scope_inventory: tamperedInventory };
  assert.notEqual(sourceManifestContentHash(tampered), manifest.hash);

  // 구버전(P0-B 신규 필드 완전 부재) 투영은 scope_inventory 변조와 무관하게 동일해야 한다.
  const stripNewFields = (value) => {
    const {
      security_resource_files: _securityResourceFiles,
      security_resource_receipts: _securityResourceReceipts,
      scope_inventory: _scopeInventory,
      scope_inventory_sha256: _scopeInventorySha256,
      scope_inventory_schema_version: _scopeInventorySchemaVersion,
      hash: _hash,
      content_hash: _contentHash,
      generated_at: _generatedAt,
      ...legacyCore
    } = value;
    return legacyCore;
  };
  assert.equal(
    sourceManifestContentHash(stripNewFields(manifest)),
    sourceManifestContentHash(stripNewFields(tampered)),
  );
  fs.rmSync(root, { recursive: true, force: true });
});

// ── P0 correction pass: narrow Supabase JSON classification (config/storage-policy only) ──

test('scope inventory narrows Supabase JSON classification to config/storage-policy paths only', () => {
  const root = mkProject();
  fs.mkdirSync(path.join(root, 'supabase', 'storage_buckets'), { recursive: true });
  fs.writeFileSync(path.join(root, 'supabase', 'config.json'), '{"project_id":"x"}\n');
  fs.writeFileSync(path.join(root, 'supabase', 'storage_buckets', 'public-shares.json'), '{"public":true}\n');
  fs.mkdirSync(path.join(root, 'src-tauri', 'supabase', 'functions', 'share-viewer'), { recursive: true });
  fs.writeFileSync(
    path.join(root, 'src-tauri', 'supabase', 'functions', 'share-viewer', 'deno.json'),
    '{"imports":{}}\n',
  );

  const manifest = createSourceManifest(root);
  const byPath = new Map(manifest.scope_inventory.map((entry) => [entry.path, entry]));

  assert.equal(byPath.get('supabase/config.json').classification, 'security-resource');
  assert.equal(byPath.get('supabase/config.json').disposition, 'analyze-security-resource');
  assert.equal(byPath.get('supabase/storage_buckets/public-shares.json').classification, 'security-resource');
  assert.equal(byPath.get('supabase/storage_buckets/public-shares.json').disposition, 'analyze-security-resource');

  const denoEntry = byPath.get('src-tauri/supabase/functions/share-viewer/deno.json');
  assert.ok(denoEntry, 'deno.json missing from scope_inventory');
  assert.equal(denoEntry.classification, 'other');
  assert.equal(denoEntry.disposition, 'inventory-only');

  assert.ok(manifest.security_resource_files.includes('supabase/config.json'));
  assert.ok(manifest.security_resource_files.includes('supabase/storage_buckets/public-shares.json'));
  assert.equal(
    manifest.security_resource_files.includes('src-tauri/supabase/functions/share-viewer/deno.json'),
    false,
  );

  fs.rmSync(root, { recursive: true, force: true });
});

test('old (pre-P0-B) manifest shape rehashes identically under the new content-hash function', () => {
  const root = mkProject();
  const manifest = createSourceManifest(root);
  const {
    security_resource_files: _securityResourceFiles,
    security_resource_receipts: _securityResourceReceipts,
    scope_inventory: _scopeInventory,
    scope_inventory_sha256: _scopeInventorySha256,
    scope_inventory_schema_version: _scopeInventorySchemaVersion,
    hash: _hash,
    content_hash: _contentHash,
    generated_at: _generatedAt,
    ...legacyCore
  } = manifest;
  // 구버전(P0-B 이전) 알고리즘을 그대로 복제 — 신규 필드를 전혀 모르는 채로 hash를 낸다.
  const legacyProjection = {
    schema_version: legacyCore.schema_version,
    source_file_count: legacyCore.source_file_count,
    loc_estimate: legacyCore.loc_estimate,
    subproject_count: legacyCore.subproject_count,
    subproject_roots: legacyCore.subproject_roots,
    units: legacyCore.units,
    git_head: legacyCore.git_head,
    policy: legacyCore.policy,
    source_files: legacyCore.source_files,
    source_receipts: legacyCore.source_receipts,
    dependency_files: legacyCore.dependency_files,
    dependency_receipts: legacyCore.dependency_receipts,
  };
  const legacyHash = crypto.createHash('sha256').update(stableJson(legacyProjection)).digest('hex');
  const legacyManifest = { ...legacyCore, hash: legacyHash, content_hash: legacyHash };
  assert.equal(sourceManifestContentHash(legacyManifest), legacyHash);
  fs.rmSync(root, { recursive: true, force: true });
});
