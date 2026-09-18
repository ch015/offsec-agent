'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  extractFileLineRefs,
  isLikelyCodePath,
  extractEvidenceManifest,
  verifyEvidence,
  verifyManifest
} = require('../evidence');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-evidence-'));
process.on('exit', () => { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch {} });

// --- isLikelyCodePath ---

test('isLikelyCodePath: recognizes code extensions', () => {
  assert.equal(isLikelyCodePath('src/auth.js'), true);
  assert.equal(isLikelyCodePath('lib/handler.ts'), true);
  assert.equal(isLikelyCodePath('main.go'), true);
  assert.equal(isLikelyCodePath('schema.sql'), true);
  assert.equal(isLikelyCodePath('config.yaml'), true);
});

test('isLikelyCodePath: rejects URLs', () => {
  assert.equal(isLikelyCodePath('https://example.com/file.js'), false);
  assert.equal(isLikelyCodePath('http://localhost:3000'), false);
});

test('isLikelyCodePath: rejects paths with spaces', () => {
  assert.equal(isLikelyCodePath('my file.js'), false);
});

test('isLikelyCodePath: recognizes Dockerfile and Makefile', () => {
  assert.equal(isLikelyCodePath('Dockerfile'), true);
  assert.equal(isLikelyCodePath('Makefile'), true);
});

test('isLikelyCodePath: recognizes paths with slashes', () => {
  assert.equal(isLikelyCodePath('src/lib/utils'), true);
});

// --- extractFileLineRefs ---

test('extractFileLineRefs: extracts simple file:line reference', () => {
  const refs = extractFileLineRefs('Found issue at src/auth.js:42');
  assert.equal(refs.length, 1);
  assert.equal(refs[0].file, 'src/auth.js');
  assert.equal(refs[0].line, 42);
  assert.equal(refs[0].endLine, null);
});

test('extractFileLineRefs: extracts comma-separated references', () => {
  const refs = extractFileLineRefs('Affected: a.js:10,b.js:20');
  assert.equal(refs.length, 2);
  assert.equal(refs[0].file, 'a.js');
  assert.equal(refs[0].line, 10);
  assert.equal(refs[1].file, 'b.js');
  assert.equal(refs[1].line, 20);
});

test('extractFileLineRefs: extracts range reference', () => {
  const refs = extractFileLineRefs('See src/auth.js:42-50');
  assert.equal(refs.length, 1);
  assert.equal(refs[0].line, 42);
  assert.equal(refs[0].endLine, 50);
});

test('extractFileLineRefs: extracts multiple references', () => {
  const refs = extractFileLineRefs('Compare src/a.js:10 with src/b.js:20');
  assert.equal(refs.length, 2);
});

test('extractFileLineRefs: deduplicates same file:line', () => {
  const refs = extractFileLineRefs('src/a.js:10 and again src/a.js:10');
  assert.equal(refs.length, 1);
});

test('extractFileLineRefs: handles backtick-wrapped references', () => {
  const refs = extractFileLineRefs('Found at `src/handler.ts:15`');
  assert.equal(refs.length, 1);
  assert.equal(refs[0].file, 'src/handler.ts');
});

test('extractFileLineRefs: ignores non-code paths', () => {
  const refs = extractFileLineRefs('Visit https://example.com:8080');
  assert.equal(refs.length, 0);
});

// --- extractEvidenceManifest ---

test('extractEvidenceManifest: groups refs by finding ID', () => {
  const content = [
    '## F-001 SQL Injection',
    'Found at src/db.js:10',
    'Also at src/db.js:20-25',
    '## F-002 XSS',
    'See src/template.js:5'
  ].join('\n');

  const reportPath = path.join(TMP, 'report1.md');
  fs.writeFileSync(reportPath, content);

  const manifest = extractEvidenceManifest(reportPath);
  assert.equal(manifest.length, 2);
  assert.equal(manifest[0].finding_id, 'F-001');
  assert.equal(manifest[0].evidences.length, 2);
  assert.equal(manifest[1].finding_id, 'F-002');
  assert.equal(manifest[1].evidences.length, 1);
});

test('extractEvidenceManifest: skips findings with no refs', () => {
  const content = [
    '## F-001 No Evidence',
    'This finding has no file references.',
    '## F-002 Has Evidence',
    'Found at src/auth.js:1'
  ].join('\n');

  const reportPath = path.join(TMP, 'report2.md');
  fs.writeFileSync(reportPath, content);

  const manifest = extractEvidenceManifest(reportPath);
  assert.equal(manifest.length, 1);
  assert.equal(manifest[0].finding_id, 'F-002');
});

// --- verifyEvidence ---

test('verifyEvidence: VERIFIED for existing file within line range', () => {
  const projDir = path.join(TMP, 'proj1');
  fs.mkdirSync(projDir, { recursive: true });
  fs.writeFileSync(path.join(projDir, 'app.js'), 'line1\nline2\nline3\nline4\nline5\n');

  const result = verifyEvidence(projDir, { file: 'app.js', line: 3, endLine: null });
  assert.equal(result.status, 'VERIFIED');
});

test('verifyEvidence: CONTENT_MISMATCH when claim code tokens absent from region', () => {
  const projDir = path.join(TMP, 'proj-content-mismatch');
  fs.mkdirSync(projDir, { recursive: true });
  fs.writeFileSync(path.join(projDir, 'svc.js'), 'const a = 1;\nconst b = 2;\nconst c = 3;\n');

  // claim이 실재하지 않는 코드(getUserById, db.query)를 지목 → 영역에 없음
  const result = verifyEvidence(
    projDir,
    { file: 'svc.js', line: 2, endLine: null, claim: 'getUserById() passes req.body to db.query without sanitization' },
    1
  );
  assert.equal(result.status, 'INVALIDATED');
  assert.equal(result.reason, 'CONTENT_MISMATCH');
});

test('verifyEvidence: VERIFIED when claim code tokens present in region', () => {
  const projDir = path.join(TMP, 'proj-content-match');
  fs.mkdirSync(projDir, { recursive: true });
  fs.writeFileSync(path.join(projDir, 'svc.js'), 'function getUserById(id) {\n  return db.query("SELECT * WHERE id=" + id);\n}\n');

  const result = verifyEvidence(
    projDir,
    { file: 'svc.js', line: 2, endLine: null, claim: 'getUserById passes input to db.query without sanitization' },
    2
  );
  assert.equal(result.status, 'VERIFIED');
});

test('verifyEvidence: prose-only claim (no code tokens) stays VERIFIED', () => {
  const projDir = path.join(TMP, 'proj-prose');
  fs.mkdirSync(projDir, { recursive: true });
  fs.writeFileSync(path.join(projDir, 'app.js'), 'line1\nline2\nline3\nline4\nline5\n');

  const result = verifyEvidence(
    projDir,
    { file: 'app.js', line: 3, endLine: null, claim: '여기서 인증 검사가 누락되어 있다' },
  );
  assert.equal(result.status, 'VERIFIED');
});

test('verifyEvidence: contentMatch=false disables content check', () => {
  const projDir = path.join(TMP, 'proj-cm-off');
  fs.mkdirSync(projDir, { recursive: true });
  fs.writeFileSync(path.join(projDir, 'svc.js'), 'const a = 1;\nconst b = 2;\n');

  const result = verifyEvidence(
    projDir,
    { file: 'svc.js', line: 1, endLine: null, claim: 'getUserById calls db.query unsafely' },
    1,
    { contentMatch: false }
  );
  assert.equal(result.status, 'VERIFIED');
});

test('verifyEvidence: INVALIDATED for missing file', () => {
  const projDir = path.join(TMP, 'proj2');
  fs.mkdirSync(projDir, { recursive: true });

  const result = verifyEvidence(projDir, { file: 'missing.js', line: 1, endLine: null });
  assert.equal(result.status, 'INVALIDATED');
  assert.equal(result.reason, 'FILE_NOT_FOUND');
});

test('verifyEvidence: rejects parent-directory traversal', () => {
  const projDir = path.join(TMP, 'proj-path-traversal');
  fs.mkdirSync(projDir, { recursive: true });
  fs.writeFileSync(path.join(TMP, 'secret.json'), '{"secret":true}\n');

  const result = verifyEvidence(projDir, { file: '../secret.json', line: 1, endLine: null });
  assert.equal(result.status, 'INVALIDATED');
  assert.equal(result.reason, 'PATH_OUTSIDE_PROJECT');
  assert.equal(result.region_preview, undefined);
});

test('verifyEvidence: rejects absolute paths', () => {
  const projDir = path.join(TMP, 'proj-absolute');
  fs.mkdirSync(projDir, { recursive: true });
  const outside = path.join(TMP, 'absolute-secret.json');
  fs.writeFileSync(outside, '{"secret":true}\n');

  const result = verifyEvidence(projDir, { file: outside, line: 1, endLine: null });
  assert.equal(result.status, 'INVALIDATED');
  assert.equal(result.reason, 'PATH_OUTSIDE_PROJECT');
});

test('verifyEvidence: rejects symlink escapes', () => {
  const projDir = path.join(TMP, 'proj-symlink');
  fs.mkdirSync(projDir, { recursive: true });
  const outside = path.join(TMP, 'symlink-secret.json');
  fs.writeFileSync(outside, '{"secret":true}\n');
  const linkPath = path.join(projDir, 'linked.json');
  try {
    fs.symlinkSync(outside, linkPath);
  } catch {
    return;
  }

  const result = verifyEvidence(projDir, { file: 'linked.json', line: 1, endLine: null });
  assert.equal(result.status, 'INVALIDATED');
  assert.equal(result.reason, 'PATH_OUTSIDE_PROJECT');
});

test('verifyEvidence: INVALIDATED for line far out of range', () => {
  const projDir = path.join(TMP, 'proj3');
  fs.mkdirSync(projDir, { recursive: true });
  fs.writeFileSync(path.join(projDir, 'small.js'), 'line1\nline2\n');

  const result = verifyEvidence(projDir, { file: 'small.js', line: 100, endLine: null }, 10);
  assert.equal(result.status, 'INVALIDATED');
  assert.equal(result.reason, 'LINE_OUT_OF_RANGE');
});

test('verifyEvidence: VERIFIED with line correction within tolerance', () => {
  const projDir = path.join(TMP, 'proj4');
  fs.mkdirSync(projDir, { recursive: true });
  fs.writeFileSync(path.join(projDir, 'app.js'), Array(10).fill('code').join('\n'));

  const result = verifyEvidence(projDir, { file: 'app.js', line: 12, endLine: null }, 10);
  assert.equal(result.status, 'VERIFIED');
  assert.equal(result.line_corrected, true);
});

// --- verifyManifest ---

test('verifyManifest: aggregates across findings', () => {
  const projDir = path.join(TMP, 'proj5');
  fs.mkdirSync(projDir, { recursive: true });
  fs.writeFileSync(path.join(projDir, 'exists.js'), 'line1\nline2\nline3\n');

  const manifest = [
    {
      finding_id: 'F-001',
      evidences: [
        { file: 'exists.js', line: 1, endLine: null },
        { file: 'gone.js', line: 1, endLine: null }
      ]
    }
  ];

  const result = verifyManifest(projDir, manifest);
  assert.equal(result.total_evidences, 2);
  assert.equal(result.verified, 1);
  assert.equal(result.invalidated, 1);
  assert.equal(result.hallucination_rate, 0.5);
  assert.equal(result.findings[0].finding_id, 'F-001');
});

test('verifyManifest: empty manifest = 0 hallucination rate', () => {
  const result = verifyManifest(TMP, []);
  assert.equal(result.total_evidences, 0);
  assert.equal(result.hallucination_rate, 0);
});

// --- CLI 진입점 (require.main === module) ---
{
  const { spawnSync } = require('node:child_process');
  const yaml = require('js-yaml');
  const EVIDENCE_CLI = path.resolve(__dirname, '..', 'evidence.js');

  const runCli = (args) => {
    const r = spawnSync('node', [EVIDENCE_CLI, ...args], { encoding: 'utf8', timeout: 10_000 });
    return { code: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
  };

  // 타깃 소스: src/auth.js 10줄
  const target = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-evid-cli-tgt-'));
  fs.mkdirSync(path.join(target, 'src'));
  fs.writeFileSync(
    path.join(target, 'src', 'auth.js'),
    Array.from({ length: 10 }, (_, i) => `const line${i + 1} = ${i + 1};`).join('\n')
  );
  process.on('exit', () => { try { fs.rmSync(target, { recursive: true, force: true }); } catch {} });

  const writeLedger = (obj) => {
    const p = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-evid-cli-led-')), 'ledger.yaml');
    fs.writeFileSync(p, yaml.dump(obj));
    return p;
  };

  test('CLI evidence: all-verified ledger exits 0', () => {
    const p = writeLedger({ findings: [
      { finding_id: 'F-001', evidence: { locations: ['src/auth.js:5'] } },
    ] });
    const r = runCli(['verify', '--ledger', p, '--target', target]);
    assert.equal(r.code, 0, r.stderr);
    assert.equal(JSON.parse(r.stdout).hallucination_rate, 0);
  });

  test('CLI evidence: hallucinated evidence exceeding rate exits 2', () => {
    const p = writeLedger({ findings: [
      { finding_id: 'F-001', evidence: { locations: ['src/nonexistent.js:5'] } },
    ] });
    const r = runCli(['verify', '--ledger', p, '--target', target, '--max-rate', '0.05']);
    assert.equal(r.code, 2);
    assert.match(r.stderr, /EVIDENCE_HALLUCINATION_EXCEEDED: rate=1 max=0.05/);
  });

  test('CLI evidence: missing target exits 1', () => {
    const p = writeLedger({ findings: [{ finding_id: 'F-1', evidence: 'src/auth.js:5' }] });
    const r = runCli(['verify', '--ledger', p, '--target', '/nonexistent/dir']);
    assert.equal(r.code, 1);
  });

  test('CLI evidence: parse error exits 1', () => {
    const r = runCli(['verify', '--ledger', '/nonexistent/ledger.yaml', '--target', target]);
    assert.equal(r.code, 1);
  });

  test('CLI evidence: no command exits 1', () => {
    const p = writeLedger({ findings: [] });
    const r = runCli(['--ledger', p, '--target', target]);
    assert.equal(r.code, 1);
  });
}
