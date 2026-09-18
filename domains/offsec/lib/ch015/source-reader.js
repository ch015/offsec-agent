'use strict';

/**
 * 소스 트리 리더 — cite-check(#3)/poc-gate(#4)를 실제 엔게이지먼트 소스 루트에 바인딩한다.
 * 결정론 게이트가 프로덕션 파이프라인(report-gate)에서 "인용/산출물의 실재성"을 검증할 때
 * 쓰는 공용 파일 백엔드.
 *
 * 담는 것:
 *  - readFile(rel)   : 루트 하위로 경로 봉쇄(path escape 차단) 후 파일 내용 | null.
 *  - resolve(cited)  : 트리 1회 인덱싱 → 축약/변형 인용 경로를 basename/suffix로 실제 상대경로에 매핑.
 *                      (FAT run#4 교훈: 검증자가 경로를 축약하면 정확-경로 매칭이 실재 guard도
 *                       false-downgrade → 경로 보강으로 그 아티팩트를 제거)
 *  - readArtifact(rel): poc 산출물 경로 읽기(readFile 별칭, 의미 구분용).
 *
 * fat-citecheck.js가 갖고 있던 makeReadFile/makeResolve를 lib로 이관(로드맵 #5). 동작 동일.
 * 결정론적. CLI: node lib/ch015/source-reader.js --self-test
 */
const fs = require('fs');
const path = require('path');

const SKIP_DIR = new Set(['.git', 'node_modules', 'vendor']);

// baseAbs 하위 전체 파일의 상대경로 목록(경로 보강 인덱스).
function indexTree(baseAbs) {
  const rels = [];
  const walk = (dir, depth) => {
    if (depth > 12) return;
    let ents = [];
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      if (SKIP_DIR.has(e.name)) continue;
      const fp = path.join(dir, e.name);
      if (e.isDirectory()) walk(fp, depth + 1);
      else rels.push(path.relative(baseAbs, fp));
    }
  };
  walk(baseAbs, 0);
  return rels;
}

// baseAbs 하위로 봉쇄된 절대경로 | null(탈출 시).
function containedPath(baseAbs, rel) {
  if (rel == null) return null;
  const abs = path.resolve(baseAbs, String(rel));
  if (abs !== baseAbs && !abs.startsWith(baseAbs + path.sep)) return null;
  return abs;
}

/**
 * sourceRoot에 바인딩된 리더 집합 생성.
 * sourceRoot 미제공(null/빈값) → null 반환(파일 백엔드 없음 → 게이트가 파일 검증을 스킵).
 * opts.indexer(주입 가능, 테스트용) → baseAbs로부터 상대경로 배열.
 */
function makeSourceReaders(sourceRoot, { indexer = indexTree } = {}) {
  if (!sourceRoot) return null;
  const baseAbs = path.resolve(sourceRoot);
  let rels = null; // 최초 resolve 호출 시 lazy 인덱싱

  const readFile = (rel) => {
    const abs = containedPath(baseAbs, rel);
    if (abs == null) return null;
    try { return fs.readFileSync(abs, 'utf8'); } catch { return null; }
  };

  const resolve = (cited) => {
    if (!cited) return [];
    if (rels == null) rels = indexer(baseAbs);
    const c = String(cited).replace(/^\.?\/+/, '');
    const bn = c.split('/').pop();
    // suffix 일치(경로 꼬리) 우선, 없으면 basename 일치. 모호하면 전부 반환(호출부가 순회).
    const suffix = rels.filter((r) => r === c || r.endsWith('/' + c));
    if (suffix.length) return suffix;
    return rels.filter((r) => r === bn || r.endsWith('/' + bn));
  };

  return { baseAbs, readFile, resolve, readArtifact: readFile };
}

function selfTest() {
  const os = require('os');
  let pass = 0, fail = 0;
  const ok = (l, c) => (c ? (pass++, console.log(`  ✅ ${l}`)) : (fail++, console.log(`  ❌ ${l}`)));

  // 임시 소스 트리 구성(헤르메틱).
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-srcrd-'));
  fs.mkdirSync(path.join(root, 'pkg', 'auth'), { recursive: true });
  fs.mkdirSync(path.join(root, '.git'), { recursive: true });
  fs.writeFileSync(path.join(root, 'pkg', 'auth', 'guard.go'), 'func isAdmin(r) bool { return check(r) }\n');
  fs.writeFileSync(path.join(root, '.git', 'secret'), 'should-not-be-indexed');

  try {
    const rd = makeSourceReaders(root);
    ok('sourceRoot 없으면 null', makeSourceReaders(null) === null && makeSourceReaders('') === null);
    ok('readFile: 실재 파일 내용', /isAdmin/.test(rd.readFile('pkg/auth/guard.go') || ''));
    ok('readFile: 없는 파일 → null', rd.readFile('pkg/auth/ghost.go') === null);
    ok('readFile: path escape(../) 봉쇄 → null', rd.readFile('../outside.txt') === null);
    ok('readFile: 절대경로 탈출 봉쇄 → null', rd.readFile('/etc/passwd') === null);
    ok('readArtifact = readFile 별칭', rd.readArtifact('pkg/auth/guard.go') === rd.readFile('pkg/auth/guard.go'));

    ok('resolve: 축약 경로 auth/guard.go → suffix 해소', rd.resolve('auth/guard.go').includes('pkg/auth/guard.go'));
    ok('resolve: basename guard.go 해소', rd.resolve('guard.go').includes('pkg/auth/guard.go'));
    ok('resolve: 선행 ./ 제거', rd.resolve('./guard.go').includes('pkg/auth/guard.go'));
    ok('resolve: 없는 파일 → 빈 배열', rd.resolve('nope.rs').length === 0);
    ok('resolve: .git은 인덱싱 제외', !rd.resolve('secret').includes('.git/secret'));

    // resolve로 축약경로 해소 후 guard-cite-check가 실재 확인 가능한지(end-to-end 계약)
    const { guardExistsInSource } = require('./refuter-cite-check.js');
    const res = guardExistsInSource({ file: 'auth/guard.go', line: 1, guard: 'isAdmin' }, rd.readFile, { resolve: rd.resolve });
    ok('cite-check 계약: 축약경로 해소 후 guard 실재 확인', res.exists === true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }

  console.log(`\n${fail === 0 ? '✅ ALL PASS' : `❌ ${fail} FAILED`} — ${pass}/${pass + fail}\n`);
  return fail === 0 ? 0 : 1;
}

if (require.main === module) {
  if (process.argv.includes('--self-test')) process.exit(selfTest());
  console.error('usage: node lib/ch015/source-reader.js --self-test');
  process.exit(2);
}

module.exports = { makeSourceReaders, indexTree, containedPath };
