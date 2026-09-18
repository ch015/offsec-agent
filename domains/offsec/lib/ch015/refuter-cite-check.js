'use strict';

/**
 * Refuter cite-check — 반증(counter-evidence) 인용의 소스 실재성 결정론 게이트. (로드맵 #3)
 *
 * 문제: 검증자가 Finding을 FALSE_POSITIVE로 기각하며 "auth.go:42의 guard가 막는다"류 counter-evidence를
 *       댈 때, 그 guard가 실제 소스에 없으면(할루시네이션) 실취약점이 잘못 기각된다. 기존
 *       candidate-ledger는 counter_evidence "텍스트 존재"만 확인(:281) — 실재성은 미검증.
 *
 * 규율(T3MP3ST refute-finding.mjs guardExistsInSource/applyCiteCheck 이식):
 *   FALSE_POSITIVE가 "소스 코드 guard"를 근거로 들면 → 그 인용(file:line + guard 토큰)이 소스에 실재해야 유효.
 *   실재하지 않으면 REFUTED(FALSE_POSITIVE) → DISPUTED 강등(= 사람이 다시 봐야 함, 자동 기각 불가).
 *
 * 결정론적(LLM 불필요). 토글 가능 → FAT가 ON/OFF ablation으로 marginal 기여 측정.
 *
 * CLI: node lib/ch015/refuter-cite-check.js --self-test
 */

// counter_evidence(문자열 또는 객체)에서 소스 인용 추출.
const LOC_RE = /([A-Za-z0-9_./-]+\.[A-Za-z0-9]+):(\d+)/;              // file.ext:NNN
const LOC_RE_G = /([A-Za-z0-9_./-]+\.[A-Za-z0-9]+):(\d+)/g;          // 다중 파일:라인
const GUARD_QUOTE_RE = /[`"']([^`"']{3,})[`"']/;                     // 따옴표/백틱 안의 코드 스니펫(대표 1개)
const GUARD_CUE_RE = /\b(guard|check|validate[ds]?|sanitiz|escap|filter|blocks?|prevents?|allowlist|denylist|whitelist|mitigat)/i;

// 코드 식별자다운 "특징 토큰"만 추출(영어 단어 배제). 인용 표현 편차에 강건한 매칭용.
//  채택: _포함 / camelCase / CONST_CASE / dotted(a.b) / 텍스트에서 foo( 또는 foo= 로 등장.
const IDENT_RE = /[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*/g;
function extractTokens(text) {
  if (!text) return [];
  const toks = new Set();
  const raw = String(text);
  for (const m of raw.match(IDENT_RE) || []) {
    if (m.length < 4) continue;
    if (/\.(go|py|js|ts|jsx|tsx|php|java|rb|rs|c|cc|cpp|h|hpp|vue|json|ya?ml|md|txt|rst)$/i.test(m)) continue; // 파일명 배제
    const codeish = m.includes('_') || m.includes('.') || /[a-z][A-Z]/.test(m)
      || /^[A-Z][A-Z0-9]{2,}$/.test(m)
      || new RegExp(`${m.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*[(=]`).test(raw);
    if (codeish) toks.add(m);
  }
  return [...toks];
}

function textOf(counterEvidence) {
  if (counterEvidence == null) return '';
  if (typeof counterEvidence === 'string') return counterEvidence;
  if (Array.isArray(counterEvidence)) return counterEvidence.map(textOf).join('\n');
  // 객체: location/guard/snippet/description/text 필드 우선
  const parts = [];
  for (const k of ['location', 'file', 'guard', 'snippet', 'code', 'description', 'text', 'reason', 'detail']) {
    if (counterEvidence[k] != null) parts.push(typeof counterEvidence[k] === 'string' ? counterEvidence[k] : JSON.stringify(counterEvidence[k]));
  }
  return parts.length ? parts.join('\n') : JSON.stringify(counterEvidence);
}

/**
 * counter_evidence에서 { file, line, guard, claimsSourceGuard } 추출.
 * claimsSourceGuard=false면 (파일 인용도, guard 단서도 없음) 코드-guard 반증이 아님 → cite-check 대상 아님.
 */
function parseCitation(counterEvidence) {
  const t = textOf(counterEvidence);
  const files = [];
  let m;
  LOC_RE_G.lastIndex = 0;
  while ((m = LOC_RE_G.exec(t)) !== null) files.push({ file: m[1], line: parseInt(m[2], 10) });
  const quoted = t.match(GUARD_QUOTE_RE);
  const hasCue = GUARD_CUE_RE.test(t);
  const file = files.length ? files[0].file : null;
  const line = files.length ? files[0].line : null;
  const guard = quoted ? quoted[1].trim() : null;
  // 특징 토큰: guard 스니펫 + 전체 텍스트에서. 인용 표현이 달라도 실제 식별자만 잡음.
  const tokens = [...new Set([...extractTokens(guard || ''), ...extractTokens(t)])];
  // 코드-레벨 guard 주장: 파일인용이 있거나(guard 단서+스니펫) 또는 특징 토큰이 있으면.
  const claimsSourceGuard = Boolean(file) || Boolean(guard && hasCue);
  return { file, line, files, guard, tokens, hasCue, claimsSourceGuard, text: t };
}

/**
 * 인용 guard가 소스에 실재하는가.
 * readFile(relPath) → 파일 내용 문자열 | null(없음). tol: file:line 근방 허용 라인 폭.
 * 반환 { exists, reason }.
 *  - 파일 없음 → exists:false (인용 파일이 소스에 없음)
 *  - guard 스니펫 有: 파일 내(line 있으면 ±tol 근방 우선, 없으면 전체)에서 스니펫 발견해야 exists:true
 *  - guard 스니펫 無, line 有: 해당 라인이 실재하고 비어있지 않으면 exists:true(약한 통과)
 *  - guard 스니펫 無, line 無 → exists:false (검증할 앵커 없음)
 */
function guardExistsInSource(citation, readFile, { tol = 10, resolve } = {}) {
  const files = (citation.files && citation.files.length)
    ? citation.files
    : (citation.file ? [{ file: citation.file, line: citation.line }] : []);
  if (!files.length) return { exists: false, reason: 'no_file_citation' };

  const tokens = (citation.tokens && citation.tokens.length)
    ? citation.tokens
    : extractTokens(citation.guard || '');

  // 인용 파일들을 읽는다. 정확 경로 실패 시 resolve(축약/변형 경로→실제 경로 후보)로 재시도.
  //  resolve(citedPath) → 실제 상대경로 문자열 | 문자열배열 | null. 미제공이면 정확 경로만.
  const tryRead = (p) => { try { return readFile(p); } catch { return null; } };
  const loaded = files.map((f) => {
    let content = tryRead(f.file);
    if (content == null && typeof resolve === 'function') {
      const alts = [].concat(resolve(f.file) || []);
      for (const alt of alts) { content = tryRead(alt); if (content != null) break; }
    }
    return { ...f, content };
  });
  const existing = loaded.filter((f) => f.content != null);
  if (!existing.length) return { exists: false, reason: 'file_not_found' };

  const norm = (s) => s.replace(/\s+/g, ' ').toLowerCase();
  if (tokens.length) {
    // 특징 토큰이 인용 파일 중 하나에 실재하면 통과. 라인 있으면 근방 우선.
    let anyInFile = false;
    for (const f of existing) {
      const lines = f.content.split(/\r?\n/);
      const contentNorm = norm(f.content);
      for (const tok of tokens) {
        const t = norm(tok);
        if (!contentNorm.includes(t)) continue;
        anyInFile = true;
        if (Number.isFinite(f.line)) {
          const lo = Math.max(0, f.line - 1 - tol), hi = Math.min(lines.length, f.line - 1 + tol + 1);
          if (norm(lines.slice(lo, hi).join(' ')).includes(t)) return { exists: true, reason: 'guard_near_line' };
        }
      }
    }
    if (anyInFile) return { exists: true, reason: 'guard_in_file' };
    return { exists: false, reason: 'guard_not_in_source' };
  }

  // 특징 토큰 없음 — line 앵커만(약한 통과).
  for (const f of existing) {
    if (!Number.isFinite(f.line)) continue;
    const src = f.content.split(/\r?\n/)[f.line - 1];
    if (src != null && src.trim().length > 0) return { exists: true, reason: 'line_present_weak' };
  }
  return { exists: false, reason: 'line_empty_or_missing' };
}

const REFUTED_STATUSES = new Set(['FALSE_POSITIVE']);

/**
 * 후보 하나에 cite-check 적용.
 * opts.readFile(relPath)→content|null, tol.
 * 반환 { applicable, passed, downgradedTo, citeCheck } — citeCheck는 후보에 병합할 감사 필드.
 * 강등: 인용 미실재면 FALSE_POSITIVE → DISPUTED (자동 기각 취소, 사람 판정 필요).
 */
function applyCiteCheck(candidate, { readFile, tol = 10, resolve, getStatus, getCounterEvidence } = {}) {
  const status = (getStatus ? getStatus(candidate) : candidate.status) || '';
  if (!REFUTED_STATUSES.has(String(status).toUpperCase())) return { applicable: false };
  const ce = getCounterEvidence
    ? getCounterEvidence(candidate)
    : (candidate.counter_evidence ?? candidate.final_mapping?.counter_evidence);
  const citation = parseCitation(ce);
  if (!citation.claimsSourceGuard) {
    // 코드-guard 반증이 아님(스코프/논리 기반). cite-check 비대상 — 통과시키되 표시.
    return { applicable: false, note: 'not_a_source_guard_refutation' };
  }
  const res = guardExistsInSource(citation, readFile, { tol, resolve });
  const citeCheck = {
    checked: true,
    passed: res.exists,
    reason: res.reason,
    citation: { file: citation.file, line: citation.line, guard: citation.guard },
  };
  if (res.exists) return { applicable: true, passed: true, citeCheck };
  return { applicable: true, passed: false, downgradedTo: 'DISPUTED', citeCheck };
}

/**
 * 후보 배열 전체에 cite-check. 강등 대상은 status를 DISPUTED로 바꾼 새 후보를 반환(불변).
 * 반환 { candidates, summary: { checked, passed, downgraded } }.
 */
function applyCiteChecks(candidates, opts = {}) {
  let checked = 0, passed = 0, downgraded = 0;
  const out = (candidates || []).map((c) => {
    const r = applyCiteCheck(c, opts);
    if (!r.applicable) return c;
    checked++;
    if (r.passed) { passed++; return { ...c, cite_check: r.citeCheck }; }
    downgraded++;
    return {
      ...c,
      status: 'DISPUTED',
      cite_check: r.citeCheck,
      cite_check_downgrade: `FALSE_POSITIVE→DISPUTED: 반증 인용 미실재(${r.citeCheck.reason})`,
    };
  });
  return { candidates: out, summary: { checked, passed, downgraded } };
}

function selfTest() {
  let pass = 0, fail = 0;
  const ok = (l, c) => (c ? (pass++, console.log(`  ✅ ${l}`)) : (fail++, console.log(`  ❌ ${l}`)));

  const SRC = {
    'auth.go': 'line1\nline2\nfunc check() {\n  if !isAdmin(r) { return err } // guard\n}\nline6',
    'proxy.go': 'a\nb\nc\nd\ne\nf\ng\nh\n',
  };
  const readFile = (p) => (p in SRC ? SRC[p] : null);

  // parseCitation
  ok('parseCitation file:line 추출', (() => { const c = parseCitation('guard at auth.go:4 blocks it'); return c.file === 'auth.go' && c.line === 4; })());
  ok('parseCitation guard 스니펫 추출', (() => { const c = parseCitation('the `isAdmin(r)` check prevents this'); return c.guard === 'isAdmin(r)' && c.claimsSourceGuard; })());
  ok('parseCitation 순수 논리(코드 아님) → 비대상', parseCitation('this is not reachable in practice, low risk').claimsSourceGuard === false);

  // guardExistsInSource
  ok('guard 근방 실재 → exists', guardExistsInSource({ file: 'auth.go', line: 4, guard: 'isAdmin(r)' }, readFile).exists === true);
  ok('guard 파일 어디에도 없음 → false', guardExistsInSource({ file: 'auth.go', line: 4, guard: 'sanitizeInput(x)' }, readFile).exists === false);
  ok('인용 파일 자체가 없음 → false', guardExistsInSource({ file: 'ghost.go', line: 1, guard: 'x' }, readFile).exists === false);
  ok('line만(guard무) 실재 라인 → weak pass', guardExistsInSource({ file: 'auth.go', line: 3, guard: null }, readFile).exists === true);
  ok('line만 빈 범위 넘어감 → false', guardExistsInSource({ file: 'proxy.go', line: 99, guard: null }, readFile).exists === false);

  // resolve: 축약/변형 경로도 실제 경로로 해소해 토큰 확인(경로 아티팩트 false-downgrade 방지)
  const resolve = (p) => {
    const base = p.split('/').pop();
    return Object.keys(SRC).filter((k) => k === base || k.endsWith('/' + base) || k.endsWith(base));
  };
  ok('resolve: 축약경로 sub/auth.go → auth.go 해소 후 guard 발견',
    guardExistsInSource({ file: 'sub/pkg/auth.go', line: 4, guard: 'isAdmin(r)' }, readFile, { resolve }).exists === true);
  ok('resolve 있어도 실제 없는 파일은 여전히 false',
    guardExistsInSource({ file: 'x/ghost.go', line: 1, guard: 'isAdmin' }, readFile, { resolve }).exists === false);
  ok('resolve 없으면 축약경로는 file_not_found',
    guardExistsInSource({ file: 'sub/pkg/auth.go', line: 4, guard: 'isAdmin(r)' }, readFile).reason === 'file_not_found');

  // applyCiteCheck: 실재 반증 → 통과(FP 유지)
  const real = applyCiteCheck({ status: 'FALSE_POSITIVE', counter_evidence: 'refuted: `isAdmin(r)` guard at auth.go:4 blocks unauthorized access' }, { readFile });
  ok('실재 guard 반증 → passed, FP 유지', real.applicable && real.passed === true && !real.downgradedTo);

  // 할루시네이션 반증 → 강등
  const halluc = applyCiteCheck({ status: 'FALSE_POSITIVE', counter_evidence: 'refuted: the `sanitizeInput(x)` guard at auth.go:4 neutralizes this' }, { readFile });
  ok('할루시네이션 guard → DISPUTED 강등', halluc.applicable && halluc.passed === false && halluc.downgradedTo === 'DISPUTED');

  // 존재하지 않는 파일 인용 → 강등
  const ghost = applyCiteCheck({ status: 'FALSE_POSITIVE', counter_evidence: 'blocked by validate() in nonexistent.go:10' }, { readFile });
  ok('없는 파일 인용 → 강등', ghost.passed === false && ghost.downgradedTo === 'DISPUTED');

  // 스코프 기반 FP(코드 guard 아님) → 비대상(통과)
  const scope = applyCiteCheck({ status: 'FALSE_POSITIVE', exclusion_reason: 'test fixture, not production code' }, { readFile });
  ok('스코프 FP → cite-check 비대상', scope.applicable === false);

  // CONFIRMED은 대상 아님
  ok('CONFIRMED → 비대상', applyCiteCheck({ status: 'CONFIRMED' }, { readFile }).applicable === false);

  // applyCiteChecks 배열 집계 + 불변 강등
  const batch = applyCiteChecks([
    { id: 'a', status: 'FALSE_POSITIVE', counter_evidence: '`isAdmin(r)` at auth.go:4' },       // pass
    { id: 'b', status: 'FALSE_POSITIVE', counter_evidence: '`sanitizeInput(x)` at auth.go:4' },  // downgrade
    { id: 'c', status: 'CONFIRMED' },                                                            // skip
  ], { readFile });
  ok('applyCiteChecks summary checked=2/pass=1/down=1', batch.summary.checked === 2 && batch.summary.passed === 1 && batch.summary.downgraded === 1);
  ok('강등 후보 status=DISPUTED', batch.candidates.find((c) => c.id === 'b').status === 'DISPUTED');
  ok('통과 후보 원 status 유지', batch.candidates.find((c) => c.id === 'a').status === 'FALSE_POSITIVE');
  ok('CONFIRMED 후보 불변', batch.candidates.find((c) => c.id === 'c').cite_check === undefined);

  console.log(`\n${fail === 0 ? '✅ ALL PASS' : `❌ ${fail} FAILED`} — ${pass}/${pass + fail}\n`);
  return fail === 0 ? 0 : 1;
}

if (require.main === module) {
  if (process.argv.includes('--self-test')) process.exit(selfTest());
  console.error('usage: node lib/ch015/refuter-cite-check.js --self-test');
  process.exit(2);
}

module.exports = { parseCitation, guardExistsInSource, applyCiteCheck, applyCiteChecks, textOf };
