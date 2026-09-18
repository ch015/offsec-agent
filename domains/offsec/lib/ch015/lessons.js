'use strict';

/**
 * Lessons 자기개선 루프 — 결정론 코어 (로드맵 재개 우선순위 #1).
 *
 * 목적: 측정된 miss(IEB recall miss / precision 오류)에서 "일반화 가능한 탐지 교훈"을 증류해
 *       다음 VA 실행에 주입 → recall/precision 향상. 단, 코퍼스에 과적합(정답 암기)되면 측정이
 *       무의미해지므로 anti-fitting 가드(로드맵 #2)를 이 루프의 안전장치로 강제한다.
 *       외부 오라클(#1)+anti-fitting(#2)이 완비된 지금에서야 이 루프가 "안전"하다(HANDOFF).
 *
 * 역할 분담(자기참조 평가 방지):
 *   - LLM(오케스트레이터)  : miss를 보고 교훈 "텍스트"를 제안한다(heuristic/cue).
 *   - 이 lib(결정론)       : (a) anti-fitting 검증 — 코퍼스 식별자·구체 아티팩트를 담은 교훈은 거부,
 *                            (b) dedupe/lifecycle, (c) held-out 분할, (d) VA 주입용 렌더.
 *   - FAT(harness)         : 교훈 ON/OFF ablation으로 Δ를 held-out fold에서 실측(fat-lessons.js).
 *
 * #3 교훈 계승: 효과를 지어내지 않는다. 교훈은 held-out paired Δpass1의 신뢰구간이 0을 넘고
 *   취약·안전 표본 precision이 비열화되지 않을 때만 PROMOTED. 그 외에는 CANDIDATE/RETIRED.
 *
 * 저장 위치: 호출자가 경로를 준다(런타임 아티팩트). 기본 권장 = harness/eval/lessons/ledger.yaml
 *   (anti-fitting SCAN_ROOTS 밖 — 탐지 자산으로 오분류되지 않게 한다).
 *
 * 결정론적(Math.random·Date 미사용). CLI: node lib/ch015/lessons.js --self-test
 */

const STATES = new Set(['CANDIDATE', 'PROMOTED', 'RETIRED']);
const SCHEMA_VERSION = 1;

// --- 텍스트 정규화 / 서명 ---------------------------------------------------

function norm(s) {
  return String(s || '').replace(/\s+/g, ' ').trim().toLowerCase();
}

// kebab slug (id 생성/정규화용).
function slugify(s) {
  return String(s || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64) || 'lesson';
}

// 결정론 문자열 해시(파티션용, Math.random 대체). FNV-1a 32-bit.
function hash32(s) {
  let h = 0x811c9dc5;
  const str = String(s);
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
  }
  return h >>> 0;
}

// dedupe 서명: CWE 클래스 + cue/heuristic 핵심어. 표현이 달라도 같은 교훈이면 병합.
function lessonSignature(lesson) {
  const cwe = norm(lesson.cwe || '');
  const cue = norm(lesson.cue || '');
  const heur = norm(lesson.heuristic || '');
  return `${cwe}|${cue}|${heur}`;
}

// --- anti-fitting 검증 ------------------------------------------------------

// corpusIds: { ghsa:[], cve:[], repo:[], paths:[] } (배열/Set 모두 허용).
function collectCorpusIds(manifestObjects) {
  const ids = { ghsa: new Set(), cve: new Set(), repo: new Set(), paths: new Set() };
  for (const gt of manifestObjects || []) {
    if (!gt || typeof gt !== 'object') continue;
    if (gt.id) ids.ghsa.add(String(gt.id));
    if (gt.cve) ids.cve.add(String(gt.cve));
    if (gt.repo) ids.repo.add(String(gt.repo));
    for (const f of gt.vuln_files || []) if (f && String(f).includes('/')) ids.paths.add(String(f));
  }
  return { ghsa: [...ids.ghsa], cve: [...ids.cve], repo: [...ids.repo], paths: [...ids.paths] };
}

const GHSA_RE = /GHSA-[0-9a-z]{4}(?:-[0-9a-z]{4}){2}/i;
const CVE_RE = /CVE-\d{4}-\d{3,}/i;
// 슬래시 포함 + 코드 확장자 = 구체 파일경로(과적합 스멜).
const FILEPATH_RE = /[\w.-]+\/[\w./-]*\.(go|py|js|ts|jsx|tsx|php|java|rb|rs|c|cc|cpp|h|hpp|vue|sol|cs|kt|swift|scala)\b/i;
const LONG_QUOTE_RE = /[`"']([^`"']{61,})[`"']/; // 60자 초과 verbatim 코드 인용 = 암기 스멜

function lessonText(lesson) {
  return [lesson.heuristic, lesson.cue, lesson.origin, lesson.cwe].filter(Boolean).map(String).join('\n');
}

// 교훈이 코퍼스 식별자를 담는가 → [{kind, needle}].
function scanCorpusLeak(text, corpusIds) {
  const hits = [];
  const kinds = ['ghsa', 'cve', 'repo', 'paths'];
  for (const kind of kinds) {
    const needles = corpusIds && corpusIds[kind] ? [...corpusIds[kind]] : [];
    for (const needle of needles) {
      if (needle && text.includes(needle)) hits.push({ kind, needle });
    }
  }
  return hits;
}

/**
 * 교훈 하나의 anti-fitting/일반화 검증. 반환 { valid, violations:[{code,detail}] }.
 * 거부 사유:
 *   MISSING_FIELDS      — heuristic 또는 cue 부재(일반 탐지 지침이 아님).
 *   CORPUS_ID_LEAK      — 코퍼스 정답 식별자(GHSA/CVE/repo/vuln-path) 참조(순환 오염).
 *   SPECIFIC_ARTIFACT   — 구체 파일경로/GHSA/CVE 패턴 포함(일반 교훈이 아니라 특정 사건 암기).
 *   VERBATIM_CODE       — 60자 초과 코드 인용(대상 코드 암기 스멜).
 *   INVALID_STATE       — state 값 오류.
 */
function validateLesson(lesson, corpusIds = {}) {
  const violations = [];
  if (!lesson || typeof lesson !== 'object') {
    return { valid: false, violations: [{ code: 'MISSING_FIELDS', detail: 'lesson is not an object' }] };
  }
  if (!norm(lesson.heuristic) || !norm(lesson.cue)) {
    violations.push({ code: 'MISSING_FIELDS', detail: 'heuristic and cue are required (general detection guidance)' });
  }
  if (lesson.state != null && !STATES.has(String(lesson.state))) {
    violations.push({ code: 'INVALID_STATE', detail: `unknown state: ${lesson.state}` });
  }
  const text = lessonText(lesson);
  const leaks = scanCorpusLeak(text, corpusIds);
  for (const l of leaks) violations.push({ code: 'CORPUS_ID_LEAK', detail: `${l.kind}:${l.needle}` });
  if (GHSA_RE.test(text)) violations.push({ code: 'SPECIFIC_ARTIFACT', detail: 'contains GHSA id pattern' });
  if (CVE_RE.test(text)) violations.push({ code: 'SPECIFIC_ARTIFACT', detail: 'contains CVE id pattern' });
  const fp = text.match(FILEPATH_RE);
  if (fp) violations.push({ code: 'SPECIFIC_ARTIFACT', detail: `contains concrete file path: ${fp[0]}` });
  if (LONG_QUOTE_RE.test(text)) violations.push({ code: 'VERBATIM_CODE', detail: 'contains >60-char verbatim code quote' });
  return { valid: violations.length === 0, violations };
}

// --- 정규화 / 병합 / lifecycle ---------------------------------------------

function normalizeLesson(lesson) {
  const heuristic = String(lesson.heuristic || '').trim();
  const id = lesson.id ? slugify(lesson.id) : `L-${slugify(lesson.cwe || '')}-${(hash32(lessonSignature(lesson)) % 100000)}`;
  const out = {
    id,
    heuristic,
    cue: String(lesson.cue || '').trim(),
    cwe: lesson.cwe ? String(lesson.cwe).trim() : null,
    origin: lesson.origin ? String(lesson.origin).trim() : null,
    state: STATES.has(String(lesson.state)) ? String(lesson.state) : 'CANDIDATE',
    evidence: lesson.evidence || null,
    created_round: Number.isFinite(lesson.created_round) ? lesson.created_round : 0,
  };
  return out;
}

/**
 * 기존 ledger에 incoming 교훈들을 병합. 각각 anti-fitting 검증 → 통과분만 dedupe 후 편입.
 * 반환 { merged:[lesson], accepted:[lesson], rejected:[{lesson,violations}] }.
 */
function mergeLessons(existing, incoming, corpusIds = {}) {
  const merged = (existing || []).map(normalizeLesson);
  const bySig = new Map(merged.map((l) => [lessonSignature(l), l]));
  const accepted = [];
  const rejected = [];
  for (const raw of incoming || []) {
    const v = validateLesson(raw, corpusIds);
    if (!v.valid) { rejected.push({ lesson: raw, violations: v.violations }); continue; }
    const lesson = normalizeLesson(raw);
    const sig = lessonSignature(lesson);
    if (bySig.has(sig)) {
      // 이미 있는 교훈 — origin만 보강(중복 추가 안 함).
      const cur = bySig.get(sig);
      if (lesson.origin && cur.origin && !cur.origin.includes(lesson.origin)) {
        cur.origin = `${cur.origin}; ${lesson.origin}`;
      } else if (lesson.origin && !cur.origin) {
        cur.origin = lesson.origin;
      }
      continue;
    }
    bySig.set(sig, lesson);
    merged.push(lesson);
    accepted.push(lesson);
  }
  return { merged, accepted, rejected };
}

function validatePromotionEvidence(evidence) {
  const errors = [];
  if (!evidence || typeof evidence !== 'object') {
    return { valid: false, errors: ['evidence is required'] };
  }
  if (!Number.isFinite(evidence.delta_pass1) || evidence.delta_pass1 <= 0 || evidence.delta_pass1 > 1) {
    errors.push('delta_pass1 must be > 0 and <= 1');
  }
  if (evidence.held_out !== true) errors.push('held_out must be true');
  if (evidence.significant !== true) errors.push('significant must be true');
  if (!Number.isInteger(evidence.k) || evidence.k < 3) errors.push('k must be >= 3');
  if (!Number.isInteger(evidence.measured_n) || evidence.measured_n < 3) errors.push('measured_n must be >= 3');
  if (!Array.isArray(evidence.ci) || evidence.ci.length !== 2 ||
      !Number.isFinite(evidence.ci[0]) || !Number.isFinite(evidence.ci[1]) ||
      evidence.ci[0] <= 0 || evidence.ci[0] > evidence.ci[1] || evidence.ci[1] > 1) {
    errors.push('ci must be an ordered finite interval within (0, 1]');
  }
  if (!Number.isFinite(evidence.precision_delta) || evidence.precision_delta < 0 || evidence.precision_delta > 1) {
    errors.push('precision_delta must be finite and between 0 and 1');
  }
  if (!Number.isFinite(evidence.safe_precision_delta) || evidence.safe_precision_delta < 0 || evidence.safe_precision_delta > 1) {
    errors.push('safe_precision_delta must be finite and between 0 and 1');
  }
  return { valid: errors.length === 0, errors };
}

// PROMOTE: held-out paired improvement + precision non-regression evidence is mandatory.
function promote(lesson, evidence) {
  const l = normalizeLesson(lesson);
  const validation = validatePromotionEvidence(evidence);
  if (!validation.valid) {
    return {
      changed: false,
      reason: `promotion evidence invalid: ${validation.errors.join('; ')}`,
      lesson: { ...l, state: 'CANDIDATE' },
    };
  }
  return { changed: true, lesson: { ...l, state: 'PROMOTED', evidence } };
}

// RETIRE: 측정 결과 무효(Δ≤0)이거나 해가 됨 → 은퇴. 사유 필수.
function retire(lesson, reason, evidence = null) {
  const l = normalizeLesson(lesson);
  return { ...l, state: 'RETIRED', retire_reason: String(reason || 'unspecified'), evidence: evidence || l.evidence };
}

// --- held-out 분할 (일반화 검증: train에서 배운 교훈을 test fold에서 측정) --------------

// id의 결정론 해시로 fold 배정 → 재현 가능. seed로 분할 셔플 변주.
function assignFold(id, k, seed = 0) {
  if (!Number.isFinite(k) || k < 2) return 0;
  return hash32(`${seed}:${id}`) % k;
}

/**
 * corpus id 목록을 k개 fold로 결정론 분할. 반환 { folds:[[id]], trainTest(f)->{train,test} }.
 * trainTest(f): fold f를 test로, 나머지를 train으로.
 */
function partitionCorpus(ids, k = 2, seed = 0) {
  const folds = Array.from({ length: k }, () => []);
  for (const id of (ids || []).slice().sort()) folds[assignFold(id, k, seed)].push(id);
  const trainTest = (f) => ({
    test: folds[f] || [],
    train: folds.filter((_, i) => i !== f).flat(),
  });
  return { folds, trainTest };
}

// --- VA 주입용 선택 / 렌더 ---------------------------------------------------

const STATE_RANK = { PROMOTED: 0, CANDIDATE: 1, RETIRED: 2 };

// Production defaults to statistically validated PROMOTED lessons only.
// CANDIDATE inclusion is an explicit experimental-arm opt-in.
function selectActiveLessons(lessons, { maxCount = 12, includeCandidates = false } = {}) {
  const active = (lessons || [])
    .map(normalizeLesson)
    .filter((lesson) => validateLesson(lesson).valid)
    .filter((lesson) => {
      if (lesson.state === 'PROMOTED') return validatePromotionEvidence(lesson.evidence).valid;
      return includeCandidates && lesson.state === 'CANDIDATE';
    });
  active.sort((a, b) => {
    const r = (STATE_RANK[a.state] ?? 9) - (STATE_RANK[b.state] ?? 9);
    if (r !== 0) return r;
    const c = norm(a.cwe).localeCompare(norm(b.cwe));
    if (c !== 0) return c;
    return a.id.localeCompare(b.id);
  });
  return active.slice(0, maxCount);
}

// VA 에이전트 프롬프트에 주입할 교훈 블록(일반 지침만). 오케스트레이터가 VA subagent 프롬프트에 삽입.
function renderLessonsPrompt(lessons, opts = {}) {
  const active = selectActiveLessons(lessons, opts);
  if (!active.length) return '';
  const lines = [
    '## 누적 탐지 교훈 (과거 측정된 miss에서 증류 — 일반 휴리스틱)',
    '아래는 과거 진단에서 놓쳤던 결함 유형의 일반화된 탐지 단서다. 특정 코드/사건이 아니라',
    '"이런 형태를 보면 이런 결함을 의심하라"는 지침이다. 대상 코드에 해당 단서가 있으면 능동적으로 확인하라.',
    '',
  ];
  for (const l of active) {
    const tag = l.state === 'PROMOTED' ? '검증됨' : '시험중';
    const cwe = l.cwe ? ` [${l.cwe}]` : '';
    lines.push(`- (${tag})${cwe} ${l.heuristic}`);
    if (l.cue) lines.push(`    단서: ${l.cue}`);
  }
  return lines.join('\n');
}

// --- ledger I/O (YAML) ------------------------------------------------------

function emptyLedger() {
  return { schema_version: SCHEMA_VERSION, lessons: [] };
}

function loadLedger(filePath) {
  const fs = require('fs');
  const yaml = require('js-yaml');
  try {
    const doc = yaml.load(fs.readFileSync(filePath, 'utf8'));
    if (!doc || typeof doc !== 'object' || !Array.isArray(doc.lessons)) return emptyLedger();
    const lessons = [];
    const rejected = [];
    for (const raw of doc.lessons) {
      const validation = validateLesson(raw);
      if (!validation.valid) {
        rejected.push({ lesson: raw, violations: validation.violations });
        continue;
      }
      const lesson = normalizeLesson(raw);
      if (lesson.state === 'PROMOTED') {
        const promotion = validatePromotionEvidence(lesson.evidence);
        if (!promotion.valid) {
          lessons.push({ ...lesson, state: 'CANDIDATE', promotion_invalid: promotion.errors });
          continue;
        }
      }
      lessons.push(lesson);
    }
    return { schema_version: doc.schema_version || SCHEMA_VERSION, lessons, rejected };
  } catch {
    return emptyLedger();
  }
}

function saveLedger(filePath, ledger) {
  const fs = require('fs');
  const path = require('path');
  const yaml = require('js-yaml');
  const doc = {
    schema_version: SCHEMA_VERSION,
    lessons: (ledger.lessons || []).map(normalizeLesson),
  };
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, yaml.dump(doc), 'utf8');
  return filePath;
}

// --- self-test --------------------------------------------------------------

function selfTest() {
  let pass = 0, fail = 0;
  const ok = (l, c) => (c ? (pass++, console.log(`  ✅ ${l}`)) : (fail++, console.log(`  ❌ ${l}`)));

  const corpusIds = collectCorpusIds([
    { id: 'GHSA-aaaa-bbbb-cccc', cve: 'CVE-2026-99999', repo: 'acme/widget', vuln_files: ['src/deep/sink.go'] },
  ]);

  const good = {
    heuristic: 'user 입력으로 동적 생성한 정규식은 ReDoS 위험 — RegExp 생성자에 외부 입력이 흐르는지 본다',
    cue: 'new RegExp(변수) 또는 문자열 연결로 만든 패턴에 사용자 값 유입',
    cwe: 'CWE-1333',
    origin: 'IEB recall miss round 3',
  };
  ok('일반 교훈 → valid', validateLesson(good, corpusIds).valid === true);

  ok('GHSA 참조 → CORPUS_ID_LEAK',
    validateLesson({ ...good, origin: 'from GHSA-aaaa-bbbb-cccc' }, corpusIds)
      .violations.some((v) => v.code === 'CORPUS_ID_LEAK'));
  ok('repo slug 참조 → CORPUS_ID_LEAK',
    validateLesson({ ...good, heuristic: good.heuristic + ' (see acme/widget)' }, corpusIds)
      .violations.some((v) => v.code === 'CORPUS_ID_LEAK'));
  ok('vuln 경로 참조 → CORPUS_ID_LEAK',
    validateLesson({ ...good, cue: 'check src/deep/sink.go' }, corpusIds)
      .violations.some((v) => v.code === 'CORPUS_ID_LEAK'));
  ok('구체 파일경로 → SPECIFIC_ARTIFACT',
    validateLesson({ ...good, cue: 'look at internal/server/handler.go for the sink' }, corpusIds)
      .violations.some((v) => v.code === 'SPECIFIC_ARTIFACT'));
  ok('CVE 패턴 → SPECIFIC_ARTIFACT',
    validateLesson({ ...good, origin: 'CVE-2025-12345' }, corpusIds)
      .violations.some((v) => v.code === 'SPECIFIC_ARTIFACT' || v.code === 'CORPUS_ID_LEAK'));
  ok('60자 초과 verbatim 코드 → VERBATIM_CODE',
    validateLesson({ ...good, cue: 'exactly `' + 'a'.repeat(70) + '`' }, corpusIds)
      .violations.some((v) => v.code === 'VERBATIM_CODE'));
  ok('heuristic/cue 부재 → MISSING_FIELDS',
    validateLesson({ heuristic: '', cue: '' }, corpusIds).violations.some((v) => v.code === 'MISSING_FIELDS'));

  // merge + dedupe
  const m1 = mergeLessons([], [good, { ...good, origin: 'IEB recall miss round 5' }], corpusIds);
  ok('중복 교훈(같은 서명)은 1건으로 병합', m1.merged.length === 1);
  ok('병합 시 origin 보강', /round 3/.test(m1.merged[0].origin) && /round 5/.test(m1.merged[0].origin));
  const m2 = mergeLessons(m1.merged, [{ ...good, cue: 'check src/deep/sink.go' }], corpusIds);
  ok('오염 교훈은 rejected(편입 안 됨)', m2.rejected.length === 1 && m2.merged.length === 1);

  // lifecycle — #3 규율(측정 없이는 PROMOTE 불가)
  ok('Δ 근거 없으면 PROMOTE 거부', promote(good, null).changed === false);
  ok('Δ<=0이면 PROMOTE 거부', promote(good, { delta_pass1: 0 }).changed === false);
  const validPromotion = {
    delta_pass1: 0.15,
    measured_n: 10,
    k: 3,
    held_out: true,
    significant: true,
    ci: [0.02, 0.28],
    precision_delta: 0,
    safe_precision_delta: 0,
  };
  const pr = promote(good, validPromotion);
  ok('held-out+CI+precision 근거면 PROMOTED', pr.changed === true && pr.lesson.state === 'PROMOTED');
  ok('정답 1건+다수 FP precision 하락이면 PROMOTE 거부',
    promote(good, { ...validPromotion, precision_delta: -0.5 }).changed === false);
  ok('K<3이면 PROMOTE 거부', promote(good, { ...validPromotion, k: 2 }).changed === false);
  ok('뒤집힌 CI면 PROMOTE 거부', promote(good, { ...validPromotion, ci: [0.3, 0.1] }).changed === false);
  ok('범위를 벗어난 Δ면 PROMOTE 거부', promote(good, { ...validPromotion, delta_pass1: 1.1 }).changed === false);
  ok('retire → RETIRED + 사유', retire(good, 'Δ0 on held-out').state === 'RETIRED');

  // held-out 분할 결정론성
  const ids = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'];
  const p = partitionCorpus(ids, 2, 0);
  const p2 = partitionCorpus(ids, 2, 0);
  ok('partition 결정론적(동일 seed → 동일 분할)', JSON.stringify(p.folds) === JSON.stringify(p2.folds));
  ok('partition 전체 커버(중복 없음)', p.folds.flat().sort().join(',') === ids.join(','));
  const tt = p.trainTest(0);
  ok('trainTest: test∩train=∅', tt.test.every((x) => !tt.train.includes(x)) && tt.test.length + tt.train.length === ids.length);
  ok('seed 다르면 분할 달라질 수 있음(변주 존재)',
    JSON.stringify(partitionCorpus(ids, 2, 1).folds) !== JSON.stringify(p.folds) ||
    JSON.stringify(partitionCorpus(ids, 2, 7).folds) !== JSON.stringify(p.folds));

  // select + render
  const lessons = [
    { ...good, id: 'L-promoted', state: 'PROMOTED', evidence: validPromotion },
    { heuristic: 'SSRF: url 파라미터를 서버가 그대로 fetch하면 내부망 접근 위험', cue: 'http client가 요청 파라미터 URL을 직접 사용', cwe: 'CWE-918', state: 'CANDIDATE' },
    { heuristic: 'retired one', cue: 'x', cwe: 'CWE-1', state: 'RETIRED' },
  ];
  const active = selectActiveLessons(lessons);
  ok('production selection은 검증된 PROMOTED만', active.length === 1 && active[0].state === 'PROMOTED');
  const rendered = renderLessonsPrompt(lessons);
  ok('render: production에 검증됨만 포함', /검증됨/.test(rendered) && !/시험중/.test(rendered));
  ok('render: experimental opt-in에서만 CANDIDATE 포함', /시험중/.test(renderLessonsPrompt(lessons, { includeCandidates: true })));
  ok('render: RETIRED 미포함', !/retired one/.test(rendered));
  ok('render: 빈 목록 → 빈 문자열', renderLessonsPrompt([]) === '');
  ok('render 출력에 코퍼스 식별자 없음(주입 안전)', scanCorpusLeak(rendered, corpusIds).length === 0);

  // ledger I/O 왕복
  const os = require('os'); const fs = require('fs'); const path = require('path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ch015-lessons-'));
  try {
    const lp = path.join(dir, 'sub', 'ledger.yaml');
    saveLedger(lp, { lessons: m1.merged });
    const back = loadLedger(lp);
    ok('ledger 저장·로드 왕복', back.lessons.length === 1 && back.lessons[0].heuristic === good.heuristic);
    const invalidPromotedPath = path.join(dir, 'invalid-promoted.yaml');
    saveLedger(invalidPromotedPath, { lessons: [{ ...good, state: 'PROMOTED', evidence: { delta_pass1: 1 } }] });
    const invalidPromoted = loadLedger(invalidPromotedPath);
    ok('근거 불충분 PROMOTED는 load 시 CANDIDATE로 강등',
      invalidPromoted.lessons[0].state === 'CANDIDATE' && selectActiveLessons(invalidPromoted.lessons).length === 0);
    ok('없는 ledger 로드 → empty', loadLedger(path.join(dir, 'nope.yaml')).lessons.length === 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }

  console.log(`\n${fail === 0 ? '✅ ALL PASS' : `❌ ${fail} FAILED`} — ${pass}/${pass + fail}\n`);
  return fail === 0 ? 0 : 1;
}

// --- CLI --------------------------------------------------------------------

function main(argv) {
  if (argv.includes('--self-test')) return selfTest();
  console.error('usage: node lib/ch015/lessons.js --self-test');
  return 2;
}

if (require.main === module) process.exit(main(process.argv.slice(2)));

module.exports = {
  SCHEMA_VERSION,
  collectCorpusIds,
  validateLesson,
  lessonSignature,
  normalizeLesson,
  mergeLessons,
  promote,
  validatePromotionEvidence,
  retire,
  assignFold,
  partitionCorpus,
  selectActiveLessons,
  renderLessonsPrompt,
  loadLedger,
  saveLedger,
  emptyLedger,
};
