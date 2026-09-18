'use strict';

/**
 * 커버리지 게이트 (대규모 스케일 전수 커버리지 강제). 결정론·순수(fs 없음 — 호출자가 데이터 주입).
 *
 * 문제(실측 2026-07-09, davinci ~392K LOC): large-scale flow가 src-tauri 백엔드(71K LOC)를 단일
 *   audit 유닛으로 처리(S4 필수분할 미적용) → 검증된 Critical 6건 중 5건 미탐. Large Scale Flow의
 *   분해/커버리지가 advisory라 강제되지 않음. 이 모듈은 세 가지를 결정론으로 검사해 위반 시 발행 차단한다.
 *
 * R1 checkDecomposition   : manifest 유닛 LOC > maxUnitLoc인데 이를 덮는 audit 유닛이 required(=ceil(loc/max))
 *                           미만이면 REQUIRE_SPLIT (S4 강제). 내부 모듈 경계 sub-unit 분해를 요구.
 * R2 checkCompleteness    : recon이 정의한 유닛 중 실행(산출물 커밋)이 없는 게 있으면 INCOMPLETE_FANOUT.
 * R3 checkCoverageRatio   : audit 유닛의 files_examined / files_in_scope < minRatio면 UNDER_COVERED.
 *
 * 참고: docs/coverage-at-scale-plan.md, S4(large-scale-flow.md/project-scanner.md).
 * CLI: node lib/ch015/coverage-gate.js --self-test
 */

const DEFAULTS = {
  maxUnitLoc: 40000,     // S4 "분할 필수" 임계
  minCoverageRatio: 0.7, // 유닛 스코프 파일 중 검사 비율 하한
};

function normPath(p) {
  return String(p || '').replace(/\\/g, '/').replace(/^\.?\/+/, '').replace(/\/+$/, '');
}

// audit 유닛 경로가 manifest 유닛(uid) 내부(같거나 하위)를 덮는가.
function auditCovers(auditPath, uid) {
  const a = normPath(auditPath);
  const u = normPath(uid);
  if (u === '' || u === '.') return true; // 루트 유닛은 모든 audit가 덮는 것으로 간주
  return a === u || a.startsWith(`${u}/`) || u.startsWith(`${a}/`);
}

// 보안관련 언어(취약점을 담을 수 있는 코드). 제외 정당화(R7)·scope 계산(R3′)에 사용.
// .jsx/.tsx/.js 포함 — React 컴포넌트도 XSS 표면(davinci-design-core jsx 오분류 제외가 HIGH 2 누락한 사례).
const SECURITY_RELEVANT_EXT = new Set([
  '.rs', '.go', '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.java', '.rb', '.php',
  '.sql', '.sh', '.bash', '.kt', '.swift', '.c', '.h', '.cc', '.cpp', '.cs', '.scala', '.ex', '.exs', '.pl', '.pm',
]);

function extOf(p) {
  const m = String(p || '').toLowerCase().match(/\.[a-z0-9]+$/);
  return m ? m[0] : '';
}

// unitPath 하위에 속하는 소스 파일들(relative posix).
function filesUnder(unitPath, sourceFiles) {
  const u = normPath(unitPath);
  return (sourceFiles || []).filter((f) => {
    const nf = normPath(f);
    if (u === '' || u === '.') return true;
    return nf === u || nf.startsWith(`${u}/`);
  });
}

// R3′: unitPath의 실제 스코프 파일 수(manifest 기준). 자기신고 scope를 대체해 표본화 은닉 차단.
function scopeCount(unitPath, sourceFiles) {
  return filesUnder(unitPath, sourceFiles).length;
}

// R7: unitPath 하위에 보안관련 언어 소스가 있는가.
function hasSecurityCode(unitPath, sourceFiles) {
  return filesUnder(unitPath, sourceFiles).some((f) => SECURITY_RELEVANT_EXT.has(extOf(f)));
}

function isExcluded(uid, excluded) {
  const u = normPath(uid);
  return (excluded || []).some((e) => {
    const x = normPath(e);
    return u === x || u.startsWith(`${x}/`);
  });
}

/**
 * R1. manifestUnits: [{id, loc}], auditUnitPaths: [path...].
 * 각 대형 유닛(loc>maxUnitLoc, 비제외)에 대해 이를 덮는 audit 유닛 수가 ceil(loc/max) 미만이면 위반.
 */
function checkDecomposition(manifestUnits, auditUnitPaths, opts = {}) {
  const maxUnitLoc = opts.maxUnitLoc ?? DEFAULTS.maxUnitLoc;
  const excluded = opts.excludedUnits || [];
  const violations = [];
  for (const u of manifestUnits || []) {
    const loc = Number(u.loc || 0);
    if (loc <= maxUnitLoc) continue;
    if (isExcluded(u.id, excluded)) continue;
    const covering = (auditUnitPaths || []).filter((p) => auditCovers(p, u.id));
    const required = Math.ceil(loc / maxUnitLoc);
    if (covering.length < required) {
      violations.push({
        code: 'REQUIRE_SPLIT',
        unit: u.id,
        loc,
        required_sub_units: required,
        actual_audit_units: covering.length,
        message: `유닛 '${u.id}'(${loc} LOC)는 ${maxUnitLoc} 초과 → 최소 ${required}개 sub-unit 분해 필요하나 audit 유닛 ${covering.length}개뿐. 내부 모듈 경계로 분할하라.`,
      });
    }
  }
  return violations;
}

/** R2. definedUnitIds vs executedUnitIds → 실행 안 된 정의 유닛(비제외) = 위반. */
function checkCompleteness(definedUnitIds, executedUnitIds, opts = {}) {
  const excluded = opts.excludedUnits || [];
  const executed = new Set((executedUnitIds || []).map(normPath));
  const violations = [];
  for (const d of definedUnitIds || []) {
    if (isExcluded(d, excluded)) continue;
    if (!executed.has(normPath(d))) {
      violations.push({
        code: 'INCOMPLETE_FANOUT',
        unit: d,
        message: `recon이 정의한 유닛 '${d}'에 VA 산출물이 없음(실행 누락). 실행하거나 명시 제외하라.`,
      });
    }
  }
  return violations;
}

/**
 * R3. auditUnits: [{id, files_in_scope, files_examined}]. 비율 < minRatio면 위반.
 * files_in_scope 0/미상이면 스킵(측정 불가 — 오차단 방지).
 */
function checkCoverageRatio(auditUnits, opts = {}) {
  const minRatio = opts.minCoverageRatio ?? DEFAULTS.minCoverageRatio;
  const excluded = opts.excludedUnits || [];
  const violations = [];
  for (const u of auditUnits || []) {
    if (isExcluded(u.id, excluded)) continue;
    const scope = Number(u.files_in_scope || 0);
    if (scope <= 0) continue;
    const examined = Number(u.files_examined || 0);
    const ratio = examined / scope;
    if (ratio < minRatio) {
      violations.push({
        code: 'UNDER_COVERED',
        unit: u.id,
        files_in_scope: scope,
        files_examined: examined,
        ratio: Number(ratio.toFixed(3)),
        min_ratio: minRatio,
        message: `유닛 '${u.id}' 커버리지 ${(ratio * 100).toFixed(0)}% (${examined}/${scope}) < ${(minRatio * 100).toFixed(0)}% 하한.`,
      });
    }
  }
  return violations;
}

/**
 * R7. 제외 유닛 정당화. excludedEntries: [{path, justification?}]. 제외 유닛에 보안관련 언어 소스가
 * 있는데 justification이 없으면 위반(코드를 무검증 제외 — davinci-design-core jsx 오분류 정면 수정).
 * 순수 asset(.json/.md/.css/이미지만) 제외는 justification 없이도 허용.
 */
function checkExclusionJustification(excludedEntries, sourceFiles, opts = {}) {
  // sourceFiles가 없으면(구버전 매니페스트) 검증 불가 → 스킵(오차단 방지).
  if (!sourceFiles || !sourceFiles.length) return [];
  const violations = [];
  for (const e of excludedEntries || []) {
    const p = normPath(e && e.path);
    if (!p) continue;
    const justified = e && typeof e.justification === 'string' && e.justification.trim().length > 0;
    if (justified) continue;
    if (hasSecurityCode(p, sourceFiles)) {
      const codeCount = filesUnder(p, sourceFiles).filter((f) => SECURITY_RELEVANT_EXT.has(extOf(f))).length;
      violations.push({
        code: 'EXCLUSION_UNJUSTIFIED',
        unit: p,
        security_code_files: codeCount,
        message: `제외 유닛 '${p}'에 보안관련 언어 소스 ${codeCount}개 존재 — justification 없이 제외 불가. 포함해 분석하거나 excluded_units에 justification을 명시하라(코드를 무검증 제외 방지).`,
      });
    }
  }
  return violations;
}

/**
 * R8. 교차파일 패턴 반복. sinkSignatures: [{pattern, classified_files:[...]}], matchesBySig: {pattern:[files]}.
 * 확인된 취약 패턴이 grep된 파일 중 classified_files에 없는 게 있으면 위반(미분류 인스턴스 — GD-01류:
 * billing.rs에서 확인한 유출 패턴이 account.rs에도 있는데 미분류). 파일-suffix 매칭으로 축약경로 허용.
 */
function checkSystemicRecurrence(sinkSignatures, matchesBySig, opts = {}) {
  const violations = [];
  const m = matchesBySig || {};
  for (const sig of sinkSignatures || []) {
    const pattern = String(sig && sig.pattern || '');
    if (!pattern) continue;
    const classified = (sig.classified_files || []).map(normPath);
    for (const f of (m[pattern] || []).map(normPath)) {
      const covered = classified.some((c) => f === c || f.endsWith(`/${c}`) || c.endsWith(`/${f}`));
      if (covered) continue;
      violations.push({
        code: 'SYSTEMIC_RECURRENCE',
        pattern,
        unit: f,
        message: `확인된 취약 패턴 '${pattern}'이 ${f}에도 존재하나 classified_files에 없음 — 미분류 인스턴스. 분류하거나 classified_files에 추가하라(동일 패턴 다중 위치 누락 방지).`,
      });
    }
  }
  return violations;
}

// R8 보조: 패턴들을 target root에서 grep해 {pattern: [relative files]} 반환(불순 — spawnSync grep).
// grep 부재/실패 시 빈 매치(스킵). node_modules/target/dist 등 제외.
function grepMatches(patterns, root) {
  const { spawnSync } = require('child_process');
  const excludes = ['node_modules', '.git', 'target', 'dist', 'build', 'vendor', '.next', 'coverage'];
  const exArgs = excludes.map((d) => `--exclude-dir=${d}`);
  const out = {};
  for (const pat of patterns || []) {
    out[pat] = [];
    try {
      // ★ root 내부에서(cwd=root) '.'를 grep한다. root를 인자로 주면 root basename이 --exclude-dir와
      //   충돌(예: 경로가 …/target)해 루트 전체가 제외되는 버그가 있다. cwd=root면 exclude-dir는 하위에만 적용.
      const r = spawnSync('grep', ['-rlE', ...exArgs, pat, '.'], { cwd: root, encoding: 'utf8', timeout: 20000 });
      if (r.status === 0 && r.stdout) {
        out[pat] = r.stdout.trim().split('\n').filter(Boolean).map((f) => normPath(f));
      }
    } catch { /* grep 없음/실패 → 스킵 */ }
  }
  return out;
}

/**
 * 종합. input: { manifestUnits, auditUnitPaths, definedUnitIds, executedUnitIds, auditUnits,
 *   excludedEntries, sourceFiles, sinkSignatures, matchesBySig, opts }.
 * 반환 { ok, violations:[...], summary }.
 */
function evaluateCoverage(input = {}) {
  const opts = input.opts || {};
  const violations = [
    ...checkDecomposition(input.manifestUnits, input.auditUnitPaths, opts),
    ...checkCompleteness(input.definedUnitIds, input.executedUnitIds, opts),
    ...checkCoverageRatio(input.auditUnits, opts),
    ...checkExclusionJustification(input.excludedEntries, input.sourceFiles, opts),
    ...checkSystemicRecurrence(input.sinkSignatures, input.matchesBySig, opts),
  ];
  const summary = {
    require_split: violations.filter((v) => v.code === 'REQUIRE_SPLIT').length,
    incomplete_fanout: violations.filter((v) => v.code === 'INCOMPLETE_FANOUT').length,
    under_covered: violations.filter((v) => v.code === 'UNDER_COVERED').length,
    exclusion_unjustified: violations.filter((v) => v.code === 'EXCLUSION_UNJUSTIFIED').length,
    systemic_recurrence: violations.filter((v) => v.code === 'SYSTEMIC_RECURRENCE').length,
  };
  return { ok: violations.length === 0, violations, summary };
}

// ── engagement 판독 (fs I/O는 여기에 국한) ───────────────────────────────────
// source_manifest.json(.units = 유닛별 LOC) + coverage_units.yaml(orchestrator가 방출한
// audit 유닛 매니페스트)를 읽어 evaluateCoverage를 구동한다.
// coverage_units.yaml 스키마:
//   excluded_units: [<uid/path>...]      # 의도적 deep-분석 제외(예: packages) — CISO 승인·보고서 공개
//   defined_units:  [<uid>...]           # recon이 정의한 유닛(R2 기준)
//   audit_units:                          # 실제 실행된 audit 유닛(R1 경로·R2 실행·R3 커버리지)
//     - { id, path, files_in_scope, files_examined }
function evaluateEngagement(engagementDir, opts = {}) {
  const fs = require('fs');
  const path = require('path');
  const yaml = require('js-yaml');
  const readJson = (p) => { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return null; } };
  const readYaml = (p) => { try { return yaml.load(fs.readFileSync(p, 'utf8')); } catch { return null; } };

  const manifest = readJson(path.join(engagementDir, 'source_manifest.json'));
  const cov = readYaml(path.join(engagementDir, 'coverage_units.yaml'));
  if (!manifest || !Array.isArray(manifest.units)) {
    return { ok: false, violations: [{ code: 'COVERAGE_DATA_MISSING', message: 'source_manifest.json에 units 없음 — 유닛별 LOC 산출 실패(구버전 매니페스트?).' }], summary: {}, dataMissing: true };
  }
  if (!cov || !Array.isArray(cov.audit_units)) {
    return { ok: false, violations: [{ code: 'COVERAGE_DATA_MISSING', message: 'coverage_units.yaml 부재/무효 — large-scale flow가 audit 유닛 매니페스트를 방출해야 커버리지 게이트가 검증 가능.' }], summary: {}, dataMissing: true };
  }
  const sourceFiles = Array.isArray(manifest.source_files) ? manifest.source_files : [];
  const auditUnits = cov.audit_units.map((u) => {
    const p = String(u.path || u.id || '');
    // R3′: scope는 manifest 실제 파일수에서 계산(자기신고 무시 — 표본화가 분모를 줄여 은닉하는 것 차단).
    //      manifest에 source_files 없으면(구버전) 자기신고로 폴백.
    const scope = sourceFiles.length ? scopeCount(p, sourceFiles) : Number(u.files_in_scope || 0);
    return {
      id: String(u.id || u.path || ''),
      path: p,
      files_in_scope: scope,
      files_examined: Number(u.files_examined || 0),
    };
  });
  // excluded_units: string | {path|id, justification} 혼용 허용.
  const excludedEntries = (Array.isArray(cov.excluded_units) ? cov.excluded_units : []).map((e) =>
    (typeof e === 'string' ? { path: e } : { path: String(e.path || e.id || ''), justification: e.justification })
  );
  // R8: sink_signatures가 있으면 target에서 grep해 미분류 인스턴스 검사(target 실재 시에만 — 오차단 방지).
  const sinkSignatures = Array.isArray(cov.sink_signatures) ? cov.sink_signatures : [];
  let matchesBySig = {};
  if (sinkSignatures.length && manifest.target_realpath && fs.existsSync(manifest.target_realpath)) {
    matchesBySig = grepMatches(sinkSignatures.map((s) => String(s.pattern || '')).filter(Boolean), manifest.target_realpath);
  }
  return evaluateCoverage({
    manifestUnits: manifest.units.map((u) => ({ id: u.id, loc: Number(u.loc || 0) })),
    auditUnitPaths: auditUnits.map((u) => u.path),
    definedUnitIds: Array.isArray(cov.defined_units) ? cov.defined_units.map(String) : auditUnits.map((u) => u.id),
    executedUnitIds: auditUnits.map((u) => u.id),
    auditUnits,
    excludedEntries,
    sourceFiles,
    sinkSignatures,
    matchesBySig,
    opts: {
      maxUnitLoc: opts.maxUnitLoc ?? cov.max_unit_loc ?? DEFAULTS.maxUnitLoc,
      minCoverageRatio: opts.minCoverageRatio ?? cov.min_coverage_ratio ?? DEFAULTS.minCoverageRatio,
      excludedUnits: opts.excludedUnits || excludedEntries.map((e) => e.path),
    },
  });
}

// ── self-test ──────────────────────────────────────────────────────────────
function selfTest() {
  let pass = 0, fail = 0;
  const ok = (l, c) => (c ? (pass++, console.log(`  ✅ ${l}`)) : (fail++, console.log(`  ❌ ${l}`)));

  // R1: 71K LOC 유닛 1개 audit → required 2, 위반
  const d1 = checkDecomposition([{ id: 'src-tauri', loc: 71345 }], ['src-tauri'], { maxUnitLoc: 40000 });
  ok('R1 대형유닛 미분할 → REQUIRE_SPLIT', d1.length === 1 && d1[0].code === 'REQUIRE_SPLIT' && d1[0].required_sub_units === 2);

  // R1: sub-unit 2개로 분할하면 통과
  const d2 = checkDecomposition([{ id: 'src-tauri', loc: 71345 }], ['src-tauri/commands', 'src-tauri/cc'], { maxUnitLoc: 40000 });
  ok('R1 sub-unit 2개 분할 → 통과', d2.length === 0);

  // R1: 임계 이하는 무위반
  ok('R1 임계 이하 무위반', checkDecomposition([{ id: 'x', loc: 10000 }], ['x'], { maxUnitLoc: 40000 }).length === 0);

  // R1: 제외 유닛은 스킵(packages)
  ok('R1 제외 유닛 스킵', checkDecomposition([{ id: 'packages/design', loc: 107755 }], [], { maxUnitLoc: 40000, excludedUnits: ['packages/design'] }).length === 0);

  // R1: 155K 루트 유닛 → required 4 (ceil(155344/40000)=4), audit 1개면 위반
  const d3 = checkDecomposition([{ id: '.', loc: 155344 }], ['src'], { maxUnitLoc: 40000 });
  ok('R1 루트 유닛 required=ceil', d3.length === 1 && d3[0].required_sub_units === 4);

  // R2: 정의 U1-U4, 실행 U1-U3 → U4 누락
  const c1 = checkCompleteness(['U1', 'U2', 'U3', 'U4'], ['U1', 'U2', 'U3']);
  ok('R2 미실행 정의유닛 → INCOMPLETE_FANOUT', c1.length === 1 && c1[0].unit === 'U4');

  // R2: 제외 유닛은 누락이어도 무위반
  ok('R2 제외 유닛 누락 허용', checkCompleteness(['U1', 'U6'], ['U1'], { excludedUnits: ['U6'] }).length === 0);

  // R3: 20/100 = 20% < 70% → UNDER_COVERED
  const r1 = checkCoverageRatio([{ id: 'src-tauri', files_in_scope: 100, files_examined: 20 }], { minCoverageRatio: 0.7 });
  ok('R3 저커버리지 → UNDER_COVERED', r1.length === 1 && r1[0].code === 'UNDER_COVERED' && r1[0].ratio === 0.2);

  // R3: 80/100 통과
  ok('R3 충분 커버리지 통과', checkCoverageRatio([{ id: 'x', files_in_scope: 100, files_examined: 80 }], { minCoverageRatio: 0.7 }).length === 0);

  // R3: scope 0이면 스킵(오차단 방지)
  ok('R3 scope 미상 스킵', checkCoverageRatio([{ id: 'x', files_in_scope: 0, files_examined: 0 }]).length === 0);

  // 종합: davinci 실측 형태 재현 → 위반 다수, ok=false
  const ev = evaluateCoverage({
    manifestUnits: [{ id: 'src-tauri', loc: 71345 }, { id: '.', loc: 155344 }],
    auditUnitPaths: ['src-tauri', 'src', 'account-pool-server'],
    definedUnitIds: ['src-tauri', 'src', 'account-pool-server', 'supabase/migrations', 'scripts'],
    executedUnitIds: ['src-tauri', 'src', 'account-pool-server'],
    auditUnits: [{ id: 'src-tauri', files_in_scope: 210, files_examined: 30 }],
    opts: { maxUnitLoc: 40000, minCoverageRatio: 0.7, excludedUnits: ['packages'] },
  });
  ok('종합: davinci 형태 → ok=false', ev.ok === false);
  ok('종합: REQUIRE_SPLIT 2건(src-tauri,.)', ev.summary.require_split === 2);
  ok('종합: INCOMPLETE_FANOUT 2건(supabase,scripts)', ev.summary.incomplete_fanout === 2);
  ok('종합: UNDER_COVERED 1건(src-tauri 14%)', ev.summary.under_covered === 1);

  // R3′: scope를 manifest에서 계산 → 표본화(examined≪실제 scope) 포착
  ok('R3′ scopeCount manifest 기준', scopeCount('src-tauri', ['src-tauri/a.rs', 'src-tauri/b.rs', 'src/x.ts']) === 2);
  const r3prime = checkCoverageRatio([{ id: 'src-tauri', files_in_scope: 428, files_examined: 40 }], { minCoverageRatio: 0.7 });
  ok('R3′ 표본화(40/428) → UNDER_COVERED', r3prime.length === 1 && r3prime[0].code === 'UNDER_COVERED');

  // R7: 제외 유닛에 보안관련 코드 있고 justification 없음 → 위반 (design-core jsx 오분류)
  const sf = ['packages/design-core/src/Button.jsx', 'packages/design-core/README.md'];
  ok('R7 hasSecurityCode(jsx)', hasSecurityCode('packages/design-core', sf) === true);
  const ex1 = checkExclusionJustification([{ path: 'packages/design-core' }], sf);
  ok('R7 코드 제외 무justification → EXCLUSION_UNJUSTIFIED', ex1.length === 1 && ex1[0].code === 'EXCLUSION_UNJUSTIFIED');
  // justification 있으면 통과
  ok('R7 justification 있으면 통과', checkExclusionJustification([{ path: 'packages/design-core', justification: 'reviewed: pure tokens' }], sf).length === 0);
  // 순수 asset(코드 없음) 제외는 무justification도 통과
  ok('R7 순수 asset 제외 허용', checkExclusionJustification([{ path: 'assets' }], ['assets/logo.svg', 'assets/style.css']).length === 0);
  // sourceFiles 없으면 스킵(오차단 방지)
  ok('R7 sourceFiles 없으면 스킵', checkExclusionJustification([{ path: 'x' }], []).length === 0);

  // R8: 확인된 패턴이 미분류 파일에도 존재 → SYSTEMIC_RECURRENCE
  const rec1 = checkSystemicRecurrence(
    [{ pattern: 'pool_server_url', classified_files: ['commands/billing.rs'] }],
    { pool_server_url: ['commands/billing.rs', 'commands/account.rs'] }
  );
  ok('R8 미분류 인스턴스 → SYSTEMIC_RECURRENCE', rec1.length === 1 && rec1[0].code === 'SYSTEMIC_RECURRENCE' && rec1[0].unit === 'commands/account.rs');
  // 모든 인스턴스 분류 → 통과
  ok('R8 전 인스턴스 분류 → 통과', checkSystemicRecurrence(
    [{ pattern: 'p', classified_files: ['a.rs', 'b.rs'] }], { p: ['a.rs', 'b.rs'] }
  ).length === 0);
  // suffix 매칭(축약경로) 허용
  ok('R8 suffix 매칭 허용', checkSystemicRecurrence(
    [{ pattern: 'p', classified_files: ['account.rs'] }], { p: ['src/commands/account.rs'] }
  ).length === 0);
  // 매치 없으면 무위반
  ok('R8 매치 없음 → 무위반', checkSystemicRecurrence([{ pattern: 'p', classified_files: [] }], {}).length === 0);

  // 완전 커버 케이스 → ok=true
  const clean = evaluateCoverage({
    manifestUnits: [{ id: 'a', loc: 10000 }],
    auditUnitPaths: ['a'],
    definedUnitIds: ['a'],
    executedUnitIds: ['a'],
    auditUnits: [{ id: 'a', files_in_scope: 10, files_examined: 10 }],
  });
  ok('종합: 완전 커버 → ok=true', clean.ok === true && clean.violations.length === 0);

  console.log(`\n${fail === 0 ? '✅ ALL PASS' : `❌ ${fail} FAILED`} — ${pass}/${pass + fail}\n`);
  return fail === 0 ? 0 : 1;
}

if (require.main === module) {
  const argv = process.argv.slice(2);
  if (argv.includes('--self-test')) process.exit(selfTest());
  const i = argv.indexOf('--engagement');
  if (i >= 0 && argv[i + 1]) {
    const res = evaluateEngagement(argv[i + 1]);
    console.log(JSON.stringify(res, null, 2));
    process.exit(res.ok ? 0 : 1);
  }
  console.error('usage: node lib/ch015/coverage-gate.js (--self-test | --engagement <dir>)');
  process.exit(2);
}

module.exports = {
  DEFAULTS,
  SECURITY_RELEVANT_EXT,
  auditCovers,
  isExcluded,
  filesUnder,
  scopeCount,
  hasSecurityCode,
  checkDecomposition,
  checkCompleteness,
  checkCoverageRatio,
  checkExclusionJustification,
  checkSystemicRecurrence,
  grepMatches,
  evaluateCoverage,
  evaluateEngagement,
};
