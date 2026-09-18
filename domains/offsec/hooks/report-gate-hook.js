#!/usr/bin/env node
/**
 * CH015 Report Gate — PreToolUse 배선
 *
 * 최종 보고서가 engagement 디렉터리에 "쓰여지기 직전" report-gate 검증을 실행해,
 * 분류 완결성 / equivalence review / pentest route coverage / ledger 정합성이
 * 깨진 보고서의 발행을 런타임에 차단한다.
 *
 * 기존엔 report-gate.js가 commands/report.md의 수동 CLI로만 존재해, LLM이 안 돌리면
 * 무효(fail-open by omission)였다. 본 훅이 그 게이트를 강제(enforce)한다.
 *
 * 활성화 조건 (모두 충족 시에만 동작 — 무관한 Write를 막지 않기 위함):
 *   - 환경변수 CH015_REPORT_GATE !== 'off'
 *   - tool ∈ {Write, Edit, MultiEdit}
 *   - file_path 가 보고서로 보이는 .md (이름에 report/result/summary 포함)
 *   - AGENT_ENGAGEMENT_DIR 가 설정되어 있고 대상이 그 디렉터리 내부에 있음
 *     (engagement 외부 경로는 reports/ 포함 게이트하지 않는다 — 최종 발행은
 *      프롬프트 측에서 engagement 경유로 작성하도록 유도하는 것으로 해결)
 *
 * 판정:
 *   - ledger/classification 산출물을 찾았고 게이트 errors 발생 → exit 2 (차단)
 *   - warnings 만 → stderr 출력 후 통과
 *   - 산출물을 못 찾음 → 기본 통과(경고). CH015_REPORT_GATE=strict 시 차단.
 *
 * 판정 (noArtifacts):
 *   - 최종 보고서로 강하게 추정되는 이름(FINAL_REPORT_RE)인데 산출물 미발견 → fail-closed(차단).
 *   - 그 외 약한 매칭은 경고+통과(strict 시 차단).
 *
 * 알려진 한계 (의도된 범위):
 *   - 본 훅은 Write/Edit/MultiEdit 도구만 게이트한다. `Bash`로 리다이렉트(`cat > report.md`,
 *     `tee`, `node -e fs.writeFileSync`)해 보고서를 쓰면 게이트를 우회한다. CH015 정상 플로우는
 *     보고서를 Write 도구로 작성하므로(스킬 지시) 1차 방어로 충분하다. 셸 리다이렉트 파싱은
 *     heredoc/변수 등으로 신뢰성이 낮아 의도적으로 구현하지 않는다(거짓 안심 방지).
 *
 * 수동 점검은 여전히 hooks/report-gate.js CLI 로 가능.
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { readStructured, validateReportGate } = require('./report-gate.js');
const { getCandidates } = require('../lib/ch015/candidate-ledger.js');
const { evaluateEngagement } = require('../lib/ch015/coverage-gate.js');
const { isHostWorkUnitEngagement, evaluateScopeAssurance } = require('../lib/ch015/scope-assurance-gate.js');

const REPORT_NAME_RE = /(report|result|summary|backlog)/i;
// 최종 발행 보고서로 강하게 추정되는 이름 — 산출물 미발견 시 fail-closed(차단) 대상.
// 08_dev_report 같은 컴포넌트 보고서/일반 result는 포함하지 않는다(과차단 방지).
const FINAL_REPORT_RE = /(security[-_]?report|va[-_]?report|pentest[-_]?report|redteam[-_]?report|executive[-_]?summary)/i;
const LEDGER_RE = /raw[_-]?findings[_-]?ledger.*\.(ya?ml)$/i;
const CLASSIFICATION_RE = /(convergence[_-]?classification|classification).*\.(ya?ml)$|(^|[_-])classification\.(ya?ml)$/i;
const PENTEST_PLAN_RE = /pentest[_-]?plan.*\.(ya?ml)$/i;

function readStdin() {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) return resolve('');
    let buf = '';
    const timeout = setTimeout(() => resolve(buf), 500);
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => (buf += c));
    process.stdin.on('end', () => { clearTimeout(timeout); resolve(buf); });
    process.stdin.on('error', () => { clearTimeout(timeout); resolve(buf); });
  });
}

function parsePayload(raw) {
  if (!raw || !raw.trim()) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

function isWithinDir(filePath, dir) {
  if (!filePath || !dir) return false;
  const fileAbs = path.resolve(filePath);
  const dirAbs = path.resolve(dir);
  return fileAbs === dirAbs || fileAbs.startsWith(dirAbs + path.sep);
}

function listFiles(dir) {
  try {
    return fs.readdirSync(dir).filter((f) => {
      try { return fs.statSync(path.join(dir, f)).isFile(); } catch { return false; }
    });
  } catch {
    return [];
  }
}

function pickLatest(dir, files) {
  // mtime 기준 최신 1개 (round suffix가 달라도 가장 최근 산출물을 채택)
  let best = null;
  let bestMtime = -1;
  for (const f of files) {
    try {
      const m = fs.statSync(path.join(dir, f)).mtimeMs;
      if (m > bestMtime) { bestMtime = m; best = f; }
    } catch { /* skip */ }
  }
  return best ? path.join(dir, best) : null;
}

function loadMergedLedger(dir, ledgerFiles) {
  const candidates = [];
  for (const f of ledgerFiles) {
    try {
      const parsed = readStructured(path.join(dir, f));
      candidates.push(...getCandidates(parsed));
    } catch { /* skip unreadable */ }
  }
  return candidates;
}

function runGate({ filePath, env, content = '' }) {
  const engagementDir = env.AGENT_ENGAGEMENT_DIR || '';
  if (!engagementDir || !fs.existsSync(engagementDir)) {
    return { activated: false };
  }
  // engagement 디렉터리 내부 쓰기만 게이트한다(무관한 외부 reports/ 경로 오활성 방지).
  if (!isWithinDir(filePath, engagementDir)) {
    return { activated: false };
  }
  const strongFinal = FINAL_REPORT_RE.test(path.basename(filePath));

  const files = listFiles(engagementDir);
  const ledgerFiles = files.filter((f) => LEDGER_RE.test(f));
  const classificationFile = pickLatest(engagementDir, files.filter((f) => CLASSIFICATION_RE.test(f)));
  const pentestPlanFile = pickLatest(engagementDir, files.filter((f) => PENTEST_PLAN_RE.test(f)));

  const ledgerCandidates = loadMergedLedger(engagementDir, ledgerFiles);
  const classification = classificationFile ? safeRead(classificationFile) : undefined;
  const pentestPlan = pentestPlanFile ? safeRead(pentestPlanFile) : undefined;
  // P1: source_manifest.json을 자동 로드해 provenance(브랜치+커밋)를 결정론적으로 강제한다.
  // 수동 CLI(--require-provenance)에만 의존하면 LLM이 안 돌릴 때 강제가 우회되므로,
  // 자동 훅이 최종 결과서(strongFinal) 쓰기 직전 직접 검증한다.
  const manifestPath = path.join(engagementDir, 'source_manifest.json');
  const manifest = fs.existsSync(manifestPath) ? safeRead(manifestPath) : undefined;

  if (ledgerCandidates.length === 0 && !classification) {
    return { activated: true, noArtifacts: true, strongFinal };
  }

  // 결정론 게이트 배선(#2): cite-check(#3)은 대상 소스가 실제 존재할 때만 활성(스테일/부재 루트에서
  // 오강등 방지). poc-gate(#4)의 산출물 루트는 engagement 디렉터리.
  // requirePocBinding: 2026-07-09 활성화(#3), **pentest 스코프**. live pentest가 poc_바인딩_방출 계약대로
  //   방출→게이트 통과함을 실증(multipart ReDoS, e2e 6/6). pentest를 수행한 엔게이지먼트(pentestPlan 존재)
  //   에서는 CONFIRMED이 pentester의 poc_artifact로 기계검증돼야 하며, 미충족 CONFIRMED은 CANDIDATE로
  //   보수적 강등(fail-safe: self-assert CONFIRMED 방지). VA-only(펜테스트 미수행)에는 강제하지 않는다
  //   (VA-CONFIRMED엔 pentest poc가 없어 전역 강제는 정당 CONFIRMED를 오강등 — 훅 테스트로 실증됨).
  //   명시 토글이 우선: CH015_REQUIRE_POC_BINDING=on 항상 강제, =off 항상 해제. self-stamp verifiedAt은
  //   토글과 무관하게 항상 무효화.
  const targetRoot = manifest && typeof manifest.target_realpath === 'string' ? manifest.target_realpath : null;
  const sourceRoot = (targetRoot && env.CH015_CITE_CHECK !== 'off' && fs.existsSync(targetRoot))
    ? targetRoot
    : null;
  const pocEnv = env.CH015_REQUIRE_POC_BINDING;
  const requirePocBinding = pocEnv === 'on' ? true : pocEnv === 'off' ? false : Boolean(pentestPlan);
  const allowEmptyCandidates = env.CH015_ALLOW_EMPTY_CANDIDATES === 'on';

  const result = validateReportGate({
    ledger: ledgerCandidates,
    classification,
    pentestPlan,
    manifest,
    requireScore: false,
    // classification 산출물이 있을 때만 equivalence review를 필수로 강제(단순 VA 오탐 차단 방지)
    requireEquivalenceReview: Boolean(classification) &&
      (ledgerCandidates.length > 0 || getCandidates(classification).length > 0),
    // 최종 결과서(va/pentest/redteam-report, executive-summary)에는 브랜치+커밋 기입을 강제.
    // 단, git repo가 아닌 대상(단일 파일, 아카이브 등)은 provenance 부재를 허용하고
    // 보고서에 경고로 기록한다 (발행은 차단하지 않는다).
    requireProvenance: strongFinal && manifest && manifest.git_head != null,
    sourceRoot,
    artifactRoot: engagementDir,
    requirePocBinding,
    allowEmptyCandidates,
  });

  // 강제 "기입" 확인: manifest에 provenance가 있어도 결과서 본문에 커밋이 실제로 안 박히면 무의미.
  // 최종 결과서 본문에 진단 커밋(full 또는 7-char short)이 포함됐는지 검사한다. 커밋 SHA는
  // 모호성 없는 추적 앵커(브랜치명은 흔한 단어와 충돌 소지 → 하드 스캔 제외, 템플릿+manifest로 보장).
  if (strongFinal && content && result.provenance && result.provenance.git_commit) {
    const commit = String(result.provenance.git_commit);
    const short = commit.slice(0, 7);
    if (!content.includes(commit) && !content.includes(short)) {
      result.errors.push({
        code: 'PROVENANCE_NOT_IN_REPORT',
        message:
          `최종 결과서 본문에 진단 커밋(${short}…)이 기입되지 않았습니다. ` +
          `브랜치+커밋해시를 결과서에 명시(기입)해야 발행할 수 있습니다.`,
      });
      result.ok = result.errors.length === 0;
    }
  }

  // 커버리지 게이트(대규모 전수 커버리지 강제, R1 분해·R2 완결성·R3 커버리지비율): large-scale flow +
  // 최종 결과서(strongFinal)에서만. coverage_units.yaml(orchestrator 방출) + source_manifest.units로
  // 검증 → 미분해/미실행/저커버 유닛 있으면 fail-closed. 표준·소형 flow는 무영향(발행 안 막음).
  // 토글: CH015_COVERAGE_GATE=off로 해제. large-scale인데 coverage_units.yaml 부재 시 COVERAGE_DATA_MISSING
  // 으로 차단 — orchestrator가 audit 유닛 매니페스트를 방출하도록 강제(davinci서 확인된 under-cover 정면 수정).
  if (strongFinal && env.CH015_COVERAGE_GATE !== 'off') {
    let fanout = null;
    try { fanout = JSON.parse(fs.readFileSync(path.join(engagementDir, 'fanout_decision.json'), 'utf8')); } catch { /* 없으면 large-scale 아님 */ }
    const isLargeScale = fanout && (fanout.flow === 'large-scale' || (fanout.va && fanout.va.mode === 'large-scale'));
    if (isLargeScale) {
      const cov = evaluateEngagement(engagementDir);
      if (cov && cov.ok === false) {
        for (const v of cov.violations) {
          result.errors.push({ code: `COVERAGE_${v.code}`, unit: v.unit, message: v.message });
        }
        result.coverage_gate = cov.summary;
        result.ok = result.errors.length === 0;
      }
    }
  }

  // 호스트 소유 work-unit scope assurance 게이트(P0-C): coverage_units.yaml 대규모 fanout 게이트와는
  // 독립적으로, sealed work plan/results 산출물(00_work_plan.json + 00_work_unit_results.json) 존재만으로
  // host-bounded work-unit engagement를 감지한다 — fanout_decision.flow 값(standard/large-scale)에
  // 좌우되지 않는다. 구조/해시/식별자/완결 유닛 계정만 검증하고, 새로운 read-ratio/finding-density
  // 임계값은 두지 않는다. results가 assurance를 아예 선언하지 않은 레거시 v1 산출물은 통과시킨다.
  // 토글: CH015_SCOPE_ASSURANCE_GATE=off로 해제.
  if (strongFinal && env.CH015_SCOPE_ASSURANCE_GATE !== 'off' && isHostWorkUnitEngagement(engagementDir)) {
    const assurance = evaluateScopeAssurance(engagementDir);
    if (!assurance.legacy && assurance.ok === false) {
      for (const v of assurance.violations) {
        result.errors.push({ code: v.code, unit: v.unit, message: v.message });
      }
      result.scope_assurance_gate = { ok: false, violations: assurance.violations };
      result.ok = result.errors.length === 0;
    }
  }

  return { activated: true, result, strongFinal };
}

function safeRead(p) {
  try { return readStructured(p); } catch { return undefined; }
}

function prospectiveContent(tool, args, filePath) {
  if (tool === 'Write') return typeof args.content === 'string' ? args.content : null;
  if (!fs.existsSync(filePath)) return null;
  let content = fs.readFileSync(filePath, 'utf8');
  const edits = tool === 'Edit' ? [args] : Array.isArray(args.edits) ? args.edits : null;
  if (!edits) return null;
  for (const edit of edits) {
    if (typeof edit.old_string !== 'string' || typeof edit.new_string !== 'string' || edit.old_string.length === 0) {
      return null;
    }
    const occurrences = content.split(edit.old_string).length - 1;
    if (occurrences === 0 || (!edit.replace_all && occurrences !== 1)) return null;
    content = edit.replace_all
      ? content.split(edit.old_string).join(edit.new_string)
      : content.replace(edit.old_string, edit.new_string);
  }
  return content;
}

async function main() {
  if (process.env.CH015_REPORT_GATE === 'off') return finish(0);

  const payload = parsePayload(await readStdin());
  if (!payload) return finish(0);

  const tool = payload.tool || payload.tool_name || '';
  const args = payload.args || payload.tool_input || {};
  const env = { ...process.env, ...(payload.env || {}) };

  if (!['Write', 'Edit', 'MultiEdit'].includes(tool)) return finish(0);

  const filePath = args.file_path || args.path || '';
  if (typeof filePath !== 'string' || !filePath) return finish(0);
  const base = path.basename(filePath);
  if (!base.toLowerCase().endsWith('.md') || !REPORT_NAME_RE.test(base)) return finish(0);

  const content = prospectiveContent(tool, args, filePath);
  if (content == null && FINAL_REPORT_RE.test(base)) {
    process.stderr.write('[CH015] Report gate FAILED — 최종 보고서 편집 결과를 결정론적으로 재구성할 수 없습니다.\n');
    return finish(2);
  }

  let outcome;
  try {
    outcome = runGate({ filePath, env, content });
  } catch (e) {
    // 게이트 자체 오류는 fail-open하지 않고 차단(검증 불가 = 발행 불가)하되, 사유를 남긴다.
    process.stderr.write(`[CH015][REPORT_GATE_ERROR] ${e.message}\n`);
    return finish(env.CH015_REPORT_GATE === 'strict' ? 2 : 0);
  }

  if (!outcome.activated) return finish(0);

  if (outcome.noArtifacts) {
    // 최종 발행 보고서로 강하게 추정되는 이름인데 ledger/classification이 없다 =
    // 분류된 Finding 없이 최종 보고서를 발행하는 것 → fail-closed(차단).
    if (outcome.strongFinal) {
      process.stderr.write(
        '[CH015] Report gate FAILED — 최종 보고서를 발행하려는데 분류 산출물(raw ledger/convergence classification)을 ' +
        'engagement 디렉터리에서 찾지 못했습니다. 분류를 먼저 산출하거나 (우회: CH015_REPORT_GATE=off) 진행하십시오.\n'
      );
      return finish(2);
    }
    process.stderr.write(
      '[CH015][REPORT_GATE] ledger/classification 산출물을 찾지 못해 구조적 게이트를 적용하지 못했습니다. ' +
      '발행 전 hooks/report-gate.js 수동 점검을 권장합니다.\n'
    );
    return finish(env.CH015_REPORT_GATE === 'strict' ? 2 : 0);
  }

  const { result } = outcome;
  for (const w of result.warnings || []) {
    process.stderr.write(`[CH015][REPORT_GATE WARN] ${w.code}: ${w.message}\n`);
  }
  if (!result.ok) {
    // VA/pentest 중간 산출물(예: 01_va_result-1st.md)은 후보를 아직 최종
    // 분류하지 않은 상태로 기록할 수 있다. 최종 발행물만 fail-closed하고,
    // 중간 산출물은 경고를 남긴 뒤 다음 phase에서 분류를 완결하게 한다.
    if (!outcome.strongFinal && env.CH015_REPORT_GATE !== 'strict') {
      process.stderr.write('[CH015][REPORT_GATE WARN] 중간 산출물은 최종 분류 게이트를 적용하지 않고 기록을 허용합니다.\n');
      for (const e of result.errors) {
        const cid = e.candidate_id ? ` ${e.candidate_id}` : '';
        process.stderr.write(`[CH015][REPORT_GATE WARN] ${e.code}${cid}: ${e.message}\n`);
      }
      return finish(0);
    }
    process.stderr.write('[CH015] Report gate FAILED — 보고서 발행 차단:\n');
    for (const e of result.errors) {
      const cid = e.candidate_id ? ` ${e.candidate_id}` : '';
      process.stderr.write(`- ${e.code}${cid}: ${e.message}\n`);
    }
    process.stderr.write('(우회: CH015_REPORT_GATE=off — 권장하지 않음)\n');
    return finish(2);
  }

  process.stderr.write('[CH015][REPORT_GATE] passed\n');
  return finish(0);
}

function finish(code) {
  process.exit(code);
}

if (require.main === module) {
  main();
}

module.exports = { prospectiveContent, runGate };
