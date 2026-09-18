#!/usr/bin/env node
/**
 * CH015 Verifier Invariants Runtime Check
 *
 * Verifier 세션의 Phase 순서 불변식(I1/I2/I3)을 런타임에 검증한다.
 * I4(Comment_Is_Data)는 본질적으로 LLM prompt-level이므로 본 모듈은
 * 알려진 prompt-injection 패턴을 의심 후보로 식별하는 보조 함수만 제공한다.
 *
 * 참조:
 *   - skills/ch015/offsec/verifier/SKILL.md (Invariants 섹션)
 *   - agents/verifier.md (Phase 순서 불변식)
 *
 * 사용 방법:
 *   1) PreToolUse 훅으로 연결 — Read/Edit/Write/Bash 도구 호출 전 검사
 *   2) 수동 사전 점검 — `node hooks/verify-invariants.js check <engagement_dir> <round>`
 *
 * I1/I2 (Read 차단):
 *   Read 인자에 VA/Pentest/Red Team 보고서 경로 패턴이 포함되어 있고,
 *   해당 engagement 디렉토리에 02a_verify_autonomous-<round>.md 가 존재하지 않으면
 *   ANCHORING_VIOLATION 을 기록하고 종료 코드 2로 중단시킨다.
 *
 * I3 (02a 파일 수정 차단 — 생성/수정 구분):
 *   02a_verify_autonomous-<round>.md가 이미 존재하는 상태에서
 *   Edit/Write/NotebookEdit/MultiEdit 대상이 되면 I3_VIOLATION 을 기록하고
 *   종료 코드 2로 중단시킨다. 미존재 시 Write 1회(R0.5 생성)는 허용한다.
 *   (R4 Gap Diff에서 새 Finding은 02b_verify_gap-<round>.md에 기록)
 *
 * I4 (보조 — 차단 안 함):
 *   detectPromptInjectionPatterns(content)로 의심 패턴 식별만 제공.
 *   실제 차단/감지는 LLM 책임 (PreToolUse는 도구 인자만 보므로 코드 본문 분석 불가).
 */

'use strict';

const fs = require('fs');
const path = require('path');

const VA_REPORT_PATTERNS = [
  /\/?0\d+_va_result[-\w]*\.md$/i,
  /\/?0\d+_va_findings_index[-\w]*\.yaml$/i,
  /\/?0\d+_va_delta[-\w]*\.yaml$/i,
  /\/?0\d+[a-z]?_pentest_result[-\w]*\.md$/i,
  /\/?0\d+[a-z]?_redteam_result[-\w]*\.md$/i,
];

// 라운드(-1st) 뒤에 그룹/유닛 접미가 붙을 수 있다(grouped: -auth, full: -a1, large-scale: -<unit>).
// [-\w]+ 로 접미를 허용해야 SoD 화이트리스트·I3·봉인 판정이 모든 규모의 02a를 인식한다.
// (다른 패턴들은 이미 [-\w]* 사용 — 이것만 누락되어 grouped/full/large-scale verify가 깨졌었다.)
const AUTONOMOUS_PATTERN = /\/?02a_verify_autonomous-[-\w]+\.md$/i;
const GAP_PATTERN = /\/?02b_verify_gap[-\w]*\.md$/i;

// [P1-1] Verifier 자신의 산출물 화이트리스트.
// 근거: agents/verifier.md Output_To_Lead의 storage_* 항목 —
//   storage_autonomous: 02a_verify_autonomous-<round>.md
//   storage_result:     02_verify_result-1st.md / 04_verify_result-2nd.md
//   storage_gap:        02b_verify_gap-<round>.md
//   storage_objections: 02_verify_objections-1st.yaml / 04_verify_objections-2nd.yaml
//   pentest_verify_result: 06a_pentest_verify_result-<round>.md
//   pentest_verify_objections: 06a_pentest_verify_objections-<round>.yaml
// verifier의 쓰기 도구는 이 패턴 밖의 봉인 산출물을 대상으로 할 수 없다(SoD).
const VERIFIER_OUTPUT_PATTERNS = [
  AUTONOMOUS_PATTERN,
  GAP_PATTERN,
  /\/?0\d+[a-z]?_verify_result[-\w]*\.md$/i,
  /\/?0\d+[a-z]?_verify_objections[-\w]*\.ya?ml$/i,
  /\/?0\d+[a-z]?_pentest_verify_result[-\w]*\.md$/i,
  /\/?0\d+[a-z]?_pentest_verify_objections[-\w]*\.ya?ml$/i,
];
const REPORT_EXTENSIONS = new Set(['.md', '.yaml', '.yml', '.json']);
const ROUND_PATTERN = /(?:^|[-_])(\d+(?:st|nd|rd|th))(?=$|[-_.])/i;

// 봉인 산출물을 "읽을" 수 있는 모든 도구. Read뿐 아니라 Grep/Glob도
// 매칭 라인/존재를 노출하므로 동일하게 R0.5 앵커링 게이트를 적용한다.
const SEALED_READ_TOOLS = new Set(['Read', 'Grep', 'Glob']);
const I3_PROTECTED_TOOLS = new Set(['Edit', 'Write', 'NotebookEdit', 'MultiEdit']);
const VERIFIER_BASH_ALLOWED = [
  /^\s*node\s+["']?[^"'\n;&|<>`$]*context-builder\.js["']?(?:\s|$)/,
  /^\s*ast-grep(?:\s|$)/,
  /^\s*semgrep(?:\s|$)/,
];
// 명령 체이닝/리다이렉트/치환 문자 — 줄바꿈(\n,\r)과 단독 &(백그라운드)도 포함해야
// `semgrep x\n cat sealed.md` 류 우회를 막는다.
const UNSAFE_SHELL_CONTROL = /(?:;|&&|\|\||\||`|\$\(|>|<|&|\n|\r)/;

// I4 보조: 코드 주석/문자열에서 의심 prompt-injection 지시어 패턴
// 차단 목적이 아닌 감지/로깅용 (LLM이 데이터로 처리하도록 환기)
const PROMPT_INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(the\s+)?(above|previous|prior)\s+instructions?/i,
  /(disregard|forget)\s+(all\s+)?(previous|above|prior)/i,
  /mark\s+(this|as|safe)/i,
  /do\s+not\s+(report|flag|analyze|audit|review)/i,
  /assume\s+(true|safe|verified|secure)/i,
  /pretend\s+(this|to\s+be|that)/i,
  /you\s+are\s+now\s+(a\s+)?(different|admin|root)/i,
  /system\s*:\s*you\s+(are|must|should)/i,
  /<\s*\|?\s*(system|im_start|admin)\s*\|?\s*>/i,
];

function logViolation(engagementDir, kind, detail) {
  try {
    const logFile = path.join(engagementDir, 'audit.log');
    fs.appendFileSync(
      logFile,
      `${new Date().toISOString()}\t${kind}\t${detail}\n`,
      'utf8'
    );
  } catch (e) {
    // fallback to stderr if audit.log cannot be written
    console.error(`[CH015][${kind}] ${detail}`);
  }
}

/**
 * Check that autonomous output for a given round already exists in engagement_dir.
 */
// grouped verify에서는 verifier마다 자기 그룹의 02a를 생성한다
// (02a_verify_autonomous-<round>-<group>.md). group 인자가 있으면 그룹별 파일을,
// 없으면 단일(02a_verify_autonomous-<round>.md)을 확인한다(sequential/하위호환).
function autonomousExists(engagementDir, round, group) {
  const suffix = group ? `-${group}` : '';
  const fname = `02a_verify_autonomous-${round}${suffix}.md`;
  return fs.existsSync(path.join(engagementDir, fname));
}

function inferEngagementDir(filePath) {
  if (typeof filePath !== 'string' || filePath.length === 0) return '';
  const dir = path.dirname(filePath);
  return dir === '.' ? process.cwd() : dir;
}

function inferRound(filePath, fallback = '1st') {
  if (typeof filePath !== 'string') return fallback;
  const m = path.basename(filePath).match(ROUND_PATTERN);
  return m && m[1] ? m[1] : fallback;
}

function roundToNumber(round) {
  const m = /^(\d+)(?:st|nd|rd|th)$/i.exec(round || '');
  return m ? parseInt(m[1], 10) : 0;
}

function numberToRound(n) {
  const mod100 = n % 100;
  const suffix =
    mod100 >= 11 && mod100 <= 13
      ? 'th'
      : { 1: 'st', 2: 'nd', 3: 'rd' }[n % 10] || 'th';
  return `${n}${suffix}`;
}

/**
 * engagement 디렉터리의 실존 산출물에서 현재 verify 라운드를 추론한다.
 * 기준: 봉인 VA/Pentest/RedTeam 산출물과 02a_verify_autonomous-* 파일명에 박힌
 * 라운드 접미사 중 최고 라운드. (예: 03_va_delta-2nd.yaml이 있으면 2nd —
 * 접미사 없는 봉인 파일을 읽을 때 무조건 '1st'로 떨어져 1라운드 02a만으로
 * 2라운드 앵커링 게이트를 통과하는 우회를 막는다.)
 * 아무 라운드 표식도 없으면 fallback 반환 (기존 정규 케이스 동작 불변).
 */
function inferEngagementRound(engagementDir, fallback = '1st') {
  if (typeof engagementDir !== 'string' || !engagementDir) return fallback;
  let max = 0;
  let entries;
  try {
    entries = fs.readdirSync(engagementDir);
  } catch {
    return fallback;
  }
  for (const name of entries) {
    // 그룹/유닛 접미(-auth, -a1, -<unit>)가 붙은 02a도 라운드 산정에 포함한다(A5).
    const auto = name.match(/^02a_verify_autonomous-(\d+(?:st|nd|rd|th))(?:-[-\w]+)?\.md$/i);
    if (auto) {
      max = Math.max(max, roundToNumber(auto[1]));
      continue;
    }
    if (!VA_REPORT_PATTERNS.some((rx) => rx.test(name))) continue;
    const m = name.match(ROUND_PATTERN);
    if (m && m[1]) max = Math.max(max, roundToNumber(m[1]));
  }
  return max > 0 ? numberToRound(max) : fallback;
}

/**
 * 경로를 canonical 절대 경로로 정규화한다. 심링크·OS 별칭(macOS의 /tmp →
 * /private/tmp 등)을 realpath로 해소하되, 대상이 아직 존재하지 않으면
 * 존재하는 최근접 부모 디렉터리를 realpath한 뒤 잔여 세그먼트를 재결합한다.
 * lexical path.resolve만 쓰면 별칭/심링크로 isWithinDir 비교를 우회할 수 있다.
 */
function canonicalizePath(p) {
  const abs = path.resolve(p);
  let cur = abs;
  const tail = [];
  for (;;) {
    try {
      const real = fs.realpathSync(cur);
      return tail.length ? path.join(real, ...tail) : real;
    } catch {
      const parent = path.dirname(cur);
      if (parent === cur) return abs; // 루트까지 미존재 — lexical 결과 사용
      tail.unshift(path.basename(cur));
      cur = parent;
    }
  }
}

function isWithinDir(filePath, dir) {
  if (!filePath || !dir) return false;
  const fileAbs = canonicalizePath(filePath);
  const dirAbs = canonicalizePath(dir);
  return fileAbs === dirAbs || fileAbs.startsWith(dirAbs + path.sep);
}

function isSealedReportPath(filePath, engagementDir) {
  if (typeof filePath !== 'string') return false;
  if (AUTONOMOUS_PATTERN.test(filePath) || GAP_PATTERN.test(filePath)) return false;
  if (VA_REPORT_PATTERNS.some((rx) => rx.test(filePath))) return true;

  const ext = path.extname(filePath).toLowerCase();
  if (!REPORT_EXTENSIONS.has(ext)) return false;
  return isWithinDir(filePath, engagementDir);
}

/**
 * Read/Grep/Glob 대상이 봉인 산출물을 노출하는지 판정.
 * Read는 파일 단위(isSealedReportPath), Grep/Glob는 engagement 디렉터리 전체를
 * 스캔하면 봉인 보고서 내용/존재를 노출할 수 있으므로 디렉터리 포함도 봉인으로 본다.
 */
function isSealedReadTarget(tool, filePath, engagementDir) {
  if (!SEALED_READ_TOOLS.has(tool)) return false;
  if (typeof filePath !== 'string') return false;
  // verifier 자신의 R0.5/R4 산출물(02a/02b)은 봉인 대상이 아니다.
  if (AUTONOMOUS_PATTERN.test(filePath) || GAP_PATTERN.test(filePath)) return false;
  if (isSealedReportPath(filePath, engagementDir)) return true;
  // 확장자 화이트리스트에 의존하지 않는다 — engagement 디렉터리 내부의 어떤 파일이든
  // (예: 보고서를 .txt로 리네임한 사본) Read/Grep/Glob 모두 봉인으로 본다.
  if (engagementDir && isWithinDir(filePath, engagementDir)) return true;
  return false;
}

/**
 * 허용된 verifier Bash(semgrep/ast-grep/context-builder)라도 인자가 봉인 산출물이나
 * engagement 디렉터리를 가리키면 차단한다(보고서 내용 덤프 우회 방지).
 */
function commandReferencesSealedPath(command, engagementDir) {
  if (typeof command !== 'string') return false;
  const tokens = [];
  for (const raw of command.split(/\s+/)) {
    const stripped = raw.replace(/^["']|["']$/g, '');
    if (!stripped) continue;
    tokens.push(stripped);
    // `--flag=/path` 글루 토큰: `=` 기준으로 추가 분해해 꼬리 경로도 검사
    // (예: semgrep --config=/eng/x.yaml 우회 봉합)
    if (stripped.includes('=')) {
      for (const part of stripped.split('=')) {
        const p = part.replace(/^["']|["']$/g, '');
        if (p) tokens.push(p);
      }
    }
  }
  for (const tok of tokens) {
    if (VA_REPORT_PATTERNS.some((rx) => rx.test(tok))) return true;
    if (engagementDir && isWithinDir(tok, engagementDir)) return true;
  }
  return false;
}

/**
 * I4 보조: 텍스트에서 prompt-injection 의심 패턴을 식별한다.
 * 반환: 발견된 패턴 목록 (없으면 빈 배열)
 *
 * 주의: 차단이 아닌 감지/로깅용. PreToolUse에서는 도구 인자만 보므로
 * 일반적으로 사용되지 않지만, 다른 hook(PostToolUse 등)에서 활용 가능.
 */
function detectPromptInjectionPatterns(content) {
  if (typeof content !== 'string' || content.length === 0) return [];
  const matches = [];
  for (const pattern of PROMPT_INJECTION_PATTERNS) {
    const m = content.match(pattern);
    if (m) {
      matches.push({
        pattern: pattern.source,
        match: m[0].slice(0, 80), // truncate for log safety
        index: m.index,
      });
    }
  }
  return matches;
}

function extractBashCommand(args) {
  if (!args || typeof args !== 'object') return '';
  const command =
    args.command ||
    args.cmd ||
    args.script ||
    args.input ||
    args.bash_command ||
    '';
  return typeof command === 'string' ? command : '';
}

function isAllowedVerifierBash(command) {
  if (typeof command !== 'string' || !command.trim()) return false;
  if (UNSAFE_SHELL_CONTROL.test(command)) return false;
  return VERIFIER_BASH_ALLOWED.some((pattern) => pattern.test(command));
}

function isVerifierOutputPath(filePath) {
  if (typeof filePath !== 'string') return false;
  return VERIFIER_OUTPUT_PATTERNS.some((rx) => rx.test(filePath));
}

/**
 * preToolUseCheck({ tool, args, env })
 *   Returns { allow: bool, reason?: string, exitCode?: number }
 *
 * 검증 순서:
 *   1) Read 도구 + verifier role + VA/Pentest/RedTeam 보고서 경로
 *      → R0.5 미완료 시 차단 (Invariant I1/I2)
 *   2) Edit/Write/NotebookEdit/MultiEdit 도구 + verifier role + 02a 파일
 *      → 항상 차단 (Invariant I3 — Autonomous_Output_Immutable)
 */
function preToolUseCheck({ tool, args, env }) {
  env ||= {};
  const role = env.AGENT_ROLE || '';

  if (tool === 'Bash' && role === 'verifier') {
    const command = extractBashCommand(args);
    const engagementDirForLog = env.AGENT_ENGAGEMENT_DIR || '';
    if (!isAllowedVerifierBash(command)) {
      if (engagementDirForLog) {
        logViolation(
          engagementDirForLog,
          'VERIFIER_BASH_SCOPE_VIOLATION',
          `verifier attempted disallowed Bash command: ${command.slice(0, 160)}`
        );
      }
      return {
        allow: false,
        reason:
          `Verifier Bash is restricted to AST tooling only ` +
          `(node ...context-builder.js, ast-grep, semgrep). command=${command}`,
        exitCode: 2,
      };
    }
    // 허용된 도구라도 봉인 보고서/engagement 디렉터리를 인자로 주면 차단 (덤프 우회 방지)
    if (commandReferencesSealedPath(command, engagementDirForLog)) {
      if (engagementDirForLog) {
        logViolation(
          engagementDirForLog,
          'VERIFIER_BASH_SEALED_PATH',
          `verifier Bash referenced sealed/engagement path: ${command.slice(0, 160)}`
        );
      }
      return {
        allow: false,
        reason:
          `Verifier Bash must not target sealed CH015 artifacts or the engagement directory. ` +
          `command=${command}`,
        exitCode: 2,
      };
    }
    return { allow: true };
  }

  const filePath = args?.file_path || args?.path;

  // V-1: verifier의 경로 없는 Grep/Glob은 cwd 전체(=engagement 디렉터리 포함 가능)를
  // 재귀 스캔하므로 R0.5 완료 전 봉인 보고서 내용을 매칭 라인으로 노출할 수 있다.
  // 명시적 scope 경로를 요구한다(경로가 있으면 아래 isSealedReadTarget가 별도 판정).
  if (role === 'verifier' && (tool === 'Grep' || tool === 'Glob') && typeof filePath !== 'string') {
    const engDir = env.AGENT_ENGAGEMENT_DIR || '';
    const rnd = env.AGENT_VERIFY_ROUND || inferEngagementRound(engDir, '1st');
    const grp = env.AGENT_VERIFY_GROUP || '';
    if (engDir && !autonomousExists(engDir, rnd, grp)) {
      logViolation(
        engDir,
        'ANCHORING_VIOLATION',
        `verifier path-less ${tool} before R0.5 (scans cwd; may expose sealed report)`
      );
      return {
        allow: false,
        reason:
          `Invariant I1/I2 — verifier must specify an explicit path outside the engagement ` +
          `directory for ${tool} before completing R0.5 (path-less ${tool} recursively scans ` +
          `the engagement directory and can expose the sealed report).`,
        exitCode: 2,
      };
    }
  }

  if (typeof filePath !== 'string') return { allow: true };

  // [P0-A] 봉인 판정의 engagement catch-all(디렉터리 내 전 파일 봉인)은 env로
  // "명시된" engagementDir가 있을 때만 적용한다. env 부재 시 dirname 추론값은
  // 봉인 판정에 쓰지 않고(쓰면 env 미주입 일반 세션의 모든 Read/Grep/Glob이
  // 차단된다 — 과차단), audit.log 위치·02a 존재 확인·라운드 추론에만 쓴다.
  // env 부재 시 fail-closed는 결정론적 파일명 패턴(VA_REPORT_PATTERNS 등)에 한정.
  const explicitEngagementDir = env.AGENT_ENGAGEMENT_DIR || '';
  const engagementDir = explicitEngagementDir || inferEngagementDir(filePath);
  // round 우선순위: env > 파일명 접미사 > engagement 실존 산출물 최고 라운드 > '1st'
  // (의도: per-round 게이트. 파일명 접미사를 engagement 최고 라운드보다 먼저 보는
  //  이유 — N라운드 산출물 열람은 02a-<N>만 요구하면 되므로, 2라운드 진행 중에도
  //  1라운드 봉인 산출물(-1st 접미사) 재열람이 02a-2nd를 요구하지 않도록
  //  라운드별로 게이트를 분리한다. 접미사 없는 파일만 최고 라운드로 보수적 판정.)
  const round =
    env.AGENT_VERIFY_ROUND ||
    inferRound(filePath, '') ||
    inferEngagementRound(engagementDir, '1st');
  // grouped verify: 이 verifier가 담당한 그룹(env). 봉인 게이트는 자기 그룹의 02a만 요구한다
  // (02a_verify_autonomous-<round>-<group>.md). 미설정(sequential)이면 단일 02a.
  const verifyGroup = env.AGENT_VERIFY_GROUP || '';
  // [P0-B] I3 스펙(verifier.md I3_Autonomous_Output_Immutable: "한 번 생성된 뒤
  // 수정하지 않는다") — 생성과 수정을 구분한다. 02a가 미존재면 Write 1회(R0.5 생성)는
  // 허용하고, 존재하면 수정으로 보고 차단한다. Edit/MultiEdit/NotebookEdit는
  // 파일 존재를 전제하는 도구이므로 항상 차단.
  const targetsAutonomous = I3_PROTECTED_TOOLS.has(tool) && AUTONOMOUS_PATTERN.test(filePath);
  const editsAutonomous =
    targetsAutonomous && (tool !== 'Write' || fs.existsSync(canonicalizePath(filePath)));
  const readsSealedReport = isSealedReadTarget(tool, filePath, explicitEngagementDir);

  // [P0-C] role 미식별(메인 루프 오케스트레이터 등) + 봉인 산출물 접근.
  //   I1/I2 앵커링은 verifier 전용 불변식이고, 그 본질은 "R0.5(02a) 완료 전
  //   VA/Pentest/RedTeam 보고서 열람 금지"다. role-less 세션을 무조건 차단하면
  //   정당한 오케스트레이터(Convergence·보고서 단계의 봉인 산출물 읽기)까지
  //   막혀 파이프라인이 멈춘다(관측된 과차단). 따라서 봉인 "읽기"는 앵커링
  //   게이트로 판정한다:
  //     - 02a 미존재(앵커링 민감 구간) → fail-closed 차단.
  //       role을 드롭해 앵커링을 우회하려는 verifier 가설도 함께 차단된다.
  //     - 02a 존재(R0.5 완료) → 앵커링 무관 시점 → 허용.
  //       verifier role 경로(아래 I1/I2 블록)도 02a 존재 시 동일하게 허용하므로 대칭.
  //   02a "쓰기" 불변(I3)은 앵커링과 독립이므로 role 무관하게 항상 차단을 유지한다.
  //   (서브에이전트 신원은 harness가 payload로 주입 — role-less는 실질적으로
  //    메인 루프이며, 설령 신원 주입이 실패하더라도 02a 미존재 구간은 위처럼 막힌다.)
  if (!role) {
    if (editsAutonomous) {
      return {
        allow: false,
        reason:
          `AGENT_ROLE is required for sealed CH015 verifier artifacts ` +
          `(02a_verify_autonomous-*.md is immutable after R0.5). ` +
          `tool=${tool} path=${filePath}`,
        exitCode: 2,
      };
    }
    if (readsSealedReport) {
      if (engagementDir && autonomousExists(engagementDir, round, verifyGroup)) {
        return { allow: true };
      }
      return {
        allow: false,
        reason:
          `AGENT_ROLE is required for sealed CH015 verifier artifacts before R0.5 ` +
          `completes (02a_verify_autonomous-${round}.md absent — anchoring window). ` +
          `tool=${tool} path=${filePath}`,
        exitCode: 2,
      };
    }
  }

  // verifier role이 아니면 모든 검증 스킵 (VA/Pentest는 02a를 작성/수정해야 할 수 있음)
  if (role !== 'verifier') return { allow: true };

  // ───────────────────────────────────────────────────────────────
  // I3: 02a_verify_autonomous-*.md 수정 차단
  // (Edit/Write/NotebookEdit/MultiEdit + 02a 경로)
  // ───────────────────────────────────────────────────────────────
  if (editsAutonomous) {
    if (engagementDir) {
      logViolation(
        engagementDir,
        'I3_VIOLATION',
        `verifier attempted ${tool} on autonomous output ${filePath} — Invariant I3 violated`
      );
    }
    return {
      allow: false,
      reason:
        `Invariant I3 violated — 02a_verify_autonomous-*.md is immutable after R0.5. ` +
        `New findings from R4 Gap Diff must be written to 02b_verify_gap-*.md. ` +
        `tool=${tool} path=${filePath}`,
      exitCode: 2,
    };
  }

  // ───────────────────────────────────────────────────────────────
  // [P1-1] SoD: verifier 쓰기 도구는 자신의 산출물(VERIFIER_OUTPUT_PATTERNS)만
  // 쓸 수 있다. VA/Pentest/RedTeam 봉인 산출물 위·변조 방지가 목적.
  //   - 파일명 결정론 매칭(VA_REPORT_PATTERNS)은 env 부재 시에도 차단
  //   - engagement 내 비-verifier 산출물 차단은 env로 명시된 engagementDir가
  //     있을 때만 적용 (P0-A와 동일 방침 — dirname 추론으로 catch-all 금지)
  // ───────────────────────────────────────────────────────────────
  if (I3_PROTECTED_TOOLS.has(tool) && !isVerifierOutputPath(filePath)) {
    const sealedByName = VA_REPORT_PATTERNS.some((rx) => rx.test(filePath));
    const withinEngagement =
      Boolean(explicitEngagementDir) && isWithinDir(filePath, explicitEngagementDir);
    if (sealedByName || withinEngagement) {
      if (engagementDir) {
        logViolation(
          engagementDir,
          'VERIFIER_WRITE_SOD_VIOLATION',
          `verifier attempted ${tool} on non-verifier artifact ${filePath} — separation of duties violated`
        );
      }
      return {
        allow: false,
        reason:
          `Separation of duties — verifier may only write its own artifacts ` +
          `(02a_verify_autonomous / 02b_verify_gap / 0N_verify_result / 0N_verify_objections / ` +
          `0Na_pentest_verify_result / 0Na_pentest_verify_objections). ` +
          `tool=${tool} path=${filePath}`,
        exitCode: 2,
      };
    }
  }

  // ───────────────────────────────────────────────────────────────
  // I1/I2: Read/Grep/Glob + VA/Pentest/RedTeam 보고서(또는 engagement 디렉터리) + R0.5 미완료
  // ───────────────────────────────────────────────────────────────
  if (readsSealedReport) {
    if (!engagementDir) {
      return {
        allow: false,
        reason: 'AGENT_ENGAGEMENT_DIR is required for verifier role',
        exitCode: 2,
      };
    }

    if (!autonomousExists(engagementDir, round, verifyGroup)) {
      logViolation(
        engagementDir,
        'ANCHORING_VIOLATION',
        `verifier attempted ${tool} of ${filePath} before 02a_verify_autonomous-${round}${verifyGroup ? `-${verifyGroup}` : ''}.md exists`
      );
      return {
        allow: false,
        reason:
          `Invariant I1/I2 violated — verifier must complete Phase R0.5 ` +
          `(write 02a_verify_autonomous-${round}.md) before reading VA/Pentest/Red Team report. ` +
          `tool=${tool} path=${filePath}`,
        exitCode: 2,
      };
    }
  }

  return { allow: true };
}

function cliMain(argv) {
  const [cmd, engagementDir, round, group] = argv.slice(2);
  if (cmd !== 'check' || !engagementDir) {
    console.error('Usage: verify-invariants.js check <engagement_dir> [round=1st] [group]');
    process.exit(64);
  }
  const r = round || '1st';
  const g = group || process.env.AGENT_VERIFY_GROUP || '';
  const suffix = g ? `-${g}` : '';
  if (!autonomousExists(engagementDir, r, g)) {
    console.error(
      `[CH015] Invariant I1 violated: 02a_verify_autonomous-${r}${suffix}.md missing in ${engagementDir}`
    );
    process.exit(2);
  }
  console.log(`[CH015] OK: autonomous output exists for round ${r}${g ? ` group ${g}` : ''}`);
}

if (require.main === module) {
  cliMain(process.argv);
}

module.exports = {
  preToolUseCheck,
  autonomousExists,
  detectPromptInjectionPatterns,
  VA_REPORT_PATTERNS,
  AUTONOMOUS_PATTERN,
  GAP_PATTERN,
  isSealedReportPath,
  isSealedReadTarget,
  isVerifierOutputPath,
  VERIFIER_OUTPUT_PATTERNS,
  commandReferencesSealedPath,
  inferEngagementDir,
  inferRound,
  inferEngagementRound,
  canonicalizePath,
  SEALED_READ_TOOLS,
  I3_PROTECTED_TOOLS,
  extractBashCommand,
  isAllowedVerifierBash,
  VERIFIER_BASH_ALLOWED,
  PROMPT_INJECTION_PATTERNS,
};
