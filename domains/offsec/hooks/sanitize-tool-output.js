#!/usr/bin/env node
'use strict';

/**
 * PostToolUse Hook — Tool Output Sanitizer
 *
 * SDK가 도구 실행 후 모델에 결과를 전달하기 전에 호출된다.
 * stdin으로 { tool_name, tool_input, tool_response, ... }를 받고,
 * 위험 패턴을 제거한 updatedToolOutput을 반환한다.
 *
 * 동작:
 *   - tool_response에서 prompt injection 패턴을 비활성화
 *   - 과도하게 큰 출력을 절단
 *   - 정상 출력은 변형 없이 통과
 *
 * 출력 (stdout JSON):
 *   - 변형 필요 시: { "hookEventName": "PostToolUse", "updatedToolOutput": "<sanitized>" }
 *   - 변형 불필요 시: exit 0, stdout 비움 (SDK가 원본 그대로 사용)
 */

const MAX_OUTPUT_CHARS = 50000; // 50K chars — 대부분의 파일 읽기에 충분

// Unicode format characters — 패턴 우회에 사용될 수 있는 불가시 문자 제거
// U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ, U+2060 WJ, U+FEFF BOM
const FORMAT_CHARS = /[​‌‍⁠﻿]/g;

// Prompt injection 패턴 — 모델의 시스템 프롬프트 경계를 위조하려는 시도
const INJECTION_PATTERNS = [
  /\[SYSTEM\]/gi,
  /<\|im_start\|>/gi,
  /<\|im_end\|>/gi,
  /<\/?instructions?>/gi,
  /<\/?system(?:-[a-z]+)?>/gi,  // <system>, <system-reminder>, </system-reminder> 등
  /<\/?anthropic>/gi,
  /Human:\s*\n/gi,
  /Assistant:\s*\n/gi,
  /<\|begin_of_turn\|>/gi,      // Gemini-style delimiter
  /<\|end_of_turn\|>/gi,
  /<<\/?SYS>>/gi,               // Llama-style delimiter
];

function sanitize(raw) {
  if (typeof raw !== 'string') {
    // 비문자열 (JSON object 등) — 문자열화 후 처리
    try {
      raw = JSON.stringify(raw);
    } catch {
      return raw;
    }
  }

  let output = raw;
  let modified = false;

  // 0. Unicode format character 제거 (ZWSP 등으로 패턴 우회 방지)
  const stripped = output.replace(FORMAT_CHARS, '');
  if (stripped !== output) {
    output = stripped;
    modified = true;
  }

  // 1. 길이 제한
  if (output.length > MAX_OUTPUT_CHARS) {
    output = output.slice(0, MAX_OUTPUT_CHARS) + '\n\n[... truncated: output exceeded 50K chars ...]';
    modified = true;
  }

  // 2. Injection 패턴 제거
  for (const pattern of INJECTION_PATTERNS) {
    const before = output;
    output = output.replace(pattern, '[FILTERED]');
    if (output !== before) modified = true;
  }

  return modified ? output : null; // null = 변형 불필요
}

async function main() {
  let input = '';
  for await (const chunk of process.stdin) {
    input += chunk;
  }

  if (!input.trim()) {
    // stdin 비어있으면 조용히 통과
    process.exit(0);
  }

  let data;
  try {
    data = JSON.parse(input);
  } catch {
    // 파싱 실패 시 조용히 통과 (fail-open for non-security hooks)
    process.exit(0);
  }

  const toolResponse = data.tool_response;
  if (toolResponse === undefined || toolResponse === null) {
    process.exit(0);
  }

  // tool_response가 object인 경우 내부 content를 처리
  let responseText;
  if (typeof toolResponse === 'string') {
    responseText = toolResponse;
  } else if (typeof toolResponse === 'object') {
    // SDK tool_response는 보통 { content: string } 또는 string[]
    responseText = JSON.stringify(toolResponse);
  } else {
    process.exit(0);
  }

  const sanitized = sanitize(responseText);

  if (sanitized === null) {
    // 변형 불필요 — 원본 그대로 전달
    process.exit(0);
  }

  // 변형 적용 — updatedToolOutput 반환
  const output = {
    hookEventName: 'PostToolUse',
    updatedToolOutput: sanitized,
  };

  process.stdout.write(JSON.stringify(output));
  process.exit(0);
}

main().catch((err) => {
  process.stderr.write(`[sanitize-hook] Error: ${err.message}\n`);
  // 에러 시에도 fail-open (도구 실행은 차단하지 않음)
  process.exit(0);
});
