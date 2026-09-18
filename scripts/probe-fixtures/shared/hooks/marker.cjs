#!/usr/bin/env node
/**
 * 프로브용 커맨드 훅. 실행 즉시 PROBE_LEDGER에 한 줄을 append 한다.
 *
 * 중요: stdin 을 기다리지 않는다. 훅 러너가 stdin 을 닫지 않는 경우
 * end 이벤트 대기는 타임아웃으로 이어지고 "훅이 실행되지 않았다"는
 * 잘못된 결론을 만든다. 먼저 쓰고, stdin 은 있으면 추가로 기록한다.
 */
'use strict';

const fs = require('fs');

const label = process.argv[2] || 'unknown';
const ledger = process.env.PROBE_LEDGER;

function append(row) {
  if (!ledger) return;
  try {
    fs.appendFileSync(ledger, `${JSON.stringify(row)}\n`);
  } catch {
    /* 원장 기록 실패는 프로브 결과에 영향을 주지 않도록 무시 */
  }
}

// 1) 실행 사실을 즉시 기록 — 이 한 줄이 "커맨드 훅이 실행됐다"의 증거다
append({
  source: 'command-hook',
  phase: 'spawned',
  label,
  plugin_root: process.env.CLAUDE_PLUGIN_ROOT ?? null,
  cwd: process.cwd(),
});

// 2) stdin 이 오면 훅 입력 내용도 기록 (짧은 타임아웃, 없으면 그냥 종료)
let raw = '';
const done = (reason) => {
  let input = null;
  if (raw) {
    try {
      input = JSON.parse(raw);
    } catch {
      input = { parse_error: true, raw: raw.slice(0, 200) };
    }
  }
  append({
    source: 'command-hook',
    phase: 'stdin',
    label,
    reason,
    hook_event_name: input?.hook_event_name ?? null,
    tool_name: input?.tool_name ?? null,
    agent_id: input?.agent_id ?? null,
    agent_type: input?.agent_type ?? null,
  });
  process.exit(0);
};

const timer = setTimeout(() => done('timeout-2s'), 2000);
process.stdin.setEncoding('utf8');
process.stdin.on('data', (c) => {
  raw += c;
});
process.stdin.on('end', () => {
  clearTimeout(timer);
  done('stdin-end');
});
process.stdin.on('error', () => {
  clearTimeout(timer);
  done('stdin-error');
});
