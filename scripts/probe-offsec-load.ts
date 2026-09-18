/**
 * offsec 도메인 로드 프로브 — 모델 턴을 거의 쓰지 않고 이식 결과를 확증한다.
 *
 * 확인하는 것:
 *   L1  domains/offsec 플러그인이 로드되어 4개 워커가 등록되는가, 이름이 무엇인가
 *   L2  벤더 훅(hooks/hooks.json)이 SDK 세션에서 발화하는가
 *   L3  계약 role의 최상위 tool allowlist/denylist가 조립되는가
 *
 * 실행: pnpm tsx scripts/probe-offsec-load.ts <대상 절대경로>
 */
import { mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { buildPhasePrompt, getOffsecPhase, loadOffsecContract } from '../src/runtime/offsec-contract.js';
import { buildOptions, runSession, type SessionSpec } from '../src/runtime/session.js';

async function main(): Promise<void> {
  const target = process.argv[2];
  if (!target) {
    console.error('사용: pnpm tsx scripts/probe-offsec-load.ts <대상 절대경로>');
    process.exit(2);
  }
  const engagementDir = mkdtempSync(join(tmpdir(), 'nunchi-offsec-probe-'));
  const contract = loadOffsecContract();
  const phase = getOffsecPhase('va', contract);
  const prompt = [
    buildPhasePrompt({ phase, target, engagementDir, scope: '계약 로드 프로브', contract }),
    'PROBE_MODE: package.json만 읽고 필수 artifact를 최소 placeholder로 생성한다.',
    '세션 시작 컨텍스트에 CH015가 있으면 summary에 VENDOR_HOOK_CONTEXT를 포함한다.',
  ].join('\n');

  const stderrLines: string[] = [];
  const spec: SessionSpec = {
    domain: 'offsec',
    phase: phase.id,
    entryAgent: phase.role,
    agentRole: phase.role,
    target,
    engagementDir,
    engagementId: 'load-probe',
    prompt,
    model: 'haiku',
    maxTurns: 8,
    onStderr: (chunk) => stderrLines.push(chunk),
  };
  const options = buildOptions(spec);
  const outcome = await runSession(spec);
  // 벤더 훅은 lib/core/io.js 의 logToStderr 로 [CH015] 접두 로그를 남긴다
  const vendorHookLines = stderrLines
    .join('')
    .split('\n')
    .filter((l) => l.includes('CH015') || l.includes('ch015'));

  const names = (outcome.registeredAgents ?? []).map((a) => a.name);
  const offsecAgents = names.filter((n) => n.startsWith('nunchi-offsec'));
  const auditLog = join(engagementDir, 'audit.log');

  console.log('\n================ offsec 로드 프로브 ================\n');

  console.log('L1  도메인 플러그인 로드');
  console.log(`    등록된 offsec 에이전트 (${offsecAgents.length}): ${offsecAgents.join(', ')}`);
  console.log(`    그 외 등록 에이전트: ${names.filter((n) => !n.startsWith('nunchi-offsec')).join(', ')}`);
  console.log(`    판정: ${offsecAgents.length === 4 ? '4개 전부 등록 (참)' : '누락 있음 (거짓)'}\n`);

  console.log('L2  벤더 훅 발화');
  console.log(`    engagement dir: ${engagementDir}`);
  console.log(`    audit.log 존재: ${existsSync(auditLog)}`);
  if (existsSync(auditLog)) {
    console.log(`    ${readFileSync(auditLog, 'utf8').trim().split('\n').slice(0, 5).join('\n    ')}`);
  }
  console.log(`    호스트 원장 행 수: ${outcome.ledger.length}`);
  console.log(`    벤더 훅 stderr 로그 (${vendorHookLines.length}행):`);
  for (const l of vendorHookLines.slice(0, 10)) console.log(`      ${l}`);
  // session-start.js 는 stdout 으로 세션 컨텍스트를 주입한다. 모델이 그 값을
  // 되읽으면 훅이 발화했다는 증거다 (ch015.config.json 로드까지 함께 확증된다).
  const contextEcho = /VENDOR_HOOK_CONTEXT\s*[:=]\s*(.+)/.exec(
    JSON.stringify(outcome.structuredOutput ?? outcome.texts.join('\n')),
  );
  console.log(`    주입된 컨텍스트 회신: ${contextEcho?.[1]?.trim() ?? '(응답 없음)'}`);
  const injected = contextEcho !== null && !/none/i.test(contextEcho[1] ?? '');
  console.log(`    판정: ${injected ? 'SessionStart 훅 발화 + config 로드 확인 (참)' : '판정 불가'}\n`);

  const allowedTools = Array.isArray(options.tools) ? options.tools : [];
  console.log('L3  계약 도구 제한');
  console.log(`    allowlist: ${JSON.stringify(allowedTools)}`);
  console.log(`    denylist: ${JSON.stringify(options.disallowedTools)}`);
  console.log(
    `    판정: ${allowedTools.includes('mcp__nunchi__submit_finding') &&
      !allowedTools.includes('Agent') && options.disallowedTools?.includes('Bash')
      ? '계약 제한 조립됨 (참)'
      : '계약 제한 불일치 (거짓)'}\n`,
  );

  console.log('원장 전체:');
  for (const r of outcome.ledger) {
    console.log(`    ${r.event} ${r.tool ?? ''} ${r.agentType ?? '(main)'} ${r.decision ?? ''}`);
  }
  console.log(`\nsubtype=${outcome.subtype} turns=${outcome.numTurns} cost=$${outcome.totalCostUsd?.toFixed(4) ?? '?'}`);
  console.log('\n--- 메인 스레드 텍스트 ---');
  console.log(outcome.texts.join('\n').slice(0, 1200));
}

main().catch((e: unknown) => {
  console.error('probe failed:', e);
  process.exit(1);
});
