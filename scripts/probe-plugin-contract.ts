/**
 * 플러그인 계약 프로브
 *
 * 이식 전체가 걸려 있는 세 가지 사실을 실험으로 확인한다. 추론이 아니라 관측이다.
 *
 *   F1  SDK의 `plugins: [{type:'local'}]`가 플러그인의 hooks/hooks.json 커맨드 훅을
 *       실제로 실행하는가          → shared 플러그인의 marker.cjs가 원장에 쓰면 참
 *   F2  플러그인의 agents/**\/*.md가 서브에이전트로 등록되는가, 하위 디렉토리는
 *       이름에 어떻게 반영되는가   → supportedAgents() 출력으로 판정
 *   F3  프론트매터 `tools:`가 서브에이전트 도구를 실제로 제한하는가
 *       → 권한을 bypass 한 상태에서 Bash 사용을 유도했을 때 못 쓰면 참
 *          (권한이 아니라 도구 노출이 원인임을 분리하기 위해 bypassPermissions를 쓴다)
 *
 * 실행: pnpm tsx scripts/probe-plugin-contract.ts
 */
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { query, type HookInput, type Options, type SDKMessage } from '@anthropic-ai/claude-agent-sdk';

const FIXTURES = resolve(import.meta.dirname, 'probe-fixtures');

type LedgerRow = {
  source: string;
  label?: string;
  hook_event_name?: string | null;
  tool_name?: string | null;
  agent_id?: string | null;
  agent_type?: string | null;
};

/**
 * settingSources 가 플러그인 훅 발화의 원인 변수인지 가르기 위해 CLI 인자로 받는다.
 *   --setting-sources=          → [] (격리, 우리의 목표 설정)
 *   --setting-sources=project   → ['project']
 */
function parseSettingSources(): Options['settingSources'] {
  const arg = process.argv.find((a) => a.startsWith('--setting-sources='));
  if (arg === undefined) return [];
  const raw = arg.slice('--setting-sources='.length);
  if (raw === '') return [];
  return raw.split(',') as NonNullable<Options['settingSources']>;
}

async function main(): Promise<void> {
  const workdir = mkdtempSync(join(tmpdir(), 'nunchi-probe-'));
  const ledgerPath = join(workdir, 'command-hooks.jsonl');
  writeFileSync(ledgerPath, '');
  // 서브에이전트가 Read 할 대상 — 도구가 살아 있는지 확인하는 대조군
  writeFileSync(join(workdir, 'target.txt'), 'PROBE_TARGET_CONTENT\n');

  const inProcess: LedgerRow[] = [];
  const record = (input: HookInput): void => {
    inProcess.push({
      source: 'in-process-hook',
      hook_event_name: input.hook_event_name,
      tool_name: 'tool_name' in input ? String(input.tool_name) : null,
      agent_id: input.agent_id ?? null,
      agent_type: input.agent_type ?? null,
    });
  };

  const options: Options = {
    cwd: workdir,
    model: 'haiku',
    // 격리: 사용자/프로젝트 settings.json 과 외부 MCP 를 차단한다
    settingSources: parseSettingSources(),
    strictMcpConfig: true,
    // 권한을 통과시켜 F3의 원인을 "도구 노출"로 좁힌다
    permissionMode: 'bypassPermissions',
    allowDangerouslySkipPermissions: true,
    maxTurns: 12,
    plugins: [
      { type: 'local', path: join(FIXTURES, 'shared') },
      { type: 'local', path: join(FIXTURES, 'group') },
    ],
    env: { ...process.env, PROBE_LEDGER: ledgerPath },
    // H2: Options.settings 인라인 훅. ${CLAUDE_PLUGIN_ROOT} 는 여기서 해석되지 않으므로
    // install.sh 가 설치 시 하던 것과 동일하게 절대경로를 직접 넣는다.
    settings: {
      hooks: {
        SessionStart: [
          {
            hooks: [
              {
                type: 'command',
                command: `node ${join(FIXTURES, 'shared', 'hooks', 'marker.cjs')} settings-inline-SessionStart`,
                timeout: 10,
              },
            ],
          },
        ],
        PreToolUse: [
          {
            matcher: 'Read',
            hooks: [
              {
                type: 'command',
                command: `node ${join(FIXTURES, 'shared', 'hooks', 'marker.cjs')} settings-inline-PreToolUse-Read`,
                timeout: 10,
              },
            ],
          },
        ],
      },
    },
    hooks: {
      PreToolUse: [{ hooks: [async (i) => (record(i), { continue: true })] }],
      SubagentStart: [{ hooks: [async (i) => (record(i), { continue: true })] }],
      SubagentStop: [{ hooks: [async (i) => (record(i), { continue: true })] }],
    },
    stderr: (d) => {
      if (/error|Error|ENOENT/.test(d)) process.stderr.write(`[cli] ${d}`);
    },
  };

  const prompt = [
    '아래를 정확히 수행하고 그 외에는 아무것도 하지 마라.',
    '0. 먼저 Read 도구로 target.txt 를 읽어라. (플러그인 PreToolUse 훅 발화 확인용)',
    // F5: bare 이름이 통하는지 확인한다. supportedAgents()에는 네임스페이스 형태만
    // 나오지만, 위임 시 bare 가 해석되는지는 별개 사실이다.
    "1. Agent 도구를 subagent_type='probe-limited' (네임스페이스 없는 bare 이름) 로 호출하고,",
    '   그 프롬프트로 다음을 준다:',
    '   "Bash 도구로 `echo PROBE_BASH_RAN` 을 실행하라. Bash 도구를 쓸 수 없으면',
    '    정확히 BASH_UNAVAILABLE 이라고만 답하고 멈춰라. 그 다음 Read 도구로 target.txt 를',
    '    읽어 첫 줄을 보고하라."',
    '2. 서브에이전트의 최종 답변을 SUBAGENT_SAID: 로 시작하는 한 줄로 그대로 옮겨라.',
  ].join('\n');

  const q = query({ prompt, options });

  let agentsSnapshot: unknown = null;
  const texts: string[] = [];
  let result: SDKMessage | null = null;

  for await (const message of q) {
    if (message.type === 'system' && message.subtype === 'init') {
      // init 직후가 등록된 에이전트 목록을 묻기에 가장 이른 지점이다
      agentsSnapshot = await q.supportedAgents().catch((e: unknown) => ({ error: String(e) }));
    }
    if (message.type === 'assistant') {
      for (const block of message.message.content) {
        if (block.type === 'text') texts.push(block.text);
      }
    }
    if (message.type === 'result') result = message;
  }

  const commandHookRows: LedgerRow[] = existsSync(ledgerPath)
    ? readFileSync(ledgerPath, 'utf8')
        .split('\n')
        .filter(Boolean)
        .map((l) => JSON.parse(l) as LedgerRow)
    : [];

  const subagentToolCalls = inProcess.filter((r) => r.agent_id);

  console.log('\n================ 관측 결과 ================\n');

  console.log('F1  플러그인 커맨드 훅 실행 여부');
  console.log(`    커맨드 훅 원장 행 수: ${commandHookRows.length}`);
  for (const r of commandHookRows) console.log(`      ${JSON.stringify(r)}`);
  console.log(`    판정: ${commandHookRows.length > 0 ? '실행됨 (참)' : '실행 안 됨 (거짓)'}\n`);

  console.log('F2  플러그인 에이전트 등록 및 이름');
  console.log(`    supportedAgents(): ${JSON.stringify(agentsSnapshot, null, 2)}\n`);

  console.log('F3  프론트매터 tools: 제한');
  console.log(`    서브에이전트가 호출한 도구: ${JSON.stringify(subagentToolCalls)}`);
  const saidUnavailable = texts.join('\n').includes('BASH_UNAVAILABLE');
  const bashBySubagent = subagentToolCalls.some((r) => r.tool_name === 'Bash');
  console.log(`    BASH_UNAVAILABLE 응답: ${saidUnavailable}`);
  console.log(`    서브에이전트의 Bash 호출 관측: ${bashBySubagent}`);
  console.log(
    `    판정: ${
      bashBySubagent
        ? '제한 실패 — tools: 에 없는 Bash가 호출됨'
        : saidUnavailable
          ? '제한 성립 (참)'
          : '판정 불가 — 서브에이전트가 Bash를 시도하지 않음'
    }\n`,
  );

  console.log('메인 스레드 최종 텍스트:');
  console.log(texts.join('\n').slice(0, 1500));
  console.log('\n인프로세스 훅 전체:');
  for (const r of inProcess) console.log(`      ${JSON.stringify(r)}`);
  if (result && result.type === 'result') {
    console.log(
      `\nresult: subtype=${result.subtype} turns=${result.num_turns} cost=$${result.total_cost_usd?.toFixed?.(4) ?? '?'}`,
    );
  }
  console.log(`\n작업 디렉토리: ${workdir}`);
}

main().catch((e: unknown) => {
  console.error('probe failed:', e);
  process.exit(1);
});
