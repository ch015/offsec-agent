/**
 * entryAgent 프로브 — `Options.agent` 가 플러그인 에이전트 이름을 해석하는가.
 *
 * SDK 문서는 "agents 옵션이나 settings 에 정의돼 있어야 한다"(`sdk.d.ts:1336`)고만
 * 적혀 있어 플러그인 제공 에이전트가 되는지는 미확인이다. 되면 위임 홉이 사라져
 * "메인 스레드가 백그라운드 위임 후 턴을 끝내 세션이 죽는" 문제가 구조적으로 없어진다.
 *
 * 실행: pnpm tsx scripts/probe-entry-agent.ts <대상 절대경로>
 */
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { buildPhasePrompt, getOffsecPhase, loadOffsecContract } from '../src/runtime/offsec-contract.js';
import { runSession } from '../src/runtime/session.js';

async function main(): Promise<void> {
  const target = process.argv[2];
  if (!target) {
    console.error('사용: pnpm tsx scripts/probe-entry-agent.ts <대상 절대경로>');
    process.exit(2);
  }

  const contract = loadOffsecContract();
  const phase = getOffsecPhase('converge', contract);
  // 정식 plugin 이름은 계약 role이 아니므로 거부되고, bare 계약 이름만 허용돼야 한다.
  for (const entryAgent of ['nunchi-offsec:offsec-lead', 'offsec-lead']) {
    try {
      const engagementDir = mkdtempSync(join(tmpdir(), 'nunchi-entry-probe-'));
      const outcome = await runSession({
        domain: 'offsec',
        target,
        engagementDir,
        engagementId: 'entry-probe',
        entryAgent,
        agentRole: phase.role,
        phase: phase.id,
        prompt: buildPhasePrompt({ phase, target, engagementDir, contract }),
        model: 'haiku',
        maxTurns: 3,
      });
      const text = outcome.texts.join(' ').replace(/\s+/g, ' ').slice(0, 160);
      const agentTypeSeen = [...new Set(outcome.ledger.map((r) => r.agentType))].filter(Boolean);
      console.log(
        `${entryAgent.padEnd(28)} subtype=${outcome.subtype} ` +
          `agent_type=${JSON.stringify(agentTypeSeen)} :: ${text}`,
      );
    } catch (e) {
      console.log(`${entryAgent.padEnd(28)} ERROR: ${String(e).slice(0, 220)}`);
    }
  }
}

main().catch((e: unknown) => {
  console.error('probe failed:', e);
  process.exit(1);
});
