import { createSdkMcpServer, tool, type McpSdkServerConfigWithInstance } from '@anthropic-ai/claude-agent-sdk';
import { z } from 'zod';

import { buildFindingContract, submitStandardFinding } from './finding-contract.js';
import { createLiveDastTools, type LiveDastContext } from './live-dast-tools.js';
import { createLiveTestBroker } from './live-test-broker.js';
import { SubmitObjectionShape, submitStandardObjection } from './objection-contract.js';
import { loadOffsecContract, type OffsecContract } from './offsec-contract.js';

export function createFindingMcpServer(input: {
  target: string;
  engagementDir: string;
  phase: string;
  role: string;
  round?: string;
  liveTestTarget?: string;
  liveTestPlan?: { path: string; sha256: string };
  liveDastContext?: LiveDastContext;
  evidenceAllowedFiles?: readonly string[];
  contract?: OffsecContract;
}): McpSdkServerConfigWithInstance {
  const contract = input.contract ?? loadOffsecContract();
  const isV2 = contract.version.startsWith('2.');
  const { SubmitFindingShape } = buildFindingContract(contract);
  const liveTestBroker = !input.liveDastContext && input.phase === 'pentest' && input.liveTestTarget && input.liveTestPlan
    ? createLiveTestBroker({
        engagementDir: input.engagementDir,
        allowedBaseUrl: input.liveTestTarget,
        planPath: input.liveTestPlan.path,
        planSha256: input.liveTestPlan.sha256,
      })
    : undefined;
  return createSdkMcpServer({
    name: 'nunchi',
    version: contract.version,
    instructions:
      'Finding과 verifier objection은 전용 도구로 제출한다. 호스트가 typed append-only record로 기록한다.',
    alwaysLoad: true,
    tools: [
      tool(
        'submit_finding',
        '검증 가능한 보안 Finding을 표준 계약으로 제출한다.',
        SubmitFindingShape,
        async (finding) => {
          try {
            const accepted = submitStandardFinding({
              ...input,
              finding: finding as Parameters<typeof submitStandardFinding>[0]['finding'],
              contract,
            });
            return { content: [{ type: 'text', text: JSON.stringify(accepted) }] };
          } catch (error) {
            return toolError(error);
          }
        },
      ),
      // submit_objection은 verifier/objection 시스템이 있는 v1 계약에서만 등록한다.
      ...(!isV2 ? [tool(
        'submit_objection',
        'Verifier의 미해결 반론을 호스트 원장에 제출한다. 반환된 findingId/type/reason/instruction을 YAML에 문자 그대로 복사해야 하며 요약·재작성하지 않는다.',
        SubmitObjectionShape,
        async (objection) => {
          try {
            const accepted = submitStandardObjection({
              engagementDir: input.engagementDir,
              contractVersion: contract.version,
              phase: input.phase,
              role: input.role,
              round: input.round,
              objection,
            });
            return { content: [{ type: 'text', text: JSON.stringify(accepted) }] };
          } catch (error) {
            return toolError(error);
          }
        },
      )] : []),
      ...(liveTestBroker ? [tool(
        'http_probe',
        '승인된 테스트 URL prefix 안에서 GET/HEAD 한 건을 실행하고 host receipt를 반환한다.',
        {
          scenarioId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/),
          accept: z.string().max(256).optional(),
        },
        async (request) => {
          try {
            const receipt = await liveTestBroker.probe(request);
            return { content: [{ type: 'text', text: JSON.stringify(receipt) }] };
          } catch (error) {
            return toolError(error);
          }
        },
      )] : []),
      ...(input.liveDastContext ? createLiveDastTools(input.liveDastContext) : []),
    ],
  });
}

function toolError(error: unknown) {
  return {
    content: [{ type: 'text' as const, text: error instanceof Error ? error.message : String(error) }],
    isError: true,
  };
}
