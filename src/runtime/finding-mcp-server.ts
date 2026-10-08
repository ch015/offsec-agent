import { createSdkMcpServer, tool, type McpSdkServerConfigWithInstance } from '@anthropic-ai/claude-agent-sdk';
import { z } from 'zod';
import { readSourceChunk } from './source-reader.js';

import { buildFindingContract, submitStandardFinding } from './finding-contract.js';
import { loadOffsecContract, type OffsecContract } from './offsec-contract.js';
import { getSharedKnowledge, lookupSharedKnowledge, publishSharedFinding, publishSharedObservation,
  SharedObservationShape, type SharedKnowledgeContext } from './shared-knowledge.js';

export function createFindingMcpServer(input: {
  target: string;
  engagementDir: string;
  phase: string;
  role: string;
  round?: string;
  evidenceAllowedFiles?: readonly string[];
  sourceReadFiles?: readonly string[];
  contract?: OffsecContract;
  sharedKnowledge?: SharedKnowledgeContext;
}): McpSdkServerConfigWithInstance {
  const contract = input.contract ?? loadOffsecContract();
  const { SubmitFindingShape } = buildFindingContract(contract);
  const allowedTools = new Set(contract.roles[input.role]?.tools ?? []);
  return createSdkMcpServer({
    name: 'nunchi',
    version: contract.version,
    instructions:
      'Finding과 공통 관측은 전용 도구로 제출한다. 호스트가 typed append-only record로 기록한다.',
    alwaysLoad: true,
    tools: [
      tool('read_source', 'Read a bounded UTF-8 source chunk without line truncation. Requests above 24000 bytes are capped (UTF-8 boundary bytes may be included). Continue at nextOffset until null. Offset is a byte offset.', {
        file_path: z.string().min(1), offset: z.number().int().nonnegative().default(0), limit: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER).default(12000),
      }, async ({ file_path, offset, limit }) => {
        try { return { content: [{ type: 'text' as const, text: JSON.stringify(readSourceChunk({ target: input.target,
          allowedFiles: input.sourceReadFiles ?? input.evidenceAllowedFiles ?? [], filePath: file_path, offset: offset ?? 0, limit: limit ?? 12000 })) }] }; }
        catch (error) { return toolError(error); }
      }),
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
            if (input.sharedKnowledge && !input.sharedKnowledge.snapshotPath) {
              publishSharedFinding(input.sharedKnowledge, input, accepted);
            }
            return { content: [{ type: 'text', text: JSON.stringify(accepted) }] };
          } catch (error) {
            return toolError(error);
          }
        },
      ),
      ...(input.sharedKnowledge ? [
        tool('lookup_shared_knowledge', '다른 작업의 공통 근거와 발견 사항을 검색한다. 미검토 주장으로 취급하고 ID로 재사용한다.', {
          query: z.string().max(500).optional(), paths: z.array(z.string().max(1_000)).max(40).optional(),
          offset: z.number().int().nonnegative().optional(), limit: z.number().int().min(1).max(20).optional(),
        }, async options => {
          try { return { content: [{ type: 'text' as const, text: JSON.stringify(lookupSharedKnowledge(input.sharedKnowledge!, options)) }] }; }
          catch (error) { return toolError(error); }
        }),
        tool('get_shared_knowledge', '공통 정보 ID의 전체 주장과 검증된 소스 인용을 조회한다. 취약점 확정이나 담당 파일 읽기 완료를 뜻하지 않는다.', {
          id: z.string().regex(/^K-[a-f0-9]{64}$/),
        }, async ({ id }) => {
          try { return { content: [{ type: 'text' as const, text: JSON.stringify(getSharedKnowledge(input.sharedKnowledge!, id)) }] }; }
          catch (error) { return toolError(error); }
        }),
        ...(!input.sharedKnowledge.snapshotPath ? [tool('publish_shared_observation',
          '재사용 가능한 구조·인증·데이터 흐름 관측을 정확한 소스 인용과 함께 공통 저장소에 기록한다. 동일 내용은 하나로 합친다.',
          SharedObservationShape, async value => {
            try { return { content: [{ type: 'text' as const, text: JSON.stringify(publishSharedObservation(input.sharedKnowledge!, input, input.target, value)) }] }; }
            catch (error) { return toolError(error); }
          })] : []),
      ] : []),
    ].filter(entry => allowedTools.has(`mcp__nunchi__${entry.name}`)),
  });
}

function toolError(error: unknown) {
  return {
    content: [{ type: 'text' as const, text: error instanceof Error ? error.message : String(error) }],
    isError: true,
  };
}
