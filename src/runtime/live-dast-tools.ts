import { tool } from '@anthropic-ai/claude-agent-sdk';
import { z } from 'zod';

import { createAdaptiveLiveTestBroker } from './live-test-broker.js';
import { LiveScenarioSchema, type LiveTestProfile } from './live-test-contract.js';
import type { LiveScenarioJournal } from './live-scenario-journal.js';
import type { AuthInteractionSelection, OpaqueAuthSession } from './live-auth-session.js';

export type LiveDastContext = Readonly<{
  engagementDir: string;
  profile: LiveTestProfile;
  profileSha256: string;
  planSha256: string;
  selection: AuthInteractionSelection;
  journal: LiveScenarioJournal;
  authSessions: ReadonlyMap<string, OpaqueAuthSession>;
}>;

export function createLiveDastTools(context: LiveDastContext) {
  const broker = createAdaptiveLiveTestBroker({
    ...context,
  });
  return [
    tool(
      'propose_live_scenario',
      'source/runtime 관찰에서 파생한 한 건의 typed scenario를 host policy 검증에 제출한다.',
      { scenario: LiveScenarioSchema, rationale: z.string().min(1).max(4096) },
      async ({ scenario, rationale }) => {
        try {
          const result = context.journal.propose(scenario, rationale);
          return { content: [{ type: 'text' as const, text: JSON.stringify(result) }] };
        } catch (error) {
          return toolError(error);
        }
      },
    ),
    tool(
      'execute_live_scenario',
      'host가 승인한 scenario 한 건을 actor session과 profile 한계 안에서 실행한다.',
      { scenarioId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/) },
      async (request) => {
        try {
          const receipt = await broker.exchange(request);
          return { content: [{ type: 'text' as const, text: JSON.stringify(receipt) }] };
        } catch (error) {
          return toolError(error);
        }
      },
    ),
  ];
}

function toolError(error: unknown) {
  return {
    content: [{ type: 'text' as const, text: error instanceof Error ? error.message : String(error) }],
    isError: true,
  };
}
