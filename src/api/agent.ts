import { assessV2, type AssessV2Input, type AssessV2Dependencies } from '../runtime/missions/assess-v2.js';
import { absolutePath, assertSessionConfigured, executeInDirectory, sessionFor, type AgentSessionOptions, type AgentExecutionOptions } from './execution.js';

export type OffsecAgentOptions = AgentSessionOptions & {
  defaults?: Pick<AssessV2Input, 'model' | 'reviewModel' | 'effort' | 'maxTurns' | 'maxBudgetUsd' | 'maxConcurrency' | 'maxFollowupHypotheses' | 'semgrepMode' | 'scope'>;
  runtime?: AssessV2Dependencies['runtime'];
  astBuilder?: AssessV2Dependencies['astBuilder'];
};
export type OffsecRunInput = AssessV2Input & { engagementDir: string };
export type OffsecRunResult = Awaited<ReturnType<typeof assessV2>> & { status: 'published' | 'incomplete' };

/** Embed the existing v2 agent in an application; no Kit, CLI or server startup. */
export function createOffsecAgent(options: OffsecAgentOptions) {
  const settings = { ...options, defaults: { model: 'opus', reviewModel: 'sonnet', ...options.defaults },
    runtime: { backend: 'file' as const, ...options.runtime } };
  assertSessionConfigured(settings);
  return {
    async run(input: OffsecRunInput, execution: AgentExecutionOptions = {}): Promise<OffsecRunResult> {
      absolutePath(input.target, 'target');
      for (const path of input.excludePaths ?? []) absolutePath(path, 'excludePaths');
      return executeInDirectory(input.engagementDir, settings, execution, async engagementDir => {
        const result = await assessV2({ ...settings.defaults, ...input, engagementDir }, {
          runtime: settings.runtime, astBuilder: settings.astBuilder, sessionRunner: sessionFor(settings, execution),
        });
        return { ...result, status: result.coverage.complete ? 'published' : 'incomplete' };
      });
    },
  };
}
export type OffsecAgent = ReturnType<typeof createOffsecAgent>;
