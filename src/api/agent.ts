import { allocateRunLocation } from '../runtime/workflow/run-location.js';
import { resumeAssessV2, assessV2, type AssessV2Input, type AssessV2Dependencies, type AssessV2ResumeOptions } from '../runtime/missions/assess-v2.js';
import { absolutePath, assertSessionConfigured, executeInDirectory, sessionFor, type AgentSessionOptions, type AgentExecutionOptions } from './execution.js';

export type OffsecAgentOptions = AgentSessionOptions & {
  defaults?: Pick<AssessV2Input, 'mode' | 'tools' | 'model' | 'reviewModel' | 'effort' | 'maxTurns' | 'costPolicy' | 'maxBudgetUsd' | 'noCostGuard' | 'maxConcurrency' | 'maxFilesPerAgent' | 'maxSourceTokensPerAgent' | 'maxFollowupHypotheses' | 'semgrepMode' | 'scope'>;
  runtime?: AssessV2Dependencies['runtime'];
  astBuilder?: AssessV2Dependencies['astBuilder'];
  scheduler?: AssessV2Dependencies['scheduler'];
  onEvent?: AssessV2Dependencies['onEvent'];
};
export type OffsecRunInput = AssessV2Input;
export type OffsecResumeOptions = AgentExecutionOptions & AssessV2ResumeOptions;
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
      execution.signal?.throwIfAborted();
      if (!input.engagementDir) input = { ...input, ...allocateRunLocation(input) };
      return executeInDirectory(input.engagementDir!, settings, execution, async engagementDir => {
        const result = await assessV2({ ...settings.defaults, ...input, engagementDir }, {
          runtime: settings.runtime, astBuilder: settings.astBuilder, scheduler: settings.scheduler, onEvent: settings.onEvent, signal: execution.signal, sessionRunner: sessionFor(settings, execution),
        });
        return { ...result, status: result.publicationStatus === 'published' && result.coverage.complete ? 'published' : 'incomplete' };
      });
    },
    async resume(engagementDir: string, execution: OffsecResumeOptions = {}): Promise<OffsecRunResult> {
      return executeInDirectory(engagementDir, settings, execution, async directory => {
        const result = await resumeAssessV2(directory, { runtime: settings.runtime, astBuilder: settings.astBuilder, scheduler: settings.scheduler, onEvent: settings.onEvent, signal: execution.signal, sessionRunner: sessionFor(settings, execution) }, execution);
        return { ...result, status: result.publicationStatus === 'published' && result.coverage.complete ? 'published' : 'incomplete' };
      });
    },
  };
}
export type OffsecAgent = ReturnType<typeof createOffsecAgent>;
