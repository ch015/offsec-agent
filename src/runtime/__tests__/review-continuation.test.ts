import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { afterEach, describe, expect, it } from 'vitest';
import { createOffsecAgent } from '../../index.js';
import { buildOptions } from '../session.js';
import { SessionExecutionError } from '../session-types.js';
import { submitStandardFinding } from '../finding-contract.js';
import { syntheticOutcome } from './resumption-fixture.js';
import { deliveryFixture } from './assessment-protocol-fixture.js';
import { FileRunStateStore } from '../workflow/state-store.js';
import { loadReviewProgress } from '../review-progress.js';

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
describe('bounded review continuation', () => {
  it.each([false, true])('continues only verified progress and stops on no progress=%s', async noProgress => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'review-continuation-'))); roots.push(root);
    const target = join(root, 'source'), engagementDir = join(root, 'run'); mkdirSync(target);
    const lines = ['export const a = 1;', 'export const b = 2;']; writeFileSync(join(target, 'app.ts'), lines.join('\n') + '\n');
    const ids: string[] = [], calls: string[] = [], observed: any[] = []; let reviews = 0;
    const agent = createOffsecAgent({ astBuilder: async () => ({ ok: false }),
      scheduler: { retryBaseMs: 1, controlIntervalMs: 1, resourceCapacity: () => 10 }, onEvent: event => observed.push(event),
      sessionRunner: async spec => {
        calls.push(spec.phase!);
        const path = join(spec.engagementDir, '03_review_result.json');
        const prior = spec.phase === 'review' && existsSync(path) ? readFileSync(path) : undefined;
        const outcome = syntheticOutcome(spec);
        if (prior) writeFileSync(path, prior);
        if (spec.workUnit) for (const [index, quote] of lines.entries()) ids.push(submitStandardFinding({
          target: spec.target, engagementDir: spec.engagementDir, phase: 'analyze', role: 'analyzer', finding: {
            title: `Fixture ${index} needs a consuming component`, verdict: 'supported', severity: 'LOW', evidenceClass: 'configuration', reachability: 'plausible',
            preconditions: ['A sensitive downstream consumer'], severityRationale: 'Potential impact requires a consumer', confidence: 0.3,
            impact: 'Unverified downstream use', remediation: 'Review consuming behavior', standards: [], unresolved: [],
            evidence: [{ path: 'app.ts', lineStart: index + 1, lineEnd: index + 1, quote }],
          } }).id);
        if (spec.phase === 'review') {
          reviews++; expect(spec.maxTurns).toBe(2);
          for (const row of outcome.ledger) spec.onLedger?.(row);
          const continuation = spec.taskData?.reviewContinuation as any;
          if (reviews > 1) {
            expect(continuation.reviewedIds).toHaveLength(Math.min(reviews - 1, 2));
            expect(spec.taskData?.reviewReuse).toBeDefined();
            expect(spec.prompt).not.toContain('outputHash');
          }
          if (reviews <= 2) {
            if (!noProgress || reviews === 1) {
              const ledger = deliveryFixture(spec, join(spec.target, 'app.ts')).map(row => ({ ...row, agentType: 'reviewer' }));
              outcome.ledger.push(...ledger);
              const options = buildOptions(spec, ledger), pre = options.hooks!.PreToolUse![0]!.hooks[0]!, post = options.hooks!.PostToolUse![0]!.hooks[0]!;
              const input = { hook_event_name: 'PreToolUse' as const, tool_use_id: `batch-${reviews}`, session_id: 'fixture', transcript_path: '', cwd: engagementDir,
                tool_name: 'Write', tool_input: { file_path: path, content: JSON.stringify({ reviewPatch: true, reviewedFindings: [{ originalFindingId: ids[reviews - 1], action: 'inconclusive', reason: 'Original source examined; a sensitive downstream consumer remains unproven.' }] }) } };
              const context = { signal: new AbortController().signal };
              const result = await pre(input, input.tool_use_id, context) as any;
              expect(result.hookSpecificOutput.permissionDecision, result.hookSpecificOutput.permissionDecisionReason).toBe('allow');
              writeFileSync(path, result.hookSpecificOutput.updatedInput.content);
              await post({ ...input, hook_event_name: 'PostToolUse', tool_response: 'written' }, input.tool_use_id, context);
            }
            throw new SessionExecutionError({ ...outcome, subtype: 'error_max_turns', terminalReason: 'max_turns', numTurns: 3 }, new Error('Reached maximum number of turns (2)'));
          }
          const options = buildOptions(spec, []), pre = options.hooks!.PreToolUse![0]!.hooks[0]!, post = options.hooks!.PostToolUse![0]!.hooks[0]!;
          const input = { hook_event_name: 'PreToolUse' as const, tool_use_id: 'finalize', session_id: 'fixture', transcript_path: '', cwd: engagementDir,
            tool_name: 'Write', tool_input: { file_path: path, content: '{"reviewPatch":true,"finalize":true}' } };
          const context = { signal: new AbortController().signal };
          const final = await pre(input, input.tool_use_id, context) as any;
          expect(final.hookSpecificOutput.permissionDecision, final.hookSpecificOutput.permissionDecisionReason).toBe('allow');
          writeFileSync(path, final.hookSpecificOutput.updatedInput.content);
          await post({ ...input, hook_event_name: 'PostToolUse', tool_response: 'written' }, input.tool_use_id, context);
        }
        if (spec.phase === 'evaluate') throw new SessionExecutionError(outcome, new Error('403 fixture stops after completed review'));
        return outcome;
      } });
    const result = await agent.run({ target, engagementDir, engagementId: 'continuation-test', mode: 'ast', tools: [], maxTurns: 2 });
    expect(result.status).toBe('incomplete'); // Deliberate evaluator/no-progress stop.
    expect(calls.filter(phase => phase === 'analyze')).toHaveLength(1);
    expect(reviews).toBe(noProgress ? 2 : 3);
    expect(observed.filter(event => event.event === 'ReviewContinuationScheduled')).toHaveLength(noProgress ? 1 : 2);
    const state = FileRunStateStore.open(engagementDir).read();
    expect(Object.values(state.attempts).filter(attempt => attempt.phase === 'review' && attempt.status === 'completed')).toHaveLength(noProgress ? 0 : 1);
    expect(Object.values(state.attempts).filter(attempt => attempt.phase === 'review' && attempt.status === 'failed').every(attempt => attempt.failureReason?.includes('error_max_turns'))).toBe(true);
    const model = (Object.values(state.attempts).find(attempt => attempt.phase === 'review')!.usage!.model)!;
    expect(loadReviewProgress({ engagementDir, target: join(engagementDir, 'source-snapshot'), runId: state.runId, model, revision: 0 })?.remainingIds).toHaveLength(noProgress ? 1 : 0);
  }, 20000);
});
