import { mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { beforeEach, describe, expect, it, vi } from 'vitest';

const queryMock = vi.hoisted(() => vi.fn());

vi.mock('@anthropic-ai/claude-agent-sdk', async (importOriginal) => ({
  ...(await importOriginal()),
  query: queryMock,
}));

import { runSession, type LedgerRow, type SessionSpec } from '../session.js';
import { AnthropicAgentRuntime } from '../providers/anthropic-agent-sdk.js';
import { SessionExecutionError } from '../session-types.js';

function spec(overrides: Partial<SessionSpec> = {}): SessionSpec {
  const target = mkdtempSync(join(tmpdir(), 'nunchi-session-stream-'));
  return {
    domain: 'offsec',
    phase: 'analyze',
    target,
    prompt: 'host prompt with user-secret-source-content',
    engagementDir: join(target, 'reports', 'run'),
    engagementId: 'run',
    ...overrides,
  };
}

describe('runSession compact boundary transport', () => {
  beforeEach(() => {
    queryMock.mockReset();
  });

  it('emits throttled stream heartbeats and provider retry pressure without storing partial reasoning or tool arguments', async () => {
    queryMock.mockImplementation(({ options }) => {
      expect(options.includePartialMessages).toBe(true);
      return (async function* () {
        for (let index = 0; index < 4; index++) yield { type: 'stream_event', parent_tool_use_id: null,
          event: { type: 'content_block_delta', delta: { type: 'thinking_delta', thinking: 'private partial reasoning and source content' } } };
        yield { type: 'system', subtype: 'api_retry', attempt: 1, max_retries: 3, retry_delay_ms: 2500, error_status: 429, error: 'rate_limit' };
        yield { type: 'result', subtype: 'success', total_cost_usd: 0.1, num_turns: 1, modelUsage: {} };
      })();
    });
    const progress = vi.fn(), input = spec({ onProgress: progress });
    const outcome = await runSession(input);
    expect(progress).toHaveBeenCalledTimes(1);
    expect(progress).toHaveBeenCalledWith({ kind: 'heartbeat', from: 'provider', detail: '' });
    expect(outcome.ledger).toContainEqual(expect.objectContaining({ event: 'ProviderPressure', retryAfterMs: 2500 }));
    expect(JSON.stringify(outcome)).not.toContain('private partial reasoning');
    const runtime = new AnthropicAgentRuntime(async () => outcome);
    const normalized = await runtime.runPhase({ contractId: 'test', contractVersion: '1', domain: 'offsec', mission: 'assessment', phase: 'analyze',
      role: 'analyzer', runId: 'test', attempt: '1', target: input.target, engagementDir: input.engagementDir, prompt: '', requiredCapabilities: [] });
    expect(normalized.events).toContainEqual(expect.objectContaining({ event: 'ProviderPressure', retryAfterMs: 2500 }));
  });

  it('persists cost immediately and preserves it when a result is followed by a stream error', async () => {
    queryMock.mockImplementation(() => (async function* () {
      yield { type: 'result', subtype: 'error_max_turns', num_turns: 3, total_cost_usd: 1.125,
        errors: ['turn limit'], modelUsage: { 'claude-opus-4-6': { inputTokens: 10, outputTokens: 5 } } };
      throw new Error('stream failed after result');
    })());
    const input = spec();
    let failure: SessionExecutionError | undefined;
    try { await runSession(input); } catch (error) { failure = error as SessionExecutionError; }
    expect(failure).toBeInstanceOf(SessionExecutionError);
    expect(failure!.outcome.totalCostUsd).toBe(1.125);
    const directory = join(input.engagementDir, 'session-usage');
    const receipt = JSON.parse(readFileSync(join(directory, readdirSync(directory)[0]!), 'utf8'));
    expect(receipt).toMatchObject({ costUsd: 1.125, turns: 3, subtype: 'error_max_turns' });
    expect(JSON.stringify(receipt)).not.toContain(input.prompt);
    const runtime = new AnthropicAgentRuntime(async () => { throw failure; });
    await expect(runtime.runPhase({ contractId: 'test', contractVersion: '1', domain: 'offsec', mission: 'assessment',
      phase: 'analyze', role: 'analyzer', runId: 'test', attempt: '1', target: input.target,
      engagementDir: input.engagementDir, prompt: '', requiredCapabilities: [],
    })).rejects.toMatchObject({ message: expect.stringContaining('subtype=error_max_turns'),
      terminal: { subtype: 'error_max_turns' }, usage: { costUsd: 1.125, turns: 3, accountingComplete: true } });
  });

  it('does not turn a missing usage receipt into confirmed zero spend', async () => {
    queryMock.mockImplementation(() => (async function* () { throw new Error('stream disconnected before usage'); })());
    const input = spec();
    const runtime = new AnthropicAgentRuntime(runSession);
    await expect(runtime.runPhase({ contractId: 'test', contractVersion: '1', domain: 'offsec', mission: 'assessment',
      phase: 'analyze', role: 'analyzer', runId: 'test', attempt: '1', target: input.target,
      engagementDir: input.engagementDir, prompt: '', requiredCapabilities: [],
    })).rejects.toMatchObject({ usage: { accountingComplete: false } });
  });

  it('emits typed compact metadata without persisting summary or source text', async () => {
    queryMock.mockImplementation(() => {
      const stream = (async function* () {
        yield { type: 'system', subtype: 'init' };
        yield {
          type: 'system',
          subtype: 'compact_boundary',
          uuid: 'boundary-stream-1',
          session_id: 'session-1',
          compact_metadata: {
            trigger: 'auto',
            pre_tokens: 2400,
            post_tokens: 640,
            duration_ms: 22,
          },
        };
        yield {
          type: 'result',
          subtype: 'success',
          result: '{"status":"complete"}',
          structured_output: { status: 'complete' },
          num_turns: 2,
          total_cost_usd: 0.1,
          modelUsage: {},
        };
      })();
      return Object.assign(stream, { supportedAgents: async () => [] });
    });

    const rows: LedgerRow[] = [];
    await runSession(spec({ onLedger: (row) => rows.push(row) }));

    expect(rows).toEqual(expect.arrayContaining([
      expect.objectContaining({
        event: 'compact_boundary',
        compaction: {
          trigger: 'auto',
          preTokens: 2400,
          postTokens: 640,
          durationMs: 22,
          boundaryId: 'boundary-stream-1',
        },
      }),
    ]));
    const serialized = JSON.stringify(rows);
    expect(serialized).not.toContain('compact_summary');
    expect(serialized).not.toContain('summary produced from user-secret-source-content');
    expect(serialized).not.toContain('user-secret-source-content');
  });
});
