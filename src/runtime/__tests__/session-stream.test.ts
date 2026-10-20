import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, statSync, symlinkSync } from 'node:fs';
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

  it('retains all five structured-output errors and their inputs when the SDK throws after its terminal receipt', async () => {
    const failureText = 'Output does not match required schema: /metrics: must have required property findingCount';
    queryMock.mockImplementation(() => (async function* () {
      for (let n = 1; n <= 5; n++) {
        yield { type: 'assistant', parent_tool_use_id: null, session_id: 'sdk-review', message: { content: [
          { type: 'thinking', thinking: 'private reasoning' },
          { type: 'tool_use', id: `output-${n}`, name: 'StructuredOutput', input: { metrics: {}, summary: `attempt ${n}` } },
        ] } };
        yield { type: 'user', parent_tool_use_id: null, message: { content: [
          { type: 'tool_result', tool_use_id: `output-${n}`, is_error: true,
            content: n % 2 ? failureText : [{ type: 'text', text: failureText }] },
        ] } };
      }
      yield { type: 'result', subtype: 'error_max_structured_output_retries', terminal_reason: 'structured_output_retry_exhausted',
        errors: ['Failed to provide valid structured output after 5 attempts'], num_turns: 5, total_cost_usd: 0.1, modelUsage: {} };
      throw new Error('Claude Code returned an error result');
    })());
    const input = spec(), events: LedgerRow[] = [];
    const runtime = new AnthropicAgentRuntime(runSession);
    let failure: any;
    try {
      await runtime.runPhase({ contractId: 'test', contractVersion: '1', domain: 'offsec', mission: 'assessment',
        phase: 'review', role: 'reviewer', runId: 'run', attempt: 'review:-:1', target: input.target,
        engagementDir: input.engagementDir, prompt: input.prompt, requiredCapabilities: [], onEvent: row => events.push(row) });
    } catch (error) { failure = error; }
    expect(failure?.terminal).toEqual({ subtype: 'error_max_structured_output_retries', reason: 'structured_output_retry_exhausted' });
    const rejected = events.filter(row => row.event === 'StructuredOutputRejected');
    expect(rejected).toHaveLength(5);
    expect(failure.events.filter((row: LedgerRow) => row.event === 'StructuredOutputRejected')).toHaveLength(5);
    for (const [i, row] of rejected.entries()) {
      expect(row.reason).toBe(failureText);
      expect(row.structuredOutput).toMatchObject({ toolCallId: `output-${i + 1}`, submission: i + 1, status: 'error', recorded: true });
    }
    const path = rejected[0]!.structuredOutput!.path;
    const document = JSON.parse(readFileSync(path, 'utf8'));
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(document).toMatchObject({ runId: 'run', attemptId: 'review:-:1', phase: 'review',
      terminal: { subtype: 'error_max_structured_output_retries', errors: { value: ['Failed to provide valid structured output after 5 attempts'] } },
      streamError: { value: 'Claude Code returned an error result' },
      schema: { value: { properties: { artifacts: { items: { enum: ['03_review_result.json'] } } } } } });
    expect(document.submissions.map((s: any) => s.input.value.summary)).toEqual([1, 2, 3, 4, 5].map(n => `attempt ${n}`));
    expect(document.submissions.every((s: any) => s.sessionId === 'sdk-review' && s.result.isError)).toBe(true);
    expect(JSON.stringify(document)).not.toContain('private reasoning');
    expect(JSON.stringify(document)).not.toContain(input.prompt);
    expect(JSON.stringify(events)).not.toContain('"metrics":{}');
  });

  it('correlates retries by tool ID, ignores unrelated and subagent traffic, and preserves a valid final result', async () => {
    const input = spec(), output = { status: 'complete' };
    const submission = { type: 'assistant', parent_tool_use_id: null, message: { content: [
      { type: 'tool_use', id: 'rejected', name: 'StructuredOutput', input: { status: 'bad' } },
    ] } };
    queryMock.mockImplementation(() => (async function* () {
      yield submission;
      yield submission; // Repeated transport delivery must not create another attempt.
      yield { type: 'assistant', parent_tool_use_id: 'child', message: { content: [
        { type: 'tool_use', id: 'child-output', name: 'StructuredOutput', input: { secret: 'child-only' } },
      ] } };
      yield { type: 'user', parent_tool_use_id: null, message: { content: [
        { type: 'tool_result', tool_use_id: 'unrelated', is_error: true, content: 'unrelated source contents' },
        { type: 'tool_result', tool_use_id: 'rejected', is_error: true, content: 'Tool permission denied' },
      ] } };
      yield { type: 'assistant', parent_tool_use_id: null, message: { content: [
        { type: 'tool_use', id: 'accepted', name: 'StructuredOutput', input: output },
      ] } };
      yield { type: 'user', parent_tool_use_id: null, message: { content: [
        { type: 'tool_result', tool_use_id: 'accepted', content: 'Structured output provided successfully' },
      ] } };
      yield { type: 'result', subtype: 'success', structured_output: output, total_cost_usd: 0.1, num_turns: 2 };
    })());
    const outcome = await runSession(input);
    expect(outcome.structuredOutput).toEqual(output);
    expect(outcome.ledger.filter(row => row.event === 'StructuredOutputSubmitted')).toHaveLength(2);
    expect(outcome.ledger.find(row => row.event === 'StructuredOutputRejected')?.reason).toBe('Tool permission denied');
    const accepted = outcome.ledger.find(row => row.event === 'StructuredOutputAccepted')!;
    const document = JSON.parse(readFileSync(accepted.structuredOutput!.path, 'utf8'));
    expect(document.submissions.map((s: any) => s.status)).toEqual(['error', 'success']);
    expect(document.terminal.subtype).toBe('success');
    expect(JSON.stringify(document)).not.toContain('child-only');
    expect(JSON.stringify(document)).not.toContain('unrelated source contents');
  });

  it('durably records a bounded pending submission before the stream breaks without a tool result', async () => {
    const input = spec();
    queryMock.mockImplementation(() => (async function* () {
      yield { type: 'assistant', parent_tool_use_id: null, message: { content: [
        { type: 'tool_use', id: 'pending', name: 'StructuredOutput', input: { summary: 'x'.repeat(100_000) } },
      ] } };
      const dir = join(input.engagementDir, 'session-diagnostics');
      const document = JSON.parse(readFileSync(join(dir, readdirSync(dir)[0]!), 'utf8'));
      expect(document.submissions[0]).toMatchObject({ status: 'pending', input: { truncated: true } });
      expect(document.submissions[0].input.preview.length).toBe(32_768);
      expect(document.submissions[0].input.sha256).toMatch(/^[a-f0-9]{64}$/);
      expect(document.submissions[0].result).toBeUndefined();
      throw new Error('stream disconnected');
    })());
    await expect(runSession(input)).rejects.toMatchObject({ message: 'stream disconnected' });
  });

  it('reports diagnostic write failure without replacing a successful SDK result', async () => {
    const input = spec();
    mkdirSync(input.engagementDir, { recursive: true });
    const outside = mkdtempSync(join(tmpdir(), 'nunchi-diagnostics-outside-'));
    symlinkSync(outside, join(input.engagementDir, 'session-diagnostics'));
    queryMock.mockImplementation(() => (async function* () {
      yield { type: 'assistant', parent_tool_use_id: null, message: { content: [
        { type: 'tool_use', id: 'ok', name: 'StructuredOutput', input: { status: 'complete' } },
      ] } };
      yield { type: 'result', subtype: 'success', structured_output: { status: 'complete' }, total_cost_usd: 0.1 };
    })());
    const outcome = await runSession(input);
    expect(outcome.structuredOutput).toEqual({ status: 'complete' });
    expect(outcome.ledger).toContainEqual(expect.objectContaining({ event: 'StructuredOutputDiagnosticWriteFailed' }));
    expect(outcome.ledger.find(row => row.event === 'StructuredOutputSubmitted')?.structuredOutput?.recorded).toBe(false);
    expect(readdirSync(outside)).toEqual([]);
    expect(existsSync(join(input.engagementDir, 'session-usage'))).toBe(true);
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

  it.each(['ends', 'throws'])('preserves the idle timeout when the cancelled SDK stream %s without a result', async ending => {
    const abortController = new AbortController();
    const reason = new Error('unit review:root idle timeout: 900000ms without provider progress');
    const close = vi.fn();
    queryMock.mockImplementation(() => Object.assign((async function* () {
      yield { type: 'assistant', parent_tool_use_id: null, message: { content: [{ type: 'text', text: 'partial review' }] } };
      abortController.abort(reason);
      if (ending === 'throws') throw new Error('SDK transport closed');
    })(), { close }));
    const input = spec();
    const runtime = new AnthropicAgentRuntime(runSession);
    await expect(runtime.runPhase({ contractId: 'test', contractVersion: '1', domain: 'offsec', mission: 'assessment',
      phase: 'review', role: 'reviewer', runId: 'test', attempt: '1', target: input.target,
      engagementDir: input.engagementDir, prompt: '', requiredCapabilities: [],
      options: { model: 'claude-sonnet-5', abortController },
    })).rejects.toMatchObject({
      message: expect.stringContaining(reason.message),
      usage: { costUsd: 0, accountingComplete: false },
      cause: expect.objectContaining({ name: 'SessionExecutionError', cause: reason }),
    });
    expect(close).toHaveBeenCalled();
  });

  it('rejects a stream that ends without a terminal result even when assistant text contains JSON', async () => {
    queryMock.mockImplementation(() => (async function* () {
      yield { type: 'assistant', parent_tool_use_id: null, message: { content: [{ type: 'text', text: '{"status":"complete"}' }] } };
    })());
    await expect(runSession(spec())).rejects.toMatchObject({
      name: 'SessionExecutionError',
      message: expect.stringContaining('terminal result receipt'),
      outcome: { texts: ['{"status":"complete"}'] },
    });
  });

  it('preserves a delivered usage receipt when cancellation closes the stream without throwing', async () => {
    const abortController = new AbortController();
    const reason = new Error('Run cancelled by user');
    queryMock.mockImplementation(() => (async function* () {
      yield { type: 'result', subtype: 'success', num_turns: 3, total_cost_usd: 1.125,
        modelUsage: { 'claude-sonnet-5': { inputTokens: 10, outputTokens: 5 } } };
      abortController.abort(reason);
    })());
    const input = spec();
    const runtime = new AnthropicAgentRuntime(runSession);
    await expect(runtime.runPhase({ contractId: 'test', contractVersion: '1', domain: 'offsec', mission: 'assessment',
      phase: 'review', role: 'reviewer', runId: 'test', attempt: '1', target: input.target,
      engagementDir: input.engagementDir, prompt: '', requiredCapabilities: [],
      options: { model: 'claude-sonnet-5', abortController },
    })).rejects.toMatchObject({
      message: expect.stringContaining(reason.message),
      usage: { costUsd: 1.125, turns: 3, accountingComplete: true },
      terminal: { subtype: 'success' },
    });
    const directory = join(input.engagementDir, 'session-usage');
    expect(JSON.parse(readFileSync(join(directory, readdirSync(directory)[0]!), 'utf8'))).toMatchObject({ costUsd: 1.125, turns: 3 });
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
