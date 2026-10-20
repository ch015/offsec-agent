import { createHash, randomUUID } from 'node:crypto';
import { join } from 'node:path';
import type { LedgerRow, SessionSpec } from './session-types.js';
import { atomicPrivateWrite } from './workflow/storage-files.js';

// Only final-output tool traffic belongs here, never prompts, reasoning or other tools.
const MAX_CAPTURE_CHARS = 32_768;
function capture(value: unknown) {
  const json = JSON.stringify(value) ?? 'null';
  return {
    sha256: createHash('sha256').update(json).digest('hex'),
    byteLength: Buffer.byteLength(json),
    ...(json.length <= MAX_CAPTURE_CHARS
      ? { truncated: false, value }
      : { truncated: true, preview: json.slice(0, MAX_CAPTURE_CHARS) }),
  };
}

export type StructuredOutputDiagnosticRef = {
  path: string;
  toolCallId: string;
  submission: number;
  status: 'pending' | 'error' | 'success';
  recorded: boolean;
};

type Submission = {
  toolCallId: string;
  submission: number;
  submittedAt: string;
  sessionId?: string;
  input: ReturnType<typeof capture>;
  status: StructuredOutputDiagnosticRef['status'];
  result?: { at: string; isError: boolean; content: ReturnType<typeof capture> };
};

/** Persist before emitting events so a subsequent SDK throw cannot discard the evidence. */
export function structuredOutputDiagnostics(
  spec: Pick<SessionSpec, 'engagementDir' | 'engagementId' | 'attemptId' | 'phase' | 'phaseRound' | 'model' | 'agentRole'>,
  schema: unknown,
  emit: (row: LedgerRow) => void,
) {
  const path = join(spec.engagementDir, 'session-diagnostics', `${randomUUID()}.json`);
  const submissions = new Map<string, Submission>();
  const document = {
    version: 1, runId: spec.engagementId, attemptId: spec.attemptId,
    phase: spec.phase, round: spec.phaseRound, model: spec.model,
    schema: capture(schema),
    submissions: [] as Submission[],
    terminal: undefined as { at: string; subtype: string; reason?: string; errors?: ReturnType<typeof capture> } | undefined,
    streamError: undefined as ReturnType<typeof capture> | undefined,
  };
  const persist = (): boolean => {
    try {
      atomicPrivateWrite(path, JSON.stringify(document) + '\n');
      return true;
    } catch (error) {
      // Diagnostics must not turn an otherwise valid provider result into a failed run.
      emit({ at: new Date().toISOString(), event: 'StructuredOutputDiagnosticWriteFailed',
        tool: 'StructuredOutput', resource: path, agentType: spec.agentRole,
        reason: error instanceof Error ? error.message : String(error) });
      return false;
    }
  };
  const record = (entry: Submission, event: string, reason?: string) => {
    const recorded = persist();
    emit({ at: new Date().toISOString(), event, tool: 'StructuredOutput', agentType: spec.agentRole,
      reason, structuredOutput: { path, toolCallId: entry.toolCallId,
        submission: entry.submission, status: entry.status, recorded } });
  };
  return {
    submitted(toolCallId: string, input: unknown, sessionId?: string) {
      if (submissions.has(toolCallId)) return;
      const entry: Submission = { toolCallId, input: capture(input), sessionId,
        submission: submissions.size + 1, submittedAt: new Date().toISOString(), status: 'pending' };
      submissions.set(toolCallId, entry);
      document.submissions.push(entry);
      record(entry, 'StructuredOutputSubmitted');
    },
    received(toolCallId: string, content: unknown, isError?: boolean) {
      const entry = submissions.get(toolCallId);
      if (!entry || entry.result) return;
      entry.status = isError === true ? 'error' : 'success';
      entry.result = { at: new Date().toISOString(), isError: isError === true, content: capture(content) };
      const text = typeof content === 'string' ? content : Array.isArray(content)
        ? content.filter(block => block?.type === 'text' && typeof block.text === 'string').map(block => block.text).join('\n') : '';
      // An error may also be a permission/tool failure. Preserve SDK wording; do not relabel it as a schema mismatch.
      record(entry, isError === true ? 'StructuredOutputRejected' : 'StructuredOutputAccepted',
        isError === true ? text.slice(0, 2048) || 'SDK tool_result reported an error; see diagnostic receipt' : undefined);
    },
    terminal(subtype: string, reason?: string, errors?: string[]) {
      if (!submissions.size && subtype !== 'error_max_structured_output_retries') return;
      document.terminal = { at: new Date().toISOString(), subtype, reason,
        ...(errors ? { errors: capture(errors) } : {}) };
      persist();
    },
    streamFailed(error: unknown) {
      if (!submissions.size && !document.terminal) return;
      document.streamError = capture(error instanceof Error ? error.message : String(error));
      persist();
    },
  };
}
