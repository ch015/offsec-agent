import type { SessionSpec, SessionOutcome } from './session.js';
export type { SessionSpec, SessionOutcome, LedgerRow } from './session.js';
export { DOMAINS } from './session-types.js';

/** Importing an embedded agent does not start or load the SDK execution stack. */
export async function runSession(spec: SessionSpec): Promise<SessionOutcome> {
  spec.abortController?.signal.throwIfAborted();
  const { runSession: run } = await import('./session.js');
  spec.abortController?.signal.throwIfAborted();
  return run(spec);
}
