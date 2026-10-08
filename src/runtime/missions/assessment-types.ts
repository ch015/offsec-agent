import type { PhaseResult } from '../offsec-contract.js';
import type { SessionOutcome } from '../session.js';
export type SemgrepMode = 'required' | 'best-effort' | 'off';
export type WorkUnitMode = 'auto' | 'force';
export type PhaseExecution = { phase: string; role: string; round?: string; result: PhaseResult; outcome: SessionOutcome };
