import type { Options } from '@anthropic-ai/claude-agent-sdk';

import type { LiveDastContext } from './live-dast-tools.js';

export const DOMAINS = ['offsec'] as const;
export type Domain = (typeof DOMAINS)[number];

/** A transport failure must not discard a result receipt already delivered by the SDK. */
export class SessionExecutionError extends Error {
  constructor(readonly outcome: import('./session.js').SessionOutcome, cause: unknown) {
    super(cause instanceof Error ? cause.message : String(cause), { cause });
    this.name = 'SessionExecutionError';
  }
}

export type SessionSpec = {
  /** Per-session credentials; never written to mission artifacts or process.env. */
  apiKey?: string;
  authMode?: 'api_key' | 'oauth';
  domain: Domain;
  mission?: string;
  /** Current assessment contract path; omission selects the bundled contract. */
  contractPath?: string;
  entryAgent?: string;
  agentRole?: string;
  phase?: string;
  phaseRound?: string;
  verifyRound?: string;
  verifyGroup?: string;
  requirePocBinding?: boolean;
  target: string;
  prompt: string;
  /** Host-owned phase input; never accepted from model tool arguments. */
  taskData?: Record<string, unknown>;
  engagementDir: string;
  engagementId: string;
  /** Host attempt identity used to reconcile durable usage receipts. */
  attemptId?: string;
  model?: string;
  effort?: NonNullable<Options['effort']>;
  maxTurns?: number;
  maxBudgetUsd?: number;
  sharedKnowledge?: import('./shared-knowledge.js').SharedKnowledgeContext;
  networkAllowedDomains?: readonly string[];
  liveTestTarget?: string;
  liveTestPlan?: { path: string; sha256: string };
  liveDastContext?: LiveDastContext;
  allowedReadFiles?: readonly string[];
  readScope?: 'default' | 'exact';
  disabledTools?: readonly string[];
  workUnit?: {
    unitKey: string;
    workPlanSha256: string;
    assignedSourceSha256: string;
    ownedSourceFiles: readonly string[];
    /** Explicit cross-unit flow ownership may cite both endpoints. */
    findingSourceFiles?: readonly string[];
    contextSourceFiles: readonly string[];
    sourceFiles: readonly string[];
  };
  onLedger?: (row: LedgerRow) => void;
  /** #9: verify-feedback에서 초기 verify의 tool ledger를 carry-forward (autonomous seal coverage용) */
  priorToolLedger?: readonly Readonly<{ tool?: string; resource?: string; query?: string; decision?: 'allow' | 'deny' }>[];
  onStderr?: (chunk: string) => void;
  onProgress?: (event: { kind: 'text' | 'tool' | 'heartbeat'; from: string; detail: string }) => void;
  abortController?: AbortController;
};

export type CompactBoundaryMetadata = {
  trigger: 'manual' | 'auto';
  preTokens: number;
  postTokens?: number;
  durationMs?: number;
  boundaryId: string;
};

export type LedgerRow = {
  at: string;
  event: string;
  agentId?: string;
  agentType?: string;
  tool?: string;
  resource?: string;
  decision?: 'allow' | 'deny';
  reason?: string;
  query?: string;
  compaction?: CompactBoundaryMetadata;
  delivery?: import('./source-delivery.js').SourceDeliveryReceipt;
  retryAfterMs?: number;
};
