import { createHash } from 'node:crypto';
import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { ProviderUsageSchema, type ProviderUsage } from '../contracts/result-contract.js';
import type { MissionRuntime } from './mission-runtime.js';
import { phaseAttemptKey, type NewRunEvent } from './state-store.js';
import { atomicPrivateWrite, readManagedFile } from './storage-files.js';

/** Usage survives result rejection, cancellation, and process recovery. */
export function persistUsageReceipt(root: string, runId: string, phase: string, round: string | undefined, attempt: number, usage: ProviderUsage): NewRunEvent {
  const identity = { phase, ...(round ? { round } : {}), attempt };
  const receiptId = createHash('sha256').update(JSON.stringify({ runId, ...identity, usage })).digest('hex');
  const event = { type: 'usage.reconciled' as const, eventId: `${runId}:usage:${receiptId}`, receiptId, ...identity, usage };
  atomicPrivateWrite(join(root, 'usage-receipts', `${receiptId}.json`), JSON.stringify(event) + '\n');
  return event;
}

export async function reconcileUsageReceipts(runtime: MissionRuntime, root: string): Promise<void> {
  const snapshot = await runtime.read();
  // Native SDK results are persisted before the stream can fail. Only traverse
  // host-owned attempt directories; never scan a source snapshot for receipts.
  const visit = (directory: string): void => {
    if (!existsSync(directory)) return;
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) throw new Error('usage receipt symlink is forbidden');
      const path = join(directory, entry.name);
      if (entry.isDirectory()) { if (entry.name === 'session-usage' || directory.includes('work-units') || entry.name === 'work-units') visit(path); continue; }
      if (!directory.endsWith('session-usage') || !entry.name.endsWith('.json')) continue;
      const receipt = JSON.parse(readManagedFile(root, path).toString());
      if (receipt.runId !== snapshot.runId || typeof receipt.attemptId !== 'string') continue;
      const attempt = snapshot.attempts[receipt.attemptId];
      if (!attempt || typeof receipt.costUsd !== 'number') continue;
      if (attempt.usage?.accountingComplete) {
        if (attempt.usage.costUsd !== receipt.costUsd) throw new Error('Native usage receipt conflicts with settled accounting');
        // The runtime receipt also carries verified model identity and failure
        // details. An equivalent SDK receipt must not overwrite that metadata.
        continue;
      }
      const usage = ProviderUsageSchema.parse({ provider: 'anthropic-agent-sdk', costUsd: receipt.costUsd,
        accountingComplete: true, turns: receipt.turns, raw: { ...receipt.modelUsage,
          sdkResult: { subtype: receipt.subtype, terminalReason: receipt.terminalReason } } });
      persistUsageReceipt(root, snapshot.runId, attempt.phase, attempt.round, attempt.attempt, usage);
    }
  };
  visit(root);
  const directory = join(root, 'usage-receipts');
  if (!existsSync(directory)) return;
  for (const name of readdirSync(directory).filter(name => name.endsWith('.json')).sort()) {
    const event = JSON.parse(readManagedFile(root, join(directory, name)).toString());
    const state = await runtime.read();
    if (state.usageReceiptIds?.includes(event.receiptId)) continue;
    const attempt = state.attempts[phaseAttemptKey(event.phase, event.round, event.attempt)];
    if (!attempt) throw new Error('orphan usage receipt');
    if (attempt.usage?.accountingComplete && !event.usage.accountingComplete) continue;
    await runtime.append(event);
  }
}
