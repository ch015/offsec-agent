import { join } from 'node:path';
import { promoteStandardFindingRecords, readStandardFindingRecordReceipts } from '../finding-contract.js';
import { atomicPrivateWrite, managedPath } from '../workflow/storage-files.js';
import type { RunSnapshot } from '../workflow/state-store.js';

/** Failed execution is not a verdict on a source-grounded claim. Retain it for review. */
export function retainFailedTaskClaims(root: string, taskIds: readonly string[], snapshot: Readonly<RunSnapshot>) {
  type Claim = { taskId: string; attemptDirectory: string; findingId: string; status: 'review-pending' };
  const claims: Claim[] = [];
  for (const taskId of taskIds) {
    const attempts = Object.values(snapshot.attempts)
      .filter(attempt => attempt.phase === 'analyze' && attempt.round === taskId
        && (attempt.status === 'failed' || attempt.status === 'completed'))
      .sort((a, b) => a.attempt - b.attempt)
      .map(attempt => {
        const directory = managedPath(root, join(root, 'work-units', taskId, `attempt-${attempt.attempt}`));
        return { ...attempt, directory, receipts: readStandardFindingRecordReceipts(directory) };
      });
    // A retried claim keeps its ID (same anchor and title, or `revises`); list it once, from the latest attempt.
    const byId = new Map<string, Claim>();
    const latest = new Map(attempts.flatMap(attempt => attempt.receipts.map(receipt => [receipt.recordName, attempt.attempt] as const)));
    for (const attempt of attempts) {
      // Choose first, then promote. Replaying older versions on resume would
      // otherwise collide with (or roll back) a newer version already at root.
      const selectedRecordNames = new Set(attempt.receipts.filter(receipt => latest.get(receipt.recordName) === attempt.attempt).map(receipt => receipt.recordName));
      if (selectedRecordNames.size) promoteStandardFindingRecords({
        fromEngagementDir: attempt.directory, toEngagementDir: root, expected: attempt.receipts, selectedRecordNames,
        superseded: attempts.filter(prior => prior.attempt < attempt.attempt && (prior.superseded || prior.status === 'failed')).flatMap(prior => prior.receipts),
      });
      for (const receipt of attempt.receipts) byId.set(receipt.findingId, { taskId, attemptDirectory: attempt.directory, findingId: receipt.findingId, status: 'review-pending' });
    }
    claims.push(...byId.values());
  }
  const path = join(root, '00_retained_claims.json');
  atomicPrivateWrite(path, JSON.stringify({ claims, instruction: 'These claims came from failed tasks. Review every canonical ID; inconclusive claims remain deferred. They do not establish task coverage.' }, null, 2));
  return { path, claims };
}
