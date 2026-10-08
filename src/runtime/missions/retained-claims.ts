import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { promoteStandardFindingRecords, readStandardFindingRecordReceipts } from '../finding-contract.js';
import { atomicPrivateWrite, managedPath } from '../workflow/storage-files.js';

/** Failed execution is not a verdict on a source-grounded claim. Retain it for review. */
export function retainFailedTaskClaims(root: string, taskIds: readonly string[]) {
  const claims: Array<{ taskId: string; attemptDirectory: string; findingId: string; status: 'review-pending' }> = [];
  for (const taskId of taskIds) {
    const directory = managedPath(root, join(root, 'work-units', taskId));
    if (!existsSync(directory)) continue;
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (!entry.isDirectory() || !/^attempt-\d+$/.test(entry.name)) continue;
      const attempt = managedPath(root, join(directory, entry.name));
      const receipts = readStandardFindingRecordReceipts(attempt);
      promoteStandardFindingRecords({ fromEngagementDir: attempt, toEngagementDir: root, expected: receipts });
      for (const receipt of receipts) claims.push({ taskId, attemptDirectory: attempt, findingId: receipt.findingId, status: 'review-pending' });
    }
  }
  const path = join(root, '00_retained_claims.json');
  atomicPrivateWrite(path, JSON.stringify({ claims, instruction: 'These claims came from failed tasks. Review every canonical ID; inconclusive claims remain deferred. They do not establish task coverage.' }, null, 2));
  return { path, claims };
}
