import { dirname, join, resolve } from 'node:path';
import { promoteStandardFindingRecords, readStandardFindingRecordReceipts, type StandardFindingRecordReceipt } from '../finding-contract.js';
import type { RunSnapshot } from '../workflow/state-store.js';
import { managedPath } from '../workflow/storage-files.js';

/** A completed retry may replace records from its own failed or invalidated attempts.
 * Unrelated root conflicts still fail; prior bytes remain in the history archive. */
export function promoteCompletedTaskFindings(input: {
  root: string; taskId: string; unitDir: string;
  expected: readonly StandardFindingRecordReceipt[];
  snapshot: Readonly<RunSnapshot>;
}) {
  const unitDir = managedPath(input.root, input.unitDir);
  const attempts = Object.values(input.snapshot.attempts).filter(attempt => attempt.phase === 'analyze' && attempt.round === input.taskId);
  const current = attempts.find(attempt => !attempt.superseded && attempt.status === 'completed'
    && resolve(input.root, 'work-units', input.taskId, `attempt-${attempt.attempt}`) === unitDir
    && attempt.artifacts?.some(artifact => dirname(artifact.path) === unitDir));
  if (!current) throw new Error(`Completed task receipt is missing for Finding promotion: ${input.taskId}`);
  const superseded = attempts.filter(attempt => (attempt.superseded || attempt.status === 'failed') && attempt.attempt < current.attempt)
    .flatMap(attempt => readStandardFindingRecordReceipts(managedPath(input.root,
      join(input.root, 'work-units', input.taskId, `attempt-${attempt.attempt}`))));
  return promoteStandardFindingRecords({ fromEngagementDir: unitDir, toEngagementDir: input.root, expected: input.expected, superseded });
}
