import { existsSync, unlinkSync } from 'node:fs';
import { basename, dirname, join, relative } from 'node:path';
import { createArtifactRef, verifyRunArtifactRef } from '../contracts/result-contract.js';
import type { MissionRuntime } from '../workflow/mission-runtime.js';
import type { RunSnapshot } from '../workflow/state-store.js';
import { atomicPrivateWrite, readManagedFile } from '../workflow/storage-files.js';
import { reportDirectory } from '../workflow/run-location.js';

const pending = '.recovery/evaluation-reopen.json';
const outputs = ['03_evaluation_input.json', '04_evaluation.json', '04_evaluation_classification.yaml',
  '07_security_report.draft.md', '07_security_report.md', '.recovery/evaluation-projection.json', '.recovery/publication-intent.json'];

/** Scoped acceptance repair: retain reviewed evidence and costs, archive only
 * evaluation/report outputs, then rerun those phases under the existing lease. */
export async function reopenEvaluation(runtime: MissionRuntime, root: string, reason: string): Promise<void> {
  const snapshot = await runtime.read();
  if (Object.values(snapshot.attempts).some(a => ['started', 'received'].includes(a.status))) throw new Error('active attempts prevent evaluation reopening');
  finishEvaluationReopen(root, snapshot);
  const revision = (snapshot.evaluationRevisions?.length ?? 0) + 1;
  const invalidated = Object.entries(snapshot.attempts).filter(([, a]) => !a.superseded && ['evaluate', 'report'].includes(a.phase));
  for (const [, attempt] of invalidated) for (const artifact of attempt.artifacts ?? []) verifyRunArtifactRef(artifact, root);
  if (snapshot.publication) verifyRunArtifactRef(snapshot.publication.artifact, root);
  const paths = [...new Set([...outputs.map(name => join(root, name)), join(reportDirectory(root), '07_security_report.md')])].filter(existsSync);
  const archivedArtifacts = paths.map(path => {
    const name = relative(root, path);
    const archived = join(root, 'evaluation-revisions', String(revision), name.startsWith('..') ? 'published/07_security_report.md' : name);
    // readManagedFile also rejects symlink escapes; external report has its own managed root.
    atomicPrivateWrite(archived, readManagedFile(name.startsWith('..') ? reportDirectory(root) : root, path));
    return createArtifactRef({ engagementDir: dirname(archived), name: basename(archived), phase: 'evaluation-revision', role: 'host', attempt: String(revision) });
  });
  atomicPrivateWrite(join(root, pending), JSON.stringify({ revision, paths }));
  const next = await runtime.append({ type: 'evaluation.reopened', eventId: `${snapshot.runId}:evaluation-reopen:${revision}`,
    revision, reason, invalidatedAttemptKeys: invalidated.map(([key]) => key), archivedArtifacts });
  finishEvaluationReopen(root, next);
}

export function finishEvaluationReopen(root: string, snapshot: Readonly<RunSnapshot>): void {
  if (!existsSync(join(root, pending))) return;
  const instruction = JSON.parse(readManagedFile(root, join(root, pending)).toString());
  if (instruction.revision !== snapshot.evaluationRevisions?.length) return; // Event was not committed.
  const allowed = new Set([...outputs.map(name => join(root, name)), join(reportDirectory(root), '07_security_report.md')]);
  for (const path of instruction.paths) {
    if (!allowed.has(path)) throw new Error('unsafe evaluation cleanup');
    if (existsSync(path)) {
      readManagedFile(relative(root, path).startsWith('..') ? reportDirectory(root) : root, path);
      unlinkSync(path);
    }
  }
  unlinkSync(join(root, pending));
}
