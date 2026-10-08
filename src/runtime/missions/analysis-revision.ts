import { existsSync, unlinkSync } from 'node:fs';
import { join, relative, basename, dirname } from 'node:path';
import { createArtifactRef, verifyRunArtifactRef } from '../contracts/result-contract.js';
import type { MissionRuntime } from '../workflow/mission-runtime.js';
import { atomicPrivateWrite, readManagedFile } from '../workflow/storage-files.js';
import { reportDirectory } from '../workflow/run-location.js';

/** Preserve previous projections before reopening only incomplete analysis work. */
export async function beginAnalysisRevision(runtime: MissionRuntime, root: string, reason: string, invalidatedTaskIds: readonly string[] = [], preserveAnalysisCheckpoint = false): Promise<void> {
  const snapshot = await runtime.read(), revision = (snapshot.analysisRevision ?? 0) + 1;
  const invalidated = Object.entries(snapshot.attempts).filter(([, a]) =>
    !a.superseded && (['review', 'evaluate', 'report'].includes(a.phase) ||
      (a.phase === 'analyze' && ((!preserveAnalysisCheckpoint && a.round === 'cross-unit-followup') || a.round?.startsWith('review-request-') || invalidatedTaskIds.includes(a.round ?? '')))));
  const artifacts = [...invalidated.flatMap(([, a]) => a.artifacts ?? []),
    ...(!preserveAnalysisCheckpoint ? snapshot.analysisCheckpoint?.artifacts ?? [] : []), ...(snapshot.completionCoverage ? [snapshot.completionCoverage] : []), ...(snapshot.publication ? [snapshot.publication.artifact] : [])];
  const archivedArtifacts = [];
  for (const artifact of new Map(artifacts.map(a => [a.path, a])).values()) {
    verifyRunArtifactRef(artifact, root);
    const name = `revisions/${revision - 1}/${relative(root, artifact.path)}`;
    atomicPrivateWrite(join(root, name), readManagedFile(root, artifact.path));
    archivedArtifacts.push(createArtifactRef({ engagementDir: dirname(join(root, name)), name: basename(name), phase: 'revision', role: 'host', attempt: String(revision) }));
  }
  // This manifest is also the recovery instruction if the process exits between
  // the state transition and removing mutable projections.
  const removable = artifacts.filter(a => relative(root, a.path).indexOf('/') === -1).map(a => a.path);
  atomicPrivateWrite(join(root, '.recovery', 'revision-cleanup.json'), JSON.stringify({ revision, paths: [...new Set(removable)] }));
  await runtime.append({ type: 'analysis.revised', eventId: `${snapshot.runId}:analysis-revision:${revision}`,
    revision, reason, invalidatedAttemptKeys: invalidated.map(([key]) => key), archivedArtifacts, preserveAnalysisCheckpoint });
  finishRevisionCleanup(root, revision);
}

export function finishRevisionCleanup(root: string, revision: number): void {
  const path = join(root, '.recovery', 'revision-cleanup.json');
  if (!existsSync(path)) return;
  const cleanup = JSON.parse(readManagedFile(root, path).toString());
  if (cleanup.revision !== revision) return;
  for (const file of cleanup.paths) {
    const name = relative(root, file);
    if (name.includes('/') || name.startsWith('.')) throw new Error('unsafe revision cleanup');
    if (existsSync(file)) { readManagedFile(root, file); unlinkSync(file); }
    const publication = join(reportDirectory(root), name);
    if (publication !== file && name === '07_security_report.md' && existsSync(publication)) {
      atomicPrivateWrite(join(reportDirectory(root), 'revisions', `${revision - 1}`, name), readManagedFile(reportDirectory(root), publication));
      unlinkSync(publication);
    }
  }
  unlinkSync(path);
}
