import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { atomicPrivateWrite, managedPath, readManagedFile } from '../workflow/storage-files.js';
import { reportDirectory } from '../workflow/run-location.js';

/** Keep the phase's immutable draft reference alive and publish a separate final projection. */
export function copyPublication(engagementDir: string, draftName: string, finalName: string, appendix = ''): string {
  const draft = managedPath(engagementDir, join(engagementDir, draftName));
  const final = managedPath(engagementDir, join(engagementDir, finalName));
  const bytes = existsSync(draft) ? Buffer.concat([readManagedFile(engagementDir, draft), Buffer.from(appendix)]) : readManagedFile(engagementDir, final);
  if (existsSync(final)) {
    if (!readManagedFile(engagementDir, final).equals(bytes)) throw new Error('publication final differs from validated draft');
  } else atomicPrivateWrite(final, bytes);
  const reportDir = reportDirectory(engagementDir), published = managedPath(reportDir, join(reportDir, finalName));
  if (published !== final) {
    if (existsSync(published) && !readManagedFile(reportDir, published).equals(bytes)) throw new Error('published report differs from validated artifact');
    atomicPrivateWrite(published, bytes);
  }
  return published;
}

export function recordPublicationIntent(engagementDir: string, finalName: string, draftName = finalName, appendix = ''): void {
  const bytes = Buffer.concat([readManagedFile(engagementDir, join(engagementDir, draftName)), Buffer.from(appendix)]);
  atomicPrivateWrite(join(engagementDir, '.recovery', 'publication-intent.json'), JSON.stringify({ kind: 'publication.prepared', finalArtifact: finalName, sha256: createHash('sha256').update(bytes).digest('hex'), bytes: bytes.byteLength }));
}
