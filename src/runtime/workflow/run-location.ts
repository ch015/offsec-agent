import { randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';
import { atomicPrivateWrite, managedPath, privateDirectory } from './storage-files.js';

export function allocateRunLocation(input: { target: string; stateHome?: string }): { engagementDir: string; engagementId: string } {
  const target = realpathSync(input.target);
  const home = resolve(input.stateHome ?? process.env.CH015_STATE_HOME ?? join(homedir(), '.ch015'));
  // Compare resolved ancestors too, so a custom alias cannot hide source/output overlap.
  let ancestor = home;
  while (!existsSync(ancestor)) ancestor = dirname(ancestor);
  const canonicalHome = resolve(realpathSync(ancestor), relative(ancestor, home));
  for (const [a, b] of [[target, canonicalHome], [canonicalHome, target]]) {
    const rel = relative(a!, b!);
    if (rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !rel.startsWith(sep))) throw new Error('analysis storage and target must not overlap');
  }
  privateDirectory(canonicalHome);
  const name = basename(target).replace(/[^\p{L}\p{N}._-]/gu, '_') || 'repository';
  const repository = managedPath(canonicalHome, join(canonicalHome, name));
  privateDirectory(repository);
  let commit: string | null = null;
  try { commit = execFileSync('git', ['-C', target, 'rev-parse', 'HEAD'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 3000 }).trim(); } catch { /* Non-Git targets are supported. */ }
  const id = randomUUID(), at = new Date().toISOString();
  const root = join(repository, `${at.replace(/[-:.]/g, '')}_${commit?.slice(0, 12) ?? 'nogit'}_${id}`);
  privateDirectory(root);
  privateDirectory(join(root, 'report'));
  atomicPrivateWrite(join(root, 'run.json'), JSON.stringify({ schemaVersion: 1, engine: 'offsec-agent', runId: id, target, commit, createdAt: at }, null, 2));
  return { engagementDir: join(root, 'engagement'), engagementId: id };
}

export function reportDirectory(engagementDir: string): string {
  const root = dirname(resolve(engagementDir)), manifest = join(root, 'run.json');
  if (basename(engagementDir) === 'engagement' && existsSync(manifest)) {
    const run = JSON.parse(readFileSync(managedPath(root, manifest), 'utf8'));
    if (run.engine === 'offsec-agent' && run.schemaVersion === 1) return managedPath(root, join(root, 'report'));
  }
  return resolve(engagementDir); // Explicit legacy locations retain their layout.
}
