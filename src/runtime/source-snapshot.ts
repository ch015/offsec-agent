import { createHash } from 'node:crypto';
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, statSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { z } from 'zod';
import { atomicPrivateWrite } from './workflow/storage-files.js';
import { compareSourceRevision } from './source-change-policy.js';

export const SOURCE_SNAPSHOT_FILE = '00_source_snapshot.json';
const Receipt = z.object({ path: z.string(), bytes: z.number().int().nonnegative(), sha256: z.string().regex(/^[a-f0-9]{64}$/), mode: z.number().int(), symlink: z.boolean() }).strict();
const Snapshot = z.object({ schemaVersion: z.literal('1'), id: z.string(), originalTarget: z.string(), files: z.array(Receipt) }).strict();
export type SourceSnapshot = z.infer<typeof Snapshot>;
const digest = (bytes: Uint8Array | string) => createHash('sha256').update(bytes).digest('hex');
const rootFor = (engagementDir: string) => join(engagementDir, 'source-snapshot');

function safePath(root: string, file: string): string {
  if (isAbsolute(file) || file.includes('\\') || file.includes('\0') || file.split('/').some(part => !part || part === '..' || part === '.')) throw new Error(`Invalid snapshot path: ${file}`);
  const absolute = resolve(root, file);
  let ancestor = absolute;
  while (!existsSync(ancestor)) ancestor = dirname(ancestor);
  {
    const canonical = resolve(realpathSync(ancestor), relative(ancestor, absolute));
    const rel = relative(realpathSync(root), canonical);
    if (rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw new Error(`Snapshot path escapes scope: ${file}`);
  }
  return absolute;
}

export function createSourceSnapshot(input: { target: string; engagementDir: string; files: readonly { path: string; sha256?: string }[] }): { target: string; snapshot: SourceSnapshot } {
  if (existsSync(join(input.engagementDir, SOURCE_SNAPSHOT_FILE))) return loadSourceSnapshot(input.engagementDir);
  const target = realpathSync(input.target), destination = rootFor(input.engagementDir);
  mkdirSync(destination, { recursive: true, mode: 0o700 });
  const files: SourceSnapshot['files'] = [];
  for (const file of [...new Map(input.files.map(item => [item.path, item])).values()].sort((a, b) => a.path.localeCompare(b.path))) {
    const source = safePath(target, file.path), stat = statSync(source), link = lstatSync(source);
    if (!stat.isFile()) throw new Error(`Snapshot source is not a file: ${file.path}`);
    const bytes = readFileSync(source), sha256 = digest(bytes);
    if (file.sha256 && file.sha256 !== sha256) throw new Error(`Source changed while capturing snapshot: ${file.path}`);
    const path = safePath(destination, file.path); mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    if (existsSync(path)) {
      if (digest(readFileSync(path)) !== sha256) throw new Error(`Partial snapshot differs: ${file.path}`);
    } else writeFileSync(path, bytes, { flag: 'wx', mode: 0o400 });
    chmodSync(path, 0o400);
    files.push({ path: file.path, bytes: bytes.length, sha256, mode: stat.mode & 0o777, symlink: link.isSymbolicLink() });
  }
  const core = { schemaVersion: '1' as const, originalTarget: target, files };
  const snapshot = Snapshot.parse({ ...core, id: digest(JSON.stringify(core)) });
  atomicPrivateWrite(join(input.engagementDir, SOURCE_SNAPSHOT_FILE), JSON.stringify(snapshot, null, 2) + '\n');
  return { target: realpathSync(destination), snapshot };
}

export function loadSourceSnapshot(engagementDir: string): { target: string; snapshot: SourceSnapshot } {
  const snapshot = Snapshot.parse(JSON.parse(readFileSync(join(engagementDir, SOURCE_SNAPSHOT_FILE), 'utf8')));
  const { id, ...core } = snapshot;
  if (digest(JSON.stringify(core)) !== id) throw new Error('Source snapshot manifest integrity failure');
  const target = realpathSync(rootFor(engagementDir));
  for (const file of snapshot.files) {
    const bytes = readFileSync(safePath(target, file.path));
    if (bytes.length !== file.bytes || digest(bytes) !== file.sha256) throw new Error(`Source snapshot integrity failure: ${file.path}`);
  }
  return { target, snapshot };
}

export function compareSnapshotToWorkspace(engagementDir: string) {
  const { target, snapshot } = loadSourceSnapshot(engagementDir);
  return snapshot.files.map(file => {
    try {
      const workspaceFile = safePath(snapshot.originalTarget, file.path);
      const change = compareSourceRevision(file.path, readFileSync(safePath(target, file.path)), readFileSync(workspaceFile));
      const stat = statSync(workspaceFile), link = lstatSync(workspaceFile);
      if ((stat.mode & 0o777) !== file.mode || link.isSymbolicLink() !== file.symlink) return { path: file.path, ...change, kind: 'analysis-relevant' as const, reuseAnalysis: false, reuseToolOutput: false, reason: 'File metadata changed' };
      return { path: file.path, ...change };
    } catch { return { path: file.path, kind: 'unknown' as const, reuseAnalysis: false, reuseToolOutput: false, reason: 'Current source unavailable' }; }
  });
}
