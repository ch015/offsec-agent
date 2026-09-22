import { createHash } from 'node:crypto';
import { chmodSync, existsSync, lstatSync, readdirSync } from 'node:fs';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';
import { z } from 'zod';
import { ArtifactReceiptSchema, type ImmutableArtifactStore } from './artifact-store.js';
import { reportDirectory } from './run-location.js';
import { atomicPrivateWrite, managedPath, privateDirectory, readManagedFile } from './storage-files.js';

const Entry = z.object({ area: z.enum(['engagement', 'report', 'run']).optional(), path: z.string().min(1), receipt: ArtifactReceiptSchema }).strict();
export const RunArchiveSchema = z.object({ schemaVersion: z.literal(1), originalEngagementDir: z.string(), entries: z.array(Entry) }).strict();
export type RunArchive = z.infer<typeof RunArchiveSchema>;
const INTERNAL = new Set(['.artifact-store', 'run-archive.json']);

/** Snapshot all host and model outputs, not just phase-declared artifacts. Call at quiescent boundaries. */
export async function archiveRun(engagementDir: string, store: ImmutableArtifactStore): Promise<{ manifest: RunArchive; uri: string }> {
  const root = resolve(engagementDir), entries: RunArchive['entries'] = [];
  const walk = async (dir: string, base = root, area: 'engagement' | 'report' = 'engagement'): Promise<void> => {
    for (const name of readdirSync(dir).sort()) {
      if ((dir === root && INTERNAL.has(name)) || name.endsWith('.tmp')) continue;
      const path = managedPath(base, join(dir, name));
      if (path === join(root, '.recovery', 'replication')) continue;
      const info = lstatSync(path);
      if (info.isDirectory()) { await walk(path, base, area); continue; }
      if (!info.isFile()) throw new Error(`unsupported archive entry: ${path}`);
      if (process.getuid && info.uid !== process.getuid()) throw new Error(`archive file belongs to another user: ${path}`);
      chmodSync(path, 0o600);
      const content = readManagedFile(base, path), hash = createHash('sha256').update(content).digest('hex');
      const receipt = await store.put({ uri: `artifact://archive/objects/${hash}`, content, mediaType: 'application/octet-stream', producer: 'archive/host/1' });
      entries.push({ area, path: relative(base, path).split(sep).join('/'), receipt });
    }
  };
  await walk(root);
  const reports = reportDirectory(root);
  if (reports !== root) {
    await walk(reports, reports, 'report');
    const metadata = readManagedFile(dirname(root), join(dirname(root), 'run.json'));
    const receipt = await store.put({ uri: `artifact://archive/objects/${createHash('sha256').update(metadata).digest('hex')}`, content: metadata, mediaType: 'application/octet-stream', producer: 'archive/host/1' });
    entries.push({ area: 'run', path: 'run.json', receipt });
  }
  const manifest: RunArchive = { schemaVersion: 1, originalEngagementDir: root, entries };
  const content = Buffer.from(JSON.stringify(manifest)), hash = createHash('sha256').update(content).digest('hex');
  const uri = `artifact://archive/manifests/${hash}`;
  await store.put({ uri, content, mediaType: 'application/json', producer: 'archive/host/1' });
  atomicPrivateWrite(join(root, 'run-archive.json'), JSON.stringify({ ...manifest, uri }, null, 2));
  return { manifest, uri };
}

/** A fresh destination only. Restore exact bytes; retained absolute execution refs describe the original location. */
export async function restoreRunArchive(input: { uri: string; store: ImmutableArtifactStore; destination: string }): Promise<RunArchive> {
  const bytes = await input.store.get(input.uri);
  const expectedHash = input.uri.match(/^artifact:\/\/archive\/manifests\/([a-f0-9]{64})$/)?.[1];
  if (!expectedHash || createHash('sha256').update(bytes).digest('hex') !== expectedHash) throw new Error('archive manifest hash mismatch');
  const manifest = RunArchiveSchema.parse(JSON.parse(Buffer.from(bytes).toString()));
  const root = resolve(input.destination);
  privateDirectory(root);
  if (readdirSync(root).length) throw new Error('archive restore requires an empty destination');
  const names = new Set<string>();
  const location = (entry: RunArchive['entries'][number]): string => {
    if (!entry.area || entry.area === 'engagement') return managedPath(root, join(root, entry.path));
    if (basename(root) !== 'engagement') throw new Error('external run archive must be restored to a run/engagement directory');
    if (entry.area === 'run' && entry.path !== 'run.json') throw new Error('unexpected run metadata');
    const base = entry.area === 'run' ? dirname(root) : join(dirname(root), 'report');
    return managedPath(base, join(base, entry.path));
  };
  // Validate the entire manifest before creating any restored files.
  for (const entry of manifest.entries) {
    if (entry.path.split('/').some(p => !p || p === '.' || p === '..') || entry.path.includes('\\') || names.has(`${entry.area ?? 'engagement'}/${entry.path}`)) throw new Error('unsafe or duplicate archive path');
    location(entry); names.add(`${entry.area ?? 'engagement'}/${entry.path}`);
  }
  for (const entry of manifest.entries) {
    const content = await input.store.get(entry.receipt.uri);
    if (content.byteLength !== entry.receipt.bytes || createHash('sha256').update(content).digest('hex') !== entry.receipt.sha256) throw new Error(`archive content mismatch: ${entry.path}`);
    const path = location(entry);
    if (existsSync(path)) {
      if (!readManagedFile(dirname(path), path).equals(Buffer.from(content))) throw new Error(`restore would overwrite existing content: ${path}`);
    } else atomicPrivateWrite(path, content);
  }
  atomicPrivateWrite(join(root, 'run-archive.json'), JSON.stringify({ ...manifest, uri: input.uri }, null, 2));
  return manifest;
}
