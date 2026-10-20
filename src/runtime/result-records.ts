import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { z } from 'zod';
import { RunEventSchema, replayRunEvents, type RunSnapshot } from './workflow/state-store.js';
import { managedPath, readManagedFile } from './workflow/storage-files.js';

export const contentHash = (value: string | Uint8Array) => createHash('sha256').update(value).digest('hex');
export const StoredReferenceSchema = z.object({
  path: z.string().min(1), sha256: z.string().regex(/^[a-f0-9]{64}$/),
}).strict();
export type StoredReference = z.infer<typeof StoredReferenceSchema>;

export function validateResultPath(path: string): void {
  if (isAbsolute(path) || path.includes('\\') || path.split('/').some(part => !part || part === '.' || part === '..')) {
    throw new Error(`Expected a repository-relative artifact path: ${path}`);
  }
}

/** An offline view of existing files. No repair, provider call or database write. */
export class ResultRecordReader {
  private readonly observed = new Map<string, Buffer | undefined>();
  constructor(readonly root: string, readonly state?: Readonly<RunSnapshot>) {}
  read(path: string, optional = false): Buffer | undefined {
    validateResultPath(path);
    if (!this.observed.has(path)) {
      const full = managedPath(this.root, join(this.root, path));
      // readManagedFile checks symlink traversal even for an existing file.
      const value = optional && !existsSync(full) ? undefined : readManagedFile(this.root, full);
      this.observed.set(path, value);
    }
    const value = this.observed.get(path);
    if (!value && !optional) throw new Error(`Required artifact missing: ${path}`);
    return value;
  }
  json(path: string, optional = false): unknown {
    const bytes = this.read(path, optional);
    return bytes ? JSON.parse(bytes.toString('utf8')) : undefined;
  }
  reference(path: string): StoredReference {
    return { path, sha256: contentHash(this.read(path)!) };
  }
  verify(ref: StoredReference): void {
    if (this.reference(ref.path).sha256 !== ref.sha256) throw new Error(`Artifact version changed: ${ref.path}`);
  }
  assertUnchanged(): void {
    for (const [path, before] of this.observed) {
      const full = managedPath(this.root, join(this.root, path)), after = existsSync(full) ? readManagedFile(this.root, full) : undefined;
      if (before === undefined ? after !== undefined : after === undefined || !before.equals(after)) throw new Error(`Artifacts changed during inspection; retry: ${path}`);
    }
  }
  references(): StoredReference[] {
    return [...this.observed].filter((row): row is [string, Buffer] => row[1] !== undefined)
      .map(([path, bytes]) => ({ path, sha256: contentHash(bytes) })).sort((a, b) => a.path.localeCompare(b.path));
  }
}

export function readResultState(reader: ResultRecordReader) {
  if (reader.state) return reader.state;
  const bytes = reader.read('run-events.jsonl')!;
  if (!bytes.length || bytes[bytes.length - 1] !== 10) throw new Error('Run event log is empty or has an incomplete last line');
  const events = bytes.toString('utf8').trimEnd().split('\n').map(line => RunEventSchema.parse(JSON.parse(line)));
  return replayRunEvents(events);
}

export function resultIdentity(reader: ResultRecordReader) {
  const state = readResultState(reader);
  return { runId: state.runId, sourceManifestFileSha256: reader.reference('source_manifest.json').sha256 };
}
