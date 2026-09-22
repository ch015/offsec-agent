import { createHash } from 'node:crypto';
import { existsSync, readdirSync, renameSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { ZodError } from 'zod';
import { ArtifactIntegrityError, ArtifactReceiptSchema, FileSystemArtifactStore, type ArtifactReceipt, type ImmutableArtifactStore } from './artifact-store.js';
import { atomicPrivateWrite, managedPath, privateDirectory, readManagedFile } from './storage-files.js';

export type StorageHealth = { pendingReplication: number; errors: string[] };
/** Local durable storage is authoritative; optional remote replication never discards local evidence. */
export class ResilientArtifactStore implements ImmutableArtifactStore {
  private readonly local: FileSystemArtifactStore;
  private readonly queue: string;
  private remoteAvailable = true;
  private readonly errors = new Set<string>();
  constructor(readonly engagementDir: string, private readonly remote?: ImmutableArtifactStore) {
    this.local = new FileSystemArtifactStore(join(engagementDir, '.artifact-store'));
    this.queue = join(engagementDir, '.recovery', 'replication');
    privateDirectory(this.queue);
  }
  async put(input: Parameters<ImmutableArtifactStore['put']>[0]): Promise<ArtifactReceipt> {
    const receipt = await this.local.put(input);
    if (!this.remote) return receipt;
    const pending = join(this.queue, `${createHash('sha256').update(input.uri).digest('hex')}.json`);
    // Write intent first: a crash after local put remains replayable.
    atomicPrivateWrite(pending, JSON.stringify(receipt));
    if (!this.remoteAvailable) return receipt;
    try {
      const actual = await this.remotePut(input);
      this.assertReceipt(actual, receipt);
      unlinkSync(pending);
    } catch (error) { this.remoteAvailable = false; this.errors.add(String(error)); }
    return receipt;
  }
  async get(uri: string): Promise<Uint8Array> { return this.local.get(uri); }
  async flush(): Promise<StorageHealth> {
    this.errors.clear();
    let unavailable = false;
    if (this.remote) for (const name of readdirSync(this.queue).filter(n => n.endsWith('.json')).sort()) {
      const path = managedPath(this.queue, join(this.queue, name));
      let localItem = true;
      try {
        const receipt = ArtifactReceiptSchema.parse(JSON.parse(readManagedFile(this.queue, path).toString()));
        if (name !== `${createHash('sha256').update(receipt.uri).digest('hex')}.json`) throw new SyntaxError('replication entry name does not match URI');
        const content = await this.local.get(receipt.uri);
        if (content.byteLength !== receipt.bytes || createHash('sha256').update(content).digest('hex') !== receipt.sha256) {
          throw new ArtifactIntegrityError('replication intent does not match local content');
        }
        await this.local.put({ ...receipt, content });
        localItem = false;
        this.assertReceipt(await this.remotePut({ ...receipt, content }), receipt);
        unlinkSync(path);
      } catch (error) {
        this.errors.add(`${name}: ${String(error)}`);
        const code = (error as NodeJS.ErrnoException)?.code;
        const invalid = error instanceof SyntaxError || error instanceof ZodError || code === 'ENOENT'
          || error instanceof ArtifactIntegrityError;
        if (localItem && invalid) { renameSync(path, `${path}.invalid`); continue; }
        unavailable = true; break;
      }
    }
    this.remoteAvailable = !unavailable;
    return this.health();
  }
  health(): StorageHealth {
    const files = existsSync(this.queue) ? readdirSync(this.queue) : [];
    const invalid = files.filter(n => n.endsWith('.invalid')).length;
    return { pendingReplication: files.filter(n => n.endsWith('.json')).length, errors: [...this.errors, ...(invalid ? [`${invalid} replication entries quarantined; originals retained`] : [])].slice(0, 20) };
  }
  private async remotePut(input: Parameters<ImmutableArtifactStore['put']>[0]): Promise<ArtifactReceipt> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([this.remote!.put(input), new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('artifact replication timeout')), 3000); })]);
    } finally { if (timer) clearTimeout(timer); }
  }
  private assertReceipt(actual: ArtifactReceipt, expected: ArtifactReceipt): void {
    for (const key of ['uri', 'sha256', 'bytes', 'mediaType', 'producer'] as const) {
      if (actual[key] !== expected[key]) throw new Error(`remote artifact receipt mismatch: ${key}`);
    }
  }
}
