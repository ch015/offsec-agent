import { createHash } from 'node:crypto';
import { existsSync, readdirSync } from 'node:fs';
import { join, relative } from 'node:path';
import type { Pool } from 'pg';
import { z } from 'zod';
import type { DatabaseConfig } from '../config.js';
import { createPostgresPool } from '../workflow/database.js';
import { atomicPrivateWrite, readManagedFile } from '../workflow/storage-files.js';
import { readStandardFindingRecordReceipts, type StandardFinding } from '../finding-contract.js';
import { readSharedKnowledge, type SharedKnowledgeContext, type SharedKnowledgeRecord } from '../shared-knowledge.js';
import { KnowledgeStorageError, PostgresKnowledgeStore, type KnowledgePin } from './postgres-knowledge.js';
import { KNOWLEDGE_BINDING, type KnowledgeBinding } from './binding.js';
export { KNOWLEDGE_BINDING, type KnowledgeBinding } from './binding.js';

export type KnowledgeOptions = { backend?: 'file' | 'postgres'; database?: DatabaseConfig; env?: NodeJS.ProcessEnv; pool?: Pool };
export const DATABASE_KNOWLEDGE_TOOLS = ['lookup_finding_records', 'get_finding_record', 'lookup_security_advisories', 'get_security_advisory'] as const;
const hash = (text: string | Buffer) => createHash('sha256').update(text).digest('hex');
const PinSchema = z.object({ catalogId: z.string().uuid(), referenceRevision: z.string().regex(/^\d+$/) }).strict();

export class KnowledgeRuntime {
  readonly store: PostgresKnowledgeStore;
  readonly scope: string;
  private pin!: KnowledgePin;
  private constructor(private readonly root: string, private readonly pool: Pool, private readonly ownsPool: boolean) {
    this.store = new PostgresKnowledgeStore(pool);
    this.scope = hash(root);
  }
  static async open(root: string, options: KnowledgeOptions = {}): Promise<KnowledgeRuntime | undefined> {
    if ((options.backend ?? 'file') === 'file') return undefined;
    const pool = options.pool ?? createPostgresPool(options.env, options.database);
    const runtime = new KnowledgeRuntime(root, pool, !options.pool);
    // pg emits idle-connection errors separately; subsequent queries still fail through
    // the sanitized storage boundary instead of terminating the entire host process.
    if (!options.pool) pool.on('error', () => undefined);
    try {
      const path = join(root, '00_reference_knowledge.json');
      const expected = existsSync(path) ? PinSchema.parse(JSON.parse(readManagedFile(root, path).toString('utf8'))) : undefined;
      runtime.pin = await runtime.store.pin(runtime.scope, expected);
      if (!expected) atomicPrivateWrite(path, JSON.stringify(runtime.pin, null, 2) + '\n');
      await runtime.syncFindings(root);
      const work = join(root, 'work-units');
      if (existsSync(work)) for (const unit of readdirSync(work, { withFileTypes: true }).filter(entry => entry.isDirectory())) {
        const directory = join(work, unit.name);
        for (const attempt of readdirSync(directory, { withFileTypes: true }).filter(entry => entry.isDirectory() && /^attempt-\d+$/.test(entry.name))) {
          await runtime.syncFindings(join(directory, attempt.name));
        }
      }
      return runtime;
    } catch (error) { if (!options.pool) await pool.end(); throw error; }
  }
  async bind(context: SharedKnowledgeContext): Promise<SharedKnowledgeContext> {
    const view = context.snapshotPath ? hash(readManagedFile(context.engagementDir, context.snapshotPath)) : 'live';
    const binding: KnowledgeBinding = { store: this.store, scope: hash(`${this.scope}:${context.namespace}`), documentScope: this.scope, view, pin: this.pin };
    // Symbols propagate through host object spreads but never through JSON inventories,
    // checkpoints or prompts. No connection string is exposed to a worker.
    const bound = { ...context, [KNOWLEDGE_BINDING]: binding };
    for (const record of readSharedKnowledge(context)) await this.store.putShared(binding.scope, view, record);
    return bound;
  }
  async syncFindings(directory: string): Promise<void> {
    for (const receipt of readStandardFindingRecordReceipts(directory)) {
      const path = join(directory, 'standard-findings', receipt.recordName);
      const bytes = readManagedFile(this.root, path).toString('utf8');
      const finding = JSON.parse(bytes) as StandardFinding;
      archiveFindingVersion(directory, receipt.recordName, bytes);
      await this.store.putDocument(this.scope, 'finding', relative(this.root, path), bytes, finding);
    }
    const history = join(directory, '.recovery', 'knowledge-finding-versions');
    if (existsSync(history)) for (const name of readdirSync(history).sort()) {
      const match = /^([a-f0-9]{64})-([a-f0-9]{64})\.json$/.exec(name);
      if (!match) continue;
      const bytes = readManagedFile(this.root, join(history, name)).toString('utf8');
      if (hash(bytes) !== match[2]) throw new KnowledgeStorageError('Finding history digest mismatch');
      await this.store.putDocument(this.scope, 'finding', relative(this.root, join(directory, 'standard-findings', `${match[1]}.json`)), bytes, JSON.parse(bytes));
    }
  }
  async saveInstruction(key: string, body: string, pinned = false): Promise<string> {
    const digest = pinned ? await this.store.pinInstruction(this.scope, key, body) : await this.store.putDocument(this.scope, 'instruction', key, body);
    const stored = await this.store.getDocument(this.scope, 'instruction', key, digest);
    if (hash(stored) !== digest) throw new KnowledgeStorageError('Instruction revision integrity mismatch');
    return stored;
  }
  async close() { if (this.ownsPool) await this.pool.end(); }
}

export async function indexSharedRecord(context: SharedKnowledgeContext, record: SharedKnowledgeRecord, producer: NonNullable<SharedKnowledgeRecord['contributors']>[number]) {
  if (context.snapshotPath) throw new KnowledgeStorageError('Shared analysis snapshot is read-only');
  const binding = context[KNOWLEDGE_BINDING];
  if (binding) await binding.store.putShared(binding.scope, binding.view, { ...record, contributors: [producer] });
}

export async function indexFinding(context: SharedKnowledgeContext, directory: string, finding: StandardFinding) {
  const binding = context[KNOWLEDGE_BINDING];
  if (!binding) return;
  const name = hash(`${finding.id}\0${finding.phase}\0${finding.role}\0${finding.round ?? ''}`) + '.json';
  const key = relative(context.engagementDir, join(directory, 'standard-findings', name));
  // Capture this exact submission, even if a concurrent resubmission changes the file.
  const bytes = JSON.stringify(finding) + '\n';
  archiveFindingVersion(directory, name, bytes);
  await binding.store.putDocument(binding.documentScope, 'finding', key, bytes, finding);
}

function archiveFindingVersion(directory: string, name: string, bytes: string) {
  const path = join(directory, '.recovery', 'knowledge-finding-versions', `${name.replace(/\.json$/, '')}-${hash(bytes)}.json`);
  if (!existsSync(path)) atomicPrivateWrite(path, bytes);
  else if (readManagedFile(directory, path).toString('utf8') !== bytes) throw new KnowledgeStorageError('Finding history digest collision');
}
