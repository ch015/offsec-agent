import { createHash } from 'node:crypto';
import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { validateEvidence, type StandardFinding } from './finding-contract.js';
import { atomicPrivateWrite, managedPath, readManagedFile } from './workflow/storage-files.js';

/** Host supplied, scoped to one sealed work plan. Never accepted as model input. */
export type SharedKnowledgeContext = {
  engagementDir: string;
  namespace: string;
  sourceFiles: readonly string[];
  /** Root phases read the immutable analysis snapshot, including after resume. */
  snapshotPath?: string;
};

const Evidence = z.object({
  path: z.string().min(1), lineStart: z.number().int().positive(), lineEnd: z.number().int().positive(),
  quote: z.string().min(1).max(20_000),
}).strict();
export const SharedObservationShape = {
  summary: z.string().trim().min(1).max(4_000),
  tags: z.array(z.string().trim().min(1).max(100)).max(12).default([]),
  evidence: z.array(Evidence).min(1).max(8),
};
const Observation = z.object(SharedObservationShape).strict();
const ProducerSchema = z.object({ role: z.string(), phase: z.string(), round: z.string().optional(),
  engagementDir: z.string(), findingId: z.string().optional() }).strict();
const RecordSchema = z.object({
  id: z.string().regex(/^K-[a-f0-9]{64}$/),
  evidenceKey: z.string().regex(/^[a-f0-9]{64}$/),
  kind: z.enum(['observation', 'finding']),
  summary: z.string(), tags: z.array(z.string()), evidence: z.array(Evidence),
  finding: z.unknown().optional(),
  contributors: z.array(ProducerSchema).optional(),
}).strict();
export type SharedKnowledgeRecord = z.infer<typeof RecordSchema>;
type Producer = z.infer<typeof ProducerSchema>;
export const SHARED_KNOWLEDGE_SNAPSHOT = '00_shared_knowledge.json';
export const SHARED_KNOWLEDGE_TOOLS = ['lookup_shared_knowledge', 'get_shared_knowledge', 'publish_shared_observation'] as const;
const digest = (value: unknown) => createHash('sha256').update(JSON.stringify(value)).digest('hex');

function root(context: SharedKnowledgeContext): string {
  if (!/^[a-f0-9]{64}$/.test(context.namespace)) throw new Error('invalid shared knowledge namespace');
  return managedPath(context.engagementDir, join(context.engagementDir, 'shared-knowledge', context.namespace));
}

function sortedEvidence(evidence: StandardFinding['evidence']) {
  return [...evidence].sort((a, b) => a.path.localeCompare(b.path) || a.lineStart - b.lineStart || a.lineEnd - b.lineEnd || a.quote.localeCompare(b.quote));
}

function publish(context: SharedKnowledgeContext, producer: Producer,
  value: Omit<SharedKnowledgeRecord, 'id' | 'evidenceKey' | 'contributors'>): SharedKnowledgeRecord {
  if (context.snapshotPath) throw new Error('shared analysis snapshot is read-only');
  const evidence = sortedEvidence(value.evidence);
  const normalized = { kind: value.kind, summary: value.summary.trim(), tags: [...new Set(value.tags)].sort(), evidence,
    ...(value.finding === undefined ? {} : { finding: value.finding }) };
  const record: SharedKnowledgeRecord = { id: `K-${digest(normalized)}`, evidenceKey: digest(evidence), ...normalized };
  const directory = root(context);
  // Identical content always produces identical bytes. Atomic rename exposes no
  // partial JSON; separate provenance files prevent competing writers losing contributors.
  atomicPrivateWrite(join(directory, 'records', `${record.id}.json`), JSON.stringify(record) + '\n');
  const origin = ProducerSchema.parse({ role: producer.role, phase: producer.phase, round: producer.round,
    engagementDir: producer.engagementDir, findingId: producer.findingId });
  atomicPrivateWrite(join(directory, 'origins', record.id, `${digest(origin)}.json`), JSON.stringify(origin) + '\n');
  return record;
}

export function publishSharedObservation(context: SharedKnowledgeContext, producer: Producer, target: string,
  input: z.input<typeof Observation>): SharedKnowledgeRecord {
  const value = Observation.parse(input);
  const evidence = validateEvidence({ target, evidence: value.evidence, allowedFiles: context.sourceFiles });
  return publish(context, producer, { kind: 'observation', summary: value.summary, tags: value.tags, evidence });
}

/** Reuse the already validated finding; sharing never promotes it to a reviewed verdict. */
export function publishSharedFinding(context: SharedKnowledgeContext, producer: Producer, finding: StandardFinding): SharedKnowledgeRecord {
  const { id: _id, phase: _phase, role: _role, round: _round, ...claim } = finding;
  return publish(context, { ...producer, findingId: finding.id }, { kind: 'finding', summary: finding.title, tags: finding.standards,
    evidence: finding.evidence, finding: claim });
}

export function readSharedKnowledge(context: SharedKnowledgeContext): SharedKnowledgeRecord[] {
  if (context.snapshotPath) {
    const snapshot = JSON.parse(readManagedFile(context.engagementDir, context.snapshotPath).toString('utf8'));
    if (snapshot.namespace !== context.namespace) throw new Error('shared knowledge snapshot namespace mismatch');
    return z.array(RecordSchema).parse(snapshot.records);
  }
  const directory = join(root(context), 'records');
  if (!existsSync(directory)) return [];
  return readdirSync(directory).filter(name => /^K-[a-f0-9]{64}\.json$/.test(name)).sort().map(name => {
    const record = RecordSchema.parse(JSON.parse(readManagedFile(directory, join(directory, name)).toString('utf8')));
    if (`${record.id}.json` !== name) throw new Error('shared knowledge record identity mismatch');
    const origins = join(root(context), 'origins', record.id);
    const contributors = existsSync(origins) ? readdirSync(origins).filter(name => /^[a-f0-9]{64}\.json$/.test(name)).sort()
      .map(name => ProducerSchema.parse(JSON.parse(readManagedFile(origins, join(origins, name)).toString('utf8')))) : [];
    return { ...record, contributors };
  });
}

export function lookupSharedKnowledge(context: SharedKnowledgeContext,
  options: { query?: string; paths?: string[]; offset?: number; limit?: number } = {}) {
  const query = (options.query ?? '').toLocaleLowerCase();
  const records = readSharedKnowledge(context).filter(record =>
    (!query || `${record.summary}\n${record.tags.join(' ')}`.toLocaleLowerCase().includes(query)) &&
    (!options.paths?.length || record.evidence.some(evidence => options.paths!.includes(evidence.path))));
  const offset = Math.max(0, Math.floor(options.offset ?? 0));
  const limit = Math.min(20, Math.max(1, Math.floor(options.limit ?? 5)));
  return { total: records.length, nextOffset: offset + limit < records.length ? offset + limit : null,
    notice: 'Shared claims are unreviewed context, not proof of task completion or vulnerability confirmation. Reuse by ID; inspect conflicting evidence.',
    records: records.slice(offset, offset + limit).map(({ finding: _finding, evidence, summary, ...record }) => ({
      ...record, summary: summary.slice(0, 600), evidence: evidence.map(({ quote: _quote, ...location }) => location),
    })) };
}

export function getSharedKnowledge(context: SharedKnowledgeContext, id: string): SharedKnowledgeRecord {
  if (!/^K-[a-f0-9]{64}$/.test(id)) throw new Error('invalid shared knowledge ID');
  const record = readSharedKnowledge(context).find(record => record.id === id);
  if (!record) throw new Error(`unknown shared knowledge ID: ${id}`);
  return record;
}

export function snapshotSharedKnowledge(context: SharedKnowledgeContext): string {
  const path = join(context.engagementDir, SHARED_KNOWLEDGE_SNAPSHOT);
  atomicPrivateWrite(path, JSON.stringify({ namespace: context.namespace, records: readSharedKnowledge(context),
    notice: 'Source citations were checked by the host; security conclusions require review. Sharing does not count as an owner Read request.' }, null, 2) + '\n');
  return path;
}
