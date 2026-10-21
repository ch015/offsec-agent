import { createHash } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import type { SharedKnowledgeRecord } from '../shared-knowledge.js';
import { parseCve, REFERENCE_NOTICE } from './cve.js';

export type KnowledgePin = { catalogId: string; referenceRevision: string };
export type KnowledgePage = { query?: string; paths?: string[]; offset?: number; limit?: number };
export type SharedKindFilter = { kind?: 'observation' };
const digest = (text: string) => createHash('sha256').update(text).digest('hex');
export class KnowledgeStorageError extends Error { override name = 'KnowledgeStorageError'; }
/** A stored run no longer matches what it pinned. Retrying or resuming repeats the same failure. */
export class KnowledgeIntegrityError extends KnowledgeStorageError { override name = 'KnowledgeIntegrityError'; }

/** Only the host owns this pool. Model calls receive a pre-bound scope, never SQL or credentials. */
export class PostgresKnowledgeStore {
  constructor(private readonly pool: Pool) {}

  async currentPin(): Promise<KnowledgePin> {
    return this.guarded(async () => {
      const row = (await this.pool.query('SELECT catalog_id::text,revision::text FROM nunchi_knowledge_catalog WHERE singleton')).rows[0];
      return { catalogId: row.catalog_id, referenceRevision: row.revision };
    });
  }

  private async guarded<T>(operation: () => Promise<T>): Promise<T> {
    try { return await operation(); } catch (error) {
      if (error instanceof KnowledgeStorageError) throw error;
      const code = (error as { code?: string })?.code;
      throw new KnowledgeStorageError(`PostgreSQL knowledge operation failed${code && /^[A-Z0-9]{5}$/.test(code) ? ` (${code})` : ''}; check connection/config and run pnpm db:migrate. Durable local records can be replayed on resume.`);
    }
  }
  private async transaction<T>(operation: (client: PoolClient) => Promise<T>): Promise<T> {
    return this.guarded(async () => {
      const client = await this.pool.connect();
      try { await client.query('BEGIN'); const result = await operation(client); await client.query('COMMIT'); return result; }
      catch (error) { await client.query('ROLLBACK').catch(() => undefined); throw error; }
      finally { client.release(); }
    });
  }

  async pin(scope: string, expected?: KnowledgePin): Promise<KnowledgePin> {
    return this.transaction(async client => {
      // Catalog revision advances in the same transaction as ingestion; a pin never
      // includes an uncommitted import that could arrive later below its watermark.
      const catalog = (await client.query('SELECT catalog_id::text, revision::text FROM nunchi_knowledge_catalog WHERE singleton')).rows[0];
      if (expected && (catalog.catalog_id !== expected.catalogId || BigInt(catalog.revision) < BigInt(expected.referenceRevision))) {
        throw new KnowledgeIntegrityError('Knowledge catalog does not match the pinned run; restore the original database snapshot.');
      }
      await client.query(`INSERT INTO nunchi_knowledge_runs(scope_id,catalog_id,reference_revision) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`,
        [scope, catalog.catalog_id, expected?.referenceRevision ?? catalog.revision]);
      const row = (await client.query('SELECT catalog_id::text,reference_revision::text FROM nunchi_knowledge_runs WHERE scope_id=$1', [scope])).rows[0];
      const pin = { catalogId: row.catalog_id as string, referenceRevision: row.reference_revision as string };
      if (pin.catalogId !== catalog.catalog_id || (expected && JSON.stringify(pin) !== JSON.stringify(expected))) throw new KnowledgeIntegrityError('Knowledge run snapshot mismatch');
      return pin;
    });
  }

  async putShared(scope: string, view: string, record: SharedKnowledgeRecord): Promise<void> {
    const { contributors = [], ...body } = record;
    await this.transaction(async client => {
      const result = await client.query(`INSERT INTO nunchi_shared_records(scope_id,view_id,record_id,body,search_text,paths)
        VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(scope_id,view_id,record_id) DO UPDATE SET body=nunchi_shared_records.body
        WHERE nunchi_shared_records.body=EXCLUDED.body RETURNING record_id`,
        [scope, view, record.id, body, `${record.summary}\n${record.tags.join(' ')}`, [...new Set(record.evidence.map(e => e.path))]]);
      if (!result.rowCount) throw new KnowledgeIntegrityError('Shared knowledge identity conflict; preserve both source records for inspection.');
      for (const origin of contributors) await client.query(`INSERT INTO nunchi_shared_origins(scope_id,view_id,record_id,digest,body)
        VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, [scope, view, record.id, digest(JSON.stringify({
          role: origin.role, phase: origin.phase, round: origin.round, engagementDir: origin.engagementDir, findingId: origin.findingId,
        })), origin]);
    });
  }

  async lookupShared(scope: string, view: string, options: KnowledgePage & SharedKindFilter = {}) {
    const { offset, limit } = page(options);
    return this.guarded(async () => {
      const result = await this.pool.query(`WITH matches AS (
        SELECT record_id,body FROM nunchi_shared_records WHERE scope_id=$1 AND view_id=$2
        AND ($3='' OR search_vector @@ websearch_to_tsquery('simple',$3))
        AND (cardinality($4::text[])=0 OR paths && $4::text[])
        AND ($7='' OR body->>'kind'=$7)
      ), selected AS (SELECT * FROM matches ORDER BY record_id OFFSET $5 LIMIT $6)
      SELECT (SELECT count(*)::int FROM matches) AS total,
        COALESCE((SELECT jsonb_agg((body - 'finding' - 'evidence' - 'summary') || jsonb_build_object(
          'summary',left(body->>'summary',600),'evidence',(SELECT jsonb_agg(e - 'quote') FROM jsonb_array_elements(body->'evidence') e)) ORDER BY record_id) FROM selected),'[]'::jsonb) AS records`,
        [scope, view, options.query ?? '', options.paths ?? [], offset, limit, options.kind ?? '']);
      const row = result.rows[0];
      return { total: row.total as number, nextOffset: offset + limit < row.total ? offset + limit : null,
        notice: 'Shared claims are unreviewed context, not proof of task completion or vulnerability confirmation. Reuse by ID; inspect conflicting evidence.', records: row.records };
    });
  }

  async getShared(scope: string, view: string, id: string, filter: SharedKindFilter = {}): Promise<SharedKnowledgeRecord> {
    if (!/^K-[a-f0-9]{64}$/.test(id)) throw new KnowledgeStorageError('Invalid shared knowledge ID');
    return this.guarded(async () => {
      const result = await this.pool.query(`SELECT body || jsonb_build_object('contributors',
        COALESCE((SELECT jsonb_agg(o.body ORDER BY digest) FROM nunchi_shared_origins o
          WHERE o.scope_id=r.scope_id AND o.view_id=r.view_id AND o.record_id=r.record_id),'[]'::jsonb)) AS record
        FROM nunchi_shared_records r WHERE scope_id=$1 AND view_id=$2 AND record_id=$3
        AND ($4='' OR body->>'kind'=$4)`, [scope, view, id, filter.kind ?? '']);
      if (!result.rowCount) throw new KnowledgeStorageError('Unknown shared knowledge ID in this scope');
      return result.rows[0].record;
    });
  }

  async putDocument(scope: string, kind: 'finding' | 'instruction', key: string, body: string,
    metadata: { id?: string; role?: string; phase?: string } = {}) {
    return this.guarded(async () => {
      const sha = digest(body);
      await this.pool.query(`INSERT INTO nunchi_knowledge_documents(scope_id,kind,record_key,digest,body,finding_id,role,phase)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`, [scope, kind, key, sha, body, metadata.id, metadata.role, metadata.phase]);
      return sha;
    });
  }

  async pinInstruction(scope: string, key: string, body: string): Promise<string> {
    const sha = digest(body);
    return this.transaction(async client => {
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1),hashtext($2))', [scope, key]);
      const conflict = await client.query(`SELECT 1 FROM nunchi_knowledge_documents
        WHERE scope_id=$1 AND kind='instruction' AND record_key=$2 AND digest<>$3 LIMIT 1`, [scope, key, sha]);
      if (conflict.rowCount) throw new KnowledgeIntegrityError('Pinned run instructions changed; restore their original revision or start a new run.');
      await client.query(`INSERT INTO nunchi_knowledge_documents(scope_id,kind,record_key,digest,body)
        VALUES($1,'instruction',$2,$3,$4) ON CONFLICT DO NOTHING`, [scope, key, sha, body]);
      return sha;
    });
  }

  async lookupFindings(scope: string, options: { id?: string; offset?: number; limit?: number } = {}) {
    const { offset, limit } = page(options);
    return this.guarded(async () => {
      const result = await this.pool.query(`WITH matches AS (SELECT record_key,digest,finding_id,role,phase,recorded_at FROM nunchi_knowledge_documents
        WHERE scope_id=$1 AND kind='finding' AND ($2::text IS NULL OR finding_id=$2)), selected AS (
        SELECT * FROM matches ORDER BY record_key,digest OFFSET $3 LIMIT $4)
        SELECT (SELECT count(*)::int FROM matches) total,COALESCE((SELECT jsonb_agg(selected ORDER BY record_key,digest) FROM selected),'[]'::jsonb) records`,
        [scope, options.id ?? null, offset, limit]);
      const row = result.rows[0];
      return { ...row, nextOffset: offset + limit < row.total ? offset + limit : null,
        notice: 'Version history, including incomplete attempts. record_key identifies provenance; digest identifies exact bytes. These records do not supersede host-selected canonical findings or prove review completion.' };
    });
  }

  async getDocument(scope: string, kind: 'finding' | 'instruction', key: string, sha: string): Promise<string> {
    return this.guarded(async () => {
      const result = await this.pool.query('SELECT body FROM nunchi_knowledge_documents WHERE scope_id=$1 AND kind=$2 AND record_key=$3 AND digest=$4', [scope, kind, key, sha]);
      if (!result.rowCount) throw new KnowledgeStorageError('Unknown document revision in this scope');
      const body = result.rows[0].body as string;
      if (digest(body) !== sha) throw new KnowledgeIntegrityError('Document revision integrity mismatch');
      return body;
    });
  }

  async importCve(raw: string, origin?: { uri: string; revision?: string }) {
    const record = parseCve(raw);
    return this.transaction(async client => {
      // Serialize the catalog commit watermark, not model execution.
      await client.query('SELECT revision FROM nunchi_knowledge_catalog WHERE singleton FOR UPDATE');
      const existing = await client.query('SELECT catalog_revision::text FROM nunchi_advisory_revisions WHERE cve_id=$1 AND digest=$2', [record.cveId, record.digest]);
      if (existing.rowCount) return { cveId: record.cveId, digest: record.digest, revision: existing.rows[0].catalog_revision, inserted: false };
      const revision = (await client.query('UPDATE nunchi_knowledge_catalog SET revision=revision+1 WHERE singleton RETURNING revision::text')).rows[0].revision;
      await client.query(`INSERT INTO nunchi_advisory_revisions(cve_id,digest,catalog_revision,source_url,source_modified_at,state,title,search_text,normalized,raw_text,import_origin)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, [record.cveId, record.digest, revision, record.sourceUrl, record.modified, record.state, record.title, record.searchText, record.normalized, raw,
          { method: 'local-import', ...origin }]);
      return { cveId: record.cveId, digest: record.digest, revision, inserted: true };
    });
  }

  async lookupAdvisories(pin: KnowledgePin, options: { query?: string; id?: string; offset?: number; limit?: number } = {}) {
    const { offset, limit } = page(options);
    return this.guarded(async () => {
      // Select the newest source revision BEFORE matching text: a rejected or corrected
      // advisory must not make an older matching description reappear as current.
      const result = await this.pool.query(`WITH matches AS (SELECT a.cve_id,a.digest,a.state,a.title,a.source_modified_at,a.ingested_at,a.source_url,a.import_origin
        FROM nunchi_advisory_revisions a WHERE a.catalog_revision <= $1 AND ($2::text IS NULL OR a.cve_id=$2)
        AND ($3='' OR a.search_vector @@ websearch_to_tsquery('simple',$3))
        AND NOT EXISTS(SELECT 1 FROM nunchi_advisory_revisions b WHERE b.cve_id=a.cve_id AND b.catalog_revision <= $1
          AND (b.source_modified_at,b.catalog_revision) > (a.source_modified_at,a.catalog_revision))),
        selected AS (SELECT * FROM matches ORDER BY cve_id OFFSET $4 LIMIT $5)
        SELECT (SELECT count(*)::int FROM matches) total,COALESCE((SELECT jsonb_agg(selected ORDER BY cve_id) FROM selected),'[]'::jsonb) records`,
        [pin.referenceRevision, options.id ?? null, options.query ?? '', offset, limit]);
      const row = result.rows[0];
      return { ...row, nextOffset: offset + limit < row.total ? offset + limit : null, snapshot: pin, notice: REFERENCE_NOTICE };
    });
  }

  async getAdvisory(pin: KnowledgePin, id: string, sha: string) {
    return this.guarded(async () => {
      const result = await this.pool.query(`SELECT cve_id,digest,state,source_url,source_modified_at,ingested_at,normalized,raw_text,import_origin
        FROM nunchi_advisory_revisions WHERE cve_id=$1 AND digest=$2 AND catalog_revision <= $3`, [id, sha, pin.referenceRevision]);
      if (!result.rowCount) throw new KnowledgeStorageError('Unknown advisory revision in this snapshot');
      if (digest(result.rows[0].raw_text) !== sha) throw new KnowledgeIntegrityError('Advisory revision integrity mismatch');
      return { ...result.rows[0], snapshot: pin, notice: REFERENCE_NOTICE };
    });
  }
}

function page(options: { offset?: number; limit?: number }) {
  const offset = options.offset ?? 0, limit = options.limit ?? 5;
  if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isInteger(limit) || limit < 1 || limit > 20) throw new KnowledgeStorageError('Invalid knowledge pagination');
  return { offset, limit };
}
