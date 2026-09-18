import { randomUUID } from 'node:crypto';

import {
  canonicalJson,
  outboxPayloadHash,
  OutboxMessageSchema,
  type OutboxMessage,
  type OutboxStore,
} from './outbox.js';
import type { SqlPool } from './run-lease.js';

type OutboxRow = {
  id: string;
  idempotency_key: string;
  topic: string;
  payload: unknown;
  payload_sha256: string;
  status: 'queued' | 'delivering' | 'delivered' | 'dead-letter';
  attempts: number | string;
  claim_token: string | null;
  claim_expires_at: Date | string | null;
  last_error: string | null;
};

function toMessage(row: OutboxRow): OutboxMessage {
  if (outboxPayloadHash(row.payload) !== row.payload_sha256) {
    throw new Error(`outbox payload hash가 일치하지 않는다: ${row.id}`);
  }
  return OutboxMessageSchema.parse({
    id: row.id,
    idempotencyKey: row.idempotency_key,
    topic: row.topic,
    payload: row.payload,
    payloadSha256: row.payload_sha256,
    status: row.status,
    attempts: Number(row.attempts),
    ...(row.claim_token ? { claimToken: row.claim_token } : {}),
    ...(row.claim_expires_at ? { claimExpiresAt: new Date(row.claim_expires_at).toISOString() } : {}),
    ...(row.last_error ? { lastError: row.last_error } : {}),
  });
}

export class PostgresOutboxStore implements OutboxStore {
  constructor(
    private readonly pool: SqlPool,
    private readonly maxAttempts = 3,
    private readonly visibilityTimeoutMs = 30_000,
  ) {
    if (!Number.isInteger(maxAttempts) || maxAttempts < 1) throw new Error('outbox maxAttempts가 잘못됐다');
    if (!Number.isInteger(visibilityTimeoutMs) || visibilityTimeoutMs < 1) {
      throw new Error('outbox visibilityTimeoutMs가 잘못됐다');
    }
  }

  async enqueue(input: { idempotencyKey: string; topic: string; payload: unknown }): Promise<OutboxMessage> {
    const id = `outbox-${randomUUID()}`;
    const hash = outboxPayloadHash(input.payload);
    const inserted = await this.pool.query(`
      INSERT INTO nunchi_outbox
        (id, idempotency_key, topic, payload_sha256, payload, status, attempts)
      VALUES ($1, $2, $3, $4, $5::jsonb, 'queued', 0)
      ON CONFLICT (idempotency_key) DO NOTHING
    `, [id, input.idempotencyKey, input.topic, hash, canonicalJson(input.payload)]);
    const existing = await this.pool.query<OutboxRow>(`
      SELECT id, idempotency_key, topic, payload, payload_sha256, status, attempts,
             claim_token, claim_expires_at, last_error
      FROM nunchi_outbox WHERE idempotency_key = $1
    `, [input.idempotencyKey]);
    const row = existing.rows[0];
    if (!row) throw new Error(`outbox insert가 확인되지 않았다: ${input.idempotencyKey}`);
    if (row.topic !== input.topic || row.payload_sha256 !== hash) {
      throw new Error(`outbox idempotency key collision: ${input.idempotencyKey}`);
    }
    void inserted;
    return toMessage(row);
  }

  async claim(limit: number): Promise<OutboxMessage[]> {
    if (!Number.isInteger(limit) || limit < 1) throw new Error('outbox claim limit가 잘못됐다');
    const connection = await this.pool.connect();
    try {
      await connection.query('BEGIN');
      await connection.query(`
        UPDATE nunchi_outbox
        SET status = CASE WHEN attempts >= $1 THEN 'dead-letter' ELSE 'queued' END,
            claim_token = NULL, claim_expires_at = NULL,
            last_error = 'delivery claim expired',
            updated_at = clock_timestamp()
        WHERE status = 'delivering' AND claim_expires_at <= clock_timestamp()
      `, [this.maxAttempts]);
      const result = await connection.query<OutboxRow>(`
        SELECT id, idempotency_key, topic, payload, payload_sha256, status, attempts,
               claim_token, claim_expires_at, last_error
        FROM nunchi_outbox
        WHERE status = 'queued' AND available_at <= clock_timestamp()
        ORDER BY created_at, id
        FOR UPDATE SKIP LOCKED
        LIMIT $1
      `, [limit]);
      const claimed: OutboxMessage[] = [];
      for (const row of result.rows) {
        const claimToken = randomUUID();
        const updated = await connection.query<OutboxRow>(`
          UPDATE nunchi_outbox
          SET status = 'delivering', attempts = attempts + 1, claim_token = $2,
              claim_expires_at = clock_timestamp() + ($3::bigint * interval '1 millisecond'),
              updated_at = clock_timestamp()
          WHERE id = $1
          RETURNING id, idempotency_key, topic, payload, payload_sha256, status, attempts,
                    claim_token, claim_expires_at, last_error
        `, [row.id, claimToken, this.visibilityTimeoutMs]);
        const next = updated.rows[0];
        if (!next) throw new Error(`outbox claim 대상이 사라졌다: ${row.id}`);
        claimed.push(toMessage(next));
      }
      await connection.query('COMMIT');
      return claimed;
    } catch (error) {
      await connection.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      connection.release();
    }
  }

  async markDelivered(id: string, claimToken: string): Promise<void> {
    const result = await this.pool.query(
      `UPDATE nunchi_outbox
       SET status = 'delivered', claim_token = NULL, claim_expires_at = NULL,
           updated_at = clock_timestamp()
       WHERE id = $1 AND status = 'delivering' AND claim_token = $2
         AND claim_expires_at > clock_timestamp()`,
      [id, claimToken],
    );
    if (result.rowCount !== 1) throw new Error(`outbox delivery claim이 유효하지 않다: ${id}`);
  }

  async markFailed(id: string, claimToken: string, reason: string): Promise<void> {
    if (!reason) throw new Error('outbox failure reason이 비어 있다');
    const result = await this.pool.query(
      `UPDATE nunchi_outbox
       SET status = CASE WHEN attempts >= $2 THEN 'dead-letter' ELSE 'queued' END,
           claim_token = NULL, claim_expires_at = NULL,
           last_error = $4, updated_at = clock_timestamp()
       WHERE id = $1 AND status = 'delivering' AND claim_token = $3
         AND claim_expires_at > clock_timestamp()`,
      [id, this.maxAttempts, claimToken, reason],
    );
    if (result.rowCount !== 1) throw new Error(`outbox failure claim이 유효하지 않다: ${id}`);
  }
}
