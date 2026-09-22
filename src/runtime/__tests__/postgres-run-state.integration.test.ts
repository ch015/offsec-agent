import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createOffsecAgent } from '../../index.js';
import { committedBudget, increaseResumeBudget } from '../missions/assessment-budget.js';
import { syntheticOutcome } from './resumption-fixture.js';
import { createHash, randomUUID } from 'node:crypto';
import { mkdirSync, mkdtempSync, realpathSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';

import { afterAll, describe, expect, it } from 'vitest';

import { createPostgresPool } from '../workflow/database.js';
import { InMemoryArtifactStore } from '../workflow/artifact-store.js';
import { createMissionRuntime } from '../workflow/mission-runtime.js';
import { PostgresOutboxStore } from '../workflow/postgres-outbox-store.js';
import { PostgresRunLeaseBackend } from '../workflow/run-lease.js';
import { PostgresRunStateStore } from '../workflow/postgres-run-state-store.js';
import { inspectRun, reconcileIncompleteAttempt, resumeRunWithInput } from '../workflow/reconciliation.js';

const enabled = Boolean(process.env.NUNCHI_DATABASE_URL);
const suite = describe.skipIf(!enabled);
const pool = enabled ? createPostgresPool() : undefined;

afterAll(async () => {
  await pool?.end();
});

suite('PostgresRunStateStore', () => {
  it('runs the mission runtime on PostgreSQL with lease, immutable artifact, state, and outbox effects', async () => {
    const database = pool!;
    const runId = `itest-mission-${randomUUID()}`;
    const engagementDir = `/tmp/${runId}`;
    mkdirSync(engagementDir, { recursive: false, mode: 0o700 });
    const artifacts = new InMemoryArtifactStore();
    const runtime = await createMissionRuntime({
      engagementDir,
      runId,
      contractId: 'itest-contract',
      contractVersion: '1.0.0',
      domain: 'soc',
      mission: 'report',
      maxBudgetUsd: 10,
    }, {
      backend: 'postgres', pool: database, artifactStore: artifacts, workerId: 'itest-mission', sharedEngagementRoot: '/tmp',
    });
    try {
      await increaseResumeBudget(runtime, { maxBudgetUsd: 1000000 }, null);
      expect((await database.query('SELECT max_budget_usd FROM nunchi_runs WHERE run_id = $1', [runId])).rows[0]?.max_budget_usd).toBe('1000000');
      await increaseResumeBudget(runtime, { noCostGuard: true }, null);
      expect((await runtime.read()).maxBudgetUsd).toBeUndefined();
      expect((await database.query('SELECT max_budget_usd FROM nunchi_runs WHERE run_id = $1', [runId])).rows[0]?.max_budget_usd).toBeNull();
      const receipt = await artifacts.put({
        uri: `artifact://${runId}/blocked.json`,
        content: new TextEncoder().encode('{"blocked":true}'),
        mediaType: 'application/json',
        producer: 'host/itest-mission',
      });
      const snapshot = await runtime.append({
        type: 'run.blocked',
        eventId: `${runId}:blocked`,
        reason: 'integration proof',
      }, {
        artifactReceipts: [receipt],
        outbox: [{
          id: `${runId}:blocked-outbox`,
          idempotencyKey: `${runId}:blocked`,
          topic: 'run.blocked',
          payload: { runId, reason: 'integration proof' },
        }],
      });
      expect(snapshot.status).toBe('blocked');
      expect((await database.query('SELECT state FROM nunchi_runs WHERE run_id = $1', [runId])).rows[0]?.state.status)
        .toBe('blocked');
      expect((await database.query('SELECT 1 FROM nunchi_artifact_receipts WHERE uri = $1', [receipt.uri])).rows)
        .toHaveLength(1);
      expect((await database.query('SELECT payload FROM nunchi_outbox WHERE id = $1', [`${runId}:blocked-outbox`])).rows[0]?.payload)
        .toEqual({ runId, reason: 'integration proof' });
    } finally {
      await runtime.close();
      await database.query('DELETE FROM nunchi_outbox WHERE id LIKE $1', [`${runId}:%`]);
      await database.query('DELETE FROM nunchi_artifact_receipts WHERE uri LIKE $1', [`artifact://${runId}/%`]);
      await database.query('DELETE FROM nunchi_run_events WHERE run_id = $1', [runId]);
      await database.query('DELETE FROM nunchi_run_leases WHERE run_id = $1', [runId]);
      await database.query('DELETE FROM nunchi_runs WHERE run_id = $1', [runId]);
      rmSync(engagementDir, { recursive: true, force: true });
    }
  });

  it('runs concurrent OffSec units with durable budget reservations and restores coverage on resume', async () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'offsec-pg-resume-'))), target = join(root, 'project');
    const runId = `itest-offsec-${randomUUID()}`, engagementDir = join(root, 'run');
    for (const name of ['a', 'b']) {
      const dir = join(target, 'packages', name); mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ name })); writeFileSync(join(dir, `${name}.ts`), `export const ${name} = 1;\n`);
    }
    let calls = 0;
    const agent = createOffsecAgent({ sessionRunner: async spec => { calls++; return syntheticOutcome(spec); },
      runtime: { backend: 'postgres', pool: pool!, artifactStore: new InMemoryArtifactStore(), sharedEngagementRoot: root } });
    try {
      const result = await agent.run({ target, engagementDir, engagementId: runId, maxBudgetUsd: 10, maxConcurrency: 2, semgrepMode: 'off' });
      expect(result.status).toBe('published'); expect(calls).toBe(5);
      const snapshot = await new PostgresRunStateStore(pool!, runId).read();
      expect(Object.values(snapshot.budgetReservations ?? {})).toHaveLength(5);
      expect(committedBudget(snapshot)).toBeCloseTo(0.05);
      unlinkSync(join(engagementDir, '00_analysis_coverage.json')); calls = 0;
      expect((await agent.resume(engagementDir)).status).toBe('published'); expect(calls).toBe(0);
    } finally {
      await pool!.query('DELETE FROM nunchi_outbox WHERE id LIKE $1', [`${runId}:%`]);
      await pool!.query('DELETE FROM nunchi_artifact_receipts WHERE uri LIKE $1', [`artifact://runs/${createHash('sha256').update(runId).digest('hex').slice(0, 32)}/%`]);
      await pool!.query('DELETE FROM nunchi_run_events WHERE run_id=$1', [runId]);
      await pool!.query('DELETE FROM nunchi_run_leases WHERE run_id=$1', [runId]);
      await pool!.query('DELETE FROM nunchi_runs WHERE run_id=$1', [runId]);
      rmSync(root, { recursive: true, force: true });
    }
  }, 30000);

  it('transactionally appends, deduplicates, serializes races, and rejects stale fences', async () => {
    const database = pool!;
    const runId = `itest-${randomUUID()}`;
    const store = await PostgresRunStateStore.create(database, {
      runId,
      contractId: 'itest-contract',
      contractVersion: '1.0.0',
      domain: 'offsec',
      mission: 'assessment',
    });
    const leases = new PostgresRunLeaseBackend(database);
    const firstLease = await leases.acquire({ runId, ownerId: 'itest-1', ttlMs: 30_000 });
    try {
      const started = {
        type: 'phase.started' as const,
        eventId: `${runId}:phase-1:started`,
        phase: 'phase-1',
        attempt: 1,
      };
      const first = await store.append(started, 1, firstLease.fencingToken);
      expect(first.lastSeq).toBe(2);

      await expect(store.append({ ...started, phase: 'different' }, 2, firstLease.fencingToken))
        .rejects.toThrow(/idempotency key 충돌/);
      expect(await store.append(started, 2, firstLease.fencingToken)).toEqual(first);

      const raceEvents = [1, 2].map((attempt) => ({
        type: 'phase.started' as const,
        eventId: `${runId}:race-${attempt}`,
        phase: `race-${attempt}`,
        attempt,
      }));
      const race = await Promise.allSettled(raceEvents.map((event) =>
        store.append(event, 2, firstLease.fencingToken),
      ));
      expect(race.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
      expect(race.filter((result) => result.status === 'rejected')).toHaveLength(1);
      expect((await store.read()).lastSeq).toBe(3);

      const receipt = {
        uri: `artifact://${runId}/phase-1.txt`,
        sha256: 'a'.repeat(64),
        bytes: 1,
        mediaType: 'text/plain',
        producer: 'host/itest',
      };
      const outboxId = `${runId}:outbox-1`;
      const coupledEvent = {
        type: 'phase.started' as const,
        eventId: `${runId}:coupled`,
        phase: 'coupled',
        attempt: 1,
      };
      const coupled = await store.appendBatchWithEffects([coupledEvent], 3, firstLease.fencingToken, {
        artifactReceipts: [receipt],
        outbox: [{
          id: outboxId,
          idempotencyKey: `${runId}:publish`,
          topic: 'run.phase.started',
          payload: { runId, phase: 'coupled' },
        }],
      });
      expect(coupled.lastSeq).toBe(4);
      expect((await database.query('SELECT 1 FROM nunchi_artifact_receipts WHERE uri = $1', [receipt.uri])).rows)
        .toHaveLength(1);
      expect((await database.query('SELECT 1 FROM nunchi_outbox WHERE id = $1', [outboxId])).rows)
        .toHaveLength(1);

      await expect(store.appendBatchWithEffects([{
        type: 'phase.started',
        eventId: `${runId}:rolled-back`,
        phase: 'rolled-back',
        attempt: 1,
      }], 4, firstLease.fencingToken, {
        artifactReceipts: [{ ...receipt, sha256: 'b'.repeat(64) }],
      })).rejects.toThrow(/immutable artifact URI collision/);
      expect((await store.read()).lastSeq).toBe(4);

      await expect(store.append({
        type: 'phase.completed',
        eventId: `${runId}:invalid-completed`,
        phase: 'phase-1',
        attempt: 1,
        artifacts: [],
        result: {},
      }, 4, firstLease.fencingToken)).rejects.toThrow(/provider receipt/);
      expect((await store.read()).lastSeq).toBe(4);
    } finally {
      await leases.release(firstLease);
      const secondLease = await leases.acquire({ runId, ownerId: 'itest-2', ttlMs: 30_000 });
      try {
        await expect(store.append({
          type: 'phase.started',
          eventId: `${runId}:stale-fence`,
          phase: 'stale-fence',
          attempt: 1,
        }, 4, firstLease.fencingToken)).rejects.toThrow(/fencing token/);
      } finally {
        await leases.release(secondLease);
        await database.query('DELETE FROM nunchi_outbox WHERE id LIKE $1', [`${runId}:%`]);
        await database.query('DELETE FROM nunchi_artifact_receipts WHERE uri LIKE $1', [`artifact://${runId}/%`]);
        await database.query('DELETE FROM nunchi_run_events WHERE run_id = $1', [runId]);
        await database.query('DELETE FROM nunchi_run_leases WHERE run_id = $1', [runId]);
        await database.query('DELETE FROM nunchi_runs WHERE run_id = $1', [runId]);
      }
    }
  });

  it('delivers PostgreSQL outbox messages at least once and dead-letters after retries', async () => {
    const database = pool!;
    const idempotencyKey = `itest-outbox-${randomUUID()}`;
    const outbox = new PostgresOutboxStore(database, 2);
    try {
      const first = await outbox.enqueue({
        idempotencyKey,
        topic: 'itest.topic',
        payload: { zz: 1, a: 2, idempotencyKey },
      });
      expect(await outbox.enqueue({
        idempotencyKey,
        topic: 'itest.topic',
        payload: { a: 2, idempotencyKey, zz: 1 },
      })).toEqual(first);
      await expect(outbox.enqueue({
        idempotencyKey,
        topic: 'itest.topic',
        payload: { changed: true },
      })).rejects.toThrow(/collision/);

      const firstClaim = (await outbox.claim(1))[0]!;
      expect(firstClaim.attempts).toBe(1);
      expect(firstClaim.payload).toEqual({ a: 2, idempotencyKey, zz: 1 });
      await outbox.markFailed(firstClaim.id, firstClaim.claimToken!, 'delivery-1');
      const secondClaim = (await outbox.claim(1))[0]!;
      expect(secondClaim.attempts).toBe(2);
      await outbox.markFailed(secondClaim.id, secondClaim.claimToken!, 'delivery-2');
      expect(await outbox.claim(1)).toEqual([]);
      expect((await database.query('SELECT status FROM nunchi_outbox WHERE id = $1', [first.id])).rows[0]?.status)
        .toBe('dead-letter');
    } finally {
      await database.query('DELETE FROM nunchi_outbox WHERE idempotency_key = $1', [idempotencyKey]);
    }
  });

  it('reclaims an expired PostgreSQL delivery and fences the stale worker', async () => {
    const database = pool!;
    const idempotencyKey = `itest-outbox-reclaim-${randomUUID()}`;
    const outbox = new PostgresOutboxStore(database, 3);
    try {
      await outbox.enqueue({ idempotencyKey, topic: 'itest.topic', payload: { recover: true } });
      const abandoned = (await outbox.claim(1))[0]!;
      await database.query(
        `UPDATE nunchi_outbox SET claim_expires_at = clock_timestamp() - interval '1 second' WHERE id = $1`,
        [abandoned.id],
      );
      await expect(outbox.markDelivered(abandoned.id, abandoned.claimToken!)).rejects.toThrow(/claim/);
      const reclaimed = (await outbox.claim(1))[0]!;
      expect(reclaimed.id).toBe(abandoned.id);
      expect(reclaimed.attempts).toBe(2);
      expect(reclaimed.claimToken).not.toBe(abandoned.claimToken);
      await expect(outbox.markDelivered(abandoned.id, abandoned.claimToken!)).rejects.toThrow(/claim/);
      await outbox.markDelivered(reclaimed.id, reclaimed.claimToken!);
    } finally {
      await database.query('DELETE FROM nunchi_outbox WHERE idempotency_key = $1', [idempotencyKey]);
    }
  });

  it('refuses to deliver a PostgreSQL outbox payload whose hash no longer matches', async () => {
    const database = pool!;
    const idempotencyKey = `itest-outbox-tamper-${randomUUID()}`;
    const outbox = new PostgresOutboxStore(database);
    try {
      const message = await outbox.enqueue({ idempotencyKey, topic: 'itest.topic', payload: { trusted: true } });
      await database.query(`UPDATE nunchi_outbox SET payload = '{"trusted":false}'::jsonb WHERE id = $1`, [message.id]);
      await expect(outbox.claim(1)).rejects.toThrow(/payload hash/);
    } finally {
      await database.query('DELETE FROM nunchi_outbox WHERE idempotency_key = $1', [idempotencyKey]);
    }
  });

  it('keeps reconcile, resume, and blocked transitions explicit on PostgreSQL state', async () => {
    const database = pool!;
    const runIds = [`itest-reconcile-${randomUUID()}`, `itest-feedback-${randomUUID()}`, `itest-soc-${randomUUID()}`];
    const leases = new PostgresRunLeaseBackend(database);
    try {
      const reconcileStore = await PostgresRunStateStore.create(database, {
        runId: runIds[0]!, contractId: 'itest', contractVersion: '1.0.0', domain: 'offsec', mission: 'assessment',
      });
      const reconcileLease = await leases.acquire({ runId: runIds[0]!, ownerId: 'itest-reconcile', ttlMs: 30_000 });
      await reconcileStore.append({ type: 'phase.started', eventId: `${runIds[0]}:started`, phase: 'scan', attempt: 1 }, 1, reconcileLease.fencingToken);
      const inspected = await inspectRun(reconcileStore);
      expect(inspected.incompleteAttempts).toHaveLength(1);
      const reconciled = await reconcileIncompleteAttempt({
        state: reconcileStore,
        expectedVersion: inspected.lastSeq,
        phase: 'scan',
        attempt: 1,
        reasonCode: 'provider-error',
        fencingToken: reconcileLease.fencingToken,
      });
      expect(reconciled.attempts['scan:-:1']?.status).toBe('failed');
      await leases.release(reconcileLease);

      const feedbackStore = await PostgresRunStateStore.create(database, {
        runId: runIds[1]!, contractId: 'itest', contractVersion: '1.0.0', domain: 'feedback', mission: 'design-review',
      });
      const feedbackLease = await leases.acquire({ runId: runIds[1]!, ownerId: 'itest-feedback', ttlMs: 30_000 });
      const manifest = {
        id: `${runIds[1]}:manifest`, name: 'manifest.json', path: `/tmp/${runIds[1]}-manifest.json`,
        mediaType: 'application/json', sha256: '1'.repeat(64), bytes: 1,
        producer: { phase: 'input', role: 'host', attempt: '0' },
      };
      const clarification = {
        id: `${runIds[1]}:clarification`, name: 'clarification.json', path: `/tmp/${runIds[1]}-clarification.json`,
        mediaType: 'application/json', sha256: '2'.repeat(64), bytes: 1,
        producer: { phase: 'analyze', role: 'host', attempt: 'analyze:-:1' },
      };
      await feedbackStore.append({
        type: 'input.recorded', eventId: `${runIds[1]}:input:0`, input: {
          inputRevision: 0, contextEpoch: '3'.repeat(64), manifest,
          allowedReadFiles: [manifest.path], fileHashes: [{ path: manifest.path, sha256: '4'.repeat(64), bytes: 1 }],
        },
      }, 1, feedbackLease.fencingToken);
      await feedbackStore.append({
        type: 'run.awaiting-input', eventId: `${runIds[1]}:awaiting`, reason: 'missing evidence', artifact: clarification,
      }, 2, feedbackLease.fencingToken);
      const resumed = await resumeRunWithInput({
        state: feedbackStore,
        expectedVersion: 3,
        fencingToken: feedbackLease.fencingToken,
        revisedInput: {
          inputRevision: 1, contextEpoch: '5'.repeat(64),
          manifest: { ...manifest, id: `${runIds[1]}:manifest:1`, sha256: '6'.repeat(64) },
          allowedReadFiles: [`/tmp/${runIds[1]}-manifest-1.json`],
          fileHashes: [{ path: `/tmp/${runIds[1]}-manifest-1.json`, sha256: '7'.repeat(64), bytes: 1 }],
          parent: { manifestSha256: manifest.sha256, triggerArtifactSha256: clarification.sha256 },
        },
      });
      expect(resumed.status).toBe('running');
      expect((await inspectRun(feedbackStore)).inputRevision).toBe(1);
      await leases.release(feedbackLease);

      const socStore = await PostgresRunStateStore.create(database, {
        runId: runIds[2]!, contractId: 'itest', contractVersion: '1.0.0', domain: 'soc', mission: 'report',
      });
      const socLease = await leases.acquire({ runId: runIds[2]!, ownerId: 'itest-soc', ttlMs: 30_000 });
      await socStore.append({ type: 'run.blocked', eventId: `${runIds[2]}:blocked`, reason: 'coverage-incomplete' }, 1, socLease.fencingToken);
      expect((await inspectRun(socStore)).status).toBe('blocked');
      await leases.release(socLease);
    } finally {
      for (const runId of runIds) {
        await database.query('DELETE FROM nunchi_run_leases WHERE run_id = $1', [runId]);
        await database.query('DELETE FROM nunchi_run_events WHERE run_id = $1', [runId]);
        await database.query('DELETE FROM nunchi_runs WHERE run_id = $1', [runId]);
      }
    }
  });
});
