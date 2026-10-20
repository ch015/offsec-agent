import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Pool } from 'pg';
import { createPostgresPool } from '../workflow/database.js';
import { PostgresKnowledgeStore } from '../knowledge/postgres-knowledge.js';
import { KnowledgeRuntime, KNOWLEDGE_BINDING, indexSharedRecord } from '../knowledge/runtime.js';
import { publishSharedObservation, snapshotSharedKnowledge, type SharedKnowledgeContext } from '../shared-knowledge.js';
import { cveFixture } from './fixtures/cve.js';
import { createOffsecAgent } from '../../api/agent.js';
import { syntheticOutcome } from './resumption-fixture.js';

vi.mock('@anthropic-ai/claude-agent-sdk', async importOriginal => {
  const actual = await importOriginal<typeof import('@anthropic-ai/claude-agent-sdk')>();
  return { ...actual, createSdkMcpServer: (config: unknown) => config,
    tool: (name: string, _description: string, _schema: unknown, handler: unknown) => ({ name, handler }) };
});
import { createFindingMcpServer } from '../finding-mcp-server.js';
type TestTool = { name: string; handler: (value: any) => Promise<{ content: Array<{ text: string }>; isError?: boolean }> };
const url = process.env.NUNCHI_KNOWLEDGE_TEST_URL ?? process.env.NUNCHI_DATABASE_URL;
const schema = `kb_test_${randomUUID().replaceAll('-', '')}`;
let admin: Pool, pool: Pool, store: PostgresKnowledgeStore;
const roots: string[] = [];

describe.skipIf(!url)('PostgreSQL knowledge integration', () => {
  beforeAll(async () => {
    admin = createPostgresPool({ NUNCHI_DATABASE_URL: url });
    await admin.query(`CREATE SCHEMA ${schema}`);
    const isolated = new URL(url!); isolated.searchParams.set('options', `-c search_path=${schema}`);
    pool = createPostgresPool({ NUNCHI_DATABASE_URL: isolated.toString() });
    await pool.query(readFileSync(new URL('../knowledge/schema.sql', import.meta.url), 'utf8'));
    // Reapplying migrations preserves data and does not require an extension.
    await pool.query(readFileSync(new URL('../knowledge/schema.sql', import.meta.url), 'utf8'));
    store = new PostgresKnowledgeStore(pool);
  });
  afterAll(async () => { await pool?.end(); if (admin) { await admin.query(`DROP SCHEMA ${schema} CASCADE`); await admin.end(); } });
  afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

  function fixture() {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'postgres-kb-'))); roots.push(root);
    const target = join(root, 'target'); mkdirSync(target);
    const source = join(target, 'app.ts'); writeFileSync(source, 'export const authenticated = true;\n');
    const context: SharedKnowledgeContext = { engagementDir: join(root, 'run'), namespace: 'a'.repeat(64), sourceFiles: [source] };
    const producer = { engagementDir: join(context.engagementDir, 'unit-a'), role: 'analyzer', phase: 'analyze', round: 'unit-a' };
    const observation = { summary: 'Authentication flag', tags: ['auth'], evidence: [{ path: 'app.ts', lineStart: 1, lineEnd: 1, quote: 'export const authenticated = true;' }] };
    const tools = (shared: SharedKnowledgeContext, role = 'analyzer', phase = 'analyze') => (createFindingMcpServer({
      target, engagementDir: producer.engagementDir, role, phase, round: 'unit-a', sharedKnowledge: shared, evidenceAllowedFiles: [source],
    }) as unknown as { tools: TestTool[] }).tools;
    return { root, context, target, source, producer, observation, tools };
  }

  it('deduplicates concurrent shared writes, retains all contributors and isolates scope/view with indexed lookup', async () => {
    const f = fixture(), runtime = (await KnowledgeRuntime.open(f.context.engagementDir, { backend: 'postgres', pool }))!;
    const context = await runtime.bind(f.context), binding = context[KNOWLEDGE_BINDING]!;
    const record = publishSharedObservation(context, f.producer, f.target, f.observation);
    await Promise.all(Array.from({ length: 12 }, (_, index) => indexSharedRecord(context, record, { ...f.producer, round: `unit-${index}` })));
    await indexSharedRecord(context, record, { round: 'unit-0', phase: f.producer.phase, role: f.producer.role, engagementDir: f.producer.engagementDir });
    const page = await store.lookupShared(binding.scope, 'live', { query: 'auth', paths: ['app.ts'] });
    expect(page.total).toBe(1); expect(page.records[0].evidence[0]).not.toHaveProperty('quote');
    expect((await store.getShared(binding.scope, 'live', record.id)).contributors).toHaveLength(12);
    await expect(store.getShared('other-run', 'live', record.id)).rejects.toThrow(/scope/);
    await expect(store.putShared(binding.scope, 'live', { ...record, summary: 'Conflicting bytes' })).rejects.toThrow(/identity conflict/);
    expect((await store.lookupShared(binding.scope, 'live', { offset: 100 })).total).toBe(1);
    expect((await store.lookupShared(binding.scope, 'live', { query: "' OR 1=1 --" })).total).toBe(0);
    const frozen = await runtime.bind({ ...context, snapshotPath: snapshotSharedKnowledge(context) });
    const late = publishSharedObservation(context, f.producer, f.target, { ...f.observation, summary: 'Later observation' });
    await indexSharedRecord(context, late, f.producer);
    expect((await store.lookupShared(binding.scope, frozen[KNOWLEDGE_BINDING]!.view)).total).toBe(1);
    expect((await store.lookupShared(binding.scope, 'live')).total).toBe(2);
    // A DB lookup must work without parsing the file snapshot on every request.
    rmSync(frozen.snapshotPath!);
    const getter = f.tools(frozen, 'reviewer', 'review').find(tool => tool.name === 'get_shared_knowledge')!;
    expect((await getter.handler({ id: record.id })).isError).not.toBe(true);
    expect(JSON.stringify(context)).not.toContain('store');
    await runtime.close();
  });

  it('preserves CVE original bytes, ADP fields, corrections, rejection and per-run snapshots', async () => {
    const original = cveFixture(), receipt = await store.importCve(original);
    const oldPin = await store.pin(randomUUID());
    expect((await store.importCve(original)).inserted).toBe(false);
    const corrected = await store.importCve(cveFixture('2026-10-09T00:00:00Z', 'REJECTED'));
    const current = await store.currentPin();
    expect((await store.lookupAdvisories(oldPin, { id: receipt.cveId })).records[0].state).toBe('PUBLISHED');
    expect((await store.lookupAdvisories(current, { id: receipt.cveId })).records[0].state).toBe('REJECTED');
    const old = await store.getAdvisory(oldPin, receipt.cveId, receipt.digest);
    expect(old.raw_text).toBe(original); expect(old.normalized.containers.adp[0].customFutureField.original).toBe(true);
    await expect(store.getAdvisory(oldPin, corrected.cveId, corrected.digest)).rejects.toThrow(/snapshot/);
    await store.importCve(cveFixture('2026-10-01T00:00:00Z'));
    expect((await store.lookupAdvisories(await store.currentPin(), { id: receipt.cveId })).records[0].digest).toBe(corrected.digest);
    const withdrawn = JSON.parse(cveFixture('2026-10-10T00:00:00Z', 'REJECTED'));
    withdrawn.containers.cna = { title: 'Withdrawn' }; withdrawn.containers.adp = [];
    await store.importCve(JSON.stringify(withdrawn));
    expect((await store.lookupAdvisories(await store.currentPin(), { query: 'Sample' })).total).toBe(0);
    const rawAgain = await store.getAdvisory(await store.currentPin(), receipt.cveId, receipt.digest);
    expect(rawAgain.raw_text).toBe(original);
  });

  it('does not include an uncommitted ingestion in a reference snapshot', async () => {
    const client = await pool.connect();
    const before = await store.currentPin();
    try {
      await client.query('BEGIN');
      await client.query('UPDATE nunchi_knowledge_catalog SET revision=revision+1 WHERE singleton');
      const pinned = await store.pin(randomUUID());
      expect(pinned.referenceRevision).toBe(before.referenceRevision);
      await client.query('ROLLBACK');
    } finally { client.release(); }
  });

  it('reuses a pinned run on resume and rejects a different catalog', async () => {
    const f = fixture();
    const first = (await KnowledgeRuntime.open(f.context.engagementDir, { backend: 'postgres', pool }))!;
    const original = readFileSync(join(f.context.engagementDir, '00_reference_knowledge.json'), 'utf8');
    await first.close();
    await store.importCve(cveFixture().replaceAll('CVE-2026-123456', 'CVE-2026-123457'));
    const resumed = (await KnowledgeRuntime.open(f.context.engagementDir, { backend: 'postgres', pool }))!;
    expect(readFileSync(join(f.context.engagementDir, '00_reference_knowledge.json'), 'utf8')).toBe(original);
    await resumed.close();
    writeFileSync(join(f.context.engagementDir, '00_reference_knowledge.json'), JSON.stringify({ ...JSON.parse(original), catalogId: randomUUID() }));
    await expect(KnowledgeRuntime.open(f.context.engagementDir, { backend: 'postgres', pool })).rejects.toThrow(/catalog/);
  });

  it('preserves same-ID finding versions and replays a durable submission after DB failure', async () => {
    const f = fixture(), runtime = (await KnowledgeRuntime.open(f.context.engagementDir, { backend: 'postgres', pool }))!;
    const context = await runtime.bind(f.context), binding = context[KNOWLEDGE_BINDING]!;
    const submit = f.tools(context).find(tool => tool.name === 'submit_finding')!;
    const finding = { title: 'Configuration review example', verdict: 'abstain', severity: 'INFO', evidenceClass: 'configuration',
      reachability: 'unconfirmed', preconditions: [], severityRationale: 'Impact is unknown pending independent verification.', confidence: 0.5,
      impact: 'Unknown', remediation: 'Review configuration.', standards: [], unresolved: ['Need configuration context'], evidence: f.observation.evidence };
    const first = await submit.handler(finding); expect(first.isError).not.toBe(true);
    const id = JSON.parse(first.content[0]!.text).id;
    const fail = vi.spyOn(binding.store, 'putDocument').mockRejectedValueOnce(new Error('Simulated DB failure'));
    const revised = await submit.handler({ ...finding, remediation: 'Check the approved configuration baseline.' });
    expect(revised.isError).toBe(true); fail.mockRestore();
    await runtime.syncFindings(f.producer.engagementDir);
    const history = await store.lookupFindings(binding.documentScope, { id });
    expect(history.total).toBe(2);
    for (const version of history.records) {
      const body = await store.getDocument(binding.documentScope, 'finding', version.record_key, version.digest);
      expect(createHash('sha256').update(body).digest('hex')).toBe(version.digest);
    }
    await expect(store.getDocument('another-run', 'finding', history.records[0].record_key, history.records[0].digest)).rejects.toThrow(/scope/);
    const instruction = 'Mandatory rule A.\nMandatory rule B.\n';
    expect(await runtime.saveInstruction('reviewer', instruction)).toBe(instruction);
    expect(await runtime.saveInstruction('reviewer', instruction + 'New revision.')).toContain('New revision');
    expect(await runtime.saveInstruction('mandatory-policy', instruction, true)).toBe(instruction);
    await expect(runtime.saveInstruction('mandatory-policy', 'Changed mid-run', true)).rejects.toThrow(/Pinned run instructions changed/);
    expect((await pool.query("SELECT count(*)::int count FROM nunchi_knowledge_documents WHERE scope_id=$1 AND kind='instruction' AND record_key='reviewer'", [binding.documentScope])).rows[0].count).toBe(2);
    await runtime.close();
  });

  it('exposes external knowledge only after the analysis snapshot and returns bounded, labelled references', async () => {
    const f = fixture();
    const receipt = await store.importCve(cveFixture().replaceAll('CVE-2026-123456', 'CVE-2026-123458'));
    const runtime = (await KnowledgeRuntime.open(f.context.engagementDir, { backend: 'postgres', pool }))!;
    const context = await runtime.bind(f.context);
    expect(f.tools(context).some(tool => tool.name.includes('advisory') || tool.name.includes('advisories'))).toBe(false);
    const frozen = await runtime.bind({ ...context, snapshotPath: snapshotSharedKnowledge(context) });
    const tools = f.tools(frozen, 'reviewer', 'review');
    const query = await tools.find(tool => tool.name === 'lookup_security_advisories')!.handler({ id: receipt.cveId });
    const page = JSON.parse(query.content[0]!.text); expect(page.notice).toContain('applicability is unknown');
    const getter = tools.find(tool => tool.name === 'get_security_advisory')!;
    let raw = '', offset: number | null = 0;
    while (offset !== null) {
      const part = await getter.handler({ id: receipt.cveId, digest: receipt.digest, section: 'raw', offset, limit: 200 });
      expect(part.isError).not.toBe(true);
      const value = JSON.parse(part.content[0]!.text); raw += value.content; offset = value.nextOffset;
    }
    expect(raw).toBe(cveFixture().replaceAll('CVE-2026-123456', 'CVE-2026-123458'));
    expect(readFileSync(join(f.context.engagementDir, 'knowledge-access.jsonl'), 'utf8')).toContain(receipt.digest);
    await runtime.close();
  });

  it('runs a complete synthetic assessment with PostgreSQL knowledge and no provider calls', async () => {
    const f = fixture();
    const result = await createOffsecAgent({ knowledge: { backend: 'postgres', pool }, sessionRunner: async spec => {
      if (spec.sharedKnowledge && spec.workUnit) {
        const record = publishSharedObservation(spec.sharedKnowledge, f.producer, spec.target, f.observation);
        await indexSharedRecord(spec.sharedKnowledge, record, f.producer);
      }
      if (spec.phase === 'review') {
        const binding = spec.sharedKnowledge![KNOWLEDGE_BINDING]!;
        expect(binding).toBeDefined(); expect((await binding.store.lookupShared(binding.scope, binding.view)).total).toBe(1);
        expect(spec.taskData).toHaveProperty('referenceKnowledge');
      }
      return syntheticOutcome(spec);
    } }).run({ target: f.target, engagementDir: f.context.engagementDir, semgrepMode: 'off' });
    expect(result.status).toBe('published');
    const checkpoint = readFileSync(join(result.engagementDir, 'assess-v2-checkpoint-input.json'), 'utf8');
    expect(checkpoint).not.toContain('postgresql://'); expect(checkpoint).not.toContain('password');
    expect((await pool.query("SELECT count(*)::int count FROM nunchi_knowledge_documents WHERE kind='instruction' AND scope_id=$1", [createHash('sha256').update(f.context.engagementDir).digest('hex')])).rows[0].count).toBeGreaterThan(5);
  }, 30000);
});
