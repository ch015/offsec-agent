import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createOffsecAgent, type OffsecRunInput } from '../../index.js';
import { FileRunStateStore } from '../workflow/state-store.js';
import { InMemoryArtifactStore } from '../workflow/artifact-store.js';
import { ResilientArtifactStore } from '../workflow/resilient-artifacts.js';
import { committedBudget, recoverLegacyBudget } from '../missions/assessment-budget.js';
import * as workExecutor from '../workflow/bounded-work-executor.js';
import { legacyCompletedCoverage } from '../missions/analysis-checkpoint.js';
import { createMissionRuntime } from '../workflow/mission-runtime.js';
import { PostgresRunStateStore } from '../workflow/postgres-run-state-store.js';
import { InMemoryRunLeaseBackend } from '../workflow/run-lease.js';
import { syntheticOutcome } from './resumption-fixture.js';
const require = createRequire(import.meta.url);
const roots: string[] = [];
function fixture(packages: string[] = []) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'offsec-resumption-'))); roots.push(root);
  const target = join(root, 'project'); mkdirSync(target);
  if (packages.length) for (const name of packages) {
    const dir = join(target, 'packages', name); mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name }));
    writeFileSync(join(dir, `${name}.ts`), `export const ${name} = 1;\n`);
  } else writeFileSync(join(target, 'app.ts'), 'export const app = 1;\n');
  return { root, target, engagementDir: join(root, 'run'), engagementId: 'resumption', semgrepMode: 'off' as const };
}
function crash(input: OffsecRunInput, mode: 'followup' | 'first-call') {
  const file = join(dirname(input.engagementDir!), 'crash.mts');
  const api = pathToFileURL(resolve(import.meta.dirname, '../../index.ts')).href;
  const helper = pathToFileURL(resolve(import.meta.dirname, 'resumption-fixture.ts')).href;
  writeFileSync(file, `import {createOffsecAgent} from ${JSON.stringify(api)};\nimport {syntheticOutcome} from ${JSON.stringify(helper)};\nawait createOffsecAgent({sessionRunner: async spec => { if (${JSON.stringify(mode)} === 'first-call' || spec.phaseRound === 'cross-unit-followup') process.exit(86); return syntheticOutcome(spec, {handoff:true}); }}).run(${JSON.stringify(input)});`);
  const result = spawnSync(process.execPath, ['--import', require.resolve('tsx'), file], { encoding: 'utf8', timeout: 30000 });
  expect(result.status, result.stderr).toBe(86);
}
afterEach(() => { vi.restoreAllMocks(); for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

describe('assessment crash and resumption boundaries', () => {
  it('restores spent budget before allocating parallel retries', async () => {
    const input = { ...fixture(['a', 'b']), maxBudgetUsd: 10, maxConcurrency: 2 };
    let initialCalls = 0;
    const first = await createOffsecAgent({ sessionRunner: async spec => syntheticOutcome(spec, { subtype: 'error_max_turns', cost: ++initialCalls <= 2 ? 3.4 : 0 }) }).run(input);
    expect(first.status).toBe('incomplete');
    expect(FileRunStateStore.open(input.engagementDir).read().totalCostUsd).toBeCloseTo(6.8);
    const allocations: number[] = []; let release!: () => void;
    const barrier = new Promise<void>(resolve => { release = resolve; });
    const resumed = await createOffsecAgent({ sessionRunner: async spec => {
      if (spec.workUnit) { allocations.push(spec.maxBudgetUsd!); if (allocations.length === 2) release(); await barrier; }
      return syntheticOutcome(spec, { cost: spec.workUnit ? spec.maxBudgetUsd! : 0 });
    } }).resume(input.engagementDir);
    expect(allocations).toHaveLength(2);
    expect(allocations.reduce((a, b) => a + b, 0)).toBeLessThanOrEqual(3.2);
    expect(resumed.status).toBe('published');
    expect(committedBudget(FileRunStateStore.open(input.engagementDir).read())).toBeLessThanOrEqual(10);
  });

  it('reuses completed units after a process exits in cross-unit followup', async () => {
    const input = { ...fixture(['a', 'b']), noCostGuard: true }; crash(input, 'followup');
    const snapshot = FileRunStateStore.open(input.engagementDir).read();
    expect(snapshot.analysisCheckpoint?.stage).toBe('units');
    unlinkSync(join(input.engagementDir, '00_analysis_coverage.json'));
    const calls: string[] = [];
    const result = await createOffsecAgent({ sessionRunner: async spec => { calls.push(spec.phaseRound ?? spec.phase!); return syntheticOutcome(spec, { handoff: true }); } }).resume(input.engagementDir);
    expect(result.status).toBe('published');
    expect(calls).toEqual(['cross-unit-followup', 'review', 'evaluate', 'report']);
    expect(FileRunStateStore.open(input.engagementDir).read().analysisCheckpoint?.stage).toBe('review');
  }, 40000);

  it('retains unknown spend across repeated resumes after a provider process exits', async () => {
    const input = { ...fixture(), maxBudgetUsd: 10, maxConcurrency: 1 }; crash(input, 'first-call');
    const before = FileRunStateStore.open(input.engagementDir).read();
    expect(committedBudget(before)).toBe(7);
    let calls = 0;
    const agent = createOffsecAgent({ sessionRunner: async spec => { calls++; return syntheticOutcome(spec); } });
    for (let retry = 0; retry < 2; retry++) {
      const result = await agent.resume(input.engagementDir);
      expect(result.status).toBe('incomplete'); expect(existsSync(result.finalReport)).toBe(true);
      expect(committedBudget(FileRunStateStore.open(input.engagementDir).read())).toBe(7);
    }
    expect(calls).toBe(0);
  }, 40000);

  it.each([
    { label: 'increased', options: { maxBudgetUsd: 20 }, expected: 20 },
    { label: 'unlimited', options: { noCostGuard: true }, expected: undefined },
  ])('persists an explicitly $label budget across repeated resumes without changing sealed input', async ({ options, expected }) => {
    const input = { ...fixture(), maxBudgetUsd: 10, maxConcurrency: 1 }; crash(input, 'first-call');
    const checkpoint = readFileSync(join(input.engagementDir, 'assess-v2-checkpoint-input.json'));
    const before = FileRunStateStore.open(input.engagementDir).read();
    let failReview = true; const calls: string[] = [], allocations: Array<number | undefined> = [];
    const agent = createOffsecAgent({ sessionRunner: async spec => {
      calls.push(spec.phase!); allocations.push(spec.maxBudgetUsd);
      return syntheticOutcome(spec, { subtype: failReview && spec.phase === 'review' ? 'error_max_turns' : 'success' });
    } });
    const first = await agent.resume(input.engagementDir, options);
    expect(first.status).toBe('incomplete');
    const after = FileRunStateStore.open(input.engagementDir).read();
    expect(after.maxBudgetUsd).toBe(expected);
    for (const [key, value] of Object.entries(before.budgetReservations!)) expect(after.budgetReservations?.[key]).toEqual(value);
    expect(committedBudget(after)).toBeGreaterThanOrEqual(7);
    expect(readFileSync(join(input.engagementDir, 'assess-v2-checkpoint-input.json'))).toEqual(checkpoint);
    const revisions = readFileSync(join(input.engagementDir, 'run-events.jsonl'), 'utf8').trim().split('\n').map(line => JSON.parse(line)).filter(event => event.type === 'run.budget-increased');
    expect(revisions).toHaveLength(1);
    expect(revisions[0]).toMatchObject({ previousMaxBudgetUsd: 10, maxBudgetUsd: expected ?? null });
    if (expected === undefined) expect(allocations.every(value => value === undefined)).toBe(true);
    else expect(allocations[0]).toBeCloseTo(7); // 20 limit - 7 uncertain spend - 6 future reserve.
    failReview = false; calls.length = 0;
    expect((await agent.resume(input.engagementDir)).status).toBe('published');
    expect(calls).toEqual(['review', 'evaluate', 'report']);
    expect(FileRunStateStore.open(input.engagementDir).read().maxBudgetUsd).toBe(expected);
  }, 40000);

  it.each([undefined, { maxBudgetUsd: 1, noCostGuard: true }])('does not impose a monetary ceiling with unlimited defaults %j', async defaults => {
    const input = fixture(); const allocations: Array<number | undefined> = [];
    const result = await createOffsecAgent({ defaults, sessionRunner: async spec => {
      allocations.push(spec.maxBudgetUsd); return syntheticOutcome(spec, { cost: 100 });
    } }).run(input);
    expect(result.status).toBe('published'); expect(allocations).toEqual([undefined, undefined, undefined, undefined]);
    expect(FileRunStateStore.open(input.engagementDir).read().maxBudgetUsd).toBeUndefined();
  });

  it('honors budget removal when creation stopped before the run ledger existed', async () => {
    const input = { ...fixture(), maxBudgetUsd: 1 };
    const creation = vi.spyOn(FileRunStateStore, 'create').mockImplementationOnce(() => { throw Object.assign(new Error('synthetic create failure'), { code: 'EIO' }); });
    const allocations: Array<number | undefined> = [];
    const agent = createOffsecAgent({ sessionRunner: async spec => { allocations.push(spec.maxBudgetUsd); return syntheticOutcome(spec, { cost: 100 }); } });
    expect((await agent.run(input)).status).toBe('incomplete');
    expect(existsSync(join(input.engagementDir, 'run-events.jsonl'))).toBe(false);
    creation.mockRestore();
    expect((await agent.resume(input.engagementDir, { noCostGuard: true })).status).toBe('published');
    expect(allocations).toEqual([undefined, undefined, undefined, undefined]);
    expect(FileRunStateStore.open(input.engagementDir).read().maxBudgetUsd).toBeUndefined();
  });

  it('preserves a partial report after invalid root output and resumes only the unfinished phases', async () => {
    const input = fixture(); let invalid = true; const calls: string[] = [];
    const agent = createOffsecAgent({ sessionRunner: async spec => {
      calls.push(spec.phase!); const outcome = syntheticOutcome(spec);
      if (invalid && spec.phase === 'review') outcome.structuredOutput = { malformed: true };
      return outcome;
    } });
    const result = await agent.run(input);
    expect(result.status).toBe('incomplete'); expect(existsSync(result.finalReport)).toBe(true);
    expect(calls.filter(phase => phase === 'review')).toHaveLength(3);
    invalid = false; calls.length = 0;
    expect((await agent.resume(input.engagementDir)).status).toBe('published');
    expect(calls).toEqual(['review', 'evaluate', 'report']);
  });

  it('restores sealed coverage instead of trusting changed, absent or torn projections', async () => {
    const input = fixture(); let calls = 0;
    const agent = createOffsecAgent({ astBuilder: async () => ({ ok: false, semgrep: { status: 'unavailable' } }),
      sessionRunner: async spec => { calls++; return syntheticOutcome(spec); } });
    const first = await agent.run({ ...input, semgrepMode: 'required' });
    expect(first.status).toBe('incomplete');
    expect(readFileSync(first.finalReport, 'utf8')).toContain('분석 범위 미완료');
    expect(readFileSync(join(input.engagementDir, '07_security_report.draft.md'), 'utf8')).not.toContain('분석 범위 미완료');
    const path = join(input.engagementDir, '00_analysis_coverage.json'); const original = readFileSync(path, 'utf8');
    for (const damage of ['modified', 'missing', 'torn']) {
      if (damage === 'missing') unlinkSync(path);
      else writeFileSync(path, damage === 'torn' ? '{' : JSON.stringify({ ...JSON.parse(original), complete: true, requiredPreanalysisComplete: true }));
      calls = 0; const result = await agent.resume(input.engagementDir);
      expect(result.status).toBe('incomplete'); expect(result.coverage.complete).toBe(false);
      expect(readFileSync(path, 'utf8')).toBe(original); expect(calls).toBe(0);
    }
  });

  it('derives legacy completed coverage from verified execution rather than its mutable JSON', async () => {
    const input = fixture(), agent = createOffsecAgent({ sessionRunner: async spec => syntheticOutcome(spec) });
    await agent.run(input);
    const path = join(input.engagementDir, 'run-events.jsonl');
    const events = readFileSync(path, 'utf8').trim().split('\n').map(line => JSON.parse(line)).filter(event => event.type !== 'analysis.checkpoint');
    writeFileSync(path, events.map((event, i) => JSON.stringify({ ...event, seq: i + 1 })).join('\n') + '\n');
    writeFileSync(join(input.engagementDir, '00_analysis_coverage.json'), '{');
    const neverCall = createOffsecAgent({ sessionRunner: async () => { throw new Error('unexpected model call'); } });
    expect((await neverCall.resume(input.engagementDir)).status).toBe('published');
    const snapshot = FileRunStateStore.open(input.engagementDir).read();
    const units = JSON.parse(readFileSync(join(input.engagementDir, '00_work_plan.json'), 'utf8')).units;
    expect(legacyCompletedCoverage({ snapshot, units, sourceErrors: [], requiredPreanalysisComplete: false, preanalysisAvailable: false }).complete).toBe(false);
  });

  it('does not claim completeness when both coverage and its recovery object are damaged', async () => {
    const input = fixture(), agent = createOffsecAgent({ sessionRunner: async spec => syntheticOutcome(spec) });
    await agent.run(input);
    const checkpoint = FileRunStateStore.open(input.engagementDir).read().analysisCheckpoint!;
    const coverage = checkpoint.artifacts.find(a => a.name === '00_analysis_coverage.json')!;
    writeFileSync(coverage.path, '{');
    writeFileSync(join(input.engagementDir, '.artifact-store/checkpoints/objects', coverage.sha256), 'damaged');
    const result = await agent.resume(input.engagementDir);
    expect(result.status).toBe('incomplete'); expect(existsSync(result.finalReport)).toBe(true);
    expect(result.coverage.complete).toBe(false);
  });

  it('resumes initialization after run.created but before input.recorded', async () => {
    const input = fixture(); const append = FileRunStateStore.prototype.appendBatch; let fail = true;
    vi.spyOn(FileRunStateStore.prototype, 'appendBatch').mockImplementation(function(this: FileRunStateStore, events, version) {
      if (fail && events.some(event => event.type === 'input.recorded')) throw Object.assign(new Error('input storage unavailable'), { code: 'EIO' });
      return append.call(this, events, version);
    });
    const agent = createOffsecAgent({ sessionRunner: async spec => syntheticOutcome(spec) });
    expect((await agent.run(input)).status).toBe('incomplete'); fail = false;
    expect((await agent.resume(input.engagementDir)).status).toBe('published');
    expect(FileRunStateStore.open(input.engagementDir).read().inputManifest).toBeDefined();
  });

  it('keeps an uncertain legacy allocation reserved after interrupted attempts are closed', async () => {
    const input = fixture();
    const runtime = await createMissionRuntime({ engagementDir: input.engagementDir, runId: 'legacy', contractId: 'c', contractVersion: '1', domain: 'test', mission: 'test', maxBudgetUsd: 10 });
    try {
      await runtime.append({ type: 'phase.started', eventId: 'start', phase: 'analyze', attempt: 1 });
      await recoverLegacyBudget(runtime, await runtime.read());
      await runtime.append({ type: 'phase.failed', eventId: 'interrupted', phase: 'analyze', attempt: 1, reason: 'process terminated' });
      expect(committedBudget(FileRunStateStore.open(input.engagementDir).read())).toBe(10);
      await recoverLegacyBudget(runtime, await runtime.read());
      expect(committedBudget(await runtime.read())).toBe(10);
    } finally { await runtime.close(); }
  });

  it('serializes the shared PostgreSQL mission writer across phase and budget events', async () => {
    const input = { ...fixture(['a', 'b']), maxBudgetUsd: 10 }; let active = 0, peak = 0;
    vi.spyOn(PostgresRunStateStore, 'create').mockImplementation(async (_pool, identity) => {
      const local = FileRunStateStore.create({ ...identity, engagementDir: input.engagementDir });
      return { backend: 'postgres', read: async () => local.read(),
        appendBatchWithEffects: async (events: Parameters<FileRunStateStore['appendBatch']>[0], expected: number) => {
          active++; peak = Math.max(peak, active);
          try { await new Promise(resolve => setTimeout(resolve, 1)); return local.appendBatch(events, expected); }
          finally { active--; }
        },
      } as unknown as PostgresRunStateStore;
    });
    const result = await createOffsecAgent({ sessionRunner: async spec => syntheticOutcome(spec), runtime: {
      backend: 'postgres', pool: {} as never, leaseBackend: new InMemoryRunLeaseBackend(), artifactStore: new InMemoryArtifactStore(), sharedEngagementRoot: input.root,
    } }).run(input);
    expect(result.status).toBe('published'); expect(peak).toBe(1);
    const snapshot = FileRunStateStore.open(input.engagementDir).read();
    expect(Object.values(snapshot.budgetReservations ?? {})).toHaveLength(5);
    expect(committedBudget(snapshot)).toBeCloseTo(0.05);
  });

  it('finishes independent work after a unit timeout and ignores the late provider completion', async () => {
    const input = fixture(['a', 'b']), execute = workExecutor.executePagedWork;
    vi.spyOn(workExecutor, 'executePagedWork').mockImplementation(options => execute({ ...options, unitTimeoutMs: 500 }));
    let release!: () => void; const waiting = new Promise<void>(resolve => { release = resolve; });
    const result = await createOffsecAgent({ sessionRunner: async spec => {
      if (spec.workUnit?.ownedSourceFiles.some(file => file.endsWith('/a.ts'))) await waiting;
      return syntheticOutcome(spec);
    } }).run(input);
    expect(result.status).toBe('incomplete'); expect(result.coverage.uncoveredFiles).toContain('packages/a/a.ts');
    const before = FileRunStateStore.open(input.engagementDir).read(); expect(before.status).toBe('completed');
    release(); await new Promise(resolve => setTimeout(resolve, 25));
    const after = FileRunStateStore.open(input.engagementDir).read();
    expect(after.lastSeq).toBe(before.lastSeq);
    expect(Object.values(after.attempts).filter(attempt => attempt.phase === 'analyze' && attempt.status === 'completed')).toHaveLength(1);
  });

  it('schedules more than 128 units without truncating the inventory', async () => {
    const input = { ...fixture(Array.from({ length: 129 }, (_, i) => `p${i}`)), maxConcurrency: 4 };
    const units = new Set<string>();
    const result = await createOffsecAgent({ astBuilder: async () => ({ ok: false }), sessionRunner: async spec => {
      if (spec.workUnit) units.add(spec.workUnit.unitKey); return syntheticOutcome(spec, { cost: 0 });
    } }).run(input);
    expect(units.size).toBe(129); expect(result.coverage.completedUnits).toBe(129);
    expect(result.status).toBe('published');
  }, 120000);

  it('isolates an unreadable source and publishes an explicit partial report for the rest', async () => {
    const input = fixture(); const bad = join(input.target, 'bad.ts'); writeFileSync(bad, 'export const bad=1;\n');
    const fs = require('node:fs'), original = fs.readFileSync;
    vi.spyOn(fs, 'readFileSync').mockImplementation((...args: unknown[]) => {
      if (String(args[0]) === bad) throw Object.assign(new Error('source unreadable'), { code: 'EACCES' });
      return original(...args);
    });
    const assigned: string[] = [];
    const result = await createOffsecAgent({ astBuilder: async () => ({ ok: false }), sessionRunner: async spec => {
      if (spec.workUnit) assigned.push(...spec.workUnit.ownedSourceFiles); return syntheticOutcome(spec);
    } }).run(input);
    expect(result.status).toBe('incomplete'); expect(assigned).toEqual([join(input.target, 'app.ts')]);
    expect(result.coverage.uncoveredFiles).toContain('bad.ts');
    expect(readFileSync(result.finalReport, 'utf8')).toContain('bad.ts');
    expect(JSON.parse(readFileSync(join(input.engagementDir, 'source_manifest.json'), 'utf8')).source_files).toContain('bad.ts');
  });

  for (const damage of ['corrupt', 'missing'] as const) it(`replicates healthy objects after a ${damage} local body`, async () => {
    const input = fixture(), remote = new InMemoryArtifactStore(); let offline = true;
    mkdirSync(input.engagementDir);
    const endpoint = { put: async (value: Parameters<InMemoryArtifactStore['put']>[0]) => { if (offline) throw new Error('offline'); return remote.put(value); }, get: remote.get.bind(remote) };
    const store = new ResilientArtifactStore(input.engagementDir, endpoint);
    const uris = ['artifact://probe/a', 'artifact://probe/b', 'artifact://probe/c'];
    for (const uri of uris) await store.put({ uri, content: Buffer.from(uri), mediaType: 'text/plain', producer: 'fixture' });
    const sorted = [...uris].sort((a, b) => createHash('sha256').update(a).digest('hex').localeCompare(createHash('sha256').update(b).digest('hex')));
    const bad = new URL(sorted[0]!); const path = join(input.engagementDir, '.artifact-store', bad.hostname, bad.pathname);
    if (damage === 'missing') unlinkSync(path); else writeFileSync(path, 'damaged');
    offline = false; const health = await store.flush();
    for (const uri of sorted.slice(1)) expect(Buffer.from(await remote.get(uri)).toString()).toBe(uri);
    expect(health.pendingReplication).toBe(0); expect(health.errors.join()).toContain('quarantined');
    await store.put({ uri: 'artifact://probe/next', content: Buffer.from('next'), mediaType: 'text/plain', producer: 'fixture' });
    expect(Buffer.from(await remote.get('artifact://probe/next')).toString()).toBe('next');
    expect(readdirSync(join(input.engagementDir, '.recovery/replication')).filter(name => name.endsWith('.invalid'))).toHaveLength(1);
  });
});
