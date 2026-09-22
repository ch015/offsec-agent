import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir, hostname } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createOffsecAgent, type SessionSpec, type SessionOutcome } from '../../index.js';
import { buildOptions } from '../session.js';
import { loadOffsecContract, getOffsecPhase, renderPhaseArtifacts, resolvePhaseMethodFiles } from '../offsec-contract.js';
import { FileRunStateStore } from '../workflow/state-store.js';
import { assertRunInputsIntact } from '../workflow/host-integrity.js';
import { FileSystemArtifactStore, InMemoryArtifactStore } from '../workflow/artifact-store.js';
import { restoreRunArchive } from '../workflow/run-archive.js';
import { ResilientArtifactStore } from '../workflow/resilient-artifacts.js';
import { acquireRunLock } from '../workflow/run-lock.js';
import { appendLedger } from '../workflow/file-ledger.js';
const roots: string[] = [];
function temp() { const root = mkdtempSync(join(tmpdir(), 'offsec-recovery-test-')); roots.push(root); return root; }
afterEach(() => { vi.restoreAllMocks(); for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function fixture() {
  const root = temp(), target = join(root, 'project'); mkdirSync(target); writeFileSync(join(target, 'app.ts'), 'export const app = 1;\n');
  return { root, target, engagementDir: join(root, 'run'), engagementId: 'test-run', semgrepMode: 'off' as const };
}
const contract = loadOffsecContract(resolve(import.meta.dirname, '../../../domains/offsec/contracts/offsec-contract.v2.json'));
async function scripted(spec: SessionSpec): Promise<SessionOutcome> {
  const phase = getOffsecPhase(spec.phase!, contract), artifacts = renderPhaseArtifacts(phase, spec.phaseRound);
  for (const file of artifacts.required) writeFileSync(join(spec.engagementDir, file), phase.id === 'report' ? '# Fixture report\nNo confirmed findings.\n' : '{}\n');
  return { texts: [], ledger: resolvePhaseMethodFiles(phase).map(resource => ({ at: new Date(0).toISOString(), event: 'PreToolUse', tool: 'Read', resource, decision: 'allow' })), totalCostUsd: 0.01, numTurns: 1, modelUsage: { [spec.model!]: { inputTokens: 1, outputTokens: 1 } }, structuredOutput: {
    contractVersion: contract.version, phase: phase.id, role: phase.role, status: 'complete', artifacts: artifacts.required, summary: 'fixture', metrics: { findingCount: 0 }, unresolved: [],
    ...(spec.workUnit ? { workUnit: { workUnitKey: spec.workUnit.unitKey, workPlanSha256: spec.workUnit.workPlanSha256, assignedSourceSha256: spec.workUnit.assignedSourceSha256 } } : {}),
  } };
}
describe('analysis durability and continuation', () => {
  it('uses an external UUID run, keeps target unchanged and disables unmanaged SDK session persistence', async () => {
    const input = fixture(), before = readdirSync(input.target);
    const agent = createOffsecAgent({ sessionRunner: async spec => { expect(buildOptions(spec).persistSession).toBe(false); return scripted(spec); } });
    const result = await agent.run({ target: input.target, stateHome: join(input.root, 'state'), semgrepMode: 'off' });
    expect(result.engagementDir).toContain('/project/'); expect(result.engagementDir).toMatch(/_[0-9a-f-]{36}\/engagement$/);
    expect(result.finalReport).toContain('/report/'); expect(readdirSync(input.target)).toEqual(before);
    expect(result.status).toBe('published'); expect(statSync(result.finalReport).mode & 0o777).toBe(0o600);
  });
  it('keeps draft references valid and restores every registered host artifact without the original directory', async () => {
    const input = fixture(), remote = new InMemoryArtifactStore();
    const result = await createOffsecAgent({ sessionRunner: scripted, runtime: { artifactStore: remote } }).run(input);
    const state = FileRunStateStore.open(result.engagementDir).read();
    expect(() => assertRunInputsIntact(state, result.engagementDir)).not.toThrow();
    expect(existsSync(join(result.engagementDir, '07_security_report.draft.md'))).toBe(true);
    const manifest = JSON.parse(readFileSync(join(result.engagementDir, 'run-archive.json'), 'utf8'));
    const entries = manifest.entries.map((e: any) => e.path);
    for (const name of ['source_manifest.json', '00_analysis_coverage.json', 'assess-v2-checkpoint-input.json', '00_work_plan.json', 'run-events.jsonl']) expect(entries).toContain(name);
    renameSync(result.engagementDir, result.engagementDir + '-offline');
    await restoreRunArchive({ uri: result.storage.archiveUri!, store: remote, destination: result.engagementDir });
    expect(() => assertRunInputsIntact(FileRunStateStore.open(result.engagementDir).read(), result.engagementDir)).not.toThrow();
    expect(Object.values(state.effects ?? {}).flatMap(e => e.outbox ?? []).some(e => e.topic === 'run.publication.completed')).toBe(true);
  });
  it('continues when the remote archive is unavailable and can later replay the durable queue', async () => {
    const input = fixture(), remote = new InMemoryArtifactStore(); let offline = true;
    const store = { put: async (value: Parameters<InMemoryArtifactStore['put']>[0]) => { if (offline) throw new Error('store offline'); return remote.put(value); }, get: remote.get.bind(remote) };
    const result = await createOffsecAgent({ sessionRunner: scripted, runtime: { artifactStore: store } }).run(input);
    expect(result.status).toBe('published'); expect(result.storage.pendingReplication).toBeGreaterThan(0);
    offline = false;
    const health = await new ResilientArtifactStore(result.engagementDir, store).flush();
    expect(health.pendingReplication).toBe(0); expect(health.errors).toEqual([]);
    expect(await remote.get(result.storage.archiveUri!)).toBeInstanceOf(Uint8Array);
  });
  it('resumes a failed review without repeating completed analysis', async () => {
    const input = fixture(); let unavailable = true; const calls: string[] = [];
    const agent = createOffsecAgent({ sessionRunner: async spec => { calls.push(spec.phase!); if (unavailable && spec.phase === 'review') throw new Error('fixture service unavailable'); return scripted(spec); } });
    const first = await agent.run(input); expect(first.publicationStatus).toBe('partial');
    expect(readFileSync(first.finalReport, 'utf8')).toContain('분석 범위 미완료');
    unavailable = false; calls.length = 0;
    const resumed = await agent.resume(input.engagementDir);
    expect(resumed.status).toBe('published'); expect(calls).toEqual(['review', 'evaluate', 'report']);
  });
  it('recovers a report whose file was published before the completion write failed, without model calls', async () => {
    const input = fixture(); let fail = true; const append = FileRunStateStore.prototype.appendBatch;
    vi.spyOn(FileRunStateStore.prototype, 'appendBatch').mockImplementation(function(this: FileRunStateStore, events, version) {
      if (fail && events.some(e => e.type === 'publication.completed')) throw Object.assign(new Error('fixture storage unavailable'), { code: 'EIO' });
      return append.call(this, events, version);
    });
    let calls = 0; const agent = createOffsecAgent({ sessionRunner: async spec => { calls++; return scripted(spec); } });
    const first = await agent.run(input); expect(first.status).toBe('incomplete');
    expect(existsSync(join(input.engagementDir, '07_security_report.md'))).toBe(true);
    expect(FileRunStateStore.open(input.engagementDir).read().status).toBe('running');
    fail = false; calls = 0;
    const recovered = await agent.resume(input.engagementDir);
    expect(recovered.status).toBe('published'); expect(calls).toBe(0);
    expect(FileRunStateStore.open(input.engagementDir).read().status).toBe('completed');
  });
  it('continues static analysis by default when Semgrep is absent', async () => {
    const input = fixture(); let calls = 0;
    const agent = createOffsecAgent({ sessionRunner: async spec => { calls++; return scripted(spec); }, astBuilder: async () => ({ ok: false, semgrep: { status: 'unavailable', error: 'fixture' } }) });
    const result = await agent.run({ ...input, semgrepMode: undefined });
    expect(result.status).toBe('published'); expect(calls).toBe(4); expect(result.coverage.preanalysisAvailable).toBe(false);
  });
  it('recovers a torn final ledger record while preserving the damaged original', () => {
    const root = temp(); const state = FileRunStateStore.create({ engagementDir: root, runId: 'r', contractId: 'c', contractVersion: '1', domain: 'test', mission: 'test' });
    appendFileSync(state.eventsPath, '{"seq":2');
    const recovered = FileRunStateStore.open(root); expect(recovered.read().lastSeq).toBe(1);
    expect(readdirSync(join(root, '.recovery')).some(n => n.startsWith('torn-ledger-'))).toBe(true);
    recovered.append({ type: 'run.completed', eventId: 'complete' }); expect(FileRunStateStore.open(root).read().status).toBe('completed');
  });
  it('replays a fsynced pending batch and rejects a corrupt middle ledger row', () => {
    const root = temp(); const state = FileRunStateStore.create({ engagementDir: root, runId: 'r', contractId: 'c', contractVersion: '1', domain: 'test', mission: 'test' });
    appendLedger(root, state.eventsPath, [{ seq: 2, at: new Date().toISOString(), runId: 'r', type: 'run.completed', eventId: 'done' }], true);
    expect(FileRunStateStore.open(root).read().status).toBe('completed');
    appendFileSync(state.eventsPath, 'broken\n'); expect(() => FileRunStateStore.open(root)).toThrow();
  });
  it('reclaims a verified dead local owner but refuses an active lock', () => {
    const root = temp(), path = join(root, 'run.lock');
    writeFileSync(path, JSON.stringify({ pid: 99999999, host: hostname() }));
    const release = acquireRunLock(path); expect(() => acquireRunLock(path)).toThrow(/already active/); release(); expect(existsSync(path)).toBe(false);
  });
  it('rejects directory symlinks in the artifact store', async () => {
    const root = temp(), storeRoot = join(root, 'store'), outside = join(root, 'outside'); mkdirSync(storeRoot); mkdirSync(outside); symlinkSync(outside, join(storeRoot, 'runs'));
    const store = new FileSystemArtifactStore(storeRoot);
    await expect(store.put({ uri: 'artifact://runs/a', content: new Uint8Array([1]), mediaType: 'text/plain', producer: 'test' })).rejects.toThrow(/symlink/);
    expect(readdirSync(outside)).toEqual([]);
  });
  it('restores an external run including metadata and reports and resumes without an SDK call', async () => {
    const input = fixture(), remote = new InMemoryArtifactStore(); let calls = 0;
    const agent = createOffsecAgent({ sessionRunner: async spec => { calls++; return scripted(spec); }, runtime: { artifactStore: remote } });
    const result = await agent.run({ target: input.target, stateHome: join(input.root, 'external'), semgrepMode: 'off' });
    const runRoot = resolve(result.engagementDir, '..'); renameSync(runRoot, runRoot + '-offline');
    await restoreRunArchive({ uri: result.storage.archiveUri!, store: remote, destination: result.engagementDir });
    expect(existsSync(join(runRoot, 'run.json'))).toBe(true); expect(existsSync(result.finalReport)).toBe(true);
    calls = 0; const resumed = await agent.resume(result.engagementDir); expect(resumed.status).toBe('published'); expect(calls).toBe(0);
  });
  it('refuses to attach resumed findings to changed source and retains the old report', async () => {
    const input = fixture(), agent = createOffsecAgent({ sessionRunner: scripted });
    const result = await agent.run(input), original = readFileSync(result.finalReport, 'utf8');
    writeFileSync(join(input.target, 'app.ts'), 'export const app = 2;\n');
    await expect(agent.resume(input.engagementDir)).rejects.toThrow('resume source changed');
    expect(readFileSync(result.finalReport, 'utf8')).toBe(original);
  });
  it('restarts failed units in new attempts and retains every old attempt', async () => {
    const input = fixture(); let unavailable = true;
    const agent = createOffsecAgent({ sessionRunner: async spec => { if (unavailable) throw new Error('fixture unavailable'); return scripted(spec); } });
    const first = await agent.run(input); expect(first.publicationStatus).toBe('partial'); expect(first.coverage.uncoveredFiles).toEqual(['app.ts']);
    unavailable = false; const resumed = await agent.resume(input.engagementDir); expect(resumed.status).toBe('published');
    const dirs = readdirSync(join(input.engagementDir, 'work-units', readdirSync(join(input.engagementDir, 'work-units'))[0]!));
    expect(dirs).toEqual(expect.arrayContaining(['attempt-1', 'attempt-2', 'attempt-3']));
  });

  it('preserves subsequent events in write-ahead batches while the ledger is unwritable', () => {
    const root = temp(), state = FileRunStateStore.create({ engagementDir: root, runId: 'r', contractId: 'c', contractVersion: '1', domain: 'test', mission: 'test' });
    renameSync(state.eventsPath, state.eventsPath + '.original'); mkdirSync(state.eventsPath);
    state.append({ type: 'phase.started', eventId: 'start', phase: 'analyze', attempt: 1 });
    state.append({ type: 'attempt.received', eventId: 'receipt', phase: 'analyze', attempt: 1, usage: { provider: 'fixture', costUsd: 0.25 } });
    expect(state.read().totalCostUsd).toBe(0.25); expect(state.recoveryWarnings.length).toBeGreaterThan(0);
    rmSync(state.eventsPath, { recursive: true }); renameSync(state.eventsPath + '.original', state.eventsPath);
    const restored = FileRunStateStore.open(root).read(); expect(restored.lastSeq).toBe(3); expect(restored.totalCostUsd).toBe(0.25);
  });
  it('does not turn snapshot projection failure into phase failure', () => {
    const root = temp(), state = FileRunStateStore.create({ engagementDir: root, runId: 'r', contractId: 'c', contractVersion: '1', domain: 'test', mission: 'test' });
    renameSync(state.snapshotPath, state.snapshotPath + '.original'); mkdirSync(state.snapshotPath);
    expect(() => state.append({ type: 'run.completed', eventId: 'done' })).not.toThrow();
    expect(FileRunStateStore.open(root).read().status).toBe('completed');
    expect(state.recoveryWarnings.some(w => w.includes('snapshot projection'))).toBe(true);
  });
  it('quarantines a corrupt replication item without blocking valid pending objects', async () => {
    const root = temp(), remote = new InMemoryArtifactStore(); let offline = true;
    const endpoint = { put: async (value: Parameters<InMemoryArtifactStore['put']>[0]) => { if (offline) throw new Error('offline'); return remote.put(value); }, get: remote.get.bind(remote) };
    const local = new ResilientArtifactStore(root, endpoint);
    await local.put({ uri: 'artifact://test/object', content: Buffer.from('retained'), mediaType: 'text/plain', producer: 'fixture' });
    writeFileSync(join(root, '.recovery/replication/000-broken.json'), '{'); offline = false;
    const health = await local.flush(); expect(health.pendingReplication).toBe(0); expect(health.errors.join()).toContain('quarantined');
    expect(Buffer.from(await remote.get('artifact://test/object')).toString()).toBe('retained');
    expect(existsSync(join(root, '.recovery/replication/000-broken.json.invalid'))).toBe(true);
  });

  it('keeps independent analysis running even when explicitly required Semgrep fails, without claiming completeness', async () => {
    const input = fixture(); let calls = 0;
    const agent = createOffsecAgent({ astBuilder: async () => ({ ok: false, semgrep: { status: 'unavailable', error: 'fixture missing Semgrep' } }), sessionRunner: async spec => {
      calls++; const outcome = await scripted(spec);
      if (spec.phase === 'report') appendFileSync(join(spec.engagementDir, '07_security_report.draft.md'), '\n분석 범위 미완료: required Semgrep unavailable.\n');
      return outcome;
    } });
    const result = await agent.run({ ...input, semgrepMode: 'required' });
    expect(calls).toBe(4); expect(result.status).toBe('incomplete'); expect(result.coverage.requiredPreanalysisComplete).toBe(false);
    expect(readFileSync(result.finalReport, 'utf8')).toContain('분석 범위 미완료');
  });

  it('rejects a backend switch on resume before opening another state store', async () => {
    const input = fixture(), agent = createOffsecAgent({ sessionRunner: scripted });
    await agent.run(input);
    const wrongBackend = createOffsecAgent({ sessionRunner: scripted, runtime: { backend: 'postgres' } });
    await expect(wrongBackend.resume(input.engagementDir)).rejects.toThrow('original file state backend');
  });

});
