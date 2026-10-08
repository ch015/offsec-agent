import { once } from 'node:events';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { managedProviderProcess } from '../provider-process.js';
import { schedulerJournal } from '../workflow/scheduler-journal.js';
import { createMissionRuntime, openMissionRuntime } from '../workflow/mission-runtime.js';
import { persistUsageReceipt, reconcileUsageReceipts } from '../workflow/usage-ledger.js';
import { createArtifactRef, verifyRunArtifactRef } from '../contracts/result-contract.js';

const roots: string[] = [];
const temp = () => { const path = realpathSync(mkdtempSync(join(tmpdir(), 'redesign-lifecycle-'))); roots.push(path); return path; };
afterEach(() => { for (const path of roots.splice(0)) rmSync(path, { recursive: true, force: true }); });

it('T11 records actual child process exit after cancellation', async () => {
  const root = temp(), controller = new AbortController(), lifetime = managedProviderProcess(root, 'analyze:unit:1');
  const child = lifetime.start({ command: process.execPath, args: ['-e', 'process.stdout.write("ready"); setInterval(() => {}, 1000);'], cwd: root, env: process.env, signal: controller.signal });
  await once(child.stdout, 'data');
  const path = join(root, 'session-processes', readdirSync(join(root, 'session-processes'))[0]!);
  expect(JSON.parse(readFileSync(path, 'utf8')).state).toBe('running');
  controller.abort(); await lifetime.exited();
  expect(JSON.parse(readFileSync(path, 'utf8')).state).toBe('terminated');
  expect(() => process.kill(JSON.parse(readFileSync(path, 'utf8')).pid, 0)).toThrow();
});

it('T11 recovers a dead coordinator but refuses to reuse occupancy owned by a live process', async () => {
  const root = temp(), journal = await schedulerJournal(root, () => {});
  journal({ event: 'TaskAttemptState', unitKey: 'u', state: 'running', active: 1, target: 1, queued: 1 });
  await expect(schedulerJournal(root, () => {})).rejects.toThrow('still alive');
  const path = join(root, '.recovery', 'scheduler.json'), previous = JSON.parse(readFileSync(path, 'utf8'));
  writeFileSync(path, JSON.stringify({ ...previous, ownerPid: 99999999 }));
  const events: string[] = []; const recovered = await schedulerJournal(root, event => events.push(event.event));
  recovered({ event: 'TaskPlanned', unitKey: 'u', state: 'ready', active: 0, target: 1, queued: 1 });
  expect(events).toContain('SchedulerProcessRecovered');
  recovered({ event: 'TaskAttemptState', unitKey: 'u', state: 'running', active: 1, target: 1, queued: 1 });
  const stale = JSON.parse(readFileSync(path, 'utf8'));
  writeFileSync(path, JSON.stringify({ ...stale, ownerIdentity: 'previous process with this reused pid' }));
  mkdirSync(join(root, 'session-processes'));
  const receiptPath = join(root, 'session-processes', 'reused-pid.json');
  writeFileSync(receiptPath, JSON.stringify({ ownerPid: process.pid, pid: process.pid, identity: 'previous provider with this reused pid', state: 'running' }));
  await expect(schedulerJournal(root, () => {})).resolves.toBeTypeOf('function');
  expect(JSON.parse(readFileSync(receiptPath, 'utf8')).state).toBe('terminated');
  expect(() => process.kill(process.pid, 0)).not.toThrow();
});

it('T12/T20 reconciles a late usage receipt after reopening a completed run exactly once', async () => {
  const root = temp(), runtime = await createMissionRuntime({ engagementDir: root, runId: 'r', contractId: 'test', contractVersion: '2.1.0', domain: 'test', mission: 'assess' }, { backend: 'file' });
  await runtime.append({ type: 'phase.started', eventId: 'started', phase: 'analyze', attempt: 1 });
  await runtime.append({ type: 'phase.failed', eventId: 'failed', phase: 'analyze', attempt: 1, reason: 'cancelled' });
  await runtime.append({ type: 'run.completed', eventId: 'done' }); await runtime.close();
  persistUsageReceipt(root, 'r', 'analyze', undefined, 1, { provider: 'test', costUsd: 1.25, accountingComplete: true });
  const reopened = await openMissionRuntime({ engagementDir: root, runId: 'r' }, { backend: 'file' });
  try {
    await reconcileUsageReceipts(reopened, root); await reconcileUsageReceipts(reopened, root);
    const state = await reopened.read(); expect(state.status).toBe('completed'); expect(state.totalCostUsd).toBe(1.25);
    expect(Object.values(state.attempts)[0]!.status).toBe('failed'); expect(state.usageReceiptIds).toHaveLength(1);
  } finally { await reopened.close(); }
});

it('T23 permits only defined revision paths and rejects arbitrary nested artifacts', () => {
  const root = temp(), revision = join(root, 'revisions', '0'); mkdirSync(revision, { recursive: true });
  writeFileSync(join(revision, 'old.md'), 'old report');
  const artifact = createArtifactRef({ engagementDir: revision, name: 'old.md', phase: 'revision', role: 'host', attempt: '1' });
  expect(() => verifyRunArtifactRef(artifact, root)).not.toThrow();
  const unsafe = join(root, 'revisions', 'outside'); mkdirSync(unsafe); writeFileSync(join(unsafe, 'old.md'), 'old report');
  expect(() => verifyRunArtifactRef({ ...artifact, path: join(unsafe, 'old.md') }, root)).toThrow('봉인 디렉터리');
  for (const suffix of ['1', '2/.recovery', '3/published']) {
    const dir = join(root, 'evaluation-revisions', suffix); mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'old.md'), 'old report');
    expect(() => verifyRunArtifactRef({ ...artifact, path: join(dir, 'old.md') }, root)).not.toThrow();
  }
  const invalid = join(root, 'evaluation-revisions/1/arbitrary'); mkdirSync(invalid); writeFileSync(join(invalid, 'old.md'), 'old report');
  expect(() => verifyRunArtifactRef({ ...artifact, path: join(invalid, 'old.md') }, root)).toThrow('봉인 디렉터리');
});

it('keeps failure and model metadata when an equivalent native usage receipt arrives', async () => {
  const root = temp(), runtime = await createMissionRuntime({ engagementDir: root, runId: 'r', contractId: 'test', contractVersion: '2.1.0', domain: 'test', mission: 'assess' }, { backend: 'file' });
  try {
    await runtime.append({ type: 'phase.started', eventId: 'started', phase: 'review', attempt: 1 });
    await runtime.append(persistUsageReceipt(root, 'r', 'review', undefined, 1, { provider: 'anthropic-agent-sdk', model: 'review-model',
      costUsd: 2.5, accountingComplete: true, raw: { reason: 'error_max_turns: max_turns' } }));
    mkdirSync(join(root, 'session-usage'));
    writeFileSync(join(root, 'session-usage', 'native.json'), JSON.stringify({ runId: 'r', attemptId: 'review:-:1', costUsd: 2.5,
      turns: 3, subtype: 'error_max_turns', modelUsage: { 'review-model': { outputTokens: 3 } } }));
    await reconcileUsageReceipts(runtime, root); await reconcileUsageReceipts(runtime, root);
    const state = await runtime.read();
    expect(state.totalCostUsd).toBe(2.5); expect(state.usageReceiptIds).toHaveLength(1);
    expect(state.attempts['review:-:1']?.usage).toMatchObject({ model: 'review-model', raw: { reason: 'error_max_turns: max_turns' } });
  } finally { await runtime.close(); }
});
