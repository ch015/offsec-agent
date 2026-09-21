import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  buildArmCommand,
  assertBenchmarkOutputIsolation,
  planBenchmarkRuns,
  signalProcessTree,
  spawnToFiles,
  type BenchmarkRunnerOptions,
} from '../../../evals/offsec/runner.js';

function options(overrides: Partial<BenchmarkRunnerOptions> = {}): BenchmarkRunnerOptions {
  return {
    corpusPath: '/sealed/corpus.json',
    sourceManifestPath: '/sealed/source.json',
    caseId: 'case-juicebox1',
    target: '/sealed/target',
    outputRoot: '/sealed/output',
    arms: ['ch015', 'current-sequential', 'current-parallel'],
    repetitions: 3,
    provider: 'anthropic',
    model: 'claude-opus-4-6',
    effort: 'high',
    maxTurns: 120,
    randomizationSeed: 73,
    semgrepMode: 'best-effort',
    maxConcurrency: 4,
    currentRoot: '/runner/current',
    ch015PluginRoot: '/runner/ch015',
    dryRun: true,
    ...overrides,
  };
}

describe('offsec benchmark runner', () => {
  it('runs v2 with a fixed independent reviewer and a supported single-worker baseline', () => {
    const value = options({ workflowVersion: 'v2', reviewModel: 'claude-sonnet-4-6' });
    expect(planBenchmarkRuns(value)).toHaveLength(9);
    const command = buildArmCommand({ options: value, arm: 'current-sequential', target: '/opaque/source', engagementDir: '/opaque/output' });
    expect(command.args).toContain('assess:v2');
    expect(command.args).toContain('--work-units=force');
    expect(command.args).toContain('--max-concurrency=1');
    expect(command.args).toContain('--review-model=claude-sonnet-4-6');
    expect(command.args).not.toContain('--verification-mode=VA_ONLY');
    expect(() => planBenchmarkRuns(options({ workflowVersion: 'v2' }))).toThrow('review model');
    expect(() => planBenchmarkRuns(options({ workflowVersion: 'v2', reviewModel: 'sonnet' }))).toThrow('고정 model');
  });
  it('produces stable randomized paired order without dropping or duplicating arms', () => {
    const first = planBenchmarkRuns(options());
    const second = planBenchmarkRuns(options());
    expect(second).toEqual(first);
    expect(first).toHaveLength(9);
    for (let repetition = 1; repetition <= 3; repetition += 1) {
      expect(first.filter((run) => run.repetition === repetition).map((run) => run.arm).sort()).toEqual([
        'ch015', 'current-parallel', 'current-sequential',
      ]);
    }
    expect(first.map((run) => run.executionOrder)).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8]);
  });

  it('uses the actual plugin and assess entrypoints with matched model conditions', () => {
    const value = options();
    const ch015 = buildArmCommand({
      options: value,
      arm: 'ch015',
      target: '/opaque/source',
      engagementDir: '/opaque/ch015-output',
    });
    const current = buildArmCommand({
      options: value,
      arm: 'current-parallel',
      target: '/opaque/source',
      engagementDir: '/opaque/current-output',
    });
    expect(ch015.executable).toBe('claude');
    expect(ch015.args).toContain('/runner/ch015');
    expect(ch015.args.at(-2)).toBe('--');
    expect(ch015.args.at(-1)).toContain('/ch015:va');
    expect(current.executable).toBe('pnpm');
    expect(current.args).toContain('assess');
    expect(current.args).toContain('--work-units=force');
    expect(ch015.args).toContain('claude-opus-4-6');
    expect(ch015.args).toContain('high');
    expect(current.args).toContain('--model=claude-opus-4-6');
    expect(current.args).toContain('--effort=high');
  });

  it('keeps the sequential current arm single-worker', () => {
    const command = buildArmCommand({
      options: options(),
      arm: 'current-sequential',
      target: '/opaque/source',
      engagementDir: '/opaque/output',
    });
    expect(command.args).toContain('--work-units=off');
    expect(command.args).toContain('--max-concurrency=1');
  });

  it('rejects aliases that can silently drift between benchmark runs', () => {
    expect(() => planBenchmarkRuns(options({ model: 'opus' }))).toThrow(/고정 model ID/);
  });

  it('rejects duplicate or non-comparable arm plans', () => {
    expect(() => planBenchmarkRuns(options({ arms: ['ch015', 'ch015'] }))).toThrow(/중복/);
    expect(() => planBenchmarkRuns(options({ arms: ['ch015', 'current-sequential'] }))).toThrow(/current-parallel/);
  });

  it('rejects output nested in a Git worktree to prevent parent-repository provenance contamination', () => {
    expect(() => assertBenchmarkOutputIsolation(join(process.cwd(), 'evals/offsec/state/run')))
      .toThrow(/Git 작업트리 밖/);
    expect(() => assertBenchmarkOutputIsolation(join(mkdtempSync(join(tmpdir(), 'offsec-isolated-')), 'run')))
      .not.toThrow();
  });

  it.skipIf(process.platform === 'win32')('terminates the detached benchmark process group', async () => {
    const pidPath = join(mkdtempSync(join(tmpdir(), 'offsec-process-tree-')), 'grandchild.pid');
    const script = [
      "const { spawn } = require('node:child_process');",
      "const { writeFileSync } = require('node:fs');",
      "const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });",
      'writeFileSync(process.argv[1], String(child.pid));',
      'setInterval(() => {}, 1000);',
    ].join(' ');
    const child = spawn(process.execPath, ['-e', script, pidPath], {
      detached: true,
      stdio: 'ignore',
    });
    const closed = new Promise<void>((resolveClose) => child.once('close', () => resolveClose()));
    for (let attempt = 0; attempt < 100 && !existsSync(pidPath); attempt += 1) {
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 10));
    }
    const grandchildPid = Number(readFileSync(pidPath, 'utf8'));
    signalProcessTree(child, 'SIGTERM');
    await closed;
    expect(child.exitCode).toBeNull();
    expect(child.signalCode).toBe('SIGTERM');
    for (let attempt = 0; attempt < 100 && processExists(grandchildPid); attempt += 1) {
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 10));
    }
    expect(processExists(grandchildPid)).toBe(false);
  });

  it.skipIf(process.platform === 'win32')('escalates to SIGKILL when a descendant ignores SIGTERM', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'offsec-process-escalation-'));
    const pidPath = join(directory, 'grandchild.pid');
    const script = [
      "const { spawn } = require('node:child_process');",
      "const { writeFileSync } = require('node:fs');",
      "const code = 'process.on(\\'SIGTERM\\', () => {}); setInterval(() => {}, 1000)';",
      "const child = spawn(process.execPath, ['-e', code], { stdio: 'ignore' });",
      'writeFileSync(process.argv[1], String(child.pid));',
      'setInterval(() => {}, 1000);',
    ].join(' ');
    await expect(spawnToFiles(
      { executable: process.execPath, args: ['-e', script, pidPath], cwd: directory },
      join(directory, 'stdout.log'),
      join(directory, 'stderr.log'),
      directory,
      { timeoutMs: 1_000, killGraceMs: 100 },
    )).resolves.toBe(124);
    const grandchildPid = Number(readFileSync(pidPath, 'utf8'));
    for (let attempt = 0; attempt < 100 && processExists(grandchildPid); attempt += 1) {
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 10));
    }
    expect(processExists(grandchildPid)).toBe(false);
  });
});

function processExists(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ESRCH') return false;
    throw error;
  }
}
