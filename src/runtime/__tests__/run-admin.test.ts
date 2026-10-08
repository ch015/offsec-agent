import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { acquireRunLock } from '../workflow/run-lock.js';
import { FileRunStateStore } from '../workflow/state-store.js';

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
it('admin rejects a wrong run identity and cannot mutate a live assessment', () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'run-admin-'))); roots.push(root);
  const engagementDir = join(root, 'run'); mkdirSync(engagementDir);
  FileRunStateStore.create({ engagementDir, runId: 'actual-run', contractId: 'test', contractVersion: '2.1.0', domain: 'test', mission: 'assess' });
  const before = readFileSync(join(engagementDir, 'run-state.json'), 'utf8');
  const cli = (args: string[]) => spawnSync(process.execPath, ['--import', 'tsx', resolve('scripts/run-admin.ts'), ...args, `--engagement=${engagementDir}`, '--backend=file'], { encoding: 'utf8', timeout: 10000 });
  const wrong = cli(['inspect', '--run-id=other-run']);
  expect(wrong.status).toBe(1); expect(wrong.stderr).toContain('does not match');
  const release = acquireRunLock(join(root, '.run.agent.lock'));
  try {
    const locked = cli(['reconcile', '--run-id=actual-run', '--expected-version=0', '--phase=analyze', '--attempt=1', '--reason=unknown']);
    expect(locked.status).toBe(1); expect(locked.stderr).toContain('already active');
  } finally { release(); }
  expect(readFileSync(join(engagementDir, 'run-state.json'), 'utf8')).toBe(before);
});
