import { spawn, execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import type { Options } from '@anthropic-ai/claude-agent-sdk';
import { atomicPrivateWrite, readManagedFile } from './workflow/storage-files.js';

const alive = (pid: number) => { try { process.kill(pid, 0); return true; } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ESRCH') return false; throw error; } };
export const processIdentity = (pid: number) => execFileSync('/bin/ps', ['-p', String(pid), '-o', 'lstart=', '-o', 'comm='], { encoding: 'utf8', timeout: 1000, stdio: ['ignore', 'pipe', 'ignore'] }).trim();

/** Native process exit is the local lifetime boundary, separate from remote billing. */
export function managedProviderProcess(directory: string, attemptId?: string, stderr?: (data: string) => void) {
  const exits: Promise<void>[] = [];
  const errors: unknown[] = [];
  const start: NonNullable<Options['spawnClaudeCodeProcess']> = options => {
    const child = spawn(options.command, options.args, { cwd: options.cwd, env: options.env,
      signal: options.signal, killSignal: 'SIGKILL', detached: process.platform !== 'win32', stdio: ['pipe', 'pipe', 'pipe'] });
    child.stderr.on('data', chunk => stderr?.(chunk.toString()));
    const path = join(directory, 'session-processes', `${randomUUID()}.json`);
    const receipt = { ownerPid: process.pid, pid: child.pid, identity: '', attemptId, state: 'running' };
    exits.push(new Promise<void>(resolve => {
      let completed = false;
      const complete = () => {
        if (completed) return; completed = true;
        receipt.state = 'terminated';
        try { atomicPrivateWrite(path, JSON.stringify(receipt)); } catch (error) { errors.push(error); }
        resolve();
      };
      child.once('close', complete);
      child.once('error', () => { if (!child.pid) complete(); });
    }));
    try {
      if (child.pid) {
        try { receipt.identity = processIdentity(child.pid); } catch (error) { if (alive(child.pid)) throw error; }
      }
      atomicPrivateWrite(path, JSON.stringify(receipt));
    } catch (error) {
      if (child.pid) {
        try { process.kill(process.platform === 'win32' ? child.pid : -child.pid, 'SIGKILL'); } catch { child.kill('SIGKILL'); }
      }
      throw error;
    }
    return child;
  };
  return { start, exited: async () => { await Promise.all(exits); if (errors.length) throw new AggregateError(errors, 'Provider process receipt could not be saved'); } };
}

export async function reconcileProviderProcesses(root: string, ownerPid: number, ownerIdentity?: string): Promise<void> {
  if (alive(ownerPid) && (!ownerIdentity || processIdentity(ownerPid) === ownerIdentity)) throw new Error(`Previous scheduler process is still alive: ${ownerPid}`);
  const receipts: string[] = [];
  const visit = (directory: string) => {
    if (!existsSync(directory)) return;
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory() && (entry.name === 'session-processes' || entry.name === 'work-units' || directory.includes('work-units'))) visit(path);
      if (entry.isFile() && directory.endsWith('session-processes') && entry.name.endsWith('.json')) receipts.push(path);
    }
  };
  visit(root);
  for (const path of receipts) {
    const receipt = JSON.parse(readManagedFile(root, path).toString());
    if (receipt.ownerPid !== ownerPid || receipt.state === 'terminated' || !receipt.pid) continue;
    if (alive(receipt.pid) && !receipt.identity) throw new Error(`Provider identity is unconfirmed: ${receipt.pid}`);
    if (alive(receipt.pid) && processIdentity(receipt.pid) === receipt.identity) {
      process.kill(process.platform === 'win32' ? receipt.pid : -receipt.pid, 'SIGKILL');
      const deadline = Date.now() + 3000;
      while (alive(receipt.pid) && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 50));
      if (alive(receipt.pid)) throw new Error(`Provider termination is unconfirmed: ${receipt.pid}`);
    }
    atomicPrivateWrite(path, JSON.stringify({ ...receipt, state: 'terminated', recovered: true, remoteUsage: 'unknown-unless-receipt' }));
  }
}
