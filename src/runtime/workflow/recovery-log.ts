import { randomUUID } from 'node:crypto';
import { appendFileSync } from 'node:fs';
import { join } from 'node:path';
import { atomicPrivateWrite, managedPath } from './storage-files.js';

/** Audit logging failure is reported, but cannot abort a model session that has its own receipt ledger. */
export function recoveryLogger(root: string, name: string, warnings: string[]): (event: unknown) => void {
  const path = managedPath(root, join(root, name));
  let lost = 0;
  return event => {
    const line = JSON.stringify(event) + '\n';
    try { managedPath(root, path); appendFileSync(path, line, { mode: 0o600 }); }
    catch (error) {
      try { atomicPrivateWrite(join(root, '.recovery', 'logs', `${randomUUID()}.jsonl`), line); }
      catch { lost++; }
      if (warnings.length < 20) warnings.push(`audit log degraded (${lost} unpersisted events): ${String(error)}`);
      else warnings[19] = `audit log still degraded; ${lost} events could not be persisted`;
    }
  };
}
