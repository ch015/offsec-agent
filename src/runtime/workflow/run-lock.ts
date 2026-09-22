import { randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { closeSync, constants, existsSync, fstatSync, lstatSync, openSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { managedPath } from './storage-files.js';
import { dirname } from 'node:path';

function started(pid: number): string | undefined {
  try { return execFileSync('ps', ['-p', String(pid), '-o', 'lstart='], { encoding: 'utf8', timeout: 1000 }).trim() || undefined; } catch { return undefined; }
}
export function acquireRunLock(path: string): () => void {
  managedPath(dirname(path), path);
  for (let attempt = 0; attempt < 3; attempt++) {
    let fd: number;
    try { fd = openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      const before = lstatSync(path);
      if (!before.isFile() || before.isSymbolicLink() || (process.getuid && before.uid !== process.getuid())) throw new Error('unsafe agent lock');
      let record: { pid: number; host?: string; processStarted?: string };
      try { record = JSON.parse(readFileSync(path, 'utf8')); } catch { throw new Error('agent lock is incomplete; owner cannot be verified'); }
      if (!Number.isInteger(record.pid) || record.pid < 1 || record.host !== hostname()) throw new Error('Agent run lock owner cannot be verified on this host');
      let dead = false;
      try { process.kill(record.pid, 0); } catch (error) { dead = (error as NodeJS.ErrnoException).code === 'ESRCH'; }
      const observed = dead ? undefined : started(record.pid);
      if (!dead && !(record.processStarted && observed && record.processStarted !== observed)) throw new Error('Agent run is already active for this engagementDir');
      const now = lstatSync(path);
      if (now.ino !== before.ino || now.dev !== before.dev || now.mtimeMs !== before.mtimeMs) continue;
      unlinkSync(path); continue;
    }
    const identity = fstatSync(fd), token = randomUUID();
    try { writeFileSync(fd, JSON.stringify({ pid: process.pid, host: hostname(), processStarted: started(process.pid), token, startedAt: new Date().toISOString() })); }
    catch (error) { closeSync(fd); if (existsSync(path) && lstatSync(path).ino === identity.ino) unlinkSync(path); throw error; }
    return () => {
      closeSync(fd);
      if (existsSync(path)) {
        const current = lstatSync(path);
        if (current.ino === identity.ino && current.dev === identity.dev && !current.isSymbolicLink()) unlinkSync(path);
      }
    };
  }
  throw new Error('Agent run lock changed during recovery; retry');
}
