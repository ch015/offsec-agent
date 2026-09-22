import { createHash } from 'node:crypto';
import { appendFileSync, closeSync, constants, existsSync, fsyncSync, openSync, readdirSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { atomicPrivateWrite, privateDirectory, readManagedFile } from './storage-files.js';

type Sequenced = { seq: number };
const hash = (text: string) => createHash('sha256').update(text).digest('hex');

/** Write-ahead batches allow recovery even when a multi-event JSONL append is torn. */
export function appendLedger<T extends Sequenced>(root: string, path: string, events: readonly T[], deferAppend = false): { pending: boolean; error?: string } {
  const pending = join(root, '.recovery', 'state'); privateDirectory(pending);
  const payload = events.map(e => JSON.stringify(e) + '\n').join('');
  const journal = join(pending, `${String(events[0]!.seq).padStart(16, '0')}.json`);
  atomicPrivateWrite(journal, JSON.stringify({ payload, sha256: hash(payload) }));
  if (deferAppend) return { pending: true };
  try {
    const fd = openSync(path, constants.O_WRONLY | constants.O_APPEND | constants.O_NOFOLLOW);
    try { appendFileSync(fd, payload); fsyncSync(fd); } finally { closeSync(fd); }
    unlinkSync(journal);
    return { pending: false };
  } catch (error) { return { pending: true, error: String(error) }; }
}

export function recoverLedger<T extends Sequenced>(root: string, path: string, parse: (value: unknown) => T): T[] {
  const content = readManagedFile(root, path).toString(), lines = content.split('\n');
  const events: T[] = []; let torn = false;
  for (const [i, line] of lines.entries()) {
    if (!line.trim()) continue;
    try { events.push(parse(JSON.parse(line))); }
    catch (error) {
      // Only an unterminated final JSON fragment is a recoverable interrupted append.
      if (i !== lines.length - 1 || content.endsWith('\n')) throw error;
      try { JSON.parse(line); } catch { torn = true; break; }
      throw error;
    }
  }
  const pending = join(root, '.recovery', 'state');
  let replayed = false;
  const journals = existsSync(pending) ? readdirSync(pending).filter(n => n.endsWith('.json')).sort() : [];
  for (const name of journals) {
    const record = JSON.parse(readManagedFile(root, join(pending, name)).toString());
    if (typeof record.payload !== 'string' || hash(record.payload) !== record.sha256) throw new Error(`state recovery checksum mismatch: ${name}`);
    for (const line of record.payload.trimEnd().split('\n')) {
      const event = parse(JSON.parse(line));
      const existing = events[event.seq - 1];
      if (existing) {
        if (JSON.stringify(existing) !== JSON.stringify(event)) throw new Error(`state recovery sequence conflict: ${event.seq}`);
      } else {
        if (event.seq !== events.length + 1) throw new Error('state recovery sequence gap');
        events.push(event); replayed = true;
      }
    }
  }
  if (torn) atomicPrivateWrite(join(root, '.recovery', `torn-ledger-${hash(content)}.jsonl`), content);
  if (torn || replayed || (content && !content.endsWith('\n'))) atomicPrivateWrite(path, events.map(e => JSON.stringify(e) + '\n').join(''));
  for (const name of journals) unlinkSync(join(pending, name));
  return events;
}
