import { createHash } from 'node:crypto';
import { readFileSync, realpathSync } from 'node:fs';
import { resolve } from 'node:path';

export function readSourceChunk(input: { target: string; allowedFiles: readonly string[]; filePath: string; offset: number; limit: number }) {
  const path = realpathSync(resolve(input.target, input.filePath));
  if (!input.allowedFiles.some(file => { try { return realpathSync(resolve(input.target, file)) === path; } catch { return false; } })) throw new Error('Source file is outside the exact read scope');
  if (!Number.isSafeInteger(input.offset) || input.offset < 0 || !Number.isSafeInteger(input.limit) || input.limit < 1) throw new Error('Read offset/limit must be safe integers; offset >= 0 and limit >= 1');
  const raw = readFileSync(path);
  // Reject binary/invalid UTF-8; never replace bytes while claiming full delivery.
  new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(raw);
  // Oversized model requests still make bounded progress; nextOffset carries
  // the remainder instead of forcing the model to recover from a tool error.
  let byteStart = Math.min(input.offset, raw.length), byteEnd = Math.min(byteStart + Math.min(input.limit, 24000), raw.length);
  while (byteStart > 0 && byteStart < raw.length && (raw[byteStart]! & 0xc0) === 0x80) byteStart--;
  while (byteEnd < raw.length && (raw[byteEnd]! & 0xc0) === 0x80) byteEnd++;
  return { sourceRead: 1, path, sha256: createHash('sha256').update(raw).digest('hex'), byteStart, byteEnd,
    totalBytes: raw.length, nextOffset: byteEnd < raw.length ? byteEnd : null, content: raw.subarray(byteStart, byteEnd).toString('utf8') };
}
