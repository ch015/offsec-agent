import { createHash } from 'node:crypto';
import { readFileSync, realpathSync } from 'node:fs';
import { resolve } from 'node:path';

/** Observed model-facing tool_result, never the pre-truncation tool_use_result. */
export type SourceDeliveryReceipt = {
  toolCallId: string;
  sourceHash: string;
  totalLines: number;
  ranges: Array<{ start: number; end: number }>;
  outputHash: string;
  status: 'verified' | 'unknown' | 'error';
  byteRanges?: Array<{ start: number; end: number }>;
  totalBytes?: number;
};

export function sourceLines(text: string): string[] {
  const lines = text.split('\n').map(line => line.endsWith('\r') ? line.slice(0, -1) : line);
  if (lines.at(-1) === '') lines.pop();
  return lines;
}

export function mergeLineRanges(ranges: readonly { start: number; end: number }[]): Array<{ start: number; end: number }> {
  const merged: Array<{ start: number; end: number }> = [];
  for (const range of [...ranges].sort((a, b) => a.start - b.start)) {
    const previous = merged.at(-1);
    if (previous && range.start <= previous.end + 1) previous.end = Math.max(previous.end, range.end);
    else merged.push({ ...range });
  }
  return merged;
}

export function sourceRangeDelivered(file: string, receipts: readonly SourceDeliveryReceipt[], start = 1, end?: number, bytes?: { byteStart: number; byteEnd: number }): boolean {
  const raw = readFileSync(file), digest = createHash('sha256').update(raw).digest('hex');
  const valid = receipts.filter(receipt => receipt.status === 'verified' && receipt.sourceHash === digest);
  if (raw.length === 0) return valid.length > 0;
  const lines = sourceLines(raw.toString('utf8'));
  const last = end ?? lines.length;
  // SDK Read verifies numbered source lines, while read_source verifies byte
  // slices. A split file may use both transports. Map verified whole lines to
  // their original byte boundaries before taking the union; never bridge a
  // missing byte just because adjacent line numbers exist elsewhere.
  const boundaries = [0];
  for (let offset = 0; offset < raw.length;) {
    const newline = raw.indexOf(10, offset);
    offset = newline < 0 ? raw.length : newline + 1;
    boundaries.push(offset);
  }
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(last) || start < 1 || last < start || last > lines.length) return false;
  const from = bytes?.byteStart ?? boundaries[start - 1]!;
  const to = bytes?.byteEnd ?? boundaries[last]!;
  if (!Number.isSafeInteger(from) || !Number.isSafeInteger(to) || from < 0 || to < from || to > raw.length) return false;
  const ranges = valid.flatMap(receipt => [
    ...(receipt.byteRanges ?? []).filter(range => Number.isSafeInteger(range.start) && Number.isSafeInteger(range.end)
      && range.start >= 0 && range.end >= range.start && range.end <= raw.length),
    ...receipt.ranges.filter(range => Number.isSafeInteger(range.start) && Number.isSafeInteger(range.end)
      && range.start >= 1 && range.end >= range.start && range.end <= lines.length)
      .map(range => ({ start: boundaries[range.start - 1]!, end: boundaries[range.end]! })),
  ]);
  let cursor = from;
  for (const range of ranges.sort((a, b) => a.start - b.start)) {
    if (range.start > cursor) break;
    cursor = Math.max(cursor, range.end);
  }
  return cursor >= to;
}

export function observeSourceDelivery(input: {
  target: string; file: string; allowedFiles: readonly string[];
  toolCallId: string; content: unknown; isError?: boolean;
  offset?: number; limit?: number;
}): { resource: string; delivery: SourceDeliveryReceipt; reason?: string } | undefined {
  let resource: string;
  try { resource = realpathSync(resolve(input.target, input.file)); } catch { return undefined; }
  if (!input.allowedFiles.some(file => {
    try { return realpathSync(resolve(input.target, file)) === resource; } catch { return false; }
  })) return undefined;
  const raw = readFileSync(resource);
  const lines = sourceLines(raw.toString('utf8'));
  const text = typeof input.content === 'string' ? input.content : Array.isArray(input.content)
    ? input.content.filter(part => part?.type === 'text' && typeof part.text === 'string').map(part => part.text).join('\n') : '';
  const receipt: SourceDeliveryReceipt = {
    toolCallId: input.toolCallId, sourceHash: createHash('sha256').update(raw).digest('hex'),
    outputHash: createHash('sha256').update(text).digest('hex'), totalLines: lines.length, totalBytes: raw.length,
    ranges: [], status: input.isError ? 'error' : 'unknown',
  };
  if (!input.isError) {
    try { new TextDecoder('utf-8', { fatal: true }).decode(raw); }
    catch { return { resource, delivery: receipt, reason: 'Invalid UTF-8 source; native replacement characters cannot establish delivery' }; }
    // Dedicated reader returns a bounded UTF-8 byte slice in a JSON envelope.
    try {
      const chunk = JSON.parse(text);
      if (chunk.sourceRead === 1 && chunk.path === resource && chunk.sha256 === receipt.sourceHash
        && Number.isSafeInteger(chunk.byteStart) && Number.isSafeInteger(chunk.byteEnd)
        && chunk.byteStart >= 0 && chunk.byteEnd >= chunk.byteStart && chunk.byteEnd <= raw.length
        && typeof chunk.content === 'string' && Buffer.from(chunk.content).equals(raw.subarray(chunk.byteStart, chunk.byteEnd))) {
        receipt.byteRanges = [{ start: chunk.byteStart, end: chunk.byteEnd }];
        receipt.status = 'verified';
        return { resource, delivery: receipt };
      }
    } catch { /* Ordinary Read uses numbered text below. */ }
    const start = input.offset ?? 1, end = input.limit === undefined ? lines.length : start + input.limit - 1;
    for (const line of text.split('\n')) {
      const match = /^\s*(\d+)(?:\t|→)(.*)$/.exec(line);
      if (!match) continue;
      const number = Number(match[1]);
      if (number >= start && number <= end && number >= 1 && number <= lines.length && match[2] === lines[number - 1]) {
        receipt.ranges.push({ start: number, end: number });
      }
    }
    receipt.ranges = mergeLineRanges(receipt.ranges);
    if (receipt.ranges.length || (raw.length === 0 && /empty file|file.*empty/i.test(text))) receipt.status = 'verified';
  }
  return { resource, delivery: receipt, ...(input.isError ? { reason: text.slice(0, 1000) } : {}) };
}
