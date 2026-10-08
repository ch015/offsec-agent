import { mkdtempSync, realpathSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { observeSourceDelivery, mergeLineRanges, sourceRangeDelivered } from '../source-delivery.js';

describe('model-facing source delivery', () => {
  const target = mkdtempSync(join(tmpdir(), 'source-delivery-'));
  const file = join(target, 'source.ts');
  writeFileSync(file, 'const a = 1;\nconst b = 2;\nconst c = 3;\n');
  const observe = (content: unknown, extra = {}) => observeSourceDelivery({ target, file, allowedFiles: [file], toolCallId: 'read-1', content, ...extra });
  it('validates the actual SDK Read text and only its returned range', () => {
    const result = observe('2\tconst b = 2;', { offset: 2, limit: 1 });
    expect(result?.delivery).toMatchObject({ totalLines: 3, ranges: [{ start: 2, end: 2 }], status: 'verified' });
  });
  it('rejects unnumbered, failed, unknown, unauthorized and changed content', () => {
    for (const content of ['const b = 2;', '2\twrong', { file: { content: 'const b = 2;', numLines: 1 } }]) {
      expect(observe(content)?.delivery.status).toBe('unknown');
    }
    expect(observe('2\tconst b = 2;', { isError: true })?.delivery.ranges).toEqual([]);
    expect(observe('2\tconst b = 2;', { allowedFiles: [] })).toBeUndefined();
  });
  it('does not fill gaps hidden by truncation and coalesces overlapping ranges', () => {
    expect(observe('1\tconst a = 1;\n[truncated]\n3\tconst c = 3;')?.delivery.ranges).toEqual([{ start: 1, end: 1 }, { start: 3, end: 3 }]);
    expect(mergeLineRanges([{ start: 2, end: 4 }, { start: 1, end: 2 }, { start: 6, end: 7 }])).toEqual([{ start: 1, end: 4 }, { start: 6, end: 7 }]);
  });

  it('combines verified line and byte reads across UTF-8/CRLF boundaries without accepting a one-byte gap', () => {
    const mixedFile = join(realpathSync(target), 'mixed.ts');
    const raw = Buffer.from('가\r\nβeta\nlast🙂');
    writeFileSync(mixedFile, raw);
    const evidence = (content: string) => observeSourceDelivery({ target, file: mixedFile, allowedFiles: [mixedFile], toolCallId: 'mixed', content })!.delivery;
    const lineReads = evidence('1\t가\n3\tlast🙂');
    const byteRead = (end: number) => evidence(JSON.stringify({ sourceRead: 1, path: mixedFile,
      sha256: createHash('sha256').update(raw).digest('hex'), byteStart: 5, byteEnd: end, content: raw.subarray(5, end).toString('utf8') }));
    const middle = byteRead(11);
    expect(sourceRangeDelivered(mixedFile, [lineReads])).toBe(false);
    expect(sourceRangeDelivered(mixedFile, [middle])).toBe(false);
    expect(sourceRangeDelivered(mixedFile, [lineReads, middle])).toBe(true);
    expect(sourceRangeDelivered(mixedFile, [lineReads, middle], 2, 3, { byteStart: 5, byteEnd: raw.length })).toBe(true);
    expect(sourceRangeDelivered(mixedFile, [lineReads, byteRead(10)])).toBe(false);
    expect(sourceRangeDelivered(mixedFile, [lineReads, { ...middle, sourceHash: '0'.repeat(64) }])).toBe(false);
    expect(sourceRangeDelivered(mixedFile, [lineReads, { ...middle, status: 'unknown' }])).toBe(false);
  });
});
