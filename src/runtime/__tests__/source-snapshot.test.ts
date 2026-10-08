import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { compareSourceRevision, mapEvidenceLines } from '../source-change-policy.js';
import { compareSnapshotToWorkspace, createSourceSnapshot, loadSourceSnapshot } from '../source-snapshot.js';
const compare = (file: string, a: string, b: string) => compareSourceRevision(file, Buffer.from(a), Buffer.from(b));

describe('snapshot identity and analysis reuse', () => {
  it('reuses supported EOL/EOF changes, keeping distinct raw identities and tool receipts', () => {
    const change = compare('auth.ts', 'export const x = 1;\r\n', 'export const x = 1;');
    expect(change).toMatchObject({ kind: 'supported-format-only', reuseAnalysis: true, reuseToolOutput: false });
    expect(change.oldDigest).not.toBe(change.newDigest);
    expect(compare('a.json', '{\r\n"a": 1\r\n}\r\n', '{\n"a": 1\n}').reuseAnalysis).toBe(true);
  });
  it('preserves single-character condition, whitespace, literal and unsupported changes', () => {
    expect(compare('a.ts', 'a == b', 'a != b').reuseAnalysis).toBe(false);
    expect(compare('a.py', 'if x:\n  pass\n', 'if x:\n pass\n').reuseAnalysis).toBe(false);
    expect(compare('a.ts', 'const x = `a\r\nb`;', 'const x = `a\nb`;').kind).toBe('unknown');
    expect(compare('a.py', 'x=1\r\n', 'x=1\n').kind).toBe('unknown');
    expect(compare('a.ts', 'const =\r\n', 'const =\n').kind).toBe('unknown');
  });
  it('maps evidence byte offsets without claiming a new read', () => {
    expect(mapEvidenceLines('a\r\nb\r\n', 'a\nb\n', 2, 2)).toMatchObject({ lineStart: 2, previous: { byteStart: 3 }, current: { byteStart: 2 } });
    expect(mapEvidenceLines('a\nb', 'x\nb', 1, 2)).toBeUndefined();
  });
  it('keeps uncommitted source fixed while classifying workspace changes and rejecting evidence tampering', () => {
    const target = mkdtempSync(join(tmpdir(), 'fixed-source-')), engagementDir = mkdtempSync(join(tmpdir(), 'snapshot-run-'));
    writeFileSync(join(target, 'auth.ts'), 'export const x = 1;\n');
    const sealed = createSourceSnapshot({ target, engagementDir, files: [{ path: 'auth.ts' }] });
    writeFileSync(join(target, 'auth.ts'), 'export const x = 1;\r\n');
    expect(readFileSync(join(sealed.target, 'auth.ts'), 'utf8')).toBe('export const x = 1;\n');
    expect(compareSnapshotToWorkspace(engagementDir)[0]).toMatchObject({ reuseAnalysis: true, kind: 'supported-format-only' });
    expect(loadSourceSnapshot(engagementDir).snapshot.id).toBe(sealed.snapshot.id);
    chmodSync(join(sealed.target, 'auth.ts'), 0o600); writeFileSync(join(sealed.target, 'auth.ts'), 'changed');
    expect(() => loadSourceSnapshot(engagementDir)).toThrow(/integrity/);
  });
  it('rejects traversal, capture drift and non-files', () => {
    const target = mkdtempSync(join(tmpdir(), 'capture-')), engagementDir = mkdtempSync(join(tmpdir(), 'capture-run-'));
    mkdirSync(join(target, 'directory')); writeFileSync(join(target, 'a.ts'), 'export {}');
    for (const file of [{ path: '../escape' }, { path: 'directory' }, { path: 'a.ts', sha256: '0'.repeat(64) }]) {
      expect(() => createSourceSnapshot({ target, engagementDir, files: [file] })).toThrow();
    }
  });
});
