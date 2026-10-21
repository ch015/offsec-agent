import { mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { atomicPrivateCreate, atomicPrivateWrite } from '../workflow/storage-files.js';

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function directory() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'storage-files-'))); roots.push(root);
  return root;
}

describe('private atomic file writes', () => {
  it('replaces a file without leaving temporary files', () => {
    const root = directory(), path = join(root, 'record.json');
    writeFileSync(path, '{"version":1}\n');
    atomicPrivateWrite(path, '{"version":2}\n');
    expect(readFileSync(path, 'utf8')).toBe('{"version":2}\n');
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(readdirSync(root)).toEqual(['record.json']);
  });

  it('creates a file once and refuses to replace it', () => {
    const root = directory(), path = join(root, 'record.json');
    atomicPrivateCreate(path, '{"version":1}\n');
    expect(readFileSync(path, 'utf8')).toBe('{"version":1}\n');
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(() => atomicPrivateCreate(path, '{"version":2}\n')).toThrow(expect.objectContaining({ code: 'EEXIST' }));
    expect(readFileSync(path, 'utf8')).toBe('{"version":1}\n');
    expect(readdirSync(root)).toEqual(['record.json']);
  });
});
