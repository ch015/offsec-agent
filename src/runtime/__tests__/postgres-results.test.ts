import { mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { Pool } from 'pg';
import { expect, it } from 'vitest';
import { PostgresResultStore } from '../postgres-results.js';

it('redacts connection failures without falling back to a local result history', async () => {
  const root = mkdtempSync(join(tmpdir(), 'results-failure-'));
  const store = new PostgresResultStore({ connect: async () => { throw new Error('postgres://sensitive:password@host/private-db'); } } as unknown as Pool);
  try {
    for (const operation of [() => store.inspect(root), () => store.append(root, {}, 'empty')]) {
      let error: unknown; try { await operation(); } catch (caught) { error = caught; }
      expect(String(error)).toContain('PostgreSQL result operation failed');
      expect(String(error)).not.toMatch(/sensitive|password|private-db/);
    }
    expect(readdirSync(root)).toEqual([]);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
