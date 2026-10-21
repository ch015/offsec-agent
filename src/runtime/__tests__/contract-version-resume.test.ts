import { mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createOffsecAgent } from '../../index.js';
import { loadOffsecContract } from '../offsec-contract.js';
import { FileRunStateStore } from '../workflow/state-store.js';
import { syntheticOutcome } from './resumption-fixture.js';

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
const snapshot = (dir: string): string[] => readdirSync(dir, { recursive: true, encoding: 'utf8' }).sort()
  .map(name => statSync(join(dir, name)).isFile() ? `${name}:${readFileSync(join(dir, name), 'base64')}` : name);

describe('contract version on resume', () => {
  it('rejects a run started under an earlier contract version without touching it', async () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'contract-version-'))); roots.push(root);
    const target = join(root, 'source'), engagementDir = join(root, 'run');
    mkdirSync(target); writeFileSync(join(target, 'app.ts'), 'export const app = 1;\n');
    const version = loadOffsecContract().version;
    expect(version).not.toBe('2.1.0');
    const agent = createOffsecAgent({ sessionRunner: async spec => syntheticOutcome(spec) });
    await agent.run({ target, engagementDir, semgrepMode: 'off', mode: 'ast', tools: [] });
    // Rewrite the run identity as if this run had been created by the 2.1.0 build.
    for (const name of readdirSync(engagementDir).filter(name => /^run-(state|events)/.test(name))) {
      const path = join(engagementDir, name);
      writeFileSync(path, readFileSync(path, 'utf8').replaceAll(`"contractVersion":"${version}"`, '"contractVersion":"2.1.0"')
        .replaceAll(`"contractVersion": "${version}"`, '"contractVersion": "2.1.0"'));
    }
    expect(FileRunStateStore.open(engagementDir).read().contractVersion).toBe('2.1.0');
    const before = snapshot(engagementDir);
    await expect(agent.resume(engagementDir)).rejects.toThrow(/incompatible assessment contract/);
    // Resume first appends a content-addressed run archive (existing behavior); the run itself is untouched.
    const run = (entries: string[]) => entries.filter(entry => !entry.startsWith('.artifact-store') && !entry.startsWith('run-archive.json'));
    expect(run(snapshot(engagementDir))).toEqual(run(before));
  });
});
