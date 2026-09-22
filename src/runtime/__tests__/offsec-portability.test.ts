import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { assess } from '../missions/assess.js';
import { assessV2 } from '../missions/assess-v2.js';
describe('project-specific OffSec exclusions', () => {
  it.each([['v1', assess], ['v2', assessV2]] as const)('seals exclusions before %s model execution and checkpointing', async (_version, mission) => {
    const target = mkdtempSync(join(tmpdir(), 'offsec-portable-'));
    const excluded = join(target, 'private'); mkdirSync(excluded);
    writeFileSync(join(target, 'app.ts'), 'export const value = 1;\n');
    writeFileSync(join(excluded, 'secret.ts'), 'export const hidden = 2;\n');
    const engagementDir = join(target, '.secops', 'run');
    let reachedModel = false;
    const operation = mission({ target, engagementDir, engagementId: 'portable-test', excludePaths: [excluded, join(target, '.secops')], semgrepMode: 'off', workUnitMode: _version === 'v1' ? 'off' : 'auto' }, {
      sessionRunner: async () => { reachedModel = true; throw new Error('fixture stops before model execution'); },
    });
    if (_version === 'v1') await expect(operation).rejects.toThrow();
    else await expect(operation).resolves.toMatchObject({ publicationStatus: 'partial', coverage: { complete: false } });
    expect(reachedModel).toBe(true);
    const manifest = JSON.parse(readFileSync(join(engagementDir, 'source_manifest.json'), 'utf8'));
    expect(manifest.source_files).toEqual(['app.ts']);
    expect(manifest.policy.excludedPaths).toContain('private');
    const checkpoint = JSON.parse(readFileSync(join(engagementDir, _version === 'v1' ? 'assess-checkpoint-input.json' : 'assess-v2-checkpoint-input.json'), 'utf8'));
    expect(checkpoint.input.excludePaths).toContain(excluded);
  });
});
