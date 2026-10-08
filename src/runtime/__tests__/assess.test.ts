import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { assess, resumeAssess } from '../missions/assess.js';
import { assessV2, resumeAssessV2 } from '../missions/assess-v2.js';
import { parseAssessV2Args } from '../missions/analysis-selection.js';
import { syntheticOutcome } from './resumption-fixture.js';
describe('canonical assessment entrypoint', () => {
  it('uses one implementation for native and compatibility names', () => {
    expect(assess).toBe(assessV2); expect(resumeAssess).toBe(resumeAssessV2);
  });
  it.each(['--verification-mode=VA_PENTEST', '--verification-mode=VA_PENTEST_REDTEAM', '--test-url=https://example.test', '--interaction-mode=owner'])('rejects retired option %s before execution', option => {
    expect(() => parseAssessV2Args(['/target', option])).toThrow(/Unknown option/);
  });
  it('refuses to overwrite previous evidence', async () => {
    const target = mkdtempSync(join(tmpdir(), 'single-assess-')), engagementDir = join(target, 'run');
    mkdirSync(engagementDir); writeFileSync(join(engagementDir, 'existing'), 'keep');
    await expect(assess({ target, engagementDir, semgrepMode: 'off' })).rejects.toThrow(/덮어쓸/);
    expect(existsSync(join(engagementDir, 'existing'))).toBe(true);
  });
  it('rejects required tool failure without a model call on the canonical API', async () => {
    const target = mkdtempSync(join(tmpdir(), 'required-tool-')); writeFileSync(join(target, 'app.ts'), 'export const x=1;');
    const sessionRunner = vi.fn(async spec => syntheticOutcome(spec));
    const result = await assess({ target, semgrepMode: 'required' }, { sessionRunner, astBuilder: async () => ({ok:false,semgrep:{status:'unavailable'}}) });
    expect(result.coverage.complete).toBe(false); expect(sessionRunner).not.toHaveBeenCalled();
  });
});
