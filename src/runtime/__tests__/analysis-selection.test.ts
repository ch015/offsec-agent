import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createOffsecAgent } from '../../index.js';
import { parseAssessV2Args, parseAnalysisTools, resolveAnalysisSelection, type AnalysisSelectionInput } from '../missions/analysis-selection.js';
import { syntheticOutcome } from './resumption-fixture.js';

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function fixture() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'offsec-tool-selection-'))); roots.push(root);
  const target = join(root, 'source'); mkdirSync(target); writeFileSync(join(target, 'app.ts'), 'export const app = 1;\n');
  return { target, engagementDir: join(root, 'run') };
}

describe('analysis mode and explicit tool selection', () => {
  it.each([
    { input: {}, expected: { mode: 'ast', semgrepMode: 'best-effort' } },
    { input: { mode: 'ast' }, expected: { mode: 'ast', semgrepMode: 'off' } },
    { input: { mode: 'ast', tools: [] }, expected: { mode: 'ast', tools: [], semgrepMode: 'off' } },
    { input: { mode: 'ast', tools: ['semgrep'] }, expected: { mode: 'ast', tools: ['semgrep'], semgrepMode: 'required' } },
    { input: { tools: ['semgrep'], semgrepMode: 'best-effort' }, expected: { mode: 'ast', tools: ['semgrep'], semgrepMode: 'best-effort' } },
    { input: { semgrepMode: 'required' }, expected: { mode: 'ast', semgrepMode: 'required' } },
  ])('resolves $input explicitly and keeps old defaults', ({ input, expected }) => {
    expect(resolveAnalysisSelection(input as AnalysisSelectionInput)).toEqual(expected);
  });
  it.each([
    { mode: 'dast' }, { tools: ['unknown'] }, { tools: 'semgrep' }, { tools: ['semgrep', 'semgrep'] },
    { tools: ['semgrep'], semgrepMode: 'off' }, { tools: [], semgrepMode: 'required' }, { semgrepMode: 'unknown' },
  ])('rejects unsupported or contradictory input %j', input => {
    expect(() => resolveAnalysisSelection(input as unknown as AnalysisSelectionInput)).toThrow();
  });
  it('accepts both space and equals syntax without appending options to the scope instruction', () => {
    const spaced = parseAssessV2Args(['/repo', '인증 점검', '--mode', 'ast', '--tools', 'semgrep', '--max-concurrency', '16']);
    const equals = parseAssessV2Args(['/repo', '인증 점검', '--mode=ast', '--tools=semgrep', '--max-concurrency=16']);
    expect(spaced).toEqual(equals);
    expect(spaced.positional).toEqual(['/repo', '인증 점검']);
    expect(parseAnalysisTools(spaced.flags.get('tools')!)).toEqual(['semgrep']);
    expect(parseAnalysisTools('none')).toEqual([]);
    expect(parseAssessV2Args(['/repo', '--', '--literal instruction']).positional).toEqual(['/repo', '--literal instruction']);
  });
  it.each([['--tools'], ['--tools', '--mode', 'ast'], ['--tools='], ['--tool', 'semgrep'], ['--mode', 'ast', '--mode=ast'], ['--resume=maybe']].map(args => ({ args })))('rejects malformed CLI $args', ({ args }) => {
    expect(() => parseAssessV2Args(args)).toThrow();
  });
  it.each(['', 'semgrepp', 'none,semgrep', 'semgrep,semgrep'])('rejects invalid tool list %s', value => {
    expect(() => parseAnalysisTools(value)).toThrow();
  });
  it('starts no model when explicitly selected Semgrep fails and can resume after tool repair', async () => {
    const input = fixture(); let calls = 0, healthy = false; const selections: boolean[] = [];
    const agent = createOffsecAgent({ defaults: { mode: 'ast', tools: ['semgrep'] },
      astBuilder: async (_target, options) => {
        selections.push(options.runSemgrep);
        return { ok: false, semgrep: healthy ? { status: 'complete' } : { status: 'version-mismatch', error: 'test version mismatch' } };
      }, sessionRunner: async spec => { calls++; return syntheticOutcome(spec); } });
    const first = await agent.run(input);
    expect(first.status).toBe('incomplete'); expect(calls).toBe(0); expect(selections).toEqual([true]);
    expect(readFileSync(first.finalReport, 'utf8')).toContain('Selected tool semgrep did not complete');
    const sealed = readFileSync(join(input.engagementDir, 'assess-v2-checkpoint-input.json'));
    expect(JSON.parse(sealed.toString()).input).toMatchObject({ mode: 'ast', tools: ['semgrep'], semgrepMode: 'required' });
    healthy = true;
    const resumed = await agent.resume(input.engagementDir);
    expect(resumed.status).toBe('published'); expect(calls).toBe(5); expect(selections).toEqual([true, true]);
    expect(readFileSync(join(input.engagementDir, 'assess-v2-checkpoint-input.json'))).toEqual(sealed);
  });
  it.each([
    { mode: 'ast', tools: [], expected: false },
    { mode: 'ast', tools: ['semgrep'], semgrepMode: 'best-effort', expected: true },
  ])('passes actual selection to preanalysis and continues under the selected policy: %j', async selection => {
    const input = fixture(); const flags: boolean[] = [];
    const { expected, ...defaults } = selection;
    const agent = createOffsecAgent({ defaults: defaults as AnalysisSelectionInput,
      astBuilder: async (_target, options) => { flags.push(options.runSemgrep); return { ok: false, semgrep: { status: 'unavailable' } }; },
      sessionRunner: async spec => syntheticOutcome(spec) });
    const result = await agent.run(input);
    expect(result.status).toBe('published'); expect(flags).toEqual([expected]);
    expect(existsSync(result.finalReport)).toBe(true);
  });
});
