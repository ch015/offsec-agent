import { syntheticOutcome } from '../../runtime/__tests__/resumption-fixture.js';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';
import { createOffsecAgent, type SessionSpec, type SessionOutcome, type PhaseMetrics } from '../../index.js';
import { buildOptions } from '../../runtime/session.js';
import { loadOffsecContract, getOffsecPhase, renderPhaseArtifacts, resolvePhaseMethodFiles } from '../../runtime/offsec-contract.js';
const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'offsec-embedded-')); roots.push(root);
  const target = join(root, 'project'); mkdirSync(target); writeFileSync(join(target, 'app.ts'), 'export const app = 1;\n');
  return { target, engagementDir: join(root, 'results/run'), engagementId: 'embedded', semgrepMode: 'off' as const };
}
const contract = loadOffsecContract(resolve(import.meta.dirname, '../../../domains/offsec/contracts/offsec-contract.v2.json'));
async function scripted(spec: SessionSpec): Promise<SessionOutcome> { return syntheticOutcome(spec); }
it('runs two projects with independent credentials, metrics and outputs through the public API', async () => {
  const parentKey = process.env.ANTHROPIC_API_KEY, parentMode = process.env.AUTH_MODE, cwd = process.cwd();
  const runs = await Promise.all(['a', 'b'].map(async name => {
    const input = { ...fixture(), engagementId: `embedded-${name}` }, metrics: PhaseMetrics[] = [];
    const agent = createOffsecAgent({ apiKey: `fixture-${name}`, onMetrics: m => metrics.push(m), sessionRunner: async spec => {
      expect(buildOptions(spec).env?.ANTHROPIC_API_KEY).toBe(`fixture-${name}`);
      return scripted(spec);
    } });
    const result = await agent.run(input); expect(result.status).toBe('published');
    expect(metrics.length).toBeGreaterThan(0); expect(metrics.every(m => m.runId === `embedded-${name}`)).toBe(true);
    expect(readFileSync(join(result.engagementDir, 'assess-v2-checkpoint-input.json'), 'utf8')).not.toContain('fixture-');
    return result;
  }));
  expect(runs[0]!.engagementDir).not.toBe(runs[1]!.engagementDir);
  expect(process.env.ANTHROPIC_API_KEY).toBe(parentKey); expect(process.env.AUTH_MODE).toBe(parentMode); expect(process.cwd()).toBe(cwd);
}, 20000); // Two complete runs fsync sealed resources and archives under parallel CI load.
it('cancels the active session and refuses late successful publication', async () => {
  const input = fixture(), controller = new AbortController(); let calls = 0, observedAbort = false;
  const agent = createOffsecAgent({ sessionRunner: async spec => {
    calls++; spec.abortController!.signal.addEventListener('abort', () => { observedAbort = true; });
    controller.abort(new Error('application cancelled'));
    return scripted(spec);
  } });
  await expect(agent.run(input, { signal: controller.signal })).rejects.toThrow('application cancelled');
  expect(observedAbort).toBe(true); expect(calls).toBe(1);
  expect(existsSync(join(input.engagementDir, '07_security_report.md'))).toBe(false);
  expect(existsSync(join(input.engagementDir, '../.run.agent.lock'))).toBe(false);
});
it('requires explicit paths and rejects pre-cancelled work before filesystem changes', async () => {
  const input = fixture(), agent = createOffsecAgent({ sessionRunner: scripted });
  await expect(agent.run({ ...input, target: '.' })).rejects.toThrow('absolute');
  await expect(agent.run(input, { signal: AbortSignal.abort(new Error('cancelled before start')) })).rejects.toThrow('cancelled before start');
  expect(existsSync(input.engagementDir)).toBe(false);
  expect(() => createOffsecAgent({})).toThrow('apiKey or sessionRunner');
});

it.each([
  { semgrepMode: 'requird' }, { maxTurns: 0 }, { maxTurns: 1.5 }, { maxTurns: Number.NaN }, { effort: 'extreme' },
])('rejects invalid execution settings before scanning or creating output: %j', async invalid => {
  const input = fixture(), astBuilder = vi.fn(), runner = vi.fn(scripted);
  const agent = createOffsecAgent({ astBuilder, sessionRunner: runner });
  await expect(agent.run({ ...input, ...invalid } as never)).rejects.toThrow(/semgrepMode|maxTurns|effort/);
  expect(astBuilder).not.toHaveBeenCalled(); expect(runner).not.toHaveBeenCalled();
  expect(existsSync(input.engagementDir)).toBe(false);
});

it('accepts the installed SDK xhigh effort level', async () => {
  const runner = vi.fn(scripted);
  const result = await createOffsecAgent({ sessionRunner: runner }).run({ ...fixture(), effort: 'xhigh' });
  expect(result.status).toBe('published');
  expect(runner.mock.calls.every(([spec]) => spec.effort === 'xhigh')).toBe(true);
});
