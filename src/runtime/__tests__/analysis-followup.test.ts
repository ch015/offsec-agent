import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { selectAnalysisFollowups } from '../workflow/analysis-followup.js';
const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
function fixture() {
  const target = mkdtempSync(join(tmpdir(), 'offsec-followup-')); dirs.push(target);
  writeFileSync(join(target, 'a.ts'), 'export const request = input;\n');
  writeFileSync(join(target, 'b.ts'), 'check(request);\n');
  const hypothesis = { question: 'Does the request retain its authorization boundary?', impact: 'high', files: ['a.ts', 'b.ts'], observations: [{ path: 'a.ts', lineStart: 1, lineEnd: 1, quote: 'export const request = input;' }] };
  return { target, hypothesis, units: [{ unitKey: 'a', ownedFiles: [{ path: 'a.ts' }] }, { unitKey: 'b', ownedFiles: [{ path: 'b.ts' }] }] };
}
describe('evidence-backed follow-up selection', () => {
  it('deduplicates and bounds real questions and preserves the deferred count', () => {
    const f = fixture(), path = join(f.target, 'handoff.yaml');
    writeFileSync(path, JSON.stringify({ hypotheses: [f.hypothesis, f.hypothesis, { ...f.hypothesis, question: 'Can the second boundary lose the tenant identifier?', impact: 'critical' }] }));
    const result = selectAnalysisFollowups({ ...f, handoffs: [{ unitKey: 'a', path }], maximum: 1 });
    expect(result.selected).toHaveLength(1);
    expect(result.selected[0].impact).toBe('critical');
    expect(result.omitted).toBe(1);
    expect(result.invalid).toBe(0);
  });
  it('does not spend a session on invented quotes, escaping paths or same-unit questions', () => {
    const f = fixture(), path = join(f.target, 'handoff.yaml');
    writeFileSync(path, JSON.stringify({ hypotheses: [
      { ...f.hypothesis, observations: [{ ...f.hypothesis.observations[0], quote: 'invented observation' }] },
      { ...f.hypothesis, files: ['a.ts', '../b.ts'] },
      { ...f.hypothesis, files: ['a.ts', 'a.ts'] },
    ] }));
    const result = selectAnalysisFollowups({ ...f, handoffs: [{ unitKey: 'a', path }], maximum: 3 });
    expect(result.selected).toEqual([]);
    expect(result.invalid).toBe(3);
  });
});
