import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { regressionFiles, validateImplementationMap } from '../../../scripts/lib/implementation-map.js';

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'implementation-map-')); roots.push(root);
  mkdirSync(join(root, 'src'));
  writeFileSync(join(root, 'src/feature.ts'), 'export function existing() {}\n// function missing() {}');
  writeFileSync(join(root, 'src/feature.test.ts'), "it('existing behavior', () => {});\nit.each([1,2])('parameter %s', () => {});");
  const map = { schemaVersion: 1, reviewedAt: '2026-10-13', scope: 'Synthetic map', features: [{
    id: 'fixture', name: 'Fixture', status: 'implemented', behavior: 'Synthetic behavior',
    entrypoints: [{ path: 'src/feature.ts', symbol: 'existing' }], callers: [{ path: 'src/feature.ts', symbol: 'existing' }],
    contracts: ['src/feature.ts'], tests: [{ path: 'src/feature.test.ts', title: 'existing behavior' }],
    invariants: ['Preserve behavior'], limitations: ['Synthetic only'],
  }], plannedCapabilities: [] as Array<{ id: string; name: string; relatedFeatureIds: string[]; acceptanceCriteria: string[] }> };
  return { root, map };
}

describe('implementation map guard', () => {
  it('validates the repository map and derives a deduplicated regression suite', () => {
    const root = resolve(import.meta.dirname, '../../..');
    const { map, errors } = validateImplementationMap(root, JSON.parse(readFileSync(join(root, 'docs/implementation-map.json'), 'utf8')));
    expect(errors).toEqual([]);
    const files = regressionFiles(map!);
    expect(files.length).toBeGreaterThan(10);
    expect(new Set(files).size).toBe(files.length);
    expect(files).toContain('src/runtime/__tests__/implementation-map.test.ts');
    expect(files).toContain('src/runtime/__tests__/review-feedback-preservation.test.ts');
  });
  it('accepts declarations and actual parameterized tests', () => {
    const { root, map } = fixture(); map.features[0]!.tests[0]!.title = 'parameter %s';
    expect(validateImplementationMap(root, map).errors).toEqual([]);
  });
  it('reports removed files and declarations even when a comment retains the old name', () => {
    const { root, map } = fixture();
    map.features[0]!.entrypoints[0]!.symbol = 'missing';
    map.features[0]!.contracts.push('gone.json');
    expect(validateImplementationMap(root, map).errors).toEqual(expect.arrayContaining([
      expect.stringContaining('missing declaration missing'), expect.stringContaining('missing/unreadable file: gone.json'),
    ]));
  });
  it.each([
    "// it('existing behavior', () => {});",
    "it.skip('existing behavior', () => {});",
    "it['skip']('existing behavior', () => {});",
    "it.todo('existing behavior');",
    "it.only('existing behavior', () => {});",
    "describe.skip('suite', () => { it('existing behavior', () => {}); });",
    "describe['skip']('suite', () => { it('existing behavior', () => {}); });",
    "describe.runIf(false)('suite', () => { it('existing behavior', () => {}); });",
    "it('renamed behavior', () => {});",
  ])('rejects non-active or renamed test references: %s', code => {
    const { root, map } = fixture(); writeFileSync(join(root, 'src/feature.test.ts'), code);
    expect(validateImplementationMap(root, map).errors).toEqual([expect.stringContaining('missing active test')]);
  });
  it.each(['../outside.ts', '/tmp/outside.ts', 'src/../feature.ts', 'src\\feature.ts'])('rejects an escaping or non-normalized path: %s', path => {
    const { root, map } = fixture(); map.features[0]!.contracts = [path];
    expect(validateImplementationMap(root, map).errors).toEqual([expect.stringContaining('repository-relative path')]);
  });
  it('rejects a symlink escaping the repository', () => {
    const { root, map } = fixture(), other = fixture();
    symlinkSync(join(other.root, 'src/feature.ts'), join(root, 'escape.ts'));
    map.features[0]!.contracts = ['escape.ts'];
    expect(validateImplementationMap(root, map).errors).toEqual([expect.stringContaining('inside the repository')]);
  });
  it('rejects duplicate IDs and disconnected proposals', () => {
    const { root, map } = fixture(); map.features.push(structuredClone(map.features[0]!));
    map.plannedCapabilities.push({ id: 'proposal', name: 'Proposal', relatedFeatureIds: ['absent'], acceptanceCriteria: ['Test before implementation'] });
    expect(validateImplementationMap(root, map).errors).toEqual(expect.arrayContaining([
      'Duplicate feature ID: fixture', 'proposal: unknown related feature: absent',
    ]));
  });
  it('rejects unknown statuses and silent schema typos', () => {
    const { root, map } = fixture(); map.features[0]!.status = 'planned';
    expect(validateImplementationMap(root, map).errors.length).toBeGreaterThan(0);
    map.features[0]!.status = 'implemented';
    expect(validateImplementationMap(root, { ...map, feature: [] }).errors.length).toBeGreaterThan(0);
  });
});
