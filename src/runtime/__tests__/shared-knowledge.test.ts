import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';
import { createOffsecAgent } from '../../api/agent.js';
import { FileRunStateStore } from '../workflow/state-store.js';
import { syntheticOutcome } from './resumption-fixture.js';
import { getSharedKnowledge, lookupSharedKnowledge, publishSharedObservation, readSharedKnowledge,
  snapshotSharedKnowledge, type SharedKnowledgeContext } from '../shared-knowledge.js';

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function fixture() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'shared-knowledge-'))); roots.push(root);
  const target = join(root, 'target'); mkdirSync(target);
  const source = join(target, 'app.ts'); writeFileSync(source, 'export const authenticated = true;\n');
  const context: SharedKnowledgeContext = { engagementDir: join(root, 'run'), namespace: 'a'.repeat(64), sourceFiles: [source] };
  const producer = { engagementDir: join(context.engagementDir, 'unit-a'), role: 'analyzer', phase: 'analyze', round: 'unit-a' };
  const observation = { summary: 'Authentication flag', tags: ['auth'], evidence: [{ path: 'app.ts', lineStart: 1, lineEnd: 1, quote: 'export const authenticated = true;' }] };
  return { root, target, source, context, producer, observation };
}

describe('shared analysis knowledge', () => {
  it('shares exact observations once across workers while preserving independent contributors', () => {
    const f = fixture();
    const first = publishSharedObservation(f.context, f.producer, f.target, f.observation);
    const second = publishSharedObservation(f.context, { ...f.producer, round: 'unit-b' }, f.target, f.observation);
    expect(first.id).toBe(second.id);
    expect(lookupSharedKnowledge(f.context, { paths: ['app.ts'], query: 'auth' }).total).toBe(1);
    expect(getSharedKnowledge(f.context, first.id).evidence[0]?.quote).toBe(f.observation.evidence[0]?.quote);
    expect(readdirSync(join(f.context.engagementDir, 'shared-knowledge', f.context.namespace, 'origins', first.id))).toHaveLength(2);
  });

  it('retains conflicting claims at the same source location for review', () => {
    const f = fixture();
    const a = publishSharedObservation(f.context, f.producer, f.target, f.observation);
    const b = publishSharedObservation(f.context, f.producer, f.target, { ...f.observation, summary: 'The flag alone does not prove request authentication' });
    expect(a.id).not.toBe(b.id); expect(a.evidenceKey).toBe(b.evidenceKey);
    expect(readSharedKnowledge(f.context)).toHaveLength(2);
  });

  it('pages a multi-megabyte frozen archive without omitting claims or returning all evidence', () => {
    const f = fixture();
    const quote = `export const value = '${'x'.repeat(16_000)}';`;
    writeFileSync(f.source, `${quote}\n`);
    const ids = new Set<string>();
    for (let i = 0; i < 123; i++) ids.add(publishSharedObservation(f.context, f.producer, f.target, {
      summary: `Claim ${i}`, tags: ['large-archive'], evidence: [{ path: 'app.ts', lineStart: 1, lineEnd: 1, quote }],
    }).id);
    const frozen = { ...f.context, snapshotPath: snapshotSharedKnowledge(f.context) };
    expect(readFileSync(frozen.snapshotPath).length).toBeGreaterThan(1_800_000);
    const seen = new Set<string>();
    let offset: number | null = 0;
    while (offset !== null) {
      const page = lookupSharedKnowledge(frozen, { paths: ['app.ts'], offset, limit: 20 });
      expect(page.total).toBe(123);
      expect(Buffer.byteLength(JSON.stringify(page))).toBeLessThan(24_000);
      for (const record of page.records) {
        expect(seen.has(record.id)).toBe(false);
        expect(record.evidence[0]).not.toHaveProperty('quote');
        seen.add(record.id);
      }
      offset = page.nextOffset;
    }
    expect(seen).toEqual(ids);
    expect(getSharedKnowledge(frozen, [...ids][0]!).evidence[0]?.quote).toBe(quote);
  });

  it('rejects fabricated quotes and sources outside the sealed inventory', () => {
    const f = fixture(); const evidence = f.observation.evidence[0]!;
    expect(() => publishSharedObservation(f.context, f.producer, f.target, { ...f.observation, evidence: [{ ...evidence, quote: 'fabricated' }] })).toThrow(/quote/);
    writeFileSync(join(f.target, 'unsealed.ts'), evidence.quote);
    expect(() => publishSharedObservation(f.context, f.producer, f.target, { ...f.observation, evidence: [{ ...evidence, path: 'unsealed.ts' }] })).toThrow(/owned source/);
    expect(readSharedKnowledge(f.context)).toHaveLength(0);
  });

  it('isolates runs and source revisions and freezes review against late workers', () => {
    const f = fixture(); const first = publishSharedObservation(f.context, f.producer, f.target, f.observation);
    const frozen = { ...f.context, snapshotPath: snapshotSharedKnowledge(f.context) };
    publishSharedObservation(f.context, f.producer, f.target, { ...f.observation, summary: 'Late observation' });
    expect(readSharedKnowledge(f.context)).toHaveLength(2); expect(readSharedKnowledge(frozen)).toHaveLength(1);
    expect(() => publishSharedObservation(frozen, f.producer, f.target, f.observation)).toThrow(/read-only/);
    expect(readSharedKnowledge({ ...f.context, namespace: 'b'.repeat(64) })).toEqual([]);
    expect(readSharedKnowledge({ ...f.context, engagementDir: join(f.root, 'other-run') })).toEqual([]);
    expect(() => getSharedKnowledge(frozen, '../escape')).toThrow(/invalid/);
    expect(getSharedKnowledge(frozen, first.id).summary).toBe(f.observation.summary);
  });

  it('does not lose shared records or provenance during cross-process publication', async () => {
    const f = fixture();
    const script = join(f.root, 'publisher.mts');
    const moduleUrl = pathToFileURL(resolve(import.meta.dirname, '../shared-knowledge.ts')).href;
    writeFileSync(script, `import {publishSharedObservation} from ${JSON.stringify(moduleUrl)};\nconst f = ${JSON.stringify(f)};\nfor(let i=0;i<20;i++) publishSharedObservation(f.context,{...f.producer,round:process.argv[2]},f.target,f.observation);\n`);
    const require = createRequire(import.meta.url);
    await Promise.all(Array.from({ length: 4 }, (_, i) => new Promise<void>((resolve, reject) => {
      const child = spawn(process.execPath, ['--import', require.resolve('tsx'), script, `unit-${i}`], { stdio: ['ignore', 'ignore', 'pipe'] });
      let errors = ''; child.stderr.on('data', chunk => { errors += chunk; });
      child.on('error', reject); child.on('close', code => code === 0 ? resolve() : reject(new Error(errors)));
    })));
    const records = readSharedKnowledge(f.context); expect(records).toHaveLength(1);
    expect(readdirSync(join(f.context.engagementDir, 'shared-knowledge', f.context.namespace, 'origins', records[0]!.id))).toHaveLength(4);
  }, 30_000);

  it('wires one shared store into parallel units, seals it for review, and records cost without a cap', async () => {
    const f = fixture(); let calls = 0; let commonId: string | undefined;
    const contexts: SharedKnowledgeContext[] = [];
    for (let i = 0; i < 15; i++) writeFileSync(join(f.target, `extra-${i}.ts`), `export const value${i} = ${i};\n`);
    const result = await createOffsecAgent({ sessionRunner: async spec => {
      calls++; expect(spec.maxBudgetUsd).toBeUndefined();
      if (spec.phase === 'recon') return syntheticOutcome(spec, { cost: 100 });
      expect(spec.sharedKnowledge).toBeDefined();
      contexts.push(spec.sharedKnowledge!);
      if (spec.workUnit) {
        const value = publishSharedObservation(spec.sharedKnowledge!, { engagementDir: spec.engagementDir, role: 'analyzer', phase: 'analyze', round: spec.phaseRound }, spec.target, f.observation);
        if (commonId) expect(value.id).toBe(commonId); commonId = value.id;
      } else {
        expect(spec.sharedKnowledge!.snapshotPath).toBeDefined();
        expect(lookupSharedKnowledge(spec.sharedKnowledge!).total).toBe(1);
      }
      return syntheticOutcome(spec, { cost: 100 });
    } }).run({ target: f.target, engagementDir: f.context.engagementDir, semgrepMode: 'off', maxBudgetUsd: 1,
      maxFilesPerAgent: 1, maxConcurrency: 16 });
    expect(result.status).toBe('published'); expect(calls).toBe(20);
    expect(new Set(contexts.map(c => c.namespace)).size).toBe(1);
    const state = FileRunStateStore.open(result.engagementDir).read();
    expect(state.maxBudgetUsd).toBeUndefined(); expect(state.totalCostUsd).toBe(calls * 100);
    expect(result.outcome.totalCostUsd).toBe(calls * 100);
    expect(state.budgetReservations ?? {}).toEqual({});
    expect(state.analysisCheckpoint?.artifacts.some(a => a.name === '00_shared_knowledge.json')).toBe(true);
    const snapshot = readFileSync(join(result.engagementDir, '00_shared_knowledge.json'), 'utf8');
    expect(JSON.parse(snapshot).records).toHaveLength(1);
  }, 30_000);
});
