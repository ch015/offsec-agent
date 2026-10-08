import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createOffsecAgent } from '../../index.js';
import { syntheticOutcome } from './resumption-fixture.js';
import { validateScannerPlan } from '../planning/scanner-contract.js';
import { partitionSource } from '../planning/task-planner.js';
import { readSourceChunk } from '../source-reader.js';
import { observeSourceDelivery, sourceRangeDelivered } from '../source-delivery.js';
import { FileRunStateStore } from '../workflow/state-store.js';
import { assertRunInputsIntact, assertHostResourceReceipts, loadHostResources, receiptsOnly } from '../workflow/host-integrity.js';
import { submitStandardFinding, readStandardFindings } from '../finding-contract.js';
import { SessionExecutionError } from '../session-types.js';
import { deliveryFixture } from './assessment-protocol-fixture.js';
import * as reviewValidation from '../v2-evaluation.js';
// These integration cases create, fsync, archive and reopen multiple full runs.
vi.setConfig({ testTimeout: 20000 });
const roots: string[] = [];
afterEach(() => { for (const path of roots.splice(0)) rmSync(path, { recursive: true, force: true }); });
function fixture() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'redesign-acceptance-'))); roots.push(root);
  const target = join(root, 'source'); mkdirSync(target);
  writeFileSync(join(target, 'app.ts'), 'export const app = 1;\nexport const b = 2;\n');
  return { root, target, engagementDir: join(root, 'run'), mode: 'ast' as const, tools: [] as [] };
}
const scheduler = { retryBaseMs: 1, controlIntervalMs: 1, resourceCapacity: () => 100 };
const astBuilder = async () => ({ ok: false });

describe('redesign acceptance', () => {
  it('reopens an old unread inconclusive review without rerunning completed analysis', async () => {
    const f = fixture(); let findingId = '', repaired = false; const calls: string[] = [];
    const oldValidation = vi.spyOn(reviewValidation, 'validateV2ReviewSourceReads').mockImplementationOnce(() => {});
    const agent = createOffsecAgent({ astBuilder, scheduler, sessionRunner: async spec => {
      calls.push(spec.phase!);
      const outcome = syntheticOutcome(spec);
      if (spec.workUnit) findingId = submitStandardFinding({ target: spec.target, engagementDir: spec.engagementDir, phase: 'analyze', role: 'analyzer',
        finding: { title: 'Configuration concern requiring independent examination', verdict: 'supported', severity: 'LOW', evidenceClass: 'configuration', reachability: 'plausible',
          preconditions: ['Sensitive downstream consumer'], severityRationale: 'The impact depends on a consuming component', confidence: 0.5,
          impact: 'Unverified downstream use', remediation: 'Examine the consuming component', standards: [], unresolved: [],
          evidence: [{ path: 'app.ts', lineStart: 1, lineEnd: 1, quote: 'export const app = 1;' }] } }).id;
      if (spec.phase === 'review') {
        writeFileSync(join(spec.engagementDir, '03_review_result.json'), JSON.stringify({ countingSchemaVersion: 1, reviewedFindings: [{ originalFindingId: findingId, action: 'inconclusive',
          reason: repaired ? 'Source examined; downstream impact remains uncertain.' : 'Legacy context warning stopped examination.' }], newFindings: [] }));
        if (repaired) outcome.ledger.push(...deliveryFixture(spec, join(spec.target, 'app.ts')));
      }
      if (spec.phase === 'evaluate') throw new SessionExecutionError(outcome, new Error('403 fixture stops after review'));
      return outcome;
    } });
    try {
      expect((await agent.run(f)).status).toBe('incomplete');
      expect(Object.values(FileRunStateStore.open(f.engagementDir).read().attempts).some(attempt => attempt.phase === 'review' && attempt.status === 'completed')).toBe(true);
      oldValidation.mockRestore(); repaired = true; calls.length = 0;
      expect((await agent.resume(f.engagementDir)).status).toBe('incomplete');
      expect(calls).toEqual(['review', 'evaluate']);
      const snapshot = FileRunStateStore.open(f.engagementDir).read();
      expect(snapshot.analysisRevision).toBe(1);
      expect(snapshot.analysisCheckpoint?.stage).toBe('review');
      expect(Object.values(snapshot.attempts).filter(attempt => attempt.phase === 'review' && attempt.status === 'completed' && !attempt.superseded)).toHaveLength(1);
      expect(existsSync(join(f.engagementDir, 'revisions/0/03_review_result.json'))).toBe(true);
      expect(() => assertRunInputsIntact(snapshot, f.engagementDir)).not.toThrow();
    } finally { oldValidation.mockRestore(); }
  });

  it('T05/T19 resumes only the missing large-file range, then executes its bridge', async () => {
    const f = fixture(); writeFileSync(join(f.target, 'other.ts'), 'export const other = 1;\n');
    writeFileSync(join(f.target, 'app.ts'), Array.from({ length: 160 }, (_, i) => `export const variable${i} = ${i};`).join('\n') + '\n');
    let fail = true, failedKey = ''; const finished = new Set<string>(), calls: string[] = [];
    const agent = createOffsecAgent({ astBuilder, scheduler, sessionRunner: async spec => {
      const request = JSON.parse(/^inputs: (.+)$/m.exec(spec.prompt)?.[1] ?? '{}').taskRequest;
      if (request) {
        calls.push(request.taskId);
        if (request.kind === 'source' && request.ownedSources[0]?.path === 'app.ts' && request.ownedSources[0]?.byteStart > 0 && !failedKey) failedKey = request.taskId;
        if (fail && request.taskId === failedKey) throw new Error('403 fixture failure');
        if (request.kind === 'range-bridge') {
          expect(request.prerequisites.slice(1).every((id: string) => finished.has(id))).toBe(true);
          expect(spec.prompt).toContain('prerequisiteResults');
        }
      }
      const outcome = syntheticOutcome(spec); if (request) finished.add(request.taskId); return outcome;
    } });
    const first = await agent.run({ ...f, maxSourceTokensPerAgent: 256, maxFilesPerAgent: 1 });
    expect(first.status).toBe('incomplete'); expect(failedKey).not.toBe(''); calls.length = 0; fail = false;
    const resumed = await agent.resume(f.engagementDir);
    expect(resumed.status, JSON.stringify(resumed.storage)).toBe('published');
    expect(calls).toHaveLength(2); expect(calls[0]).toBe(failedKey); expect(calls[1]).not.toBe(failedKey);
  });
  it('T18 preserves source-grounded claims from a failed task as review-pending', async () => {
    const f = fixture(); let id = '';
    const agent = createOffsecAgent({ astBuilder, scheduler, sessionRunner: async spec => {
      if (spec.workUnit) {
        id = submitStandardFinding({ target: spec.target, engagementDir: spec.engagementDir, role: 'analyzer', phase: 'analyze',
          finding: { title: 'Unresolved exported configuration concern', verdict: 'abstain', severity: 'INFO', evidenceClass: 'configuration', reachability: 'unconfirmed',
            preconditions: ['Requires a sensitive consumer'], severityRationale: 'Fixture claim has no confirmed impact', confidence: 0.2, impact: 'Unconfirmed use of an exported constant',
            remediation: 'Review the consuming operation', standards: [], unresolved: ['No sensitive consumer was demonstrated'],
            evidence: [{ path: 'app.ts', lineStart: 1, lineEnd: 1, quote: 'export const app = 1;' }] } }).id;
        throw new SessionExecutionError(syntheticOutcome(spec, { cost: 0.25 }), new Error('403 permission denied after recording the claim'));
      }
      return syntheticOutcome(spec);
    } });
    const result = await agent.run(f);
    expect(result.status).toBe('incomplete'); expect(readStandardFindings(f.engagementDir).map(record => record.id)).toContain(id);
    expect(result.outcome.totalCostUsd).toBeCloseTo(0.26);
    expect(result.outcome.costAccountingComplete).toBe(true);
    const retained = JSON.parse(readFileSync(join(f.engagementDir, '00_retained_claims.json'), 'utf8'));
    expect(retained.claims).toEqual([expect.objectContaining({ findingId: id, status: 'review-pending' })]);
  });
  it('T02/T03 lists all 21 missing Scanner owners, rejects duplicate and outside ownership', () => {
    const files = Array.from({ length: 278 }, (_, i) => `src/${i}.ts`);
    const plan = { schemaVersion: '1', units: [{ id: 'module', files: files.slice(0, 257), responsibility: 'Request processing responsibility', rationale: 'Single request and trust boundary', boundaryEvidence: [files[0]], assumptions: [] }], interfaces: [], prioritySurfaces: [], crossUnitFlows: [], unresolved: [] };
    let error = ''; try { validateScannerPlan(plan, files); } catch (value) { error = String(value); }
    expect(error).toContain('(21)'); for (const file of files.slice(257)) expect(error).toContain(file);
    plan.units[0]!.files = [...files, files[0]!]; expect(() => validateScannerPlan(plan, files)).toThrow('Duplicate');
    plan.units[0]!.files = [...files, '../outside.ts']; expect(() => validateScannerPlan(plan, files)).toThrow('outside');
  });

  it('T05 splits UTF-8 and long single lines without a byte gap or lost ending', () => {
    const raw = Buffer.from('가'.repeat(4000) + '\r\nconst x = 2;\n');
    const ranges = partitionSource('a.ts', 'a'.repeat(64), raw, 997);
    expect(ranges.length).toBeGreaterThan(10); expect(ranges[0]!.byteStart).toBe(0);
    expect(ranges.at(-1)!.byteEnd).toBe(raw.length);
    ranges.forEach((range, i) => {
      if (i) expect(range.byteStart).toBe(ranges[i - 1]!.byteEnd);
      expect(range.byteEnd - range.byteStart).toBeLessThanOrEqual(1000);
      expect(() => new TextDecoder('utf-8', { fatal: true }).decode(raw.subarray(range.byteStart, range.byteEnd))).not.toThrow();
    });
  });

  it('T03 rejects an unrelated flow owner, missing endpoint, and omitted graph boundary', () => {
    const files = ['a.ts', 'b.ts', 'c.ts'];
    const plan = { schemaVersion: '1', units: files.map((file, i) => ({ id: `U${i}`, files: [file], responsibility: 'A separate execution responsibility', rationale: 'A separate trust and state boundary', boundaryEvidence: [file], assumptions: [] })), interfaces: [], prioritySurfaces: [], unresolved: [],
      crossUnitFlows: [{ id: 'F1', fromUnit: 'U0', toUnit: 'U1', ownerUnit: 'U2', files: ['a.ts', 'b.ts'], question: 'Verify the imported value across this module boundary' }] };
    expect(() => validateScannerPlan(plan, files)).toThrow('Invalid Scanner flow owner');
    plan.crossUnitFlows[0]!.ownerUnit = 'U0'; plan.crossUnitFlows[0]!.files = ['a.ts', 'c.ts'];
    expect(() => validateScannerPlan(plan, files)).toThrow('Invalid Scanner flow evidence');
    plan.crossUnitFlows = [];
    expect(() => validateScannerPlan(plan, files, { edges: [{ from: 'a.ts', resolvedTargets: ['b.ts'] }] } as Parameters<typeof validateScannerPlan>[2])).toThrow('missing cross-unit responsibility');
  });

  it('T13 verifies dedicated reader output while rejecting missing bytes and wrong snapshots', () => {
    const f = fixture(), file = join(f.target, 'app.ts'); writeFileSync(file, '가나다'.repeat(100));
    const receipts = []; let offset = 0;
    while (true) {
      const chunk = readSourceChunk({ target: f.target, allowedFiles: [file], filePath: file, offset, limit: 100 });
      const observed = observeSourceDelivery({ target: f.target, allowedFiles: [file], file, toolCallId: String(offset), content: JSON.stringify(chunk) })!;
      receipts.push(observed.delivery); if (chunk.nextOffset === null) break; offset = chunk.nextOffset;
    }
    expect(sourceRangeDelivered(file, receipts)).toBe(true);
    expect(sourceRangeDelivered(file, receipts.filter((_, i) => i !== 1))).toBe(false);
    expect(sourceRangeDelivered(file, receipts.map(receipt => ({ ...receipt, sourceHash: '0'.repeat(64) })))).toBe(false);
    expect(() => readSourceChunk({ target: f.target, allowedFiles: [], filePath: file, offset: 0, limit: 100 })).toThrow('exact read scope');
  });

  it('T13/T14 does not complete a task with no source delivery or no file analysis evidence', async () => {
    for (const defect of ['delivery', 'analysis']) {
      const f = fixture();
      const agent = createOffsecAgent({ scheduler, astBuilder, sessionRunner: async spec => {
        const outcome = syntheticOutcome(spec);
        if (spec.workUnit) {
          if (defect === 'delivery') outcome.ledger = outcome.ledger.filter(row => row.event !== 'SourceDelivery');
          else writeFileSync(join(spec.engagementDir, '02_file_assessments.json'), '{"files":[],"flows":[]}');
        }
        return outcome;
      } });
      const result = await agent.run(f);
      expect(result.status).toBe('incomplete'); expect(result.coverage.complete).toBe(false);
      expect(Object.values(FileRunStateStore.open(result.engagementDir).read().attempts).filter(attempt => attempt.phase === 'analyze' && attempt.status === 'completed')).toHaveLength(0);
    }
  });

  it('T19/T22 resumes only failed tasks after a partial publication and preserves the old report', async () => {
    const f = fixture(); writeFileSync(join(f.target, 'b.ts'), 'export const value = 1;\n');
    let fail = true; const calls: string[] = [];
    const agent = createOffsecAgent({ astBuilder, scheduler, sessionRunner: async spec => {
      if (spec.workUnit) { calls.push(spec.workUnit.ownedSourceFiles[0]!); if (fail && spec.workUnit.ownedSourceFiles[0]!.endsWith('/b.ts')) throw new Error('403 permission denied'); }
      return syntheticOutcome(spec);
    } });
    const first = await agent.run({ ...f, maxFilesPerAgent: 1 });
    expect(first.status).toBe('incomplete');
    expect(FileRunStateStore.open(f.engagementDir).read().status).toBe('incomplete');
    const oldReport = readFileSync(first.finalReport, 'utf8'); calls.length = 0; fail = false;
    const resumed = await agent.resume(f.engagementDir);
    expect(resumed.status).toBe('published'); expect(calls).toHaveLength(1); expect(calls[0]).toContain('/b.ts');
    expect(readFileSync(join(f.engagementDir, 'revisions/0/07_security_report.md'), 'utf8')).toBe(oldReport);
    expect(() => assertRunInputsIntact(FileRunStateStore.open(f.engagementDir).read(), f.engagementDir)).not.toThrow();
  });

  it('T25/T27 reuses validated EOL changes without Scanner or Analyzer calls and distinguishes reuse coverage', async () => {
    const f = fixture(); const calls: string[] = [];
    const agent = createOffsecAgent({ astBuilder, scheduler, sessionRunner: async spec => { calls.push(spec.phase!); return syntheticOutcome(spec); } });
    await agent.run(f); calls.length = 0;
    writeFileSync(join(f.target, 'app.ts'), 'export const app = 1;\r\nexport const b = 2;');
    const result = await agent.run({ ...f, engagementDir: join(f.root, 'revision'), reuseFrom: f.engagementDir });
    expect(result.status, JSON.stringify(result.storage)).toBe('published'); expect(calls).toEqual(['review', 'evaluate', 'report']);
    expect(result.coverage.sourceReadCoverage?.filesDelivered).toEqual([]);
    expect(result.coverage.sourceReadCoverage?.filesValidatedReuse).toEqual(['app.ts']);
    expect(result.outcome.totalCostUsd).toBeCloseTo(0.03);
    expect(readFileSync(result.finalReport, 'utf8')).toContain('검증된 기존 분석 재사용: 1개');
  });

  it('T28 allows JSON serialization changes while rejecting execution-policy changes', () => {
    const f = fixture(), path = join(f.root, 'contract.json'); writeFileSync(path, '{"tools":["Read"],"version":1}');
    const receipts = receiptsOnly(loadHostResources([path]));
    writeFileSync(path, '{\n "version":1, "tools": ["Read"]\n}\n'); expect(() => assertHostResourceReceipts(receipts)).not.toThrow();
    writeFileSync(path, '{"tools":["Bash"],"version":1}'); expect(() => assertHostResourceReceipts(receipts)).toThrow('hash');
    expect(receipts[0]!.sha256).not.toBe(createHash('sha256').update(readFileSync(path)).digest('hex'));
  });
});

it('T04/T26 reanalyzes a changed condition while reusing an unrelated completed task', async () => {
  const f = fixture(); writeFileSync(join(f.target, 'other.ts'), 'export const other = 1;\n');
  const calls: string[] = [];
  const agent = createOffsecAgent({ astBuilder, scheduler, sessionRunner: async spec => {
    if (spec.workUnit) calls.push(...spec.workUnit.ownedSourceFiles); return syntheticOutcome(spec);
  } });
  await agent.run({ ...f, maxFilesPerAgent: 1 }); calls.length = 0;
  writeFileSync(join(f.target, 'app.ts'), 'export const app = 2;\nexport const b = 2;\n');
  const result = await agent.run({ ...f, engagementDir: join(f.root, 'revision'), reuseFrom: f.engagementDir, maxFilesPerAgent: 1 });
  expect(result.status, JSON.stringify(result.storage)).toBe('published');
  expect(calls).toHaveLength(1); expect(calls[0]).toContain('/app.ts');
  expect(result.coverage.sourceReadCoverage?.filesValidatedReuse).toEqual(['other.ts']);
});

it('T27 reanalyzes a byte-cited flow after EOL changes and retains unaffected work', async () => {
  const f = fixture(); rmSync(join(f.target, 'app.ts'));
  for (const name of ['a', 'b']) { mkdirSync(join(f.target, 'packages', name), { recursive: true }); writeFileSync(join(f.target, 'packages', name, 'package.json'), '{}'); }
  writeFileSync(join(f.target, 'packages/a/a.ts'), "import { b } from '../b/b';\nexport const a = b;\n");
  writeFileSync(join(f.target, 'packages/b/b.ts'), 'export const b = 1;\n');
  const analyzed: string[] = [];
  const agent = createOffsecAgent({ astBuilder, scheduler, sessionRunner: async spec => {
    const outcome = syntheticOutcome(spec);
    if (spec.workUnit) {
      analyzed.push(...spec.workUnit.ownedSourceFiles);
      const path = join(spec.engagementDir, '02_file_assessments.json'), value = JSON.parse(readFileSync(path, 'utf8'));
      for (const flow of value.flows) for (const evidence of flow.evidence) {
        evidence.byteStart = 0; evidence.byteEnd = Buffer.byteLength(evidence.quote);
      }
      writeFileSync(path, JSON.stringify(value));
    }
    return outcome;
  } });
  await agent.run(f); analyzed.length = 0;
  writeFileSync(join(f.target, 'packages/b/b.ts'), 'export const b = 1;\r\n');
  const result = await agent.run({ ...f, engagementDir: join(f.root, 'revision'), reuseFrom: f.engagementDir });
  expect(result.status, JSON.stringify(result.storage)).toBe('published');
  expect(analyzed.some(file => file.endsWith('/packages/a/a.ts'))).toBe(true);
  expect(analyzed.some(file => file.endsWith('/packages/b/b.ts'))).toBe(false);
  expect(result.coverage.sourceReadCoverage?.filesValidatedReuse).toContain('packages/b/b.ts');
});

it.each([false, true, 'interrupted'] as const)('T21 investigates only requested evidence and defers a repeated request (%s)', async repeated => {
  const f = fixture(); rmSync(join(f.target, 'app.ts'));
  for (const name of ['a', 'b']) { mkdirSync(join(f.target, 'packages', name), { recursive: true }); writeFileSync(join(f.target, 'packages', name, 'package.json'), '{}'); }
  writeFileSync(join(f.target, 'packages/a/a.ts'), "import { b } from '../b/b';\nexport const a = b;\n");
  writeFileSync(join(f.target, 'packages/b/b.ts'), 'export const b = 1;\n');
  let reviews = 0, requests = 0, interruptOnce = repeated === 'interrupted'; const units: string[] = [];
  const request = { id: 'R1', question: 'Does this cross-module export pass through an authorization guard?', files: ['packages/a/a.ts', 'packages/b/b.ts'], missingEvidence: 'Trace the exported value and confirm whether a guard exists on the boundary', findingIds: [], flowIds: ['FLOW-0'] };
  const agent = createOffsecAgent({ astBuilder, scheduler, sessionRunner: async spec => {
    const outcome = syntheticOutcome(spec);
    if (spec.workUnit) units.push(spec.workUnit.unitKey);
    if (spec.phase === 'review') {
      reviews++;
      writeFileSync(join(spec.engagementDir, '03_review_result.json'), JSON.stringify({ countingSchemaVersion: 1, reviewedFindings: [], newFindings: [], additionalEvidenceRequests: reviews === 1 || repeated === true ? [request] : [] }));
    }
    if (spec.phaseRound?.startsWith('review-request-')) {
      requests++;
      if (interruptOnce) { interruptOnce = false; throw new Error('403 interrupted follow-up fixture'); }
      writeFileSync(join(spec.engagementDir, '02_followup_answers.json'), JSON.stringify({ answers: [{ id: 'R1', status: 'resolved', reason: 'The observed import uses a constant export and has no protected operation', evidence: [{ path: 'packages/b/b.ts', lineStart: 1, lineEnd: 1, quote: 'export const b = 1;' }] }] }));
      (outcome.structuredOutput as { artifacts: string[] }).artifacts.push('02_followup_answers.json');
    }
    return outcome;
  } });
  let result = await agent.run(f);
  if (repeated === 'interrupted') { expect(result.status).toBe('incomplete'); result = await agent.resume(f.engagementDir); }
  expect(result.publicationStatus, JSON.stringify(result.storage)).toBe('published'); expect(result.coverage.complete).toBe(repeated !== true);
  expect(requests).toBe(repeated === 'interrupted' ? 2 : 1); expect(reviews).toBe(2); expect(new Set(units).size).toBe(units.length);
  expect(() => assertRunInputsIntact(FileRunStateStore.open(result.engagementDir).read(), result.engagementDir)).not.toThrow();
});
