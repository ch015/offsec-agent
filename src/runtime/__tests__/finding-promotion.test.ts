import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createOffsecAgent } from '../../index.js';
import { promoteStandardFindingRecords, readStandardFindingRecordReceipts, readStandardFindings, submitStandardFinding } from '../finding-contract.js';
import { beginAnalysisRevision } from '../missions/analysis-revision.js';
import { promoteCompletedTaskFindings } from '../missions/finding-promotion.js';
import { retainFailedTaskClaims } from '../missions/retained-claims.js';
import { createArtifactRef } from '../contracts/result-contract.js';
import { openMissionRuntime } from '../workflow/mission-runtime.js';
import { FileRunStateStore, type RunSnapshot } from '../workflow/state-store.js';
import { syntheticOutcome } from './resumption-fixture.js';
import { deliveryFixture } from './assessment-protocol-fixture.js';
import { SessionExecutionError } from '../session-types.js';

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function fixture() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'finding-promotion-'))); roots.push(root);
  const target = join(root, 'source'); mkdirSync(target);
  writeFileSync(join(target, 'app.ts'), 'export const app = 1;\n');
  return { root, target, engagementDir: join(root, 'run') };
}
function submit(target: string, engagementDir: string, round: string, impact: string, title = 'Configuration observation') {
  return submitStandardFinding({ target, engagementDir, phase: 'analyze', role: 'analyzer', round,
    finding: { title, verdict: 'supported', severity: 'LOW', evidenceClass: 'configuration',
      reachability: 'plausible', preconditions: ['A consuming application'], severityRationale: 'Impact depends on the consuming application',
      confidence: 0.5, impact, remediation: 'Review the consumer', standards: [], unresolved: [],
      evidence: [{ path: 'app.ts', lineStart: 1, lineEnd: 1, quote: 'export const app = 1;' }] } });
}

function failedAttempts(taskId: string, attempts: number[]): RunSnapshot {
  return { runId: 'fixture', contractId: 'fixture', contractVersion: '1', domain: 'offsec', mission: 'assessment',
    status: 'running', totalCostUsd: 0, lastSeq: 0, completedPhases: [], attempts: Object.fromEntries(attempts.map(attempt =>
      [`attempt-${attempt}`, { phase: 'analyze', round: taskId, attempt, status: 'failed' as const }])) };
}

describe('finding promotion across analysis revisions', () => {
  it('retains the latest failed version in numeric attempt order and never rolls it back on resume', () => {
    const f = fixture(), taskId = 'unit-test', attempts = [1, 2, 10];
    for (const attempt of attempts) submit(f.target, join(f.engagementDir, 'work-units', taskId, `attempt-${attempt}`), taskId, `Attempt ${attempt}`);
    const snapshot = failedAttempts(taskId, attempts);
    const first = retainFailedTaskClaims(f.engagementDir, [taskId], snapshot);
    expect(first.claims).toHaveLength(3);
    expect(readStandardFindings(f.engagementDir).map(finding => finding.impact)).toEqual(['Attempt 10']);
    expect(retainFailedTaskClaims(f.engagementDir, [taskId], snapshot).claims).toEqual(first.claims);
    expect(readStandardFindings(f.engagementDir).map(finding => finding.impact)).toEqual(['Attempt 10']);
    submit(f.target, join(f.engagementDir, 'work-units', taskId, 'attempt-11'), taskId, 'Attempt 11');
    retainFailedTaskClaims(f.engagementDir, [taskId], failedAttempts(taskId, [...attempts, 11]));
    expect(readStandardFindings(f.engagementDir).map(finding => finding.impact)).toEqual(['Attempt 11']);
  });

  it('only retains host-tracked terminal attempts', () => {
    const f = fixture(), taskId = 'unit-test';
    for (const attempt of [1, 2, 3]) submit(f.target, join(f.engagementDir, 'work-units', taskId, `attempt-${attempt}`), taskId, `Attempt ${attempt}`);
    const snapshot = failedAttempts(taskId, [1, 2]);
    snapshot.attempts['attempt-2']!.status = 'started';
    expect(retainFailedTaskClaims(f.engagementDir, [taskId], snapshot).claims).toHaveLength(1);
    expect(readStandardFindings(f.engagementDir).map(finding => finding.impact)).toEqual(['Attempt 1']);
  });

  it('keeps claims only present in an older failed attempt while selecting newer overlapping claims', () => {
    const f = fixture(), taskId = 'unit-test';
    const oldDir = join(f.engagementDir, 'work-units', taskId, 'attempt-1');
    submit(f.target, oldDir, taskId, 'Older overlapping assessment');
    submit(f.target, oldDir, taskId, 'Independent earlier observation', 'Separate configuration observation');
    submit(f.target, join(f.engagementDir, 'work-units', taskId, 'attempt-2'), taskId, 'Latest overlapping assessment');
    retainFailedTaskClaims(f.engagementDir, [taskId], failedAttempts(taskId, [1, 2]));
    expect(readStandardFindings(f.engagementDir).map(finding => finding.impact).sort())
      .toEqual(['Independent earlier observation', 'Latest overlapping assessment']);
  });

  it('promotes a completed retry over a retained failed attempt and archives its previous bytes', () => {
    const f = fixture(), taskId = 'unit-test';
    const oldDir = join(f.engagementDir, 'work-units', taskId, 'attempt-1');
    const unitDir = join(f.engagementDir, 'work-units', taskId, 'attempt-2');
    submit(f.target, oldDir, taskId, 'Incomplete assessment');
    const snapshot = failedAttempts(taskId, [1]);
    retainFailedTaskClaims(f.engagementDir, [taskId], snapshot);
    const old = readStandardFindingRecordReceipts(f.engagementDir)[0]!;
    submit(f.target, unitDir, taskId, 'Completed assessment');
    writeFileSync(join(unitDir, '02_analysis_result.md'), 'Completed fixture analysis');
    const artifact = createArtifactRef({ engagementDir: unitDir, name: '02_analysis_result.md', phase: 'analyze', role: 'analyzer', attempt: '2' });
    snapshot.attempts.current = { phase: 'analyze', round: taskId, attempt: 2, status: 'completed', artifacts: [artifact] };
    const input = { root: f.engagementDir, taskId, unitDir, expected: readStandardFindingRecordReceipts(unitDir), snapshot };
    promoteCompletedTaskFindings(input);
    expect(readStandardFindings(f.engagementDir).map(finding => finding.impact)).toEqual(['Completed assessment']);
    expect(existsSync(join(f.engagementDir, '.recovery/finding-history', old.recordName, `${old.sha256}.json`))).toBe(true);
    expect(() => promoteCompletedTaskFindings(input)).not.toThrow();
  });

  it('archives exact superseded bytes before replacing a record, and is idempotent', () => {
    const f = fixture(), oldDir = join(f.root, 'old'), newDir = join(f.root, 'new');
    submit(f.target, oldDir, 'task', 'Previous assessment');
    const oldReceipts = readStandardFindingRecordReceipts(oldDir), old = oldReceipts[0]!;
    promoteStandardFindingRecords({ fromEngagementDir: oldDir, toEngagementDir: f.engagementDir, expected: oldReceipts });
    const latest = submit(f.target, newDir, 'task', 'Revised assessment');
    const input = { fromEngagementDir: newDir, toEngagementDir: f.engagementDir,
      expected: readStandardFindingRecordReceipts(newDir), superseded: oldReceipts };
    promoteStandardFindingRecords(input);
    expect(readStandardFindings(f.engagementDir)).toEqual([latest]);
    expect(readFileSync(join(f.engagementDir, '.recovery/finding-history', old.recordName, `${old.sha256}.json`)))
      .toEqual(readFileSync(join(oldDir, 'standard-findings', old.recordName)));
    expect(() => promoteStandardFindingRecords(input)).not.toThrow();
  });

  it.each(['missing', 'wrong-hash', 'wrong-id'])('rejects a collision with %s supersession evidence', defect => {
    const f = fixture(), oldDir = join(f.root, 'old'), newDir = join(f.root, 'new');
    const original = submit(f.target, oldDir, 'task', 'Original');
    const receipts = readStandardFindingRecordReceipts(oldDir);
    promoteStandardFindingRecords({ fromEngagementDir: oldDir, toEngagementDir: f.engagementDir, expected: receipts });
    submit(f.target, newDir, 'task', 'Replacement');
    const superseded = defect === 'missing' ? [] : receipts.map(receipt => ({ ...receipt,
      ...(defect === 'wrong-hash' ? { sha256: '0'.repeat(64) } : { findingId: 'F-000000000000' }) }));
    expect(() => promoteStandardFindingRecords({ fromEngagementDir: newDir, toEngagementDir: f.engagementDir,
      expected: readStandardFindingRecordReceipts(newDir), superseded })).toThrow('root record');
    expect(readStandardFindings(f.engagementDir)).toEqual([original]);
    expect(existsSync(join(f.engagementDir, '.recovery/finding-history'))).toBe(false);
  });

  it('rejects a changed source receipt even when replacement was authorized', () => {
    const f = fixture(), oldDir = join(f.root, 'old'), newDir = join(f.root, 'new');
    submit(f.target, oldDir, 'task', 'Original');
    const superseded = readStandardFindingRecordReceipts(oldDir);
    promoteStandardFindingRecords({ fromEngagementDir: oldDir, toEngagementDir: f.engagementDir, expected: superseded });
    submit(f.target, newDir, 'task', 'Expected replacement');
    const expected = readStandardFindingRecordReceipts(newDir);
    submit(f.target, newDir, 'task', 'Changed after receipt');
    expect(() => promoteStandardFindingRecords({ fromEngagementDir: newDir, toEngagementDir: f.engagementDir, expected, superseded })).toThrow('집계 전에 변경');
  });

  it.each(['not-superseded', 'other-task', 'unfinished-current'])('does not authorize replacement for %s attempts', defect => {
    const f = fixture(), taskId = 'unit-test';
    const oldDir = join(f.engagementDir, 'work-units', taskId, 'attempt-1');
    const unitDir = join(f.engagementDir, 'work-units', taskId, 'attempt-2');
    const original = submit(f.target, oldDir, taskId, 'Original');
    promoteStandardFindingRecords({ fromEngagementDir: oldDir, toEngagementDir: f.engagementDir, expected: readStandardFindingRecordReceipts(oldDir) });
    submit(f.target, unitDir, taskId, 'Changed');
    writeFileSync(join(unitDir, '02_analysis_result.md'), 'Completed fixture analysis');
    const artifact = createArtifactRef({ engagementDir: unitDir, name: '02_analysis_result.md', phase: 'analyze', role: 'analyzer', attempt: '2' });
    const snapshot: RunSnapshot = { runId: 'fixture', contractId: 'fixture', contractVersion: '1', domain: 'offsec', mission: 'assessment',
      status: 'running', totalCostUsd: 0, lastSeq: 0, completedPhases: [], analysisRevision: 1, attempts: {
        prior: { phase: 'analyze', round: defect === 'other-task' ? 'unit-other' : taskId, attempt: 1, status: 'completed', superseded: defect !== 'not-superseded' },
        current: { phase: 'analyze', round: taskId, attempt: 2, status: defect === 'unfinished-current' ? 'failed' : 'completed', artifacts: [artifact] },
      } };
    expect(() => promoteCompletedTaskFindings({ root: f.engagementDir, taskId, unitDir,
      expected: readStandardFindingRecordReceipts(unitDir), snapshot })).toThrow();
    expect(readStandardFindings(f.engagementDir)).toEqual([original]);
    expect(existsSync(join(f.engagementDir, '.recovery/finding-history'))).toBe(false);
  });

  it('preserves the current record when its history archive is damaged', () => {
    const f = fixture(), oldDir = join(f.root, 'old'), newDir = join(f.root, 'new');
    const original = submit(f.target, oldDir, 'task', 'Original');
    const superseded = readStandardFindingRecordReceipts(oldDir), old = superseded[0]!;
    promoteStandardFindingRecords({ fromEngagementDir: oldDir, toEngagementDir: f.engagementDir, expected: superseded });
    submit(f.target, newDir, 'task', 'Changed');
    const archiveDir = join(f.engagementDir, '.recovery/finding-history', old.recordName); mkdirSync(archiveDir, { recursive: true });
    writeFileSync(join(archiveDir, `${old.sha256}.json`), 'damaged history');
    expect(() => promoteStandardFindingRecords({ fromEngagementDir: newDir, toEngagementDir: f.engagementDir,
      expected: readStandardFindingRecordReceipts(newDir), superseded })).toThrow('history integrity');
    expect(readStandardFindings(f.engagementDir)).toEqual([original]);
  });

  it('rejects a different finding identity even with a matching ID and superseded receipt', () => {
    const f = fixture(), oldDir = join(f.root, 'old'), newDir = join(f.root, 'new');
    const original = submit(f.target, oldDir, 'task', 'Original');
    const superseded = readStandardFindingRecordReceipts(oldDir);
    promoteStandardFindingRecords({ fromEngagementDir: oldDir, toEngagementDir: f.engagementDir, expected: superseded });
    const different = submit(f.target, newDir, 'task', 'Different observation');
    writeFileSync(join(newDir, 'standard-findings', superseded[0]!.recordName), JSON.stringify({ ...different, title: 'Different finding with a colliding ID' }));
    expect(() => promoteStandardFindingRecords({ fromEngagementDir: newDir, toEngagementDir: f.engagementDir,
      expected: readStandardFindingRecordReceipts(newDir), superseded })).toThrow('root record');
    expect(readStandardFindings(f.engagementDir)).toEqual([original]);
  });

  it('resumes a revised task with the same finding ID and preserves completed analysis on a second resume', async () => {
    const f = fixture(); let impact = 'Original assessment', findingId = ''; const calls: string[] = [];
    const agent = createOffsecAgent({ astBuilder: async () => ({ ok: false }),
      scheduler: { resourceCapacity: () => 100, controlIntervalMs: 1, retryBaseMs: 1 },
      sessionRunner: async spec => {
        calls.push(spec.phaseRound ?? spec.phase!);
        if (spec.workUnit) findingId = submit(spec.target, spec.engagementDir, spec.phaseRound!, impact).id;
        const outcome = syntheticOutcome(spec);
        if (spec.phase === 'review') {
          writeFileSync(join(spec.engagementDir, '03_review_result.json'), JSON.stringify({ countingSchemaVersion: 1,
            reviewedFindings: [{ originalFindingId: findingId, action: 'inconclusive', reason: 'Consumer behavior remains unverified after reading the source' }], newFindings: [] }));
          outcome.ledger.push(...deliveryFixture(spec, join(spec.target, 'app.ts')));
        }
        return outcome;
      } });
    const first = await agent.run({ ...f, mode: 'ast', tools: [] });
    expect(first.publicationStatus, JSON.stringify(first.storage.errors)).toBe('published');
    const previous = readStandardFindingRecordReceipts(f.engagementDir)[0]!;
    const state = FileRunStateStore.open(f.engagementDir).read();
    const task = Object.values(state.attempts).find(a => a.phase === 'analyze' && a.round?.startsWith('unit-'))!;
    const runtime = await openMissionRuntime({ engagementDir: f.engagementDir, runId: state.runId });
    try { await beginAnalysisRevision(runtime, f.engagementDir, 'Recheck incomplete evidence', [task.round!]); }
    finally { await runtime.close(); }
    impact = 'Revised assessment'; calls.length = 0;
    const resumed = await agent.resume(f.engagementDir);
    expect(resumed.publicationStatus, JSON.stringify(resumed.storage.errors)).toBe('published');
    expect(calls).toEqual([task.round, 'review', 'evaluate', 'report']);
    expect(readStandardFindings(f.engagementDir).find(finding => finding.id === findingId)?.impact).toBe(impact);
    expect(existsSync(join(f.engagementDir, '.recovery/finding-history', previous.recordName, `${previous.sha256}.json`))).toBe(true);
    calls.length = 0;
    await agent.resume(f.engagementDir);
    expect(calls).toEqual([]);
  }, 20_000);

  it('resumes two failed runs with evolving findings through a successful retry and publication', async () => {
    const f = fixture(); let failed = true, findingId = '', analyses = 0; const calls: string[] = [];
    const agent = createOffsecAgent({ astBuilder: async () => ({ ok: false }),
      scheduler: { resourceCapacity: () => 100, controlIntervalMs: 1, retryBaseMs: 1 },
      sessionRunner: async spec => {
        calls.push(spec.phase!);
        const outcome = syntheticOutcome(spec);
        if (spec.workUnit) {
          findingId = submit(spec.target, spec.engagementDir, spec.phaseRound!, `Assessment ${++analyses}`).id;
          if (failed) throw new SessionExecutionError(outcome, new Error('403 fixture interrupted after recording a claim'));
        }
        if (spec.phase === 'review') {
          writeFileSync(join(spec.engagementDir, '03_review_result.json'), JSON.stringify({ countingSchemaVersion: 1,
            reviewedFindings: [{ originalFindingId: findingId, action: 'inconclusive', reason: 'Consumer behavior remains unverified after reading the source' }], newFindings: [] }));
          outcome.ledger.push(...deliveryFixture(spec, join(spec.target, 'app.ts')));
        }
        return outcome;
      } });
    expect((await agent.run({ ...f, mode: 'ast', tools: [] })).status).toBe('incomplete');
    expect((await agent.resume(f.engagementDir)).status).toBe('incomplete');
    expect(analyses).toBe(2);
    expect(readStandardFindings(f.engagementDir).map(finding => finding.impact)).toEqual(['Assessment 2']);
    failed = false;
    expect((await agent.resume(f.engagementDir)).status).toBe('published');
    expect(analyses).toBe(3);
    expect(readStandardFindings(f.engagementDir).map(finding => finding.impact)).toEqual(['Assessment 3']);
    calls.length = 0;
    expect((await agent.resume(f.engagementDir)).status).toBe('published');
    expect(calls).toEqual([]);
  }, 20_000);
});
