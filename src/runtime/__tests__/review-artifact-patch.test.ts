import { afterEach, describe, expect, it } from 'vitest';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { prepareReviewPatch } from '../review-artifact-patch.js';
import { submitStandardFinding } from '../finding-contract.js';
import { loadOffsecContract } from '../offsec-contract.js';
import { resolveV2Review } from '../v2-review-resolution.js';
import { validateV2ReviewSourceReads } from '../v2-evaluation.js';
import { buildOptions, type SessionSpec } from '../session.js';
import { deliveryFixture } from './assessment-protocol-fixture.js';
import { getDomainAdapter } from '../domains/registry.js';
import { prepareReviewProgress, finishReviewProgress, loadReviewProgress, stageReviewReopen, finishReviewReopen, reviewProgressAdvance } from '../review-progress.js';

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function fixture(count = 2, sharedEvidence = false) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'review-patch-'))); roots.push(root);
  const target = join(root, 'source'), engagementDir = join(root, 'run'); mkdirSync(target); mkdirSync(engagementDir);
  const source = join(target, 'app.ts'), path = join(engagementDir, '03_review_result.json');
  const lines = Array.from({ length: Math.max(count, 1) }, (_, index) => `export const token${index} = 'fixture-value-${index}';`);
  writeFileSync(source, lines.join('\n') + '\n');
  const findings = Array.from({ length: count }, (_, index) => submitStandardFinding({ target, engagementDir,
    phase: 'analyze', role: 'analyzer', contract: loadOffsecContract(), finding: {
      title: `Credential ${index}`, verdict: 'supported', severity: 'MEDIUM', evidenceClass: 'configuration', reachability: 'plausible',
      preconditions: ['Source disclosure'], severityRationale: 'Source contains an embedded reusable credential.', confidence: 0.8,
      impact: 'Disclosure of an embedded credential', remediation: 'Use runtime secret storage', standards: ['CWE-798'], unresolved: [],
      evidence: [{ path: 'app.ts', lineStart: sharedEvidence ? 1 : index + 1, lineEnd: sharedEvidence ? 1 : index + 1,
        quote: lines[sharedEvidence ? 0 : index]! }],
    } }));
  const events = deliveryFixture({ target } as SessionSpec, source);
  const row = (index: number, action = 'retained', extra = {}) => ({ originalFindingId: findings[index]!.id, action,
    reviewedSeverity: findings[index]!.severity, reason: 'Independently examined the exact source and credential use.', ...extra });
  const prepare = (patch: unknown, receipts = events) => prepareReviewPatch({ target, engagementDir, events: receipts, content: JSON.stringify(patch) })!;
  const save = (patch: unknown) => { const prepared = prepare(patch); writeFileSync(path, prepared.content); return JSON.parse(prepared.content); };
  return { target, engagementDir, source, path, findings, events, row, prepare, save };
}

describe('bounded incremental review artifacts', () => {
  it('enforces independent counting on both full writes and patches without trusting a model version flag', () => {
    const f = fixture(1), adapter = getDomainAdapter('offsec');
    const input = { phase: adapter.getPhase('review').legacy, engagementDir: f.engagementDir, target: f.target,
      name: '03_review_result.json', taskData: { independentCounting: true }, events: f.events };
    const review = { countingSchemaVersion: 0, reviewedFindings: [f.row(0)], newFindings: [] };
    expect(() => adapter.validateArtifactWrite!({ ...input, content: JSON.stringify(review) })).toThrow('COUNTING_ASSESSMENT_REQUIRED');
    expect(() => adapter.validateArtifactWrite!({ ...input, content: JSON.stringify({ reviewPatch: true, finalize: true, reviewedFindings: [f.row(0)] }) })).toThrow('COUNTING_ASSESSMENT_REQUIRED');
    const counting = { kind: 'observation', reason: 'The synthetic credential is a test observation with no deployed consumer.' };
    const prepared = adapter.validateArtifactWrite!({ ...input, content: JSON.stringify({ ...review, reviewedFindings: [f.row(0, 'retained', { counting })] }) })!;
    expect(JSON.parse(prepared.content).countingSchemaVersion).toBe(1);
    expect(resolveV2Review(f.engagementDir, JSON.parse(prepared.content)).vulnerabilityInventory)
      .toMatchObject({ independentVulnerabilityCount: 0, observationCount: 1, acceptedRecordCount: 1 });
  });
  it('resumes missing counting metadata as finalization progress without rereading unchanged evidence', () => {
    const f = fixture(1), context = { ...f, runId: 'counting-run', model: 'review-model', revision: 0 };
    const events = f.events.map(event => ({ ...event, actor: 'reviewer' }));
    const first = f.prepare({ reviewPatch: true, countingSchemaVersion: 1, reviewedFindings: [f.row(0)] });
    prepareReviewProgress(context, { attempt: '1', content: first.content, events });
    writeFileSync(f.path, first.content); finishReviewProgress(context, true);
    const before = loadReviewProgress(context)!;
    expect(before.remainingIds).toEqual([]);
    expect(before.finalizationIssues[0]).toContain(`${f.findings[0]!.id} COUNTING_ASSESSMENT_REQUIRED`);
    const counting = { kind: 'vulnerability', causeId: 'VC-fixture-secret', component: 'fixture credential',
      rootCause: 'A reusable credential is embedded in source', fixBoundary: 'Externalize the reusable credential value', primaryEvidence: f.findings[0]!.evidence };
    const last = prepareReviewPatch({ ...f, events: [], reuse: before.reuse,
      content: JSON.stringify({ reviewPatch: true, finalize: true, reviewedFindings: [f.row(0, 'retained', { counting })] }) })!;
    prepareReviewProgress(context, { attempt: '2', content: last.content, events: [], reuse: before.reuse });
    writeFileSync(f.path, last.content); finishReviewProgress(context, true);
    const after = loadReviewProgress(context)!;
    expect(after.finalizationIssues).toEqual([]);
    expect(reviewProgressAdvance(before, after, new Set([f.findings[0]!.id])))
      .toEqual({ newlyReviewed: 0, newlyFinalized: 1, advanced: true });
  });
  it('counts finalized original severity decisions as progress but rejects regressions and invented work', () => {
    const originalIds = new Set(['A', 'B']);
    const prior = { reviewedIds: ['A', 'B'], finalizationIssues: ['A requires reviewedSeverity', 'B requires reviewedSeverity'] };
    expect(reviewProgressAdvance(prior, { ...prior, finalizationIssues: ['B requires reviewedSeverity'] }, originalIds))
      .toEqual({ newlyReviewed: 0, newlyFinalized: 1, advanced: true });
    expect(reviewProgressAdvance(prior, prior, originalIds).advanced).toBe(false);
    expect(reviewProgressAdvance(prior, { reviewedIds: ['A'], finalizationIssues: [] }, originalIds).advanced).toBe(false);
    expect(reviewProgressAdvance({ reviewedIds: ['A'], finalizationIssues: [] },
      { reviewedIds: ['A', 'B'], finalizationIssues: ['A requires reviewedSeverity'] }, originalIds).advanced).toBe(false);
    expect(reviewProgressAdvance(prior, { ...prior, reviewedIds: ['A', 'B', 'new-reviewer-id'] }, originalIds).advanced).toBe(false);
  });
  it('repairs legacy severity decisions without rewriting or dropping staged reasoning', () => {
    const f = fixture(1);
    f.save({ reviewPatch: true, reviewedFindings: [f.row(0, 'retained', { reviewedSeverity: undefined, verificationEvidence: ['original proof'] })] });
    expect(() => f.prepare({ reviewPatch: true, finalize: true })).toThrow('requires reviewedSeverity');
    const before = readFileSync(f.path, 'utf8');
    expect(() => f.prepare({ reviewPatch: true, reviewedSeverities: { [f.findings[0]!.id]: 'LOW' } })).toThrow('submit_finding');
    expect(readFileSync(f.path, 'utf8')).toBe(before);
    const final = f.save({ reviewPatch: true, finalize: true, reviewedSeverities: { [f.findings[0]!.id]: 'MEDIUM' } });
    expect(final.reviewedFindings[0]).toMatchObject({ reviewedSeverity: 'MEDIUM', verificationEvidence: ['original proof'], reason: f.row(0).reason });
    expect(() => f.prepare({ reviewPatch: true, reviewedSeverities: { 'F-invented': 'LOW' } })).toThrow('existing retained/corrected');
  });
  it('recovers metadata repair across revision interruption without reusing analyzer reads', () => {
    const f = fixture(1), context = { ...f, runId: 'run', model: 'review-model', revision: 0 };
    const events = f.events.map(event => ({ ...event, actor: 'reviewer' }));
    const draft = f.prepare({ reviewPatch: true, reviewedFindings: [f.row(0, 'retained', { reviewedSeverity: undefined })] });
    prepareReviewProgress(context, { attempt: 'review:1', content: draft.content, events });
    writeFileSync(f.path, draft.content); finishReviewProgress(context, true);
    const progress = loadReviewProgress(context)!;
    expect(progress.finalizationIssues).toHaveLength(1);
    expect(() => stageReviewReopen(context, { ids: progress.reuse.ids, events: events.map(event => ({ ...event, actor: 'analyzer' })) })).toThrow('original source');
    stageReviewReopen(context, progress.reuse);
    finishReviewReopen(context); // Crash before the revision event leaves the journal pending.
    expect(existsSync(join(f.engagementDir, '.recovery/review-reopen.json'))).toBe(true);
    rmSync(f.path); // Revision archived and removed the mutable artifact.
    const next = { ...context, revision: 1 };
    expect(() => finishReviewReopen({ ...next, runId: 'wrong-run' })).toThrow('identity');
    finishReviewReopen(next); finishReviewReopen(next);
    const restored = loadReviewProgress(next)!;
    expect(restored).toMatchObject({ reviewedIds: [f.findings[0]!.id], remainingIds: [], draft: true });
    expect(restored.reuse.events).toEqual(progress.reuse.events);
    expect(restored.finalizationIssues).toHaveLength(1);
    const final = prepareReviewPatch({ ...f, events: [], reuse: restored.reuse,
      content: JSON.stringify({ reviewPatch: true, finalize: true, reviewedSeverities: { [f.findings[0]!.id]: 'MEDIUM' } }) })!;
    expect(JSON.parse(final.content).reviewDraft).toBeUndefined();
  });
  it('resumes committed decisions with independent receipts, recovering a crash after Write', () => {
    const f = fixture(2), context = { ...f, runId: 'run', model: 'review-model', revision: 0 };
    const events = f.events.map(event => ({ ...event, actor: 'reviewer' }));
    const first = f.prepare({ reviewPatch: true, reviewedFindings: [f.row(0)] });
    prepareReviewProgress(context, { attempt: 'review:1', content: first.content, events });
    // A permitted but unexecuted Write provides no completed work.
    expect(loadReviewProgress(context)).toBeUndefined();
    prepareReviewProgress(context, { attempt: 'review:1', content: first.content, events });
    writeFileSync(f.path, first.content);
    // No PostToolUse callback: simulate process death immediately after Write.
    const progress = loadReviewProgress(context)!;
    expect(progress.reviewedIds).toEqual([f.findings[0]!.id]);
    expect(progress.remainingIds).toEqual([f.findings[1]!.id]);
    expect(progress.reuse.events).toHaveLength(1);
    expect(() => prepareReviewPatch({ ...f, content: JSON.stringify({ reviewPatch: true, reviewedFindings: [f.row(1)] }), events: [], reuse: progress.reuse })).toThrow('original source');
    const final = prepareReviewPatch({ ...f, events, reuse: progress.reuse,
      content: JSON.stringify({ reviewPatch: true, finalize: true, reviewedFindings: [f.row(1)] }) })!;
    prepareReviewProgress(context, { attempt: 'review:2', content: final.content, events, reuse: progress.reuse });
    writeFileSync(f.path, final.content); finishReviewProgress(context, true);
    expect(loadReviewProgress(context)).toMatchObject({ draft: false, remainingIds: [] });
    expect(() => validateV2ReviewSourceReads(f.engagementDir, f.target, [], loadReviewProgress(context)!.reuse)).not.toThrow();
  });
  it('preserves committed work on failed writes and rejects altered bytes or cross-run reuse', () => {
    const f = fixture(), context = { ...f, runId: 'run', model: 'review-model', revision: 0 };
    const events = f.events.map(event => ({ ...event, actor: 'reviewer' }));
    const first = f.prepare({ reviewPatch: true, reviewedFindings: [f.row(0)] });
    prepareReviewProgress(context, { attempt: '1', content: first.content, events }); writeFileSync(f.path, first.content); finishReviewProgress(context, true);
    const next = f.prepare({ reviewPatch: true, reviewedFindings: [f.row(1)] });
    prepareReviewProgress(context, { attempt: '2', content: next.content, events }); finishReviewProgress(context, false);
    expect(loadReviewProgress(context)!.reviewedIds).toEqual([f.findings[0]!.id]);
    expect(() => loadReviewProgress({ ...context, runId: 'other' })).toThrow('different run');
    expect(() => loadReviewProgress({ ...context, model: 'different-model' })).toThrow('reviewer model');
    expect(loadReviewProgress({ ...context, revision: 1 })).toBeUndefined();
    writeFileSync(f.path, first.content.replace('Independently', 'Altered'));
    expect(() => loadReviewProgress(context)).toThrow('differs');
    writeFileSync(f.path, first.content); writeFileSync(f.source, readFileSync(f.source, 'utf8') + '// changed\n');
    expect(() => loadReviewProgress(context)).toThrow('original source');
  });
  it('never checkpoints analyzer receipts as independent review or retains reuse after finding changes', () => {
    const f = fixture(), context = { ...f, runId: 'run', model: 'review-model', revision: 0 };
    const first = f.prepare({ reviewPatch: true, reviewedFindings: [f.row(0)] });
    expect(() => prepareReviewProgress(context, { attempt: '1', content: first.content,
      events: f.events.map(event => ({ ...event, actor: 'analyzer' })) })).toThrow('original source');
    prepareReviewProgress(context, { attempt: '1', content: first.content, events: f.events.map(event => ({ ...event, actor: 'reviewer' })) });
    writeFileSync(f.path, first.content); finishReviewProgress(context, true);
    const root = join(f.engagementDir, 'standard-findings');
    // Change the canonical finding while preserving ID and source bytes.
    const record = readdirSync(root).map(name => join(root, name)).find(path => JSON.parse(readFileSync(path, 'utf8')).id === f.findings[0]!.id)!;
    const value = JSON.parse(readFileSync(record, 'utf8')); value.remediation = 'Changed remediation requires reassessment'; writeFileSync(record, JSON.stringify(value));
    expect(loadReviewProgress(context)!.reviewedIds).toEqual([]);
  });
  it('preserves 45 decisions across bounded writes, updates exact IDs, and requires explicit finalization', () => {
    const f = fixture(45);
    f.save({ reviewPatch: true, reviewedFindings: Array.from({ length: 20 }, (_, i) => f.row(i)) });
    expect(() => validateV2ReviewSourceReads(f.engagementDir, f.target, f.events)).toThrow('Review draft');
    f.save({ reviewPatch: true, reviewedFindings: [f.row(3, 'inconclusive')] });
    f.save({ reviewPatch: true, reviewedFindings: Array.from({ length: 20 }, (_, i) => f.row(i + 20)) });
    f.save({ reviewPatch: true, reviewedFindings: Array.from({ length: 5 }, (_, i) => f.row(i + 40)) });
    expect(() => resolveV2Review(f.engagementDir)).toThrow('Review draft');
    const final = f.save({ reviewPatch: true, finalize: true, reviewedFindings: [] });
    expect(final.reviewDraft).toBeUndefined(); expect(final.reviewedFindings).toHaveLength(45);
    expect(final.summary).toMatchObject({ retained: 44, inconclusive: 1 });
    expect(resolveV2Review(f.engagementDir).severityDistribution.MEDIUM).toBe(44);
    expect(() => validateV2ReviewSourceReads(f.engagementDir, f.target, f.events)).not.toThrow();
  });
  it('cannot finalize a missing decision or lose the accepted draft after a rejected patch', () => {
    const f = fixture(); f.save({ reviewPatch: true, reviewedFindings: [f.row(0)] });
    const before = readFileSync(f.path, 'utf8');
    expect(() => f.prepare({ reviewPatch: true, finalize: true, reviewedFindings: [] })).toThrow(f.findings[1]!.id);
    expect(readFileSync(f.path, 'utf8')).toBe(before);
    expect(() => f.prepare({ reviewPatch: true, reviewedFindings: [f.row(0), f.row(0)] })).toThrow('Duplicate ID');
    expect(() => f.prepare({ reviewPatch: true, reviewedFindings: [f.row(0, 'retained', { originalFindingId: 'F-123_removed' })] })).toThrow('unknown ID');
    expect(readFileSync(f.path, 'utf8')).toBe(before);
  });
  it('requires actual original reads before staging retained, rejected or inconclusive decisions', () => {
    const f = fixture();
    for (const action of ['retained', 'rejected', 'inconclusive']) {
      expect(() => f.prepare({ reviewPatch: true, reviewedFindings: [f.row(0, action)] }, [])).toThrow('original source');
    }
    expect(existsSync(f.path)).toBe(false);
  });
  it('allows shared citations across batches but requires explicit same-cause counting before finalization', () => {
    const f = fixture(2, true);
    expect(() => f.prepare({ reviewPatch: true, reviewedFindings: Array.from({ length: 21 }, () => f.row(0)) })).toThrow();
    f.save({ reviewPatch: true, countingSchemaVersion: 1, reviewedFindings: [f.row(0)] });
    f.save({ reviewPatch: true, reviewedFindings: [f.row(1)] });
    expect(() => f.prepare({ reviewPatch: true, finalize: true })).toThrow('COUNTING_ASSESSMENT_REQUIRED');
    const counting = { kind:'vulnerability',causeId:'VC-shared-credential',component:'fixture credentials',
      rootCause:'A reusable credential is embedded in source',fixBoundary:'Externalize the same shared credential value',primaryEvidence:f.findings[0]!.evidence };
    f.save({reviewPatch:true,reviewedFindings:[f.row(0,'retained',{counting}),
      f.row(1,'rejected',{mergedFrom:[f.findings[0]!.id],counting})]});
    f.save({ reviewPatch: true, finalize: true });
    expect(resolveV2Review(f.engagementDir).vulnerabilityInventory.independentVulnerabilityCount).toBe(1);
    expect(resolveV2Review(f.engagementDir).dispositions.find(row => row.id === f.findings[1]!.id)?.finalStatus).toBe('FOLDED_INTO');
  });
  it('keeps full-write behavior and does not treat an empty draft as completed', () => {
    const f = fixture(0);
    expect(f.prepare({ reviewedFindings: [], newFindings: [] })).toBeUndefined();
    f.save({ reviewPatch: true });
    expect(() => validateV2ReviewSourceReads(f.engagementDir, f.target, [])).toThrow('Review draft');
    f.save({ reviewPatch: true, finalize: true });
    expect(() => validateV2ReviewSourceReads(f.engagementDir, f.target, [])).not.toThrow();
  });
  it('does not silently discard malformed prior state or accept stale delivery after source changes', () => {
    const f = fixture(); f.save({ reviewPatch: true, reviewedFindings: [f.row(0)] });
    writeFileSync(f.path, '{');
    expect(() => f.prepare({ reviewPatch: true, reviewedFindings: [f.row(1)] })).toThrow();
    rmSync(f.path);
    writeFileSync(f.source, readFileSync(f.source, 'utf8') + '// source changed\n');
    expect(() => f.prepare({ reviewPatch: true, reviewedFindings: [f.row(0)] })).toThrow('original source');
  });
  it('updates real SDK Write input and serializes concurrent patches until success or failure', async () => {
    const f = fixture();
    const options = buildOptions({ domain: 'offsec', phase: 'review', target: f.target, engagementDir: f.engagementDir,
      engagementId: 'patch-test', prompt: '', readScope: 'exact', allowedReadFiles: [f.source] }, f.events);
    const pre = options.hooks!.PreToolUse![0]!.hooks[0]!;
    const post = options.hooks!.PostToolUse![0]!.hooks[0]!;
    const failed = options.hooks!.PostToolUseFailure![0]!.hooks[0]!;
    const ctx = { signal: new AbortController().signal };
    const input = (id: string, index: number) => ({ hook_event_name: 'PreToolUse' as const, tool_use_id: id, session_id: 'test', transcript_path: '', cwd: f.engagementDir,
      tool_name: 'Write', tool_input: { file_path: f.path, content: JSON.stringify({ reviewPatch: true, reviewedFindings: [f.row(index)] }) } });
    const first = await pre(input('first', 0), 'first', ctx) as any;
    expect(first.hookSpecificOutput.additionalContext).toContain('1/2');
    expect(JSON.parse(first.hookSpecificOutput.updatedInput.content).reviewDraft).toBe(true);
    expect((await pre(input('second', 1), 'second', ctx) as any).hookSpecificOutput.permissionDecisionReason).toContain('still in progress');
    writeFileSync(f.path, first.hookSpecificOutput.updatedInput.content);
    await post({ ...input('first', 0), hook_event_name: 'PostToolUse', tool_response: 'written' }, 'first', ctx);
    const second = await pre(input('second', 1), 'second', ctx) as any;
    expect(JSON.parse(second.hookSpecificOutput.updatedInput.content).reviewedFindings).toHaveLength(2);
    await failed({ ...input('second', 1), hook_event_name: 'PostToolUseFailure', error: 'disk error' }, 'second', ctx);
    const retry = await pre(input('retry', 1), 'retry', ctx) as any;
    expect(retry.hookSpecificOutput.permissionDecision).toBe('allow');
    const outside = await pre({ ...input('outside', 1), tool_input: { ...input('outside', 1).tool_input, file_path: join(f.target, '03_review_result.json') } }, 'outside', ctx) as any;
    expect(outside.hookSpecificOutput.permissionDecision).toBe('deny');
  });
});
