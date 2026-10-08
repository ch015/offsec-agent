import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { buildOptions, type LedgerRow } from '../session.js';
import { observeSourceDelivery } from '../source-delivery.js';
import { validateAnalysisAssessments, type AssessmentTask } from '../planning/analysis-assessments.js';
import { AnthropicAgentRuntime } from '../providers/anthropic-agent-sdk.js';
import { loadOffsecContract } from '../offsec-contract.js';
import { submitStandardFinding } from '../finding-contract.js';

it('returns all quote and endpoint defects before Write, then accepts a repaired artifact with actual source delivery', async () => {
  const target = realpathSync(mkdtempSync(join(tmpdir(), 'analysis-write-feedback-'))), engagementDir = join(target, 'run');
  mkdirSync(engagementDir);
  const a = 'export const a = 1;\n', b = 'export const b = 2;\n';
  writeFileSync(join(target, 'a.ts'), a); writeFileSync(join(target, 'b.ts'), b);
  const taskRequest: AssessmentTask = { kind: 'source', contextRanges: [], ownedSources: [{ path: 'a.ts',
    sha256: createHash('sha256').update(a).digest('hex'), lineStart: 1, lineEnd: 1, byteStart: 0, byteEnd: Buffer.byteLength(a) }],
    flowResponsibilities: [{ id: 'F1', fromUnit: 'a', toUnit: 'b', ownerUnit: 'a', files: ['a.ts', 'b.ts'], question: 'Verify the value passed across these two modules' }] };
  const ledger: LedgerRow[] = [];
  const options = buildOptions({ domain: 'offsec', phase: 'analyze', target, engagementDir, engagementId: 'test', prompt: '',
    taskData: { taskRequest }, readScope: 'exact', allowedReadFiles: [join(target, 'a.ts'), join(target, 'b.ts')] }, ledger);
  const hook = options.hooks!.PreToolUse![0]!.hooks[0]!;
  const value = { files: [{ path: 'a.ts', status: 'analyzed', rationale: 'The immutable constant contains no input processing.', evidence: [{ lineStart: 1, lineEnd: 1, quote: 'wrong quote' }] }],
    flows: [{ id: 'F1', status: 'analyzed', rationale: 'The module boundary passes only an immutable constant.', evidenceFiles: ['a.ts'], evidence: [{ path: 'a.ts', lineStart: 1, lineEnd: 1, quote: a.trim() }] }] };
  const write = async () => hook({ hook_event_name: 'PreToolUse', tool_use_id: 'write-1', session_id: 'test', transcript_path: '', cwd: engagementDir,
    tool_name: 'Write', tool_input: { file_path: join(engagementDir, '02_file_assessments.json'), content: JSON.stringify(value) } }, 'write-1', { signal: new AbortController().signal });
  const denied = await write() as any;
  expect(denied.hookSpecificOutput.permissionDecision).toBe('deny');
  expect(denied.hookSpecificOutput.permissionDecisionReason).toContain('Invalid file analysis evidence: a.ts:1-1');
  expect(denied.hookSpecificOutput.permissionDecisionReason).toContain('Flow evidence must account for both endpoints');
  expect(existsSync(join(engagementDir, '02_file_assessments.json'))).toBe(false);
  value.files[0]!.evidence[0]!.quote = a.trim(); value.flows[0]!.evidenceFiles.push('b.ts');
  value.flows[0]!.evidence.push({ path: 'b.ts', lineStart: 1, lineEnd: 1, quote: b.trim() });
  expect((await write() as any).hookSpecificOutput.permissionDecisionReason).toContain('Missing verified source delivery');
  for (const [file, text] of [['a.ts', a], ['b.ts', b]]) {
    const observed = observeSourceDelivery({ target, file: file!, allowedFiles: [file!], toolCallId: file!, content: `1\t${text!.trim()}` })!;
    ledger.push({ at: new Date().toISOString(), event: 'SourceDelivery', ...observed });
  }
  expect((await write() as any).hookSpecificOutput?.permissionDecision).not.toBe('deny');
  rmSync(target, { recursive: true, force: true });
});

it('rejects an unexpected flow path without reading outside assigned endpoints', () => {
  const target = realpathSync(mkdtempSync(join(tmpdir(), 'analysis-flow-scope-')));
  expect(() => validateAnalysisAssessments({ target, files: [], flowIds: ['F1'], flows: [{ id: 'F1', files: [] }],
    value: { files: [], flows: [{ id: 'F1', status: 'analyzed', rationale: 'Attempted quote from a file outside this task scope.', evidenceFiles: ['../../not-present'],
      evidence: [{ path: '../../not-present', lineStart: 1, lineEnd: 1, quote: 'not read' }] }] } })).toThrow('Flow quote outside assigned endpoints');
  rmSync(target, { recursive: true, force: true });
});

it('passes host validation data through the provider without parsing model prompt text', async () => {
  const taskData = { taskRequest: { ownedSources: ['host-owned'] } };
  const runtime = new AnthropicAgentRuntime(async spec => {
    expect(spec.taskData).toBe(taskData); return { texts: [], ledger: [], totalCostUsd: 0, modelUsage: {}, subtype: 'success' };
  });
  await runtime.runPhase({ contractId: 'test', contractVersion: '1', domain: 'offsec', mission: 'assessment', phase: 'analyze', role: 'analyzer',
    runId: 'test', attempt: '1', target: '/tmp', engagementDir: '/tmp', prompt: 'untrusted model-visible text', requiredCapabilities: [], taskData });
});

it('returns all missing review decisions and original reads before Write so the same session can repair them', async () => {
  const target = realpathSync(mkdtempSync(join(tmpdir(), 'review-write-feedback-'))), engagementDir = join(target, 'run');
  mkdirSync(engagementDir);
  try {
    const contract = loadOffsecContract(resolve(import.meta.dirname, '../../../domains/offsec/contracts/offsec-contract.v2.json'));
    const sources = ['a', 'b'].map(name => ({ path: join(target, `${name}.ts`), quote: `export const ${name} = 'fixture-secret';` }));
    const findings = sources.map(source => {
      writeFileSync(source.path, `${source.quote}\n`);
      return submitStandardFinding({ contract, target, engagementDir, phase: 'analyze', role: 'analyzer', finding: {
        title: `Credential in ${source.path}`, verdict: 'supported', severity: 'MEDIUM', evidenceClass: 'configuration', reachability: 'plausible',
        preconditions: ['Source access'], severityRationale: 'A reusable credential is embedded in source.', confidence: 0.8,
        impact: 'Disclosure of an embedded credential', remediation: 'Use runtime secret storage', standards: ['CWE-798'], unresolved: [],
        evidence: [{ path: source.path, lineStart: 1, lineEnd: 1, quote: source.quote }],
      } });
    });
    const ledger: LedgerRow[] = [];
    const options = buildOptions({ domain: 'offsec', phase: 'review', target, engagementDir, engagementId: 'test', prompt: '',
      readScope: 'exact', allowedReadFiles: sources.map(source => source.path) }, ledger);
    const hook = options.hooks!.PreToolUse![0]!.hooks[0]!;
    const review = { reviewedFindings: [] as Array<{ originalFindingId: string; action: string; reason: string }>, newFindings: [] };
    const write = async () => await hook({ hook_event_name: 'PreToolUse', tool_use_id: 'review-write', session_id: 'test', transcript_path: '', cwd: engagementDir,
      tool_name: 'Write', tool_input: { file_path: join(engagementDir, '03_review_result.json'), content: JSON.stringify(review) } }, 'review-write', { signal: new AbortController().signal }) as any;
    const unclassified = await write();
    expect(unclassified.hookSpecificOutput.permissionDecision).toBe('deny');
    for (const finding of findings) expect(unclassified.hookSpecificOutput.permissionDecisionReason).toContain(finding.id);
    for (const source of sources) expect(unclassified.hookSpecificOutput.permissionDecisionReason).toContain(`${source.path}:1-1`);
    review.reviewedFindings = findings.map(finding => ({ originalFindingId: finding.id, action: 'retained', reviewedSeverity: finding.severity, reason: 'Embedded credential in a production source file.' }));
    const unread = await write();
    expect(unread.hookSpecificOutput.permissionDecision).toBe('deny');
    for (const source of sources) expect(unread.hookSpecificOutput.permissionDecisionReason).toContain(`${source.path}:1-1`);
    review.reviewedFindings[0]!.action = 'inconclusive';
    expect((await write()).hookSpecificOutput.permissionDecisionReason).toContain(`${sources[0]!.path}:1-1`);
    expect(existsSync(join(engagementDir, '03_review_result.json'))).toBe(false);
    for (const source of sources) ledger.push({ at: new Date().toISOString(), event: 'SourceDelivery',
      ...observeSourceDelivery({ target, file: source.path, allowedFiles: sources.map(source => source.path), toolCallId: source.path, content: `1\t${source.quote}` })! });
    expect((await write()).hookSpecificOutput?.permissionDecision).not.toBe('deny');
    writeFileSync(join(engagementDir, '03_review_result.json'), JSON.stringify(review));
    await options.hooks!.PostToolUse![0]!.hooks[0]!({ hook_event_name: 'PostToolUse', tool_use_id: 'review-write', session_id: 'test', transcript_path: '', cwd: engagementDir,
      tool_name: 'Write', tool_input: { file_path: join(engagementDir, '03_review_result.json'), content: JSON.stringify(review) }, tool_response: 'written' },
    'review-write', { signal: new AbortController().signal });
    review.reviewedFindings[0]!.action = 'invalid';
    const invalidAfterRead = await write();
    expect(invalidAfterRead.hookSpecificOutput.permissionDecision).toBe('deny');
    expect(invalidAfterRead.hookSpecificOutput.permissionDecisionReason).toContain('requires action');
  } finally { rmSync(target, { recursive: true, force: true }); }
});
