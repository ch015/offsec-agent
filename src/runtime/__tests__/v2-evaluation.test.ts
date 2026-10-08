import { deliveryFixture } from './assessment-protocol-fixture.js';
import type { SessionSpec } from '../session.js';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { submitStandardFinding } from '../finding-contract.js';
import { loadOffsecContract } from '../offsec-contract.js';
import { validateV2Evaluation, validateV2EvaluationArtifact, validateV2ReviewSourceReads } from '../v2-evaluation.js';
import { buildOptions } from '../session.js';
import { OffsecDomainAdapter } from '../domains/offsec.js';

const contractPath = resolve(import.meta.dirname, '../../../domains/offsec/contracts/offsec-contract.v2.json');
const contract = loadOffsecContract(contractPath);
function fixture() {
  const target = mkdtempSync(join(tmpdir(), 'v2-evaluation-source-'));
  const engagementDir = mkdtempSync(join(tmpdir(), 'v2-evaluation-run-'));
  writeFileSync(join(target, 'app.js'), "const secret = 'fixture-token';\n");
  const record = submitStandardFinding({ target, engagementDir, phase: 'analyze', role: 'analyzer', contract,
    finding: { title: 'Hardcoded test token', verdict: 'supported', severity: 'MEDIUM',
      evidenceClass: 'configuration', reachability: 'plausible', preconditions: ['Source disclosure'],
      severityRationale: 'Source disclosure reveals a reusable authentication credential.',
      confidence: 0.8, impact: 'Credential disclosure', remediation: 'Use external secret storage',
      standards: ['CWE-798'], unresolved: [],
      evidence: [{ path: 'app.js', lineStart: 1, lineEnd: 1, quote: "const secret = 'fixture-token';" }] },
  });
  const evaluation = { severityDistribution: { CRITICAL: 0, HIGH: 0, MEDIUM: 1, LOW: 0, INFO: 0 } };
  const review = { reviewedFindings: [{ originalFindingId: record.id, action: 'retained', reviewedSeverity: record.severity, reason: 'Source contains a reusable credential.' }] };
  const classification = {
    candidates: [{ id: record.id, final_status: 'CONFIRMED', severity: 'MEDIUM',
      evidence: { locations: ['app.js:1'] }, validity: { reachable: 'source disclosure', business_relevance: 'credential use', exploit_path: 'source to token' } }],
    equivalence_review: { status: 'COMPLETE', reviewed_candidate_count: 1, unresolved: [],
      groups: [{ group_id: 'G1', members: [record.id], decision: 'KEEP', reason: 'A single credential storage root cause.' }] },
  };
  function save() {
    writeFileSync(join(engagementDir, '03_review_result.json'), JSON.stringify(review));
    writeFileSync(join(engagementDir, '04_evaluation.json'), JSON.stringify(evaluation));
    writeFileSync(join(engagementDir, '04_evaluation_classification.yaml'), JSON.stringify(classification));
  }
  save(); return { target, engagementDir, record, review, evaluation, classification, save };
}
describe('v2 real-model evaluation regression', () => {
  it.each(['retained', 'rejected', 'inconclusive'])('requires independent source Read even for %s review decisions', action => {
    const f = fixture();
    f.review.reviewedFindings[0]!.action = action; f.save();
    expect(() => validateV2ReviewSourceReads(f.engagementDir, f.target, [])).toThrow('original source');
    expect(() => validateV2ReviewSourceReads(f.engagementDir, f.target, deliveryFixture({ target: f.target } as SessionSpec, join(f.target, 'app.js')))).not.toThrow();
  });
  it('accepts canonical severity and publication-compatible classifications', () => {
    const f = fixture(); expect(() => validateV2Evaluation(f.engagementDir)).not.toThrow();
  });
  it('rejects a retained MEDIUM finding rewritten as HIGH even if counts agree', () => {
    const f = fixture(); f.classification.candidates[0]!.severity = 'HIGH';
    f.evaluation.severityDistribution.HIGH = 1; f.evaluation.severityDistribution.MEDIUM = 0; f.save();
    expect(() => validateV2Evaluation(f.engagementDir)).toThrow('severity mismatch');
  });
  it('rejects missing findings, inconsistent counts, and missing equivalence review', () => {
    const f = fixture(); f.evaluation.severityDistribution.MEDIUM = 2; f.save();
    expect(() => validateV2Evaluation(f.engagementDir)).toThrow('severityDistribution.MEDIUM');
    f.evaluation.severityDistribution.MEDIUM = 1; f.classification.equivalence_review.status = 'PENDING'; f.save();
    expect(() => validateV2Evaluation(f.engagementDir)).toThrow('EQUIVALENCE_REVIEW_INCOMPLETE');
    f.classification.candidates = []; f.save();
    expect(() => validateV2Evaluation(f.engagementDir)).toThrow('every canonical finding');
    expect(() => validateV2Evaluation(f.engagementDir)).toThrow(`missing IDs: ${f.record.id}`);
  });
  it('returns duplicate positions, unknown IDs, incorrect statuses and severities together', () => {
    const f = fixture(), candidate = f.classification.candidates[0]!;
    const classification = { ...f.classification, candidates: [
      { ...candidate, severity: 'HIGH', final_status: 'BACKLOG' }, candidate, { ...candidate, id: 'F-999999999999' },
    ] };
    let error = '';
    try { validateV2EvaluationArtifact(f.engagementDir, '04_evaluation_classification.yaml', JSON.stringify(classification)); }
    catch (caught) { error = String(caught); }
    expect(error).toContain(`duplicate ID ${f.record.id} at rows 1 and 2`);
    expect(error).toContain('unknown ID F-999999999999 at row 3');
    expect(error).toContain(`severity mismatch for ${f.record.id}`);
    expect(error).toContain('expected final_status CONFIRMED or DOWNGRADED');
    expect(() => validateV2EvaluationArtifact(f.engagementDir, '04_evaluation_classification.yaml', JSON.stringify(f.classification))).not.toThrow();
  });
  it('returns all incorrect severity totals in one repair request', () => {
    const f = fixture();
    let error = '';
    try { validateV2EvaluationArtifact(f.engagementDir, '04_evaluation.json', JSON.stringify({ severityDistribution: {} })); }
    catch (caught) { error = String(caught); }
    for (const severity of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']) expect(error).toContain(`severityDistribution.${severity}`);
  });
  it('binds artifact identifiers to phase basenames in provider output', () => {
    const f = fixture();
    const schema = buildOptions({ domain: 'offsec', phase: 'evaluate', contractPath,
      target: f.target, engagementDir: f.engagementDir, engagementId: 'fixture', prompt: 'fixture' }).outputFormat!.schema;
    expect((schema.properties as any).artifacts.items.enum).toEqual(['04_evaluation.json', '04_evaluation_classification.yaml']);
  });
  it.each(['REJECT', 'FOLD', 'FOLDED_INTO'])('rejects group decision %s with expected values before Write', decision => {
    const f = fixture();
    f.classification.equivalence_review.groups[0]!.decision = decision;
    expect(() => validateV2EvaluationArtifact(f.engagementDir, '04_evaluation_classification.yaml', JSON.stringify(f.classification)))
      .toThrow('Allowed decisions: MERGE, SPLIT, KEEP');
  });
  it('keeps coverage limitations separate while still blocking actual unresolved equivalence', () => {
    const f = fixture();
    validateV2EvaluationArtifact(f.engagementDir, '04_evaluation.json', JSON.stringify({ ...f.evaluation, limitations: ['Unexamined basket routes'] }));
    const content = { ...f.classification, equivalence_review: { ...f.classification.equivalence_review, unresolved: ['Two submitted IDs may be duplicates'] } };
    expect(() => validateV2EvaluationArtifact(f.engagementDir, '04_evaluation_classification.yaml', JSON.stringify(content))).toThrow('EQUIVALENCE_REVIEW_UNRESOLVED');
  });
  it('does not let an evaluator revive a rejected claim or silently discard an accepted one', () => {
    const f = fixture(); f.review.reviewedFindings[0]!.action = 'rejected'; f.save();
    expect(() => validateV2Evaluation(f.engagementDir)).toThrow('expected final_status FALSE_POSITIVE');
    f.review.reviewedFindings[0]!.action = 'retained'; f.classification.candidates[0]!.final_status = 'BACKLOG'; f.save();
    expect(() => validateV2Evaluation(f.engagementDir)).toThrow('expected final_status CONFIRMED or DOWNGRADED');
  });
  it('still blocks fabricated source-guard counterevidence instead of fabricating CISO approval', () => {
    const f = fixture(); f.review.reviewedFindings[0]!.action = 'rejected'; f.save();
    const classification = { ...f.classification, candidates: [{ ...f.classification.candidates[0], final_status: 'FALSE_POSITIVE',
      counter_evidence: 'refuted: `isAdmin(r)` guard at app.js:1 blocks unauthorized access' }] };
    expect(() => validateV2EvaluationArtifact(f.engagementDir, '04_evaluation_classification.yaml', JSON.stringify(classification), f.target))
      .toThrow('DISPUTED_UNRESOLVED_AT_PUBLISH');
  });
  it('repairs invalid classifications inside the same SDK session without writing bad content', async () => {
    const f = fixture();
    const options = buildOptions({ domain: 'offsec', phase: 'evaluate', contractPath,
      target: f.target, engagementDir: f.engagementDir, engagementId: 'fixture', prompt: 'fixture' });
    const hook = options.hooks!.PreToolUse![0]!.hooks[0] as unknown as (input: Record<string, unknown>) => Promise<{ hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string } }>;
    const path = join(f.engagementDir, '04_evaluation_classification.yaml');
    const original = readFileSync(path, 'utf8');
    const write = () => hook({ hook_event_name: 'PreToolUse', tool_name: 'Write', tool_input: { file_path: path, content: JSON.stringify(f.classification) } });
    f.classification.equivalence_review.groups[0]!.decision = 'FOLD';
    const denied = await write();
    expect(denied.hookSpecificOutput?.permissionDecision).toBe('deny');
    expect(denied.hookSpecificOutput?.permissionDecisionReason).toContain('MERGE, SPLIT, KEEP');
    expect(readFileSync(path, 'utf8')).toBe(original);
    f.classification.equivalence_review.groups[0]!.decision = 'KEEP';
    expect((await write()).hookSpecificOutput?.permissionDecision).not.toBe('deny');
    // Path authorization still takes precedence over artifact content validation.
    const outside = await hook({ hook_event_name: 'PreToolUse', tool_name: 'Write', tool_input: { file_path: join(f.target, '04_evaluation_classification.yaml'), content: '{}' } });
    expect(outside.hookSpecificOutput?.permissionDecision).toBe('deny');
    expect(outside.hookSpecificOutput?.permissionDecisionReason).toContain('현재 phase 계약 파일');
  });
  it('validates review references on Write before starting evaluation', () => {
    const f = fixture(), adapter = new OffsecDomainAdapter(contract);
    const input = { phase: adapter.getPhase('review').legacy, engagementDir: f.engagementDir, target: f.target, name: '03_review_result.json' };
    expect(() => adapter.validateArtifactWrite({ ...input, content: JSON.stringify({ reviewedFindings: [] }) })).toThrow(`did not classify ${f.record.id}`);
    expect(() => adapter.validateArtifactWrite({ ...input, content: JSON.stringify(f.review) })).toThrow('original source');
    expect(() => adapter.validateArtifactWrite({ ...input, content: JSON.stringify(f.review),
      events: deliveryFixture({ target: f.target } as SessionSpec, join(f.target, 'app.js')) })).not.toThrow();
  });

});
