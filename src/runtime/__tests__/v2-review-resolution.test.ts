import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { submitStandardFinding, type StandardFinding } from '../finding-contract.js';
import { loadOffsecContract } from '../offsec-contract.js';
import { canonicalV2Findings, resolveV2Review, ReviewFinalizationError } from '../v2-review-resolution.js';
import { validateV2EvaluationArtifact } from '../v2-evaluation.js';

const contract = loadOffsecContract(resolve(import.meta.dirname, '../../../domains/offsec/contracts/offsec-contract.v2.json'));
function fixture() {
  const target = mkdtempSync(join(tmpdir(), 'review-resolution-source-'));
  const engagementDir = mkdtempSync(join(tmpdir(), 'review-resolution-run-'));
  writeFileSync(join(target, 'app.js'), "const secret = 'fixture-token';\n");
  const positions = new Map<string, number>();
  function submit(title: string, role = 'analyzer', verdict: StandardFinding['verdict'] = 'supported') {
    if (!positions.has(title)) { positions.set(title, positions.size + 1); writeFileSync(join(target, 'app.js'), Array.from(positions.keys(), (_, i) => `const secret${i + 1} = 'fixture-token';`).join('\n') + '\n'); }
    const line = positions.get(title)!;
    return submitStandardFinding({ contract, target, engagementDir, role, phase: role === 'reviewer' ? 'review' : 'analyze',
      finding: { title, verdict, severity: 'MEDIUM', evidenceClass: 'configuration', reachability: 'plausible',
        preconditions: ['Source access'], severityRationale: 'Reusable credential disclosure', confidence: 0.8,
        impact: 'Credential disclosure', remediation: 'External secret storage', standards: ['CWE-798'], unresolved: verdict === 'supported' ? [] : ['Requires independent verification'],
        evidence: [{ path: 'app.js', lineStart: line, lineEnd: line, quote: `const secret${line} = 'fixture-token';` }] } });
  }
  const review: { reviewedFindings: Array<Record<string, unknown>>; newFindings: string[] } = { reviewedFindings: [], newFindings: [] };
  const save = () => writeFileSync(join(engagementDir, '03_review_result.json'), JSON.stringify(review));
  const row = (id: string, action: string, extra = {}) => review.reviewedFindings.push({ originalFindingId: id, action,
    reviewedSeverity: canonicalV2Findings(engagementDir).get(id)?.severity, reason: 'Verified source and claim', ...extra });
  const ledger = () => readdirSync(join(engagementDir, 'standard-findings')).sort().map(name => [name, readFileSync(join(engagementDir, 'standard-findings', name), 'utf8')]);
  return { target, engagementDir, submit, review, save, row, ledger };
}
describe('host projection of reviewed findings', () => {
  it('rejects explicit reason/rating contradictions even when reviewedSeverity copies the ledger', () => {
    const f = fixture(), a = f.submit('Explicit rating contradiction');
    for (const reason of ['Source checked. LOW given the deployment preconditions.',
      'Source checked. HIGH is justified: a privileged action is reachable.',
      'Source checked. LOW for an avoidable weak-RNG anti-pattern is justified.',
      '소스를 확인했다. 심각도는 HIGH로 판정한다.']) {
      f.review.reviewedFindings = []; f.row(a.id, 'retained', { reason }); f.save();
      expect(() => resolveV2Review(f.engagementDir)).toThrow('reason explicitly asserts');
      expect(() => resolveV2Review(f.engagementDir, undefined, { partial: true })).not.toThrow();
    }
    for (const reason of ['MEDIUM is justified; HIGH would require evidence of a privileged consumer.',
      'The prior reason said "LOW is justified". Reassessment supports MEDIUM.',
      'HIGH would be justified if privileged reachability were proven. MEDIUM is appropriate here.',
      'HIGH is justified only if a privileged consumer exists; that remains unproven. MEDIUM is appropriate.']) {
      f.review.reviewedFindings = []; f.row(a.id, 'retained', { reason }); f.save();
      expect(() => resolveV2Review(f.engagementDir)).not.toThrow();
    }
  });
  it('requires an explicit retained severity and rejects a prose-only downgrade before publication', () => {
    const f = fixture(), a = f.submit('Rating needs independent review');
    f.row(a.id, 'retained', { reviewedSeverity: undefined, reason: 'LOW given the limited deployment preconditions.' }); f.save();
    expect(resolveV2Review(f.engagementDir, undefined, { partial: true }).dispositions).toHaveLength(1);
    expect(() => resolveV2Review(f.engagementDir)).toThrow(ReviewFinalizationError);
    f.review.reviewedFindings[0]!.reviewedSeverity = 'LOW'; f.save();
    expect(() => resolveV2Review(f.engagementDir, undefined, { partial: true })).toThrow('submit_finding');
    expect(() => validateV2EvaluationArtifact(f.engagementDir, '04_evaluation.json', '{"severityDistribution":{"MEDIUM":1}}')).toThrow('reviewedSeverity LOW');
    f.submit('Rating needs independent review', 'reviewer');
    f.review.reviewedFindings[0] = { originalFindingId: a.id, action: 'corrected', correctedFindingId: a.id,
      reviewedSeverity: 'MEDIUM', reason: 'Reassessed the deployment exposure; the canonical MEDIUM rating is supported.' };
    f.save(); expect(resolveV2Review(f.engagementDir).severityDistribution.MEDIUM).toBe(1);
  });
  it('T17 treats shared citations as hints and requires causal metadata for independent totals', () => {
    const f = fixture();
    const quote = 'res.send(readFileSync(req.query.path));'; writeFileSync(join(f.target, 'app.js'), quote + '\n');
    const evidence = [{ path: 'app.js', lineStart: 1, lineEnd: 1, quote }];
    const submit = (title: string) => submitStandardFinding({ contract, target: f.target, engagementDir: f.engagementDir, role: 'analyzer', phase: 'analyze',
      finding: { title, verdict: 'supported', severity: 'HIGH', evidenceClass: 'data-flow', reachability: 'confirmed', preconditions: ['Public request handler'],
        severityRationale: 'Untrusted request reaches filesystem and response operations', confidence: 0.8, impact: 'File contents reach a client response',
        remediation: 'Constrain paths and encode the response for its media type', standards: [], unresolved: [], evidence } });
    const a = submit('Arbitrary file read'), b = submit('User-controlled path file disclosure');
    f.row(a.id, 'retained'); f.row(b.id, 'retained'); f.save();
    expect(resolveV2Review(f.engagementDir).citationOverlapGroups).toEqual([[a.id,b.id].sort()]);
    expect(resolveV2Review(f.engagementDir).vulnerabilityInventory.independentVulnerabilityCount).toBeNull();
    f.review.reviewedFindings[0]!.distinctCause = { rootCause: 'Filesystem path from the request lacks a directory allowlist', impact: 'Disclosure of files readable by the server process', evidence };
    f.review.reviewedFindings[1]!.distinctCause = { rootCause: 'Response sends attacker-selected HTML bytes without output encoding', impact: 'Script execution in a browser interpreting the HTML response', evidence };
    f.save(); expect(resolveV2Review(f.engagementDir).severityDistribution.HIGH).toBe(2);
    f.review.reviewedFindings[1]!.distinctCause = { rootCause: 'Different title for the same path disclosure vulnerability', impact: 'Disclosure of files readable by the server process', evidence };
    f.save(); expect(resolveV2Review(f.engagementDir).vulnerabilityInventory.independentVulnerabilityCount).toBeNull();
    writeFileSync(join(f.engagementDir, '03_review_result.json'), JSON.stringify({ ...f.review, countingSchemaVersion: 1 }));
    expect(() => resolveV2Review(f.engagementDir)).toThrow('COUNTING_ASSESSMENT_REQUIRED');
    expect(() => resolveV2Review(f.engagementDir, undefined, {partial:true})).not.toThrow();
  });
  it('does not classify repeated citations within one finding as two different findings', () => {
    const f = fixture(), a = f.submit('One supported cause');
    const path = readdirSync(join(f.engagementDir, 'standard-findings')).map(name => join(f.engagementDir, 'standard-findings', name))
      .find(path => JSON.parse(readFileSync(path, 'utf8')).id === a.id)!;
    const record = JSON.parse(readFileSync(path, 'utf8')); record.evidence.push(record.evidence[0]); writeFileSync(path, JSON.stringify(record));
    f.row(a.id, 'retained'); f.save();
    expect(resolveV2Review(f.engagementDir).severityDistribution.MEDIUM).toBe(1);
  });
  it('reproduces the 29 historical IDs / 27 accepted findings Juice Shop case without rewriting history', () => {
    const f = fixture();
    for (let i = 0; i < 25; i++) f.row(f.submit(`Retained ${i}`).id, 'retained');
    const rejected = f.submit('Unsupported aggregate', 'analyzer', 'escalate');
    const original = f.submit('Incorrect evidence aggregate', 'analyzer', 'escalate');
    const corrected = f.submit('Corrected evidence', 'reviewer');
    const added = f.submit('Reviewer discovery', 'reviewer');
    f.row(rejected.id, 'rejected');
    f.row(original.id, 'corrected', { correctedFindingId: corrected.id });
    f.review.newFindings.push(added.id); f.save();
    const before = f.ledger(), resolved = resolveV2Review(f.engagementDir);
    expect(resolved.dispositions).toHaveLength(29);
    expect(resolved.severityDistribution.MEDIUM).toBe(27);
    expect(resolved.dispositions.find(r => r.id === rejected.id)).toMatchObject({ finalStatus: 'FALSE_POSITIVE' });
    expect(resolved.dispositions.find(r => r.id === original.id)).toMatchObject({ finalStatus: 'FOLDED_INTO', foldedInto: corrected.id });
    expect(f.ledger()).toEqual(before);
    const classification = {
      candidates: resolved.dispositions.map(d => ({ id: d.id, final_status: d.finalStatus, severity: d.severity,
        folded_into: d.foldedInto, counter_evidence: d.reason, evidence: { locations: ['app.js:1'] } })),
      equivalence_review: { status: 'COMPLETE', reviewed_candidate_count: 29, unresolved: [], groups: [
        { group_id: 'correction', decision: 'MERGE', members: [original.id, corrected.id], representative: corrected.id, affected_instances: ['app.js:1'] },
      ] },
    };
    expect(() => validateV2EvaluationArtifact(f.engagementDir, '04_evaluation_classification.yaml', JSON.stringify(classification), f.target)).not.toThrow();
    expect(() => validateV2EvaluationArtifact(f.engagementDir, '04_evaluation.json', JSON.stringify({ severityDistribution: resolved.severityDistribution }))).not.toThrow();
    classification.candidates.find(c => c.id === original.id)!.folded_into = added.id;
    expect(() => validateV2EvaluationArtifact(f.engagementDir, '04_evaluation_classification.yaml', JSON.stringify(classification))).toThrow(`requires folded_into ${corrected.id}`);
  });
  it('supports same-ID corrections and preserves inconclusive risks as backlog', () => {
    const f = fixture(), original = f.submit('Same ID correction');
    f.submit('Same ID correction', 'reviewer');
    const inconclusive = f.submit('Unresolved risk', 'analyzer', 'abstain');
    f.row(original.id, 'corrected', { correctedFindingId: original.id }); f.row(inconclusive.id, 'inconclusive'); f.save();
    const result = resolveV2Review(f.engagementDir);
    expect(result.severityDistribution.MEDIUM).toBe(1);
    expect(result.dispositions.find(d => d.id === inconclusive.id)?.finalStatus).toBe('BACKLOG');
  });
  it('folds an explicit single duplicate without inventing a representative for multi-cause aggregates', () => {
    const f = fixture(), a = f.submit('Cause A'), b = f.submit('Cause B'), duplicate = f.submit('Duplicate A'), aggregate = f.submit('Aggregate AB');
    f.row(a.id, 'retained'); f.row(b.id, 'retained');
    f.row(duplicate.id, 'rejected', { mergedFrom: [duplicate.id, a.id] });
    f.row(aggregate.id, 'rejected', { mergedFrom: [aggregate.id, a.id, b.id] }); f.save();
    const result = resolveV2Review(f.engagementDir);
    expect(result.severityDistribution.MEDIUM).toBe(2);
    expect(result.dispositions.find(d => d.id === duplicate.id)).toMatchObject({ finalStatus: 'FOLDED_INTO', foldedInto: a.id });
    expect(result.dispositions.find(d => d.id === aggregate.id)).toMatchObject({ finalStatus: 'FALSE_POSITIVE', relatedIds: [a.id, b.id] });
  });
  it('rejects missing, duplicate, and invented review references', () => {
    const f = fixture(), a = f.submit('A'); f.save();
    expect(() => resolveV2Review(f.engagementDir)).toThrow(`did not classify ${a.id}`);
    f.row(a.id, 'retained'); f.row(a.id, 'rejected'); f.save();
    expect(() => resolveV2Review(f.engagementDir)).toThrow('exactly once');
    f.review.reviewedFindings.pop(); f.review.reviewedFindings[0]!.action = 'corrected';
    f.review.reviewedFindings[0]!.correctedFindingId = 'F-999999'; f.save();
    expect(() => resolveV2Review(f.engagementDir)).toThrow('submitted reviewer correctedFindingId');
    f.review.reviewedFindings[0]!.action = 'retained'; f.review.newFindings.push('F-999999'); f.save();
    expect(() => resolveV2Review(f.engagementDir)).toThrow('not submitted by reviewer');
  });
  it('reports duplicate row positions, unknown IDs, invalid actions and all missing IDs together', () => {
    const f = fixture(), a = f.submit('A'), b = f.submit('B'), c = f.submit('C'), d = f.submit('D');
    f.row(a.id, 'retained'); f.row(a.id, 'rejected');
    f.row('F-999999999999', 'retained'); f.row(b.id, 'invalid'); f.save();
    let error = '';
    try { resolveV2Review(f.engagementDir); } catch (caught) { error = String(caught); }
    expect(error).toContain(`${a.id} (duplicate rows 1 and 2)`);
    expect(error).toContain('F-999999999999 (unknown ID at row 3)');
    expect(error).toContain(`${b.id} requires action`);
    for (const finding of [b, c, d]) expect(error).toContain(finding.id);
  });
  it('does not automatically accept unreviewed additions or unsupported escalations', () => {
    const f = fixture(), a = f.submit('Unproven', 'analyzer', 'escalate'); f.row(a.id, 'retained'); f.save();
    expect(() => resolveV2Review(f.engagementDir)).toThrow('cannot accept');
    f.review.reviewedFindings[0]!.action = 'inconclusive';
    const addition = f.submit('Unlisted addition', 'reviewer'); f.save();
    expect(() => resolveV2Review(f.engagementDir)).toThrow(`did not account for reviewer finding ${addition.id}`);
    f.row(addition.id, 'inconclusive'); f.save();
    expect(resolveV2Review(f.engagementDir).dispositions.every(d => d.finalStatus === 'BACKLOG')).toBe(true);
  });
  it('returns all unsupported verdicts, missing corrections and unknown additions in one repair request', () => {
    const f = fixture(), a = f.submit('Escalated A', 'analyzer', 'escalate'), b = f.submit('Abstained B', 'analyzer', 'abstain');
    const c = f.submit('Needs correction C'), d = f.submit('Needs correction D');
    f.row(a.id, 'retained'); f.row(b.id, 'retained');
    f.row(c.id, 'corrected', { correctedFindingId: 'F-999999999998' });
    f.row(d.id, 'corrected', { correctedFindingId: 'F-999999999997' });
    f.review.newFindings.push('F-999999999996'); f.save();
    const before = f.ledger();
    let error = '';
    try { resolveV2Review(f.engagementDir); } catch (caught) { error = String(caught); }
    for (const finding of [a, b]) expect(error).toContain(`cannot accept ${finding.id}`);
    for (const finding of [c, d]) expect(error).toContain(`correction for ${finding.id}`);
    expect(error).toContain('not submitted by reviewer: F-999999999996');
    expect(f.ledger()).toEqual(before);
    f.review.reviewedFindings.forEach(row => { row.action = 'inconclusive'; });
    f.review.newFindings = []; f.save();
    expect(resolveV2Review(f.engagementDir).dispositions.every(row => row.finalStatus === 'BACKLOG')).toBe(true);
  });
  it('allows multiple reviewed corrections to share one submitted representative without double counting', () => {
    const f = fixture(), a = f.submit('A'), b = f.submit('B'), representative = f.submit('Combined evidence', 'reviewer');
    f.row(a.id, 'corrected', { correctedFindingId: representative.id });
    f.row(b.id, 'corrected', { correctedFindingId: representative.id }); f.save();
    const result = resolveV2Review(f.engagementDir);
    expect(result.dispositions.filter(d => d.finalStatus === 'FOLDED_INTO')).toHaveLength(2);
    expect(result.severityDistribution.MEDIUM).toBe(1);
  });
});
