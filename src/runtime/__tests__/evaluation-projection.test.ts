import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { submitStandardFinding } from '../finding-contract.js';
import { assertEvaluationProjection, buildEvaluationClassification, writeEvaluationProjection } from '../evaluation-projection.js';
import { validateV2EvaluationArtifact } from '../v2-evaluation.js';
import { loadPreanalysisEvidence } from '../workflow/preanalysis-evidence.js';
import { canonicalFindingAppendix } from '../report-appendix.js';
import { normalizeCurrentV2OffsecFindings } from '../../../evals/offsec/adapters/current-v2.js';
import type { BenchmarkRunRecord } from '../offsec-benchmark.js';

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function fixture(count = 5) {
  const root = mkdtempSync(join(tmpdir(), 'evaluation-projection-')); roots.push(root);
  const lines = Array.from({ length: count }, (_, index) => `export const fixture_${index} = ${index};`);
  writeFileSync(join(root, 'app.js'), lines.join('\n') + '\n');
  const submit = (index: number, role = 'analyzer', title = `Fixture ${index}`) => submitStandardFinding({ target: root, engagementDir: root,
    role, phase: role === 'reviewer' ? 'review' : 'analyze', finding: { title, verdict: 'supported', severity: 'LOW',
      evidenceClass: 'configuration', reachability: 'plausible', preconditions: ['Synthetic fixture'], severityRationale: 'Fixture only',
      confidence: 0.5, impact: 'Fixture impact', remediation: 'Review consuming behavior', standards: [], unresolved: ['Not a live exploit'],
      evidence: [{ path: 'app.js', lineStart: index + 1, lineEnd: index + 1, quote: lines[index]! }] } });
  const records = lines.map((_, index) => submit(index));
  const rows: any[] = records.map(record => ({ originalFindingId: record.id, action: 'retained', reviewedSeverity: 'LOW', reason: `Reviewed the isolated fixture constant at app.js:${record.evidence[0]!.lineStart}` }));
  const save = () => writeFileSync(join(root, '03_review_result.json'), JSON.stringify({ reviewedFindings: rows, newFindings: [] }));
  save();
  const preanalysis = loadPreanalysisEvidence(join(root, 'missing.yaml'), root, [join(root, 'app.js')]);
  const write = () => writeEvaluationProjection({ root, coverage: { complete: true, semanticCoverage: 'not-proven' }, preanalysis,
    validate: content => validateV2EvaluationArtifact(root, '04_evaluation_classification.yaml', content, root, { prepareHostProjection: true }) });
  return { root, records, rows, submit, save, write, preanalysis };
}

describe('host projection of finalized review', () => {
  it('publishes one independent cause, two corroborating records and a separate observation', () => {
    const f = fixture(3);
    const cause = { kind: 'vulnerability', causeId: 'VC-same-root-cause', component: 'fixture',
      rootCause: 'The same independent security control is absent', fixBoundary: 'Repair the common configuration validation boundary' };
    f.rows[0].counting = { ...cause, primaryEvidence: f.records[0]!.evidence };
    f.rows[1].counting = { ...cause, primaryEvidence: f.records[1]!.evidence };
    f.rows[2].counting = {kind: 'observation', reason: 'This fixture illustrates a quality issue without a security impact'};
    f.save();
    const reviewPath = join(f.root,'03_review_result.json');
    writeFileSync(reviewPath,JSON.stringify({...JSON.parse(readFileSync(reviewPath,'utf8')),countingSchemaVersion:1}));
    f.write();
    const c = buildEvaluationClassification(f.root);
    expect(c.vulnerability_inventory).toMatchObject({ independentVulnerabilityCount:1,acceptedRecordCount:3,observationCount:1 });
    expect(c.vulnerability_inventory.causes[0]!.evidence).toHaveLength(2);
    const input = JSON.parse(readFileSync(join(f.root, '03_evaluation_input.json'), 'utf8'));
    const evaluation = {severityDistribution:input.severityDistribution,actualToolCoverage:input.actualToolCoverage,vulnerabilityInventory:input.vulnerabilityInventory};
    expect(() => validateV2EvaluationArtifact(f.root,'04_evaluation.json',JSON.stringify(evaluation))).not.toThrow();
    evaluation.vulnerabilityInventory.independentVulnerabilityCount = 3;
    expect(() => validateV2EvaluationArtifact(f.root,'04_evaluation.json',JSON.stringify(evaluation))).toThrow('vulnerabilityInventory must equal');
    expect(canonicalFindingAppendix(f.root)).toContain('독립 취약점: **1**');
    expect(canonicalFindingAppendix(f.root)).toContain('별도 관찰: **1**');
    const normalized = normalizeCurrentV2OffsecFindings({engagementDir:f.root,run:{runId:'run-'+'a'.repeat(20),runSha256:'b'.repeat(64),caseId:'case-'+'c'.repeat(8),arm:'current-parallel'} as BenchmarkRunRecord});
    expect(normalized).toHaveLength(1); expect(normalized[0]!.findingId).toBe('VC-same-root-cause');
    expect(normalized[0]!.evidence).toHaveLength(2);
  });
  it('serializes more than 300 IDs without dropping corrected, rejected or backlog history', () => {
    const f = fixture(301), corrected = f.submit(0, 'reviewer', 'Corrected first fixture');
    f.rows[0] = { ...f.rows[0], action: 'corrected', correctedFindingId: corrected.id };
    f.rows[1] = { ...f.rows[1], action: 'rejected', mergedFrom: [f.records[1]!.id, f.records[0]!.id], reason: 'Duplicate of the corrected first fixture' };
    f.rows[2] = { ...f.rows[2], action: 'rejected', reason: 'Synthetic constant has no sensitive consumer' };
    f.rows[3] = { ...f.rows[3], action: 'inconclusive', reason: 'A consuming application remains unexamined' }; f.save();
    const result = f.write(), classification = buildEvaluationClassification(f.root);
    expect(result.candidates).toBe(302);
    expect(classification.candidates.find(row => row.id === f.records[1]!.id)).toMatchObject({ final_status: 'FOLDED_INTO', folded_into: corrected.id });
    expect(classification.candidates.find(row => row.id === f.records[2]!.id)?.final_status).toBe('FALSE_POSITIVE');
    expect(classification.candidates.find(row => row.id === f.records[3]!.id)?.final_status).toBe('BACKLOG');
    expect(classification.candidates.find(row => row.id === corrected.id)?.unresolved).toEqual(['Not a live exploit']);
    expect(() => assertEvaluationProjection(f.root)).not.toThrow();
    const original = readFileSync(result.classificationPath, 'utf8'); f.write();
    expect(readFileSync(result.classificationPath, 'utf8')).toBe(original);
    const appendix = canonicalFindingAppendix(f.root);
    expect(appendix.match(/^### F-\d{12}$/gm)).toHaveLength(302);
    for (const record of [...f.records, corrected]) expect(appendix).toContain(`### ${record.id}\n`);
    expect(appendix).toContain('FOLDED_INTO'); expect(appendix).toContain('FALSE_POSITIVE'); expect(appendix).toContain('BACKLOG');
    expect(appendix).toContain('Not a live exploit');
    expect(appendix).toContain(result.classificationSha256); expect(appendix).toContain(result.inputSha256);
    expect(canonicalFindingAppendix(f.root)).toBe(appendix);
  }, 15000);
  it('rejects rewriting the sealed classification even when severity counts are unchanged', () => {
    const f = fixture(), result = f.write(), content = JSON.parse(readFileSync(result.classificationPath, 'utf8'));
    content.candidates[0].title = 'Invented replacement title';
    expect(() => validateV2EvaluationArtifact(f.root, '04_evaluation_classification.yaml', JSON.stringify(content), f.root)).toThrow('immutable');
  });
  it.each(['review', 'finding', 'input'])('rejects stale or modified %s input', change => {
    const f = fixture(), result = f.write();
    if (change === 'review') { f.rows[0].reason += ' changed'; f.save(); }
    if (change === 'finding') f.submit(0, 'reviewer', f.records[0]!.title);
    if (change === 'input') writeFileSync(result.path, '{}');
    expect(() => assertEvaluationProjection(f.root)).toThrow(/stale|integrity/);
  });
  it('keeps the source counterevidence gate and does not create artifacts for a fabricated guard', () => {
    const f = fixture(); f.rows[0] = { ...f.rows[0], action: 'rejected', reason: 'The isAdmin(request) guard at app.js:1 blocks access' }; f.save();
    expect(() => f.write()).toThrow('DISPUTED_UNRESOLVED');
    expect(existsSync(join(f.root, '03_evaluation_input.json'))).toBe(false);
  });
  it('renders untrusted finding markup as text in the host appendix', () => {
    const f = fixture(1), corrected = f.submit(0, 'reviewer', '<script>alert(1)</script> [misleading](javascript:alert(1))');
    f.rows[0] = { ...f.rows[0], action: 'corrected', correctedFindingId: corrected.id }; f.save(); f.write();
    const appendix = canonicalFindingAppendix(f.root);
    expect(appendix).not.toContain('<script>');
    expect(appendix).toContain('&lt;script&gt;');
    expect(appendix).not.toContain('[misleading](javascript:');
    f.rows[0].reason = 'Changed after sealing'; f.save();
    expect(() => canonicalFindingAppendix(f.root)).toThrow('stale');
  });
  it.each(['semgrepFindings', 'parsedFiles', 'parsedExtensions'])('rejects stale %s statistics instead of silently treating missing input as zero', field => {
    const f = fixture();
    f.preanalysis.semgrepFindings = Array.from({ length: 9 }, () => ({ file: 'app.js' }));
    f.preanalysis.parsedFiles = ['app.js'];
    const projection = f.write(), input = JSON.parse(readFileSync(projection.path, 'utf8'));
    const evaluation = { severityDistribution: input.severityDistribution, actualToolCoverage: input.actualToolCoverage, vulnerabilityInventory: input.vulnerabilityInventory };
    expect(() => validateV2EvaluationArtifact(f.root, '04_evaluation.json', JSON.stringify(evaluation))).not.toThrow();
    evaluation.actualToolCoverage[field] = field === 'parsedExtensions' ? { '.sol': 1 } : 0;
    expect(() => validateV2EvaluationArtifact(f.root, '04_evaluation.json', JSON.stringify(evaluation))).toThrow(`actualToolCoverage.${field}`);
    delete evaluation.actualToolCoverage[field];
    expect(() => validateV2EvaluationArtifact(f.root, '04_evaluation.json', JSON.stringify(evaluation))).toThrow(`actualToolCoverage.${field}`);
  });
  it('distinguishes explicit overlapping aggregates from source-guard refutations', () => {
    const f = fixture(); f.rows[0] = { ...f.rows[0], action: 'rejected', mergedFrom: [f.records[0]!.id, f.records[1]!.id, f.records[2]!.id],
      reason: 'The same two reviewed causes overlap this aggregate; there is no independent finding.' }; f.save();
    f.write();
    expect(buildEvaluationClassification(f.root).candidates.find(row => row.id === f.records[0]!.id)?.counter_evidence).toMatchObject({ related_finding_ids: [f.records[1]!.id, f.records[2]!.id] });
  });
});
