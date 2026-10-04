import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { submitStandardFinding } from '../finding-contract.js';
import { loadOffsecContract } from '../offsec-contract.js';
import { validateV2Evaluation, validateV2ReviewSourceReads } from '../v2-evaluation.js';
import { buildOptions } from '../session.js';

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
  const classification = {
    candidates: [{ id: record.id, final_status: 'CONFIRMED', severity: 'MEDIUM',
      evidence: { locations: ['app.js:1'] }, validity: { reachable: 'source disclosure', business_relevance: 'credential use', exploit_path: 'source to token' } }],
    equivalence_review: { status: 'COMPLETE', reviewed_candidate_count: 1, unresolved: [],
      groups: [{ group_id: 'G1', members: [record.id], decision: 'KEEP', reason: 'A single credential storage root cause.' }] },
  };
  function save() {
    writeFileSync(join(engagementDir, '04_evaluation.json'), JSON.stringify(evaluation));
    writeFileSync(join(engagementDir, '04_evaluation_classification.yaml'), JSON.stringify(classification));
  }
  save(); return { target, engagementDir, record, evaluation, classification, save };
}
describe('v2 real-model evaluation regression', () => {
  it('requires a reviewer source Read independently of analyzer quotations', () => {
    const f = fixture();
    writeFileSync(join(f.engagementDir, '03_review_result.json'), JSON.stringify({ reviewedFindings: [{ originalFindingId: f.record.id, action: 'retained' }] }));
    expect(() => validateV2ReviewSourceReads(f.engagementDir, f.target, [])).toThrow('original source');
    expect(() => validateV2ReviewSourceReads(f.engagementDir, f.target, [{ at: new Date().toISOString(), event: 'PreToolUse', tool: 'Read', resource: join(f.target, 'app.js'), decision: 'allow' }])).not.toThrow();
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
  });
  it('binds artifact identifiers to phase basenames in provider output', () => {
    const f = fixture();
    const schema = buildOptions({ domain: 'offsec', phase: 'evaluate', contractPath,
      target: f.target, engagementDir: f.engagementDir, engagementId: 'fixture', prompt: 'fixture' }).outputFormat!.schema;
    expect((schema.properties as any).artifacts.items.enum).toEqual(['04_evaluation.json', '04_evaluation_classification.yaml']);
  });
});
