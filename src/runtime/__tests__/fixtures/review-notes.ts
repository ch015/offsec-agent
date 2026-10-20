import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { FileRunStateStore } from '../../workflow/state-store.js';
import { submitStandardFinding, readStandardFindingRecordReceipts } from '../../finding-contract.js';
import { ResultRecordReader } from '../../result-records.js';
import type { ReviewNoteInput } from '../../review-notes.js';

export function reviewNotesFixture(base: string, runId = 'notes-fixture') {
  const root = join(base, 'run'), target = join(base, 'source'); mkdirSync(root); mkdirSync(target);
  const state = FileRunStateStore.create({ engagementDir: root, runId, contractId: 'fixture', contractVersion: '1', domain: 'offsec', mission: 'assessment' });
  writeFileSync(join(root, 'source_manifest.json'), JSON.stringify({ source_files: ['app.ts'] }));
  writeFileSync(join(root, '03_review_result.json'), JSON.stringify({ reviewedFindings: [] }));
  writeFileSync(join(target, 'app.ts'), 'export const a = 1;\n');
  const finding = submitStandardFinding({ target, engagementDir: root, role: 'analyzer', phase: 'analyze', finding: {
    title: 'Fixture consumer uncertain', verdict: 'supported', severity: 'LOW', evidenceClass: 'configuration', reachability: 'plausible',
    preconditions: ['A sensitive downstream consumer'], severityRationale: 'Unverified downstream impact', confidence: 0.3,
    impact: 'Unverified downstream use', remediation: 'Review the consuming component', standards: [], unresolved: [],
    evidence: [{ path: 'app.ts', lineStart: 1, lineEnd: 1, quote: 'export const a = 1;' }],
  } });
  const references = () => {
    const reader = new ResultRecordReader(root);
    return [reader.reference('03_review_result.json'), ...readStandardFindingRecordReceipts(root).map(record => reader.reference(`standard-findings/${record.recordName}`))];
  };
  const note: ReviewNoteInput = { id: 'D1', kind: 'dispute', author: 'fixture human reviewer', findingIds: [finding.id],
    rationale: 'Record both interpretations until the consuming behavior is established.',
    assertions: ['The downstream consumer may treat the value as sensitive.', 'The fixture does not establish that a sensitive consumer exists.'], references: references() };
  return { root, base, finding, references, note, state };
}

