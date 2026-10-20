import { mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { tmpdir } from 'node:os';
import { afterEach, expect, it } from 'vitest';
import { createOffsecAgent } from '../../api/agent.js';
import { submitStandardFinding } from '../finding-contract.js';
import { auditResultRecords, renderResultAudit } from '../result-audit.js';
import { contentHash } from '../result-records.js';
import { appendReviewNote } from '../review-notes.js';
import { syntheticOutcome } from './resumption-fixture.js';
import { deliveryFixture } from './assessment-protocol-fixture.js';
import { runResultAdmin } from '../../../scripts/results-admin.js';
import { FileRunStateStore } from '../workflow/state-store.js';

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
it('keeps missing coverage unknown instead of displaying zero uncovered files', () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'missing-audit-'))); roots.push(root);
  FileRunStateStore.create({ engagementDir: root, runId: 'missing-coverage', contractId: 'fixture', contractVersion: '1', domain: 'offsec', mission: 'assessment' });
  writeFileSync(join(root, 'source_manifest.json'), '{"source_files":[]}');
  const audit = auditResultRecords(root);
  expect(audit.coverage).toMatchObject({ originalComplete: null, finalRecordedComplete: null, beforeUncoveredFiles: null, afterUncoveredFiles: null,
    removedFromRecordedList: null, addedToRecordedList: null });
  expect(renderResultAudit(audit)).toContain('미확인 파일: 미기록 → 미기록');
  expect(audit.issues.map(issue => issue.code)).toContain('completion-coverage-unavailable');
});
it('reconciles recorded answers without erasing unresolved checks or changing published artifacts', async () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'result-audit-'))); roots.push(root);
  const target = join(root, 'source'), engagementDir = join(root, 'run'); mkdirSync(target);
  const quote = 'export const session = 1;'; writeFileSync(join(target, 'app.ts'), quote + '\n');
  let findingId = '', reviews = 0, sessionCalls = 0;
  const agent = createOffsecAgent({ astBuilder: async () => ({ ok: false }), scheduler: { retryBaseMs: 1, controlIntervalMs: 1, resourceCapacity: () => 10 },
    sessionRunner: async spec => {
      sessionCalls++;
      const outcome = syntheticOutcome(spec);
      if (spec.workUnit) {
        findingId = submitStandardFinding({ target: spec.target, engagementDir: spec.engagementDir, role: 'analyzer', phase: 'analyze', finding: {
          title: 'Fixture consumer remains uncertain', verdict: 'supported', severity: 'LOW', evidenceClass: 'configuration', reachability: 'plausible',
          preconditions: ['A sensitive downstream consumer'], severityRationale: 'Unverified downstream impact', confidence: 0.3,
          impact: 'Unverified downstream use', remediation: 'Review consuming behavior', standards: [], unresolved: [],
          evidence: [{ path: 'app.ts', lineStart: 1, lineEnd: 1, quote }],
        } }).id;
        const path = join(spec.engagementDir, '02_file_assessments.json'), assessments = JSON.parse(readFileSync(path, 'utf8'));
        expect(assessments.securityAssessments.length).toBeGreaterThan(0);
        assessments.securityAssessments[0].cases[0] = { ...assessments.securityAssessments[0].cases[0], result: 'unresolved', reason: 'A different consuming component remains outside this fixture evidence.' };
        writeFileSync(path, JSON.stringify(assessments));
      }
      if (spec.phase === 'review') {
        reviews++;
        writeFileSync(join(spec.engagementDir, '03_review_result.json'), JSON.stringify({ countingSchemaVersion: 1,
          reviewedFindings: [{ originalFindingId: findingId, action: 'inconclusive', reason: 'Original source examined; downstream behavior remains unproven.' }], newFindings: [],
          additionalEvidenceRequests: reviews === 1 ? [{ id: 'R1', question: 'Does the fixture export a constant value at the stated source location?',
            files: ['app.ts'], missingEvidence: 'Confirm the declaration separately from the unresolved consumer.', findingIds: [findingId], flowIds: [] }] : [] }));
        outcome.ledger.push(...deliveryFixture(spec, join(spec.target, 'app.ts')));
      }
      if (spec.phaseRound?.startsWith('review-request-')) {
        writeFileSync(join(spec.engagementDir, '02_followup_answers.json'), JSON.stringify({ answers: [{ id: 'R1', status: 'resolved',
          reason: 'The export is a constant; this answer does not establish the downstream consumer.', evidence: [{ path: 'app.ts', lineStart: 1, lineEnd: 1, quote }] }] }));
        (outcome.structuredOutput as { artifacts: string[] }).artifacts.push('02_followup_answers.json');
      }
      return outcome;
    } });
  const result = await agent.run({ target, engagementDir, mode: 'ast', tools: [] });
  expect(result.publicationStatus, JSON.stringify(result.storage)).toBe('published');
  expect(result.coverage.complete).toBe(false);
  const files = () => readdirSync(engagementDir, { recursive: true, withFileTypes: true }).filter(entry => entry.isFile())
    .map(entry => join(entry.parentPath, entry.name)).sort().map(path => [relative(engagementDir, path), contentHash(readFileSync(path))]);
  const before = files(), calls = sessionCalls;
  const audit = auditResultRecords(engagementDir);
  expect(files()).toEqual(before); expect(sessionCalls).toBe(calls);
  expect(audit.issues).toEqual([]);
  expect(audit.publicationVerified).toBe(true);
  expect(audit.coverage).toMatchObject({ originalComplete: false, finalRecordedComplete: false,
    beforeUncoveredFiles: ['app.ts'], afterUncoveredFiles: ['app.ts'], originalUnresolvedChecks: 1, finalRecordedUnresolvedChecks: 1, removedFromRecordedList: [] });
  expect(audit.followups[0]!.requests[0]).toMatchObject({ id: 'R1', answerStatus: 'resolved' });
  expect(audit.findings.dispositions).toMatchObject({ CONFIRMED: 0, BACKLOG: 1 });
  expect(renderResultAudit(audit)).toContain('1 → 1');
  await expect(runResultAdmin(['inspect', `--engagement=${engagementDir}`, `--output=${join(engagementDir, '07_security_report.md')}`])).rejects.toThrow('outside the engagement');
  const reportBefore = readFileSync(join(engagementDir, '07_security_report.md'));
  const references = audit.references.filter(ref => ref.path.startsWith('standard-findings/') || ref.path === '03_review_result.json');
  appendReviewNote(engagementDir, { id: 'D1', kind: 'dispute', author: 'fixture human reviewer', findingIds: [findingId], references,
    assertions: ['A constant export is proven by the quoted original source.', 'The downstream consuming behavior remains unproven by this quote.'],
    rationale: 'Keep the distinction between an answered question and unresolved coverage explicit.' }, 'empty');
  const noted = auditResultRecords(engagementDir);
  expect(noted.notes.openCount).toBe(1);
  expect(noted.issues.map(issue => issue.code)).toEqual(['manual-disputes-open']);
  expect(readFileSync(join(engagementDir, '07_security_report.md'))).toEqual(reportBefore);
  writeFileSync(join(engagementDir, '00_completion_coverage.json'), '{}');
  expect(() => auditResultRecords(engagementDir)).toThrow();
}, 20000);
