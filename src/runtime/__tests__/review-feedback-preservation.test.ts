import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { createOffsecAgent } from '../../api/agent.js';
import { submitStandardFinding } from '../finding-contract.js';
import { validateV2ReviewSourceReads } from '../v2-evaluation.js';
import type { ReviewReuse } from '../review-progress.js';
import { FileRunStateStore } from '../workflow/state-store.js';
import { syntheticOutcome } from './resumption-fixture.js';
import { deliveryFixture } from './assessment-protocol-fixture.js';

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

it('preserves unrelated decisions and receipts while requiring fresh evidence for a requested finding', async () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'review-feedback-'))); roots.push(root);
  const target = join(root, 'source'), engagementDir = join(root, 'run'); mkdirSync(target);
  const sources = ['a', 'b'].map(name => ({ path: `${name}.ts`, quote: `export const ${name} = 1;` }));
  for (const source of sources) writeFileSync(join(target, source.path), source.quote + '\n');
  const ids = new Map<string, string>(), units: string[] = [], calls: string[] = [];
  let reviews = 0, followups = 0, originalReview = '';
  let unrelated: { originalFindingId: string; action: string; reason: string };
  const agent = createOffsecAgent({ astBuilder: async () => ({ ok: false }),
    scheduler: { retryBaseMs: 1, controlIntervalMs: 1, resourceCapacity: () => 10 },
    sessionRunner: async spec => {
      calls.push(spec.phase!);
      const outcome = syntheticOutcome(spec);
      if (spec.workUnit) {
        units.push(spec.workUnit.unitKey);
        for (const source of sources.filter(source => spec.workUnit!.ownedSourceFiles.includes(join(spec.target, source.path)))) {
          ids.set(source.path, submitStandardFinding({ target: spec.target, engagementDir: spec.engagementDir, phase: 'analyze', role: 'analyzer', finding: {
            title: `Fixture ${source.path} consumer remains unverified`, verdict: 'supported', severity: 'LOW', evidenceClass: 'configuration', reachability: 'plausible',
            preconditions: ['A sensitive downstream consumer'], severityRationale: 'Potential impact requires a consumer', confidence: 0.3,
            impact: 'Unverified downstream use', remediation: 'Review consuming behavior', standards: [], unresolved: [],
            evidence: [{ ...source, lineStart: 1, lineEnd: 1 }],
          } }).id);
        }
      }
      if (spec.phaseRound?.startsWith('review-request-')) {
        followups++;
        expect(spec.taskData?.reviewRequests).toEqual([expect.objectContaining({ findingIds: [ids.get('a.ts')], files: ['a.ts'] })]);
        writeFileSync(join(spec.engagementDir, '02_followup_answers.json'), JSON.stringify({ answers: [{ id: 'R1', status: 'resolved',
          reason: 'The fixture exports a constant and contains no protected operation', evidence: [{ ...sources[0], lineStart: 1, lineEnd: 1 }] }] }));
        (outcome.structuredOutput as { artifacts: string[] }).artifacts.push('02_followup_answers.json');
      }
      if (spec.phase === 'review') {
        reviews++;
        expect(ids.size).toBe(2);
        const requested = { originalFindingId: ids.get('a.ts')!, action: 'inconclusive',
          reason: reviews === 1 ? 'Source examined; downstream use needs additional evidence.' : 'Requested constant verified; sensitive downstream use remains unproven.' };
        unrelated ??= { originalFindingId: ids.get('b.ts')!, action: 'inconclusive', reason: 'Source examined; an unrelated consuming component remains unproven.' };
        const review = { countingSchemaVersion: 1, reviewedFindings: [requested, unrelated], newFindings: [],
          additionalEvidenceRequests: reviews === 1 ? [{ id: 'R1', question: 'Does the requested fixture export a constant or a protected operation?', files: ['a.ts'],
            missingEvidence: 'Confirm the requested export before considering downstream impact', findingIds: [ids.get('a.ts')], flowIds: [] }] : [] };
        writeFileSync(join(spec.engagementDir, '03_review_result.json'), JSON.stringify(review));
        if (reviews === 1) {
          originalReview = JSON.stringify(review);
          for (const source of sources) outcome.ledger.push(...deliveryFixture(spec, join(spec.target, source.path)));
        } else {
          expect(reviews).toBe(2);
          const reuse = spec.taskData?.reviewReuse as ReviewReuse;
          expect(reuse.ids).toEqual([ids.get('b.ts')]);
          expect(reuse.events.some(event => event.event === 'SourceDelivery' && event.resource === join(spec.target, 'b.ts'))).toBe(true);
          expect(readFileSync(spec.taskData!.previousReview as string, 'utf8')).toBe(originalReview);
          // The old receipt for a.ts exists, but the requested ID is excluded.
          expect(() => validateV2ReviewSourceReads(spec.engagementDir, spec.target, [], reuse, review)).toThrow(ids.get('a.ts'));
          outcome.ledger.push(...deliveryFixture(spec, join(spec.target, 'a.ts')));
          expect(outcome.ledger.some(event => event.event === 'SourceDelivery' && event.resource === join(spec.target, 'b.ts'))).toBe(false);
          expect(() => validateV2ReviewSourceReads(spec.engagementDir, spec.target, outcome.ledger, reuse, review)).not.toThrow();
        }
      }
      return outcome;
    } });
  const result = await agent.run({ target, engagementDir, mode: 'ast', tools: [] });
  expect(result.publicationStatus, JSON.stringify(result.storage)).toBe('published');
  expect(reviews).toBe(2); expect(followups).toBe(1);
  expect(new Set(units).size).toBe(units.length);
  expect(readFileSync(join(engagementDir, 'revisions/0/03_review_result.json'), 'utf8')).toBe(originalReview);
  const finalReview = JSON.parse(readFileSync(join(engagementDir, '03_review_result.json'), 'utf8'));
  expect(finalReview.reviewedFindings.find((row: { originalFindingId: string }) => row.originalFindingId === ids.get('b.ts'))).toEqual(unrelated!);
  const classification = JSON.parse(readFileSync(join(engagementDir, '04_evaluation_classification.yaml'), 'utf8'));
  expect(classification.candidates).toHaveLength(2);
  expect(classification.candidates.every((row: { final_status: string }) => row.final_status === 'BACKLOG')).toBe(true);
  expect(FileRunStateStore.open(engagementDir).read().analysisRevision).toBe(1);
  const report = readFileSync(join(engagementDir, '07_security_report.md'));
  calls.length = 0;
  expect((await agent.resume(engagementDir)).publicationStatus).toBe('published');
  expect(calls).toEqual([]);
  expect(readFileSync(join(engagementDir, '07_security_report.md'))).toEqual(report);
}, 20000);
