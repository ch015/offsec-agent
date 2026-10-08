import { sourceRangeDelivered } from './source-delivery.js';
import { readFileSync, realpathSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { createRequire } from 'node:module';
import { load } from 'js-yaml';
import { readStandardFindings } from './finding-contract.js';
import type { ProviderRuntimeEvent } from './providers/provider-runtime.js';
import { canonicalV2Findings, evaluationSeverities, resolveV2Review } from './v2-review-resolution.js';
import { assertEvaluationProjection, assertEvaluationToolCoverage } from './evaluation-projection.js';
import { isDeepStrictEqual } from 'node:util';

const gate = createRequire(import.meta.url)('../../domains/offsec/hooks/report-gate-hook.js') as {
  runGate(input: { filePath: string; env: Record<string, string>; content: string }): {
    result?: { ok: boolean; errors?: unknown[] };
  };
};
const reportGate = createRequire(import.meta.url)('../../domains/offsec/hooks/report-gate.js') as {
  validateReportGate(input: Record<string, unknown>): { ok: boolean; errors: unknown[] };
  getEquivalenceReview(ledger: unknown, classification: unknown): unknown;
  validateEquivalenceReview(review: unknown, candidates: unknown[], options: Record<string, unknown>): { errors: { code: string }[] };
};
const object = (value: unknown): Record<string, unknown> =>
  value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};

/** Shared v1/v2 syntax check; intermediate v1 decisions need not be publication-ready. */
export function validateOffsecClassificationSyntax(content: string): void {
  const classification = load(content);
  const review = reportGate.getEquivalenceReview(undefined, classification);
  if (!review) return;
  const errors = reportGate.validateEquivalenceReview(review, [], { requireEquivalenceReview: false }).errors
    .filter(error => error.code === 'EQUIVALENCE_GROUP_DECISION_INVALID');
  if (errors.length) throw new Error(`Classification decision invalid: ${JSON.stringify(errors)}`);
}

/** Every review decision requires delivery of the cited original source. */
export class ReviewSourceDeliveryError extends Error {}

export function validateV2ReviewSourceReads(engagementDir: string, target: string, events: readonly ProviderRuntimeEvent[], reuse?: { ids: string[]; events: ProviderRuntimeEvent[] }, proposedReview?: unknown, options?: { partial: true }): void {
  const records = readStandardFindings(engagementDir);
  if (!records.length) { resolveV2Review(engagementDir, proposedReview, options); return; }
  // Disposition errors and unread sources are independent. Return both in one
  // repair request instead of making the model rewrite a large review before
  // it can learn which original evidence it still needs to read.
  let resolutionError: unknown;
  try { resolveV2Review(engagementDir, proposedReview, options); }
  catch (error) { resolutionError = error; }
  const review = object(proposedReview);
  const scopedIds = options?.partial ? new Set<unknown>([
    ...(Array.isArray(review.newFindings) ? review.newFindings : []),
    ...(Array.isArray(review.reviewedFindings) ? review.reviewedFindings.flatMap(value => {
      const row = object(value);
      return [row.originalFindingId, row.correctedFindingId, ...(Array.isArray(row.mergedFrom) ? row.mergedFrom : [])];
    }) : []),
  ]) : undefined;

  const missing = new Map<string, Map<string, Set<string>>>();
  for (const record of records) {
    if (scopedIds && !scopedIds.has(record.id)) continue;
    for (const evidence of record.evidence) {
      const source = realpathSync(resolve(target, evidence.path));
      const receipts = [...events, ...(reuse?.ids.includes(record.id) ? reuse.events : [])].filter(event => event.event === 'SourceDelivery' && event.resource === source && event.delivery).map(event => event.delivery!);
      if (!sourceRangeDelivered(source, receipts, evidence.lineStart, evidence.lineEnd)) {
        const ranges = missing.get(source) ?? new Map<string, Set<string>>();
        const location = `${evidence.lineStart}-${evidence.lineEnd}`, ids = ranges.get(location) ?? new Set<string>();
        ids.add(record.id); ranges.set(location, ids); missing.set(source, ranges);
      }
    }
  }
  if (missing.size) {
    const message = `v2 review requires verified delivery of the original source before accepting these decisions. Read all listed source ranges, then retry this Write:\n${[...missing].map(([source, ranges]) => `${source}:${[...ranges].map(([location, ids]) => `${location} [${[...ids].join(', ')}]`).join('; ')}`).join('\n')}`;
    throw new ReviewSourceDeliveryError([resolutionError instanceof Error ? resolutionError.message : resolutionError, message].filter(Boolean).join('\n'));
  }
  if (resolutionError) throw resolutionError;
}

/** Validate each proposed Write independently so repairs stay in the same session. */
export function validateV2EvaluationArtifact(engagementDir: string, name: string, content: string, target?: string, options?: { prepareHostProjection: true }): void {
  if (name !== '04_evaluation.json' && name !== '04_evaluation_classification.yaml') return;
  if (name === '04_evaluation_classification.yaml' && !options?.prepareHostProjection) assertEvaluationProjection(engagementDir, content);
  const canonical = canonicalV2Findings(engagementDir);
  const reviewed = resolveV2Review(engagementDir);
  if (name === '04_evaluation.json') {
    const evaluation = object(JSON.parse(content));
    assertEvaluationToolCoverage(engagementDir, evaluation);
    const actual = object(evaluation.severityDistribution);
    const errors: string[] = [];
    // Historical sealed inputs have no inventory and remain readable. New
    // projections require the deterministic inventory, including a null count
    // when historical review metadata is insufficient.
    const sealedInputPath = join(engagementDir, '03_evaluation_input.json');
    let sealedInventory: unknown;
    try { sealedInventory = JSON.parse(readFileSync(sealedInputPath, 'utf8')).vulnerabilityInventory; }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    if (sealedInventory !== undefined && !isDeepStrictEqual(evaluation.vulnerabilityInventory, sealedInventory)) {
      errors.push('v2 evaluation vulnerabilityInventory must equal the sealed host inventory; accepted finding counts are not independent vulnerabilities');
    }
    for (const severity of evaluationSeverities) {
      if (actual[severity] !== reviewed.severityDistribution[severity]) {
        errors.push(`v2 evaluation severityDistribution.${severity} must equal reviewed count ${reviewed.severityDistribution[severity]}`);
      }
    }
    if (errors.length) throw new Error(errors.join('\n'));
    return;
  }
  const classification = object(load(content));
  if (!Array.isArray(classification.candidates)) throw new Error('v2 evaluation requires classification.candidates with id, final_status and canonical severity');
  const candidates = classification.candidates.map(object);
  const identityErrors: string[] = [], firstRow = new Map<string, number>();
  for (const [index, candidate] of candidates.entries()) {
    const id = candidate.id;
    if (typeof id !== 'string' || !canonical.has(id)) identityErrors.push(`unknown ID ${String(id)} at row ${index + 1}`);
    if (typeof id !== 'string') continue;
    if (firstRow.has(id)) identityErrors.push(`duplicate ID ${id} at rows ${firstRow.get(id)} and ${index + 1}`);
    else firstRow.set(id, index + 1);
  }
  const missing = [...canonical.keys()].filter(id => !firstRow.has(id));
  if (missing.length) identityErrors.push(`missing IDs: ${missing.join(', ')}`);
  const errors = identityErrors.length
    ? [`v2 evaluation classification must account for every canonical finding ID exactly once:\n${identityErrors.join('\n')}`] : [];
  const dispositions = new Map(reviewed.dispositions.map(row => [row.id, row]));
  for (const candidate of candidates) {
    const record = canonical.get(candidate.id as string);
    if (!record) continue;
    if (candidate.severity !== record.severity) {
      errors.push(`v2 evaluation severity mismatch for ${record.id}: expected ${record.severity}, got ${String(candidate.severity)}`);
    }
    const disposition = dispositions.get(record.id)!;
    const allowed = disposition.finalStatus === 'CONFIRMED' ? ['CONFIRMED', 'DOWNGRADED'] : [disposition.finalStatus];
    if (!allowed.includes(String(candidate.final_status))) {
      errors.push(`v2 evaluation ${record.id} reviewed as ${disposition.action}: expected final_status ${allowed.join(' or ')}, got ${String(candidate.final_status)}. ${disposition.reason}`);
    }
    if (disposition.foldedInto && candidate.folded_into !== disposition.foldedInto) {
      errors.push(`v2 evaluation ${record.id} requires folded_into ${disposition.foldedInto}`);
    }
  }
  if (errors.length) throw new Error(errors.join('\n'));
  const outcome = reportGate.validateReportGate({ classification, requireScore: false,
    sourceRoot: target, artifactRoot: engagementDir, allowEmptyCandidates: canonical.size === 0 });
  if (!outcome.ok) throw new Error(`v2 evaluation classification invalid: ${JSON.stringify(outcome.errors)}`);
}

/** Final validation remains authoritative even when a provider skips Write hooks. */
export function validateV2Evaluation(engagementDir: string): void {
  assertEvaluationProjection(engagementDir);
  assertEvaluationToolCoverage(engagementDir);
  // Empty assessments still pass the existing publication/coverage gate later.
  if (canonicalV2Findings(engagementDir).size === 0) return;
  for (const name of ['04_evaluation_classification.yaml', '04_evaluation.json']) {
    validateV2EvaluationArtifact(engagementDir, name, readFileSync(join(engagementDir, name), 'utf8'));
  }
  const outcome = gate.runGate({
    filePath: join(engagementDir, '07_security_report.draft.md'),
    env: { AGENT_ENGAGEMENT_DIR: engagementDir, CH015_REPORT_GATE: 'on', CH015_REQUIRE_POC_BINDING: 'off' },
    content: '',
  });
  if (outcome.result?.ok !== true) throw new Error(`v2 evaluation publication prerequisites failed: ${JSON.stringify(outcome.result?.errors)}`);
}
