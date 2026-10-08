import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { extname, join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { canonicalV2Findings, resolveV2Review } from './v2-review-resolution.js';
import { readStandardFindingRecordReceipts } from './finding-contract.js';
import { atomicPrivateWrite, readManagedFile } from './workflow/storage-files.js';
import type { PreanalysisEvidence } from './workflow/preanalysis-evidence.js';

export const EVALUATION_CLASSIFICATION = '04_evaluation_classification.yaml';
export const EVALUATION_INPUT = '03_evaluation_input.json';
const receiptName = '.recovery/evaluation-projection.json';
const digest = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');
const sourceDigests = (root: string) => ({
  review: digest(readManagedFile(root, join(root, '03_review_result.json'))),
  findings: digest(JSON.stringify(readStandardFindingRecordReceipts(root))),
});

/** Serialize already-reviewed decisions. This function makes no new severity,
 * reachability, counterevidence, or duplicate-equivalence decisions. */
export function buildEvaluationClassification(root: string) {
  const canonical = canonicalV2Findings(root), review = resolveV2Review(root);
  const byId = new Map(review.dispositions.map(row => [row.id, row]));
  const confirmedRepresentative = (id: string, seen = new Set<string>()): boolean => {
    if (seen.has(id)) return false;
    seen.add(id);
    const row = byId.get(id);
    return row?.finalStatus === 'CONFIRMED' || !!row?.foldedInto && confirmedRepresentative(row.foldedInto, seen);
  };
  const source = JSON.parse(readManagedFile(root, join(root, '03_review_result.json')).toString());
  const rows = new Map<string, any>((source.reviewedFindings ?? []).map((row: any) => [row.originalFindingId, row]));
  const locations = (id: string) => canonical.get(id)!.evidence.map(ref => `${ref.path}:${ref.lineStart}-${ref.lineEnd}`);
  const candidates = review.dispositions.map(row => {
    const finding = canonical.get(row.id)!;
    return { id: row.id, final_status: row.finalStatus, severity: finding.severity, confidence: finding.confidence,
      title: finding.title, evidence: { locations: locations(row.id), source_references: finding.evidence },
      validity: { reachable: `${finding.reachability}: ${finding.preconditions.join('; ')}`,
        business_relevance: finding.impact, exploit_path: row.reason },
      preconditions: finding.preconditions, unresolved: finding.unresolved, remediation: finding.remediation,
      standards: finding.standards, review_reason: row.reason,
      ...(row.foldedInto ? { folded_into: row.foldedInto } : {}),
      ...(row.finalStatus === 'FALSE_POSITIVE' ? { counter_evidence: row.relatedIds.length > 1 && row.relatedIds.every(id => confirmedRepresentative(id)) ? {
        text: 'Reviewer excluded an overlapping aggregate from independent counting. This is not a source-guard refutation.',
        related_finding_ids: row.relatedIds, original_review_reason: row.reason,
      } : row.reason } : {}),
      ...(row.finalStatus === 'BACKLOG' ? { backlog_reason: row.reason } : {}),
    };
  });
  const groups = review.dispositions.filter(row => row.finalStatus !== 'FOLDED_INTO').map(row => {
    const folded = review.dispositions.filter(other => other.foldedInto === row.id);
    const members = [row.id, ...folded.map(other => other.id)];
    return { group_id: `review-${row.id}`, members, decision: folded.length ? 'MERGE' : 'KEEP',
      reason: [row.reason, ...folded.map(other => `${other.id}: ${other.reason}`)].join('\n'),
      ...(rows.get(row.id)?.distinctCause ? { distinct_cause: rows.get(row.id).distinctCause } : {}),
      ...(folded.length ? { representative: row.id, affected_instances: [...new Set(members.flatMap(locations))] } : {}),
    };
  });
  const distinctGroups = review.dispositions.filter(row => row.finalStatus === 'CONFIRMED' && rows.get(row.id)?.distinctCause)
    .map(row => ({ group_id: `distinct-${row.id}`, members: [row.id], decision: 'KEEP',
      reason: `${rows.get(row.id).distinctCause.rootCause}\n${rows.get(row.id).distinctCause.impact}`,
      distinct_cause: rows.get(row.id).distinctCause }));
  return { generated_by: 'host', decision_source: '03_review_result.json', ...sourceDigests(root), candidates,
    vulnerability_inventory: review.vulnerabilityInventory,
    citation_overlap_hints: review.citationOverlapGroups,
    equivalence_review: { status: 'COMPLETE', reviewed_candidate_count: candidates.length, unresolved: [], groups: [...groups, ...distinctGroups] } };
}

export function assertEvaluationProjection(root: string, content?: string): void {
  const receiptPath = join(root, receiptName);
  if (!existsSync(receiptPath)) return; // Read-only compatibility for earlier evaluations.
  const receipt = JSON.parse(readManagedFile(root, receiptPath).toString());
  const current = sourceDigests(root);
  if (receipt.review !== current.review || receipt.findings !== current.findings) throw new Error('Host evaluation projection is stale: review or finding records changed');
  const actual = content ?? readManagedFile(root, join(root, EVALUATION_CLASSIFICATION));
  if (digest(actual) !== receipt.classification) throw new Error('The host-generated classification is immutable. Preserve its reviewed IDs, evidence and decisions; write the overall assessment to 04_evaluation.json only.');
  if (digest(readManagedFile(root, join(root, EVALUATION_INPUT))) !== receipt.input) throw new Error('Host evaluation input integrity mismatch');
}

/** Reuse a completed evaluation's sealed inputs when only reporting remains. */
export function readEvaluationProjection(root: string) {
  if (!existsSync(join(root, receiptName))) return undefined;
  assertEvaluationProjection(root);
  const content = readManagedFile(root, join(root, EVALUATION_CLASSIFICATION));
  return { path: join(root, EVALUATION_INPUT), classificationPath: join(root, EVALUATION_CLASSIFICATION),
    sha256: digest(content), classificationSha256: digest(content), inputSha256: digest(readManagedFile(root, join(root, EVALUATION_INPUT))),
    candidates: JSON.parse(content.toString()).candidates.length as number };
}

export function assertEvaluationToolCoverage(root: string, evaluation?: Record<string, unknown>): void {
  if (!existsSync(join(root, receiptName))) return;
  assertEvaluationProjection(root);
  const input = JSON.parse(readManagedFile(root, join(root, EVALUATION_INPUT)).toString());
  if (input.toolCoverageSchemaVersion !== 1) return; // Earlier completed evaluations remain readable.
  const actual = (evaluation ?? JSON.parse(readManagedFile(root, join(root, '04_evaluation.json')).toString())).actualToolCoverage as Record<string, unknown> | undefined;
  const errors = Object.entries(input.actualToolCoverage as Record<string, unknown>)
    .filter(([key]) => !['basis', 'limitations'].includes(key))
    .filter(([key, expected]) => !isDeepStrictEqual(actual?.[key], expected))
    .map(([key, expected]) => `actualToolCoverage.${key} must equal host preanalysis value ${JSON.stringify(expected)}`);
  if (errors.length) throw new Error(`Evaluation tool statistics differ from sealed host evidence. Copy actualToolCoverage from 03_evaluation_input.json and reconcile prose; absent fields are not zero:\n${errors.join('\n')}`);
}

export function writeEvaluationProjection(input: { root: string; coverage: Record<string, unknown>; preanalysis: PreanalysisEvidence;
  validate(content: string): void }) {
  const classification = buildEvaluationClassification(input.root);
  const content = JSON.stringify(classification, null, 2) + '\n';
  input.validate(content); // Existing canonical, equivalence and counterevidence gates remain mandatory.
  const countExtensions = (files: readonly string[]) => Object.fromEntries([...new Set(files.map(file => extname(file) || '(none)'))].sort()
    .map(extension => [extension, files.filter(file => (extname(file) || '(none)') === extension).length]));
  const p = input.preanalysis;
  const summary = { generatedBy: 'host', toolCoverageSchemaVersion: 1, classificationPath: join(input.root, EVALUATION_CLASSIFICATION),
    classificationSha256: digest(content), decisionSource: '03_review_result.json', ...sourceDigests(input.root),
    severityDistribution: resolveV2Review(input.root).severityDistribution,
    severityDistributionBasis: 'accepted records, including observations; use vulnerabilityInventory for independent causes',
    vulnerabilityInventory: classification.vulnerability_inventory,
    dispositionCounts: Object.fromEntries(['CONFIRMED', 'FOLDED_INTO', 'FALSE_POSITIVE', 'BACKLOG'].map(status =>
      [status, classification.candidates.filter(row => row.final_status === status).length])),
    analysisCoverage: Object.fromEntries(['complete', 'semanticCoverage', 'ownedFilesRead', 'ownedFileCount', 'completedUnits', 'totalUnits',
      'uncoveredFiles', 'preanalysisLimitations', 'deferredFollowupQuestions', 'deferredReviewRequests', 'securityControlCoverage'].map(key => [key, input.coverage[key]])),
    actualToolCoverage: { basis: 'Host preanalysis artifact, distinct from dependency-graph parser metadata',
      available: p.available, parsedFiles: p.parsedFiles.length, parsedExtensions: countExtensions(p.parsedFiles),
      unsupportedFiles: p.unsupportedFiles.length, unsupportedExtensions: countExtensions(p.unsupportedFiles),
      skippedFiles: p.skippedFiles.length, parseFailures: p.parseFailures.length, parseWarnings: p.parseWarnings.length,
      semgrepFindings: p.semgrepFindings.length, semgrepDiagnostics: p.semgrepDiagnostics.length,
      taintPaths: p.taintPaths.length, dataFlows: p.dataFlows.length,
      semgrepFileStatuses: Object.fromEntries([...new Set(p.semgrepFileCoverage.map(file => String(file.status)))].sort().map(status =>
        [status, p.semgrepFileCoverage.filter(file => file.status === status).length])), limitations: p.limitations },
    instructions: 'Classification is a host projection of finalized Reviewer decisions, not a new host security judgment. Do not rewrite it or enumerate all ledger files again. Read selected records only when needed for overall assessment. Actual tool coverage takes precedence over graph-parser metadata. Copy vulnerabilityInventory into 04_evaluation.json exactly. Use its independentVulnerabilityCount for vulnerability totals, not accepted record counts or severityDistribution; null means unclassified, not zero. Preserve corroborating impacts and exclude superseded claims. Write 04_evaluation.json and include both evaluation artifacts in the phase result.' };
  const summaryContent = JSON.stringify(summary, null, 2) + '\n';
  atomicPrivateWrite(join(input.root, EVALUATION_CLASSIFICATION), content);
  atomicPrivateWrite(join(input.root, EVALUATION_INPUT), summaryContent);
  atomicPrivateWrite(join(input.root, receiptName), JSON.stringify({ ...sourceDigests(input.root), classification: digest(content), input: digest(summaryContent) }) + '\n');
  return { path: join(input.root, EVALUATION_INPUT), classificationPath: join(input.root, EVALUATION_CLASSIFICATION),
    sha256: digest(content), classificationSha256: digest(content), inputSha256: digest(summaryContent), candidates: classification.candidates.length };
}
