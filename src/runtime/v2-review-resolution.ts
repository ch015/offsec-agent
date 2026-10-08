import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { readStandardFindings, type StandardFinding } from './finding-contract.js';
import { assertVulnerabilityInventoryComplete, buildVulnerabilityInventory } from './vulnerability-inventory.js';

export const evaluationSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;
type ReviewAction = 'retained' | 'corrected' | 'rejected' | 'inconclusive' | 'new';
export type ReviewDisposition = {
  id: string;
  severity: StandardFinding['severity'];
  action: ReviewAction;
  finalStatus: 'CONFIRMED' | 'FALSE_POSITIVE' | 'BACKLOG' | 'FOLDED_INTO';
  reason: string;
  foldedInto?: string;
  relatedIds: string[];
};
const object = (value: unknown): Record<string, unknown> =>
  value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};

export class ReviewFinalizationError extends Error {}

/** Severity is an explicit reviewer decision, never inferred from prose. A
 * changed rating must be submitted to the canonical finding ledger first. */
export function reviewSeverityIssues(engagementDir: string, proposedReview?: unknown, allowMissing = false): string[] {
  const canonical = canonicalV2Findings(engagementDir);
  const path = join(engagementDir, '03_review_result.json');
  const review = object(proposedReview ?? (existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : undefined));
  const issues: string[] = [];
  for (const value of Array.isArray(review.reviewedFindings) ? review.reviewedFindings : []) {
    const row = object(value);
    if (row.action !== 'retained' && row.action !== 'corrected') continue;
    const id = row.action === 'corrected' ? row.correctedFindingId ?? row.originalFindingId : row.originalFindingId;
    const finding = canonical.get(String(id));
    if (!finding || (allowMissing && row.reviewedSeverity === undefined)) continue;
    if (!evaluationSeverities.includes(row.reviewedSeverity as StandardFinding['severity'])) {
      issues.push(`${String(row.originalFindingId)} requires reviewedSeverity (CRITICAL/HIGH/MEDIUM/LOW/INFO), explicitly chosen by the reviewer; canonical ${finding.id} is ${finding.severity}.`);
    } else if (row.reviewedSeverity !== finding.severity) {
      issues.push(`${String(row.originalFindingId)} reviewedSeverity ${String(row.reviewedSeverity)} differs from canonical ${finding.id} severity ${finding.severity}. If the rating changed, submit_finding with the corrected severity and use action corrected + correctedFindingId; do not change only the explanation.`);
    }
    if (!allowMissing && typeof row.reason === 'string') {
      // Conservative consistency lint, not a semantic severity adjudicator.
      // Match direct sentence-level assertions, excluding quoted/history text
      // and conditional comparisons such as "HIGH would be justified if ...".
      const direct = /(?:^|[.!?;]\s+)(CRITICAL|HIGH|MEDIUM|LOW|INFO)(?: severity)? (?:is (?:appropriate|justified|warranted)(?!\s+(?:only\s+)?(?:if|when)\b)|given\b|due to\b|for [^.;]{0,200}\bis justified\b)/g;
      const korean = /(?:^|[.!?;]\s+)심각도(?:는|를)?\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)(?:로 (?:판정|평가)|(?:가|이) 적절)/g;
      const asserted = [...row.reason.matchAll(direct), ...row.reason.matchAll(korean)].map(match => match[1]!);
      const contradictory = [...new Set(asserted.filter(severity => severity !== finding.severity))];
      if (contradictory.length) issues.push(`${String(row.originalFindingId)} reason explicitly asserts ${contradictory.join('/')} but reviewed/canonical severity is ${finding.severity}. Reassess the actual preconditions and evidence, then correct the finding or the unsupported rationale consistently. Copying the canonical severity into reviewedSeverity does not repair this contradiction.`);
    }
  }
  return issues;
}

export function canonicalV2Findings(engagementDir: string): Map<string, StandardFinding> {
  const canonical = new Map<string, StandardFinding>();
  for (const record of readStandardFindings(engagementDir)) {
    if (!canonical.has(record.id) || record.role === 'reviewer') canonical.set(record.id, record);
  }
  return canonical;
}

/** Project review decisions over the append-only ledger without deleting audit history. */
export function resolveV2Review(engagementDir: string, proposedReview?: unknown, options?: { partial: true }) {
  const records = readStandardFindings(engagementDir);
  const canonical = canonicalV2Findings(engagementDir);
  const distribution = Object.fromEntries(evaluationSeverities.map(s => [s, 0])) as Record<StandardFinding['severity'], number>;
  const path = join(engagementDir, '03_review_result.json');
  const review = object(proposedReview ?? (existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : undefined));
  if (review.reviewDraft === true && !options?.partial) throw new Error('Review draft is not complete. Finalize with a reviewPatch Write and finalize:true after classifying all findings.');
  if (!canonical.size) return { dispositions: [] as ReviewDisposition[], severityDistribution: distribution, citationOverlapGroups: [] as string[][],
    vulnerabilityInventory: buildVulnerabilityInventory({ canonical, dispositions: [], review }) };
  if (!Array.isArray(review.reviewedFindings)) throw new Error('v2 review requires reviewedFindings');
  const originals = new Set(records.filter(r => r.role !== 'reviewer').map(r => r.id));
  const rows = new Map<string, Record<string, unknown>>();
  const resolved = new Map<string, ReviewDisposition>();
  const reviewerIds = new Set(records.filter(r => r.role === 'reviewer').map(r => r.id));
  const actions = ['retained', 'corrected', 'rejected', 'inconclusive'];
  const assign = (id: string, action: ReviewAction, status: ReviewDisposition['finalStatus'], reason: string, foldedInto?: string) => {
    const record = canonical.get(id);
    if (!record) throw new Error(`v2 review references unknown finding ${id}`);
    if (resolved.has(id)) throw new Error(`v2 review assigns conflicting decisions to ${id}`);
    if (status === 'CONFIRMED' && record.verdict !== 'supported') {
      throw new Error(`v2 review cannot accept ${id} with verdict ${record.verdict}; submit a supported correction or mark inconclusive`);
    }
    resolved.set(id, { id, severity: record.severity, action, finalStatus: status, reason,
      ...(foldedInto ? { foldedInto } : {}), relatedIds: [] });
  };
  const rowErrors: string[] = [], firstRow = new Map<string, number>();
  for (const [index, value] of review.reviewedFindings.entries()) {
    const row = object(value), id = row.originalFindingId;
    if (typeof id !== 'string' || !canonical.has(id)) {
      rowErrors.push(`v2 review requires each original finding exactly once: ${String(id)} (unknown ID at row ${index + 1})`);
      continue;
    }
    if (firstRow.has(id)) {
      rowErrors.push(`v2 review requires each original finding exactly once: ${id} (duplicate rows ${firstRow.get(id)} and ${index + 1})`);
      continue;
    }
    firstRow.set(id, index + 1);
    if (!actions.includes(String(row.action)) || typeof row.reason !== 'string' || !row.reason.trim()) {
      rowErrors.push(`v2 review ${id} requires action retained/corrected/rejected/inconclusive and a reason (row ${index + 1})`);
      continue;
    }
    rows.set(id, row);
  }
  const unclassified = [...originals].filter(id => !rows.has(id));
  if (unclassified.length && !options?.partial) rowErrors.push(`v2 review did not classify ${unclassified.join(', ')}`);
  const decisionErrors: string[] = [];
  const validateDecision = (validate: () => void) => {
    try { validate(); }
    catch (error) { decisionErrors.push(error instanceof Error ? error.message : String(error)); }
  };
  const replacements = new Map<string, string>();
  for (const [id, row] of rows) {
    validateDecision(() => {
      const action = row.action as Exclude<ReviewAction, 'new'>, reason = row.reason as string;
      if (action === 'corrected') {
        const replacement = row.correctedFindingId ?? id;
        if (typeof replacement !== 'string' || !reviewerIds.has(replacement)) {
          throw new Error(`v2 review correction for ${id} requires a submitted reviewer correctedFindingId`);
        }
        if (replacement !== id) {
          assign(id, action, 'FOLDED_INTO', reason, replacement);
          replacements.set(replacement, reason);
        } else assign(id, action, 'CONFIRMED', reason);
      } else {
        assign(id, action, action === 'retained' ? 'CONFIRMED' : action === 'rejected' ? 'FALSE_POSITIVE' : 'BACKLOG', reason);
      }
    });
  }
  for (const [id, reason] of replacements) {
    validateDecision(() => {
      const existing = resolved.get(id);
      if (existing && existing.finalStatus !== 'CONFIRMED') throw new Error(`v2 review correction target ${id} has a conflicting decision`);
      if (!existing) assign(id, 'corrected', 'CONFIRMED', reason);
    });
  }
  const newIds = review.newFindings ?? [];
  if (!Array.isArray(newIds)) decisionErrors.push('v2 review newFindings must be an array of submitted reviewer IDs');
  for (const id of Array.isArray(newIds) ? newIds : []) {
    validateDecision(() => {
      if (typeof id !== 'string' || !reviewerIds.has(id)) throw new Error(`v2 review new finding was not submitted by reviewer: ${String(id)}`);
      assign(id, 'new', 'CONFIRMED', 'New finding submitted by reviewer');
    });
  }
  // A single explicitly reviewed representative is safe to fold. An aggregate
  // overlapping multiple independent findings has no unique representative.
  const representative = (id: string, seen = new Set<string>()): string | undefined => {
    if (seen.has(id)) return undefined;
    seen.add(id);
    const value = resolved.get(id);
    if (value?.finalStatus === 'CONFIRMED') return id;
    if (value?.foldedInto) return representative(value.foldedInto, seen);
    const related = rows.get(id)?.mergedFrom;
    if (value?.action === 'rejected' && Array.isArray(related)) {
      const targets = [...new Set(related.filter(other => other !== id))];
      if (targets.length === 1 && typeof targets[0] === 'string') return representative(targets[0], seen);
    }
    return undefined;
  };
  for (const [id, row] of rows) {
    if (row.mergedFrom === undefined) continue;
    validateDecision(() => {
      if (!Array.isArray(row.mergedFrom) || row.mergedFrom.some(v => typeof v !== 'string' || !canonical.has(v))) {
        throw new Error(`v2 review ${id} mergedFrom must reference existing finding IDs`);
      }
      const relatedIds = [...new Set(row.mergedFrom as string[])].filter(v => v !== id);
      const disposition = resolved.get(id);
      if (!disposition) return;
      disposition.relatedIds = relatedIds;
      const target = relatedIds.length === 1 ? representative(relatedIds[0]!) : undefined;
      if (row.action === 'rejected' && target) {
        disposition.finalStatus = 'FOLDED_INTO';
        disposition.foldedInto = target;
      }
    });
  }
  const unaccounted = [...reviewerIds].filter(id => !resolved.has(id));
  if (unaccounted.length && !options?.partial) decisionErrors.push(`v2 review did not account for reviewer finding ${unaccounted.join(', ')} in correctedFindingId or newFindings`);
  const dispositions = [...resolved.values()].sort((a, b) => a.id.localeCompare(b.id));
  // Shared source is a search hint, not a duplicate verdict. Different
  // independently fixable controls routinely cite the same middleware/model.
  const citations = new Map<string, Set<string>>();
  for (const d of dispositions.filter(d => d.finalStatus === 'CONFIRMED')) {
    for (const ref of canonical.get(d.id)!.evidence) {
      const key = JSON.stringify([ref.path,ref.lineStart,ref.lineEnd,ref.quote]);
      const ids = citations.get(key) ?? new Set<string>(); ids.add(d.id); citations.set(key,ids);
    }
  }
  const citationOverlapGroups = [...new Map([...citations.values()].filter(ids => ids.size > 1)
    .map(ids => [...ids].sort()).map(ids => [JSON.stringify(ids),ids])).values()];
  const errors = [...rowErrors, ...decisionErrors];
  if (errors.length) throw new Error(errors.join('\n'));
  const severityIssues = reviewSeverityIssues(engagementDir, review, options?.partial === true);
  if (severityIssues.length) throw new ReviewFinalizationError(severityIssues.join('\n'));
  for (const row of dispositions) if (row.finalStatus === 'CONFIRMED') distribution[row.severity]++;
  const vulnerabilityInventory = buildVulnerabilityInventory({ canonical, dispositions, review });
  if (review.countingSchemaVersion === 1 && !options?.partial) {
    try { assertVulnerabilityInventoryComplete(vulnerabilityInventory); }
    catch (error) { throw new ReviewFinalizationError(error instanceof Error ? error.message : String(error)); }
  }
  return { dispositions, severityDistribution: distribution, citationOverlapGroups, vulnerabilityInventory };
}
