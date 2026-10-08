import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { canonicalV2Findings, evaluationSeverities, resolveV2Review } from './v2-review-resolution.js';
import { validateV2ReviewSourceReads } from './v2-evaluation.js';
import type { ProviderRuntimeEvent } from './providers/provider-runtime.js';

const rowSchema = z.object({
  originalFindingId: z.string().min(1), action: z.enum(['retained', 'corrected', 'rejected', 'inconclusive']),
  reason: z.string().trim().min(1),
}).passthrough();
const patchSchema = z.object({
  reviewPatch: z.literal(true), finalize: z.boolean().optional(),
  countingSchemaVersion: z.literal(1).optional(),
  reviewedFindings: z.array(rowSchema).max(20).default([]), newFindings: z.array(z.string().min(1)).max(20).optional(),
  reviewedSeverities: z.record(z.string(), z.enum(evaluationSeverities)).optional(),
  limitations: z.array(z.string()).optional(), additionalEvidenceRequests: z.array(z.unknown()).optional(),
}).strict();
const object = (value: unknown): Record<string, unknown> =>
  value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};

export const REVIEW_PATCH_GUIDANCE = 'For large reviews, work on at most 20 findings at a time: read that group of finding records and cited originals, Write a reviewPatch, then continue with the next IDs. Use bounded Write patches to 03_review_result.json. Example: {"reviewPatch":true,"reviewedFindings":[{"originalFindingId":"<exact existing ID>","action":"retained","reviewedSeverity":"MEDIUM","reason":"Specific source-grounded judgment supporting that exact severity"}]}. At most 20 decisions per patch. The host upserts exact IDs and preserves previously staged decisions. Read the cited originals before each batch. Send one Write at a time. Never invent IDs or add suffixes. Every retained/corrected row must explicitly choose reviewedSeverity equal to the canonical finding (the correctedFindingId target for corrections). If your rating changes, submit_finding with the corrected severity first; a prose-only downgrade is not a correction. For already-staged rows, {"reviewPatch":true,"reviewedSeverities":{"<exact original ID>":"MEDIUM"}} updates only that field and preserves the reason/evidence/distinctCause. Independently choose the rating after checking its reasoning; do not blindly copy it. Each patch may touch at most 20 IDs total. The usual correctedFindingId, mergedFrom and distinctCause fields remain supported. If supplied, newFindings replaces that complete ID list; otherwise the host preserves it. To finish, Write {"reviewPatch":true,"finalize":true,"reviewedFindings":[]}: the host checks every original finding, corrections, duplicates and independent source reads, computes the summary, and materializes the complete review. A draft cannot complete the phase.' + ' For independent counting, use countingSchemaVersion:1. Every retained/corrected result and reviewer addition needs a reviewedFindings row with counting: {kind:"vulnerability",causeId:"VC-meaningful-cause",component:"scope/component",rootCause:"specific failed security control",fixBoundary:"independently fixable code or configuration boundary",primaryEvidence:[{path,lineStart,lineEnd,quote}]} or {kind:"observation",reason:"why this is not an exploitable security defect"}. Reuse a causeId only for the same component, rootCause and fixBoundary, including source and test evidence for that same defect. For corrected rows this metadata describes the correctedFindingId record. List reviewer additions as reviewed retained rows, not also in newFindings. Duplicate rejected+mergedFrom rows need their own matching counting definition and primary evidence. Do not fold distinct causes to resolve shared citations. Corrections supersede old claims; duplicates preserve corroborating impact and evidence. INFO is not automatically an observation and LOW is not automatically a vulnerability.';

/** Prepare an SDK Write; validation never mutates an artifact on rejection. */
export function prepareReviewPatch(input: {
  engagementDir: string; target: string; content: string; events: readonly ProviderRuntimeEvent[];
  reuse?: Parameters<typeof validateV2ReviewSourceReads>[3];
  requireIndependentCounting?: boolean;
}): { content: string; additionalContext: string } | undefined {
  const proposed = object(JSON.parse(input.content));
  if (proposed.reviewPatch !== true) return undefined;
  const patch = patchSchema.parse(proposed);
  const path = join(input.engagementDir, '03_review_result.json');
  const previous = existsSync(path) ? object(JSON.parse(readFileSync(path, 'utf8'))) : {};
  const rows = new Map<string, Record<string, unknown>>();
  const priorRows = previous.reviewedFindings ?? [];
  if (!Array.isArray(priorRows)) throw new Error('Existing review has invalid reviewedFindings; repair it with a full validated Write.');
  for (const value of priorRows) {
    const row = rowSchema.parse(value);
    if (rows.has(row.originalFindingId)) throw new Error(`Existing review has duplicate ID ${row.originalFindingId}; repair it with a full validated Write.`);
    rows.set(row.originalFindingId, row);
  }
  const patchIds = new Set<string>();
  for (const row of patch.reviewedFindings) {
    if (patchIds.has(row.originalFindingId)) throw new Error(`Duplicate ID within review patch: ${row.originalFindingId}`);
    patchIds.add(row.originalFindingId); rows.set(row.originalFindingId, row);
  }
  for (const [id, severity] of Object.entries(patch.reviewedSeverities ?? {})) {
    if (patchIds.has(id)) throw new Error(`Duplicate ID within review patch: ${id}`);
    const row = rows.get(id);
    if (!row || !['retained', 'corrected'].includes(String(row.action))) {
      throw new Error(`reviewedSeverities requires an existing retained/corrected row: ${id}`);
    }
    patchIds.add(id); rows.set(id, { ...row, reviewedSeverity: severity });
  }
  if (patchIds.size > 20) throw new Error('Review patch may update at most 20 decisions, including reviewedSeverities');
  const priorNew = previous.newFindings ?? [];
  if (!Array.isArray(priorNew) || priorNew.some(id => typeof id !== 'string')) throw new Error('Existing review has invalid newFindings.');
  const newFindings = [...new Set(patch.newFindings ?? priorNew)] as string[];
  const summary = Object.fromEntries(['retained', 'corrected', 'rejected', 'inconclusive'].map(action =>
    [action, [...rows.values()].filter(row => row.action === action).length]));
  const merged = {
    ...(input.requireIndependentCounting || patch.countingSchemaVersion === 1 || previous.countingSchemaVersion === 1 ? { countingSchemaVersion: 1 } : {}),
    reviewedFindings: [...rows.values()], newFindings, summary: { ...summary, new: newFindings.length },
    limitations: patch.limitations ?? previous.limitations ?? [],
    ...(patch.additionalEvidenceRequests !== undefined || previous.additionalEvidenceRequests !== undefined
      ? { additionalEvidenceRequests: patch.additionalEvidenceRequests ?? previous.additionalEvidenceRequests } : {}),
    ...(patch.finalize ? {} : { reviewDraft: true }),
  };
  const options = patch.finalize ? undefined : { partial: true as const };
  validateV2ReviewSourceReads(input.engagementDir, input.target, input.events, input.reuse, merged, options);
  const resolved = resolveV2Review(input.engagementDir, merged, options);
  const accounted = new Set(resolved.dispositions.map(row => row.id));
  const allIds = [...canonicalV2Findings(input.engagementDir).keys()];
  const remaining = allIds.filter(id => !accounted.has(id));
  return { content: JSON.stringify(merged, null, 2) + '\n',
    additionalContext: patch.finalize ? `Review finalized: ${accounted.size} finding IDs, independent source reads verified. Independent vulnerability count: ${resolved.vulnerabilityInventory.independentVulnerabilityCount ?? 'unclassified'}.`
      : `Review draft staged ${accounted.size}/${allIds.length} finding IDs. Unclassified IDs: ${remaining.join(', ') || 'none'}. ${remaining.length ? 'Read originals and submit the next small reviewPatch.' : 'Finalize with {"reviewPatch":true,"finalize":true,"reviewedFindings":[]}.'}` };
}
