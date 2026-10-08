import { createHash } from 'node:crypto';
import { existsSync, realpathSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { readStandardFindings } from './finding-contract.js';
import type { ProviderRuntimeEvent } from './providers/provider-runtime.js';
import { canonicalV2Findings, resolveV2Review, reviewSeverityIssues } from './v2-review-resolution.js';
import { validateV2ReviewSourceReads } from './v2-evaluation.js';
import { atomicPrivateWrite, readManagedFile } from './workflow/storage-files.js';

export type ReviewReuse = { ids: string[]; events: ProviderRuntimeEvent[] };
export type ReviewProgressContext = {
  engagementDir: string; target: string; runId: string; model: string; revision: number;
};
const hash = (content: string | Buffer) => createHash('sha256').update(content).digest('hex');
const hashSchema = z.string().regex(/^[a-f0-9]{64}$/);
const eventSchema = z.object({
  at: z.string(), event: z.literal('SourceDelivery'), actor: z.literal('reviewer'), resource: z.string(),
  delivery: z.object({
    toolCallId: z.string(), sourceHash: hashSchema, outputHash: hashSchema,
    totalLines: z.number().int().nonnegative(), totalBytes: z.number().int().nonnegative().optional(),
    ranges: z.array(z.object({ start: z.number().int().positive(), end: z.number().int().positive() })),
    byteRanges: z.array(z.object({ start: z.number().int().nonnegative(), end: z.number().int().nonnegative() })).optional(),
    status: z.literal('verified'),
  }).passthrough(),
}).passthrough();
const entrySchema = z.object({
  attempt: z.string(), content: z.string(), sha256: hashSchema,
  findingHashes: z.record(z.string(), hashSchema), events: z.array(eventSchema),
});
const checkpointSchema = z.object({
  schemaVersion: z.literal(1), runId: z.string(), target: z.string(), model: z.string(), revision: z.number().int().nonnegative(),
  committed: entrySchema.optional(), pending: entrySchema.optional(),
});
type Checkpoint = z.infer<typeof checkpointSchema>;
type Entry = z.infer<typeof entrySchema>;
const checkpointPath = (root: string) => join(root, '.recovery', 'review-progress.json');
const artifactPath = (root: string) => join(root, '03_review_result.json');

/** All historical records for an ID matter, including the original evidence of
 * a corrected finding. A new/changed record invalidates reuse for that ID. */
function findingHashes(root: string): Record<string, string> {
  const grouped = new Map<string, string[]>();
  for (const record of readStandardFindings(root)) {
    const values = grouped.get(record.id) ?? []; values.push(JSON.stringify(record)); grouped.set(record.id, values);
  }
  return Object.fromEntries([...grouped].map(([id, values]) => [id, hash(JSON.stringify(values.sort()))]));
}
function readCheckpoint(context: ReviewProgressContext): Checkpoint {
  const identity = { schemaVersion: 1 as const, runId: context.runId, target: realpathSync(context.target), model: context.model, revision: context.revision };
  const path = checkpointPath(context.engagementDir);
  if (!existsSync(path)) return identity;
  const checkpoint = checkpointSchema.parse(JSON.parse(readManagedFile(context.engagementDir, path).toString()));
  if (checkpoint.runId !== identity.runId || checkpoint.target !== identity.target || checkpoint.model !== identity.model) {
    throw new Error('Review progress belongs to a different run, source snapshot or reviewer model');
  }
  if (checkpoint.revision !== identity.revision) return identity;
  for (const entry of [checkpoint.committed, checkpoint.pending]) {
    if (entry && hash(entry.content) !== entry.sha256) throw new Error('Review progress content integrity mismatch');
  }
  return checkpoint;
}
function save(context: ReviewProgressContext, checkpoint: Checkpoint): void {
  atomicPrivateWrite(checkpointPath(context.engagementDir), JSON.stringify(checkpoint) + '\n');
}

/** A prepared Write is not accepted until its exact bytes exist on disk. This
 * also recovers a crash between the SDK Write and its PostToolUse callback. */
function reconcile(context: ReviewProgressContext, checkpoint: Checkpoint): Entry | undefined {
  if (!checkpoint.committed && !checkpoint.pending) return undefined;
  const path = artifactPath(context.engagementDir);
  const current = existsSync(path) ? hash(readManagedFile(context.engagementDir, path)) : undefined;
  if (checkpoint.pending?.sha256 === current) {
    checkpoint.committed = checkpoint.pending; delete checkpoint.pending; save(context, checkpoint);
    return checkpoint.committed;
  }
  if (checkpoint.committed?.sha256 === current) {
    if (checkpoint.pending) { delete checkpoint.pending; save(context, checkpoint); }
    return checkpoint.committed;
  }
  if (!current && !checkpoint.committed) { delete checkpoint.pending; save(context, checkpoint); return undefined; }
  throw new Error('Review artifact differs from its host-validated progress checkpoint; preserve it for integrity review');
}

export function loadReviewProgress(context: ReviewProgressContext): {
  reuse: ReviewReuse; reviewedIds: string[]; remainingIds: string[]; finalizationIssues: string[]; draft: boolean; path: string;
} | undefined {
  const entry = reconcile(context, readCheckpoint(context));
  if (!entry) return undefined;
  const current = findingHashes(context.engagementDir);
  const ids = Object.keys(entry.findingHashes).filter(id => current[id] === entry.findingHashes[id]);
  const events = entry.events as ProviderRuntimeEvent[];
  // Verify each unchanged decision again against the actual snapshot bytes.
  // Changed IDs are deliberately excluded; the next session must revisit them.
  const review = JSON.parse(entry.content), unchanged = new Set(ids);
  const scoped = { ...review, reviewedFindings: review.reviewedFindings.filter((row: any) =>
    [row.originalFindingId, row.correctedFindingId, ...(row.mergedFrom ?? [])].filter(Boolean).every(id => unchanged.has(id))),
    newFindings: (review.newFindings ?? []).filter((id: string) => unchanged.has(id)) };
  validateV2ReviewSourceReads(context.engagementDir, context.target, [], { ids, events }, scoped, { partial: true });
  const resolved = resolveV2Review(context.engagementDir, scoped, { partial: true });
  const reviewedIds = resolved.dispositions.map(row => row.id);
  return { reuse: { ids: reviewedIds, events }, reviewedIds,
    remainingIds: [...canonicalV2Findings(context.engagementDir).keys()].filter(id => !reviewedIds.includes(id)),
    finalizationIssues: [...reviewSeverityIssues(context.engagementDir, scoped),
      ...(scoped.countingSchemaVersion === 1 ? resolved.vulnerabilityInventory.issues.flatMap(issue =>
        issue.findingIds.map(id => `${id} ${issue.code}: ${issue.message}`)) : [])],
    draft: review.reviewDraft === true, path: artifactPath(context.engagementDir) };
}

const reopenPath = (root: string) => join(root, '.recovery', 'review-reopen.json');
const reopenSchema = z.object({
  runId: z.string(), model: z.string(), target: z.string(), revision: z.number().int().nonnegative(),
  content: z.string(), sha256: hashSchema, reuse: z.object({ ids: z.array(z.string()), events: z.array(eventSchema) }),
});

/** Journal metadata repair before archiving the old revision. Completed source
 * observations are preserved, while the review must finalize again. */
export function stageReviewReopen(context: ReviewProgressContext, reuse: ReviewReuse): void {
  reuse = { ids: reuse.ids, events: reuse.events.filter(event => event.event === 'SourceDelivery'
    && event.actor === 'reviewer' && event.delivery?.status === 'verified') };
  const review = JSON.parse(readManagedFile(context.engagementDir, artifactPath(context.engagementDir)).toString());
  review.reviewDraft = true;
  const content = JSON.stringify(review, null, 2) + '\n';
  validateV2ReviewSourceReads(context.engagementDir, context.target, [], reuse, review, { partial: true });
  atomicPrivateWrite(reopenPath(context.engagementDir), JSON.stringify(reopenSchema.parse({
    runId: context.runId, model: context.model, target: realpathSync(context.target), revision: context.revision + 1,
    content, sha256: hash(content), reuse,
  })) + '\n');
}

export function finishReviewReopen(context: ReviewProgressContext): void {
  const path = reopenPath(context.engagementDir);
  if (!existsSync(path)) return;
  const pending = reopenSchema.parse(JSON.parse(readManagedFile(context.engagementDir, path).toString()));
  if (pending.runId !== context.runId || pending.model !== context.model || pending.target !== realpathSync(context.target)
    || hash(pending.content) !== pending.sha256) throw new Error('Review reopen journal identity or integrity mismatch');
  if (pending.revision === context.revision + 1) return; // Revision event not committed yet.
  if (pending.revision !== context.revision) throw new Error('Review reopen journal revision is stale');
  const reuse = pending.reuse as ReviewReuse;
  prepareReviewProgress(context, { attempt: `host-review-reopen:${context.revision}`, content: pending.content, events: [], reuse });
  atomicPrivateWrite(artifactPath(context.engagementDir), pending.content);
  finishReviewProgress(context, true);
  unlinkSync(path);
}

/** Called only by the host after artifact validation, before the actual Write.
 * Neither this path nor its source-delivery receipts are agent-writable. */
export function prepareReviewProgress(context: ReviewProgressContext, input: {
  attempt: string; content: string; events: readonly ProviderRuntimeEvent[]; reuse?: ReviewReuse;
}): void {
  const checkpoint = readCheckpoint(context);
  reconcile(context, checkpoint);
  const review = JSON.parse(input.content), partial = review.reviewDraft === true ? { partial: true as const } : undefined;
  const events = input.events.filter(event => event.event === 'SourceDelivery' && event.actor === 'reviewer' && event.delivery?.status === 'verified');
  validateV2ReviewSourceReads(context.engagementDir, context.target, events, input.reuse, review, partial);
  const ids = resolveV2Review(context.engagementDir, review, partial).dispositions.map(row => row.id), allHashes = findingHashes(context.engagementDir);
  const observations = [...events, ...(input.reuse?.events ?? [])].filter(event => event.actor === 'reviewer' && event.delivery?.status === 'verified');
  checkpoint.pending = entrySchema.parse({ attempt: input.attempt, content: input.content, sha256: hash(input.content),
    findingHashes: Object.fromEntries(ids.map(id => [id, allHashes[id]])),
    events: [...new Map(observations.map(event => [JSON.stringify(event), event])).values()],
  });
  save(context, checkpoint);
}

export function finishReviewProgress(context: ReviewProgressContext, succeeded: boolean): void {
  const checkpoint = readCheckpoint(context);
  if (succeeded) reconcile(context, checkpoint);
  else if (checkpoint.pending) { delete checkpoint.pending; save(context, checkpoint); }
}

export function mergeReviewReuse(...values: Array<ReviewReuse | undefined>): ReviewReuse | undefined {
  const present = values.filter((value): value is ReviewReuse => !!value);
  return present.length ? { ids: [...new Set(present.flatMap(value => value.ids))],
    events: [...new Map(present.flatMap(value => value.events).map(event => [JSON.stringify(event), event])).values()] } : undefined;
}

/** Bound continuation by progress on the original assignment, including a
 * legacy review's explicit severity repair. New self-created IDs cannot keep
 * an otherwise stagnant review alive. */
export function reviewProgressAdvance(
  previous: { reviewedIds: string[]; finalizationIssues: string[] } | undefined,
  next: { reviewedIds: string[]; finalizationIssues: string[] } | undefined,
  originalIds: ReadonlySet<string>,
): { newlyReviewed: number; newlyFinalized: number; advanced: boolean } {
  const priorIds = new Set(previous?.reviewedIds ?? []), nextIds = new Set(next?.reviewedIds ?? []);
  const priorIssues = new Set((previous?.finalizationIssues ?? []).map(issue => issue.split(' ')[0]!));
  const nextIssues = new Set((next?.finalizationIssues ?? []).map(issue => issue.split(' ')[0]!));
  const newlyReviewed = [...nextIds].filter(id => originalIds.has(id) && !priorIds.has(id)).length;
  const newlyFinalized = [...priorIssues].filter(id => originalIds.has(id) && nextIds.has(id) && !nextIssues.has(id)).length;
  const regressed = [...priorIds].some(id => originalIds.has(id) && (!nextIds.has(id)
    || (nextIssues.has(id) && !priorIssues.has(id))));
  return { newlyReviewed, newlyFinalized, advanced: !regressed && newlyReviewed + newlyFinalized > 0 };
}
