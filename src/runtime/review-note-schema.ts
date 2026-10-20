import { z } from 'zod';
import { StoredReferenceSchema } from './result-records.js';

export const ReviewNoteId = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/);
export const ReviewNoteText = z.string().trim().min(20).max(10000);
export const ReviewAuthor = z.string().trim().min(1).max(200);
const base = { id: ReviewNoteId, author: ReviewAuthor,
  references: z.array(StoredReferenceSchema).min(1).max(50), rationale: ReviewNoteText };
export const ReviewEntryReferenceSchema = z.object({ id: ReviewNoteId, sha256: z.string().regex(/^[a-f0-9]{64}$/) }).strict();
export const ManualReviewAssignmentSchema = z.object({ ...base, kind: z.literal('review-assignment'),
  assignee: ReviewAuthor, instructions: ReviewNoteText }).strict();
export const ReviewSubjectSchema = z.object({ artifact: StoredReferenceSchema, topic: z.string().trim().min(1).max(200) }).strict();

// Keep the original dispute/resolution field order: existing entry hashes survive.
export const ReviewNoteInputSchema = z.discriminatedUnion('kind', [
  z.object({ ...base, kind: z.literal('dispute'), findingIds: z.array(z.string().regex(/^F-[a-f0-9]+$/)).min(1).max(100),
    assertions: z.array(ReviewNoteText).min(2).max(20) }).strict(),
  z.object({ ...base, kind: z.literal('resolution'), disputeId: ReviewNoteId,
    outcome: z.enum(['resolved', 'unresolved']) }).strict(),
  ManualReviewAssignmentSchema,
  z.object({ ...base, kind: z.literal('review-response'), assignment: ReviewEntryReferenceSchema,
    replyTo: ReviewEntryReferenceSchema,
    results: z.array(z.object({ path: z.string().min(1), status: z.enum(['completed', 'needs-information', 'not-reviewed']),
      reason: ReviewNoteText }).strict()).min(1).max(50),
  }).strict(),
  z.object({ ...base, kind: z.literal('review-feedback'), assignment: ReviewEntryReferenceSchema,
    response: ReviewEntryReferenceSchema.optional(), action: z.enum(['accept', 'request-changes', 'cancel']),
  }).strict(),
  z.object({ ...base, kind: z.literal('review-opinion'), subject: ReviewSubjectSchema,
    position: z.enum(['support', 'oppose', 'uncertain']),
  }).strict(),
  z.object({ ...base, references: z.array(StoredReferenceSchema).min(1).max(10000), kind: z.literal('review-mediation'), subject: ReviewSubjectSchema,
    opinions: z.array(ReviewEntryReferenceSchema).min(1).max(10000),
    outcome: z.enum(['adopt', 'defer', 'needs-information']), selectedOpinion: ReviewEntryReferenceSchema.optional(),
  }).strict(),
]);
export type ReviewNoteInput = z.infer<typeof ReviewNoteInputSchema>;
export const ManualReviewBatchSchema = z.object({ schemaVersion: z.literal(1),
  assignments: z.array(ManualReviewAssignmentSchema).min(1).max(500) }).strict();
