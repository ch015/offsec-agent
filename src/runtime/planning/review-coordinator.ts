import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';

export const ReviewRequestSchema = z.object({ id: z.string().min(1), question: z.string().trim().min(20),
  files: z.array(z.string()).min(1), missingEvidence: z.string().trim().min(20), findingIds: z.array(z.string()), flowIds: z.array(z.string()) }).strict();
export type ReviewRequest = z.infer<typeof ReviewRequestSchema>;
const fingerprint = (request: ReviewRequest) => createHash('sha256').update(JSON.stringify({
  question: request.question.trim().toLowerCase(), files: [...request.files].sort(), missingEvidence: request.missingEvidence.trim().toLowerCase(),
  findingIds: [...request.findingIds].sort(), flowIds: [...request.flowIds].sort(),
})).digest('hex');

export function reviewRequests(directory: string, files: readonly string[], findingIds: readonly string[], flowIds: readonly string[], seen: ReadonlySet<string>) {
  const review = JSON.parse(readFileSync(join(directory, '03_review_result.json'), 'utf8'));
  const requests = z.array(ReviewRequestSchema).parse(review.additionalEvidenceRequests ?? []);
  if (new Set(requests.map(request => request.id)).size !== requests.length) throw new Error('Duplicate review request IDs');
  const selected: Array<ReviewRequest & { fingerprint: string }> = [], deferred: Array<{ id: string; reason: string }> = [];
  for (const request of requests) {
    if (request.files.some(file => !files.includes(file)) || request.findingIds.some(id => !findingIds.includes(id))
      || request.flowIds.some(id => !flowIds.includes(id)) || !request.findingIds.length && !request.flowIds.length) throw new Error(`Review request outside assigned finding/flow scope: ${request.id}`);
    const hash = fingerprint(request);
    if (seen.has(hash)) deferred.push({ id: request.id, reason: 'Repeated question and missing evidence; no new information requested' });
    else selected.push({ ...request, fingerprint: hash });
  }
  return { selected, deferred };
}

const Evidence = z.object({ path: z.string(), lineStart: z.number().int().positive(), lineEnd: z.number().int().positive(), quote: z.string().min(1) }).strict();
export const FollowupAnswersSchema = z.object({ answers: z.array(z.object({ id: z.string(), status: z.enum(['resolved', 'deferred']),
  reason: z.string().trim().min(20), evidence: z.array(Evidence) }).strict()) }).strict();

export function validateFollowupAnswers(directory: string, target: string, requests: readonly ReviewRequest[]) {
  const value = FollowupAnswersSchema.parse(JSON.parse(readFileSync(join(directory, '02_followup_answers.json'), 'utf8')));
  const seen = new Set<string>();
  for (const answer of value.answers) {
    const request = requests.find(request => request.id === answer.id);
    if (!request || seen.has(answer.id)) throw new Error(`Unexpected follow-up answer: ${answer.id}`);
    seen.add(answer.id);
    if (answer.status === 'resolved' && !answer.evidence.length) throw new Error(`Resolved follow-up requires evidence: ${answer.id}`);
    for (const evidence of answer.evidence) {
      if (!request.files.includes(evidence.path)) throw new Error('Follow-up evidence outside requested files');
      const lines = readFileSync(join(target, evidence.path), 'utf8').split(/\r?\n/);
      if (evidence.lineEnd < evidence.lineStart || evidence.lineEnd > lines.length || !lines.slice(evidence.lineStart - 1, evidence.lineEnd).join('\n').includes(evidence.quote)) throw new Error('Follow-up evidence does not match source');
    }
  }
  if (requests.some(request => !seen.has(request.id))) throw new Error('Missing review follow-up answers');
  return value;
}
