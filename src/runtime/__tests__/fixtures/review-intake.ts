import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { contentHash, resultIdentity, ResultRecordReader, type StoredReference } from '../../result-records.js';
import type { ReviewNoteInput, ReviewNoteHistory } from '../../review-notes.js';
import { entryRef } from './manual-review.js';

type Entry = ReviewNoteHistory['entries'][number];
export function opinionFor(artifact: StoredReference, id: string, position: 'support' | 'oppose' | 'uncertain'): Extract<ReviewNoteInput, { kind: 'review-opinion' }> {
  return { kind: 'review-opinion', id, author: `reader-${id}`, references: [artifact],
    rationale: 'The reader recorded an explicit opinion about this editorial statement.',
    subject: { artifact, topic: 'The document includes sufficient editorial context' }, position };
}
export function mediationFor(opinions: Entry[], outcome: 'adopt' | 'defer' | 'needs-information', id = 'MEDIATION'): Extract<ReviewNoteInput, { kind: 'review-mediation' }> {
  const first = opinions[0]!;
  if (first.note.kind !== 'review-opinion') throw new Error('Expected an opinion fixture');
  const refs = new Map(opinions.flatMap(entry => entry.note.references).map(ref => [ref.path, ref]));
  return { kind: 'review-mediation', id, author: 'human-coordinator', references: [...refs.values()],
    rationale: 'The human coordinator explicitly recorded this decision and retained all earlier opinions.',
    subject: first.note.subject, opinions: opinions.map(entryRef), outcome, ...(outcome === 'adopt' ? { selectedOpinion: entryRef(first) } : {}) };
}
export function writeIntake(root: string, directory: string, expectedHead: string, values: unknown[]) {
  mkdirSync(directory, { recursive: true });
  const submissions = values.map((value, index) => {
    const path = `submission-${index}.json`, body = typeof value === 'string' ? value : JSON.stringify(value);
    writeFileSync(join(directory, path), body);
    return { path, sha256: contentHash(body) };
  });
  const manifest = { schemaVersion: 1, identity: resultIdentity(new ResultRecordReader(root)), expectedHead, submissions };
  const input = join(directory, 'manifest.json'); writeFileSync(input, JSON.stringify(manifest));
  return { input, manifest, directory };
}
