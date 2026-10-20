import { contentHash, validateResultPath } from './result-records.js';
import type { ReviewNoteInput } from './review-note-schema.js';
import type { ReviewNoteHistory } from './review-notes.js';

type Entry = ReviewNoteHistory['entries'][number];
type Opinion = Extract<ReviewNoteInput, { kind: 'review-opinion' }>;
type Mediation = Extract<ReviewNoteInput, { kind: 'review-mediation' }>;
type OpinionEntry = Entry & { note: Opinion };
type MediationEntry = Entry & { note: Mediation };
type Group = { key: string; subject: Opinion['subject']; opinions: OpinionEntry[]; mediations: MediationEntry[] };
export const reviewSubjectKey = (subject: Opinion['subject']) => contentHash(JSON.stringify([
  subject.artifact.path, subject.artifact.sha256, subject.topic,
]));
const refMatches = (ref: { id: string; sha256: string }, entry: Entry) => ref.id === entry.note.id && ref.sha256 === entry.sha256;
const bindsOpinions = (note: Mediation, entries: OpinionEntry[]) => note.opinions.length === entries.length &&
  new Set(note.opinions.map(ref => ref.id)).size === entries.length && entries.every(entry => note.opinions.some(ref => refMatches(ref, entry)));

/** Explicit labels only: no language interpretation, voting or automatic adjudication. */
export function projectReviewMediation(entries: readonly Entry[]): Group[] {
  const groups = new Map<string, Group>();
  for (const entry of entries) {
    const note = entry.note;
    if (note.kind !== 'review-opinion' && note.kind !== 'review-mediation') continue;
    const artifact = note.subject.artifact;
    validateResultPath(artifact.path);
    if (artifact.path.startsWith('review-notes/')) throw new Error('Review subject must not cite mutable review history');
    if (!note.references.some(ref => ref.path === artifact.path && ref.sha256 === artifact.sha256)) throw new Error('Review opinion or mediation must bind its exact subject version');
    const key = reviewSubjectKey(note.subject), group = groups.get(key) ?? { key, subject: note.subject, opinions: [], mediations: [] };
    if (note.kind === 'review-opinion') group.opinions.push(entry as OpinionEntry);
    else {
      if (!bindsOpinions(note, group.opinions)) throw new Error('Mediation must bind every current opinion ID and entry hash exactly once');
      if (note.outcome === 'adopt') {
        if (!note.selectedOpinion || !group.opinions.some(opinion => refMatches(note.selectedOpinion!, opinion))) throw new Error('Adoption requires an explicitly selected current opinion');
        if (group.opinions.find(opinion => refMatches(note.selectedOpinion!, opinion))!.note.position === 'uncertain') throw new Error('An uncertain opinion must remain deferred or needs-information');
      } else if (note.selectedOpinion) throw new Error('Deferred or needs-information mediation must not select an opinion');
      // The person must cite every evidence path at its current version. Old
      // opinion bytes remain available, even when supplemental evidence changed.
      const paths = new Set(group.opinions.flatMap(opinion => opinion.note.references.map(ref => ref.path)));
      if ([...paths].some(path => !note.references.some(ref => ref.path === path))) throw new Error('Mediation must cite all opinion evidence paths at their current versions');
      group.mediations.push(entry as MediationEntry);
    }
    groups.set(key, group);
  }
  return [...groups.values()];
}

export function summarizeReviewMediation(entries: readonly Entry[], stale: ReadonlyMap<string, string[]>) {
  const groups = projectReviewMediation(entries).map(group => {
    const latest = group.mediations.at(-1);
    const decisionCurrent = !!latest && bindsOpinions(latest.note, group.opinions);
    const historicalStaleReferences = [...new Set(group.opinions.flatMap(entry => stale.get(entry.note.id) ?? []))];
    const staleReferences = decisionCurrent ? stale.get(latest.note.id) ?? [] : historicalStaleReferences;
    const status = staleReferences.length ? 'stale' : !decisionCurrent ? 'awaiting-mediation'
      : latest.note.outcome === 'adopt' ? 'adopted' : latest.note.outcome === 'defer' ? 'deferred' : 'needs-information';
    return { ...group, conflictingPositions: new Set(group.opinions.map(entry => entry.note.position)).size > 1,
      status, decisionCurrent, selectedOpinion: status === 'adopted' ? latest!.note.selectedOpinion! : null,
      staleReferences, historicalStaleReferences, latestMediation: latest ?? null };
  });
  return { groups, groupCount: groups.length, openCount: groups.filter(group => group.status !== 'adopted').length,
    conflictingGroupCount: groups.filter(group => group.conflictingPositions).length,
    notice: 'Human-authored opinions and mediation annotations only. Matching labels are not verified agreement. Adoption never changes canonical findings, coverage or publication; author labels are not authenticated.' };
}
