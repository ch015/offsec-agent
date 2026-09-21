import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { load } from 'js-yaml';
import { z } from 'zod';

const HypothesisSchema = z.object({
  question: z.string().trim().min(12).max(1000),
  impact: z.enum(['critical', 'high', 'medium', 'low']),
  files: z.array(z.string().min(1)).min(2).max(12),
  observations: z.array(z.object({
    path: z.string().min(1), lineStart: z.number().int().positive(), lineEnd: z.number().int().positive(),
    quote: z.string().min(1).max(4000),
  }).strict()).min(1).max(4),
}).strict();
export type FollowupHypothesis = z.infer<typeof HypothesisSchema> & { unitKey: string };

/** Models propose unresolved questions. The host only checks evidence, scope and bounds. */
export function selectAnalysisFollowups(input: {
  target: string;
  units: readonly { unitKey: string; ownedFiles: readonly { path: string }[] }[];
  handoffs: readonly { unitKey: string; path: string }[];
  maximum: number;
}): { selected: FollowupHypothesis[]; omitted: number; invalid: number } {
  const owner = new Map(input.units.flatMap(unit => unit.ownedFiles.map(file => [file.path, unit.unitKey] as const)));
  const candidates: FollowupHypothesis[] = [];
  const seen = new Set<string>();
  let invalid = 0;
  for (const handoff of input.handoffs) {
    try {
      const text = readFileSync(handoff.path, 'utf8');
      if (Buffer.byteLength(text) > 128 * 1024) throw new Error('oversized handoff');
      const raw = load(text) as { hypotheses?: unknown };
      if (!raw || !Array.isArray(raw.hypotheses) || raw.hypotheses.length > 8) throw new Error('invalid handoff');
      for (const value of raw.hypotheses) {
        try {
          const hypothesis = HypothesisSchema.parse(value);
          const files = [...new Set(hypothesis.files)].sort();
          if (files.some(file => !owner.has(file)) || !files.some(file => owner.get(file) === handoff.unitKey)) throw new Error('invalid ownership');
          if (new Set(files.map(file => owner.get(file))).size < 2) throw new Error('not a cross-unit question');
          for (const observation of hypothesis.observations) {
            if (!files.includes(observation.path) || observation.lineEnd < observation.lineStart || observation.lineEnd - observation.lineStart > 100) throw new Error('invalid observation');
            const lines = readFileSync(resolve(input.target, observation.path), 'utf8').split(/\r?\n/);
            if (observation.lineEnd > lines.length || !lines.slice(observation.lineStart - 1, observation.lineEnd).join('\n').includes(observation.quote)) throw new Error('unverified observation');
          }
          const key = JSON.stringify([files, hypothesis.question.toLowerCase().replace(/\s+/g, ' ')]);
          if (seen.has(key)) continue;
          seen.add(key);
          candidates.push({ ...hypothesis, files, unitKey: handoff.unitKey });
        } catch { invalid++; }
      }
    } catch { invalid++; }
  }
  const priorities = { critical: 0, high: 1, medium: 2, low: 3 };
  candidates.sort((a, b) => priorities[a.impact] - priorities[b.impact] || a.unitKey.localeCompare(b.unitKey) || a.question.localeCompare(b.question));
  return { selected: candidates.slice(0, input.maximum), omitted: Math.max(0, candidates.length - input.maximum), invalid };
}
