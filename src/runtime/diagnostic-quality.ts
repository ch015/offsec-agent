import { z } from 'zod';

const Id = z.string().trim().min(1);
export const DiagnosticJudgmentSchema = z.object({
  predictionId: Id,
  decision: z.enum(['known-valid', 'novel-valid', 'false-positive', 'duplicate', 'unresolved']),
  // Assigned by source adjudication, never inferred from titles, CWEs or line overlap.
  causeId: Id.nullable(),
  duplicateOf: Id.nullable(),
  sourceEvidenceValid: z.boolean(),
  conditionsValid: z.boolean(),
  rationale: z.string().trim().min(20),
}).strict().superRefine((row, ctx) => {
  const accepted = row.decision === 'known-valid' || row.decision === 'novel-valid';
  if (accepted !== (row.causeId !== null)) ctx.addIssue({ code: 'custom', message: 'Only accepted judgments require causeId' });
  if ((row.decision === 'duplicate') !== (row.duplicateOf !== null)) ctx.addIssue({ code: 'custom', message: 'Only duplicate judgments require duplicateOf' });
});
export type DiagnosticJudgment = z.infer<typeof DiagnosticJudgmentSchema>;

export const DiagnosticQualityInputSchema = z.object({
  project: Id,
  runId: Id,
  truthCauseIds: z.array(Id),
  predictionIds: z.array(Id),
  judgments: z.array(DiagnosticJudgmentSchema),
  negativeControls: z.array(z.object({ id: Id, result: z.enum(['pass', 'fail', 'unresolved']), rationale: z.string().trim().min(20) }).strict()),
  executionComplete: z.boolean(),
  sourceDeliveryComplete: z.boolean(),
  independentCountingComplete: z.boolean(),
  frozenTruthVerified: z.boolean(),
  precisionThreshold: z.number().min(0).max(1).default(0.9),
  recallThreshold: z.number().min(0).max(1).default(0.9),
}).strict();
export type DiagnosticQualityInput = z.input<typeof DiagnosticQualityInputSchema>;

/** Internal diagnostic measurements, not a statistical population guarantee.
 * Labels identify independently fixable causes. Recall uses the frozen known
 * causes; new valid causes are reported separately and never shrink that set.
 * Unresolved judgments prevent acceptance instead of disappearing from a gate.
 */
export function scoreDiagnosticQuality(raw: DiagnosticQualityInput) {
  const input = DiagnosticQualityInputSchema.parse(raw);
  const unique = (values: readonly string[], what: string) => {
    const set = new Set(values);
    if (set.size !== values.length) throw new Error(`Duplicate ${what}`);
    return set;
  };
  const truth = unique(input.truthCauseIds, 'ground-truth cause IDs');
  const predictions = unique(input.predictionIds, 'prediction IDs');
  unique(input.negativeControls.map(row => row.id), 'negative-control IDs');
  unique(input.judgments.map(row => row.predictionId), 'judgment IDs');
  const byId = new Map(input.judgments.map(row => [row.predictionId, row]));
  if (byId.size !== predictions.size || [...byId.keys()].some(id => !predictions.has(id))) throw new Error('Every prediction requires exactly one judgment');
  const known = new Set<string>(), novel = new Set<string>();
  let falsePositives = 0, duplicates = 0, unresolved = 0, invalidAccepted = 0;
  const acceptedCauseRows = new Map<string, DiagnosticJudgment>();
  for (const row of input.judgments) {
    if (row.decision === 'known-valid' || row.decision === 'novel-valid') {
      if (truth.has(row.causeId!) !== (row.decision === 'known-valid')) throw new Error(`Judgment disagrees with frozen truth membership: ${row.predictionId}`);
      if (acceptedCauseRows.has(row.causeId!)) throw new Error(`Accepted cause counted twice; adjudicate duplicate explicitly: ${row.causeId}`);
      acceptedCauseRows.set(row.causeId!, row);
      if (!row.sourceEvidenceValid || !row.conditionsValid) { invalidAccepted++; continue; }
      (row.decision === 'known-valid' ? known : novel).add(row.causeId!);
    } else if (row.decision === 'false-positive') falsePositives++;
    else if (row.decision === 'unresolved') unresolved++;
    else {
      duplicates++;
      const canonical = byId.get(row.duplicateOf!);
      if (!canonical || !['known-valid', 'novel-valid'].includes(canonical.decision)) throw new Error(`Duplicate must point directly to an accepted prediction: ${row.predictionId}`);
      // An unsupported duplicate can conceal a materially false extension.
      if (!row.sourceEvidenceValid || !row.conditionsValid) unresolved++;
    }
  }
  const truePositives = known.size + novel.size;
  const denominator = truePositives + falsePositives;
  const precision = denominator ? truePositives / denominator : null;
  const precisionLowerBound = denominator + unresolved + invalidAccepted
    ? truePositives / (denominator + unresolved + invalidAccepted) : null;
  const recall = truth.size ? known.size / truth.size : null;
  const f1 = precision === null || recall === null ? null : precision + recall ? 2 * precision * recall / (precision + recall) : 0;
  const failedControls = input.negativeControls.filter(row => row.result === 'fail').map(row => row.id);
  const unresolvedControls = input.negativeControls.filter(row => row.result === 'unresolved').map(row => row.id);
  const failures: string[] = [];
  if (!input.executionComplete) failures.push('execution-incomplete');
  if (!input.sourceDeliveryComplete) failures.push('source-delivery-incomplete');
  if (!input.independentCountingComplete) failures.push('independent-counting-incomplete');
  if (!input.frozenTruthVerified) failures.push('truth-provenance-unverified');
  if (unresolved) failures.push('unresolved-predictions');
  if (invalidAccepted) failures.push('invalid-accepted-evidence-or-conditions');
  if (failedControls.length) failures.push('negative-control-failed');
  if (unresolvedControls.length) failures.push('negative-control-unresolved');
  if (!input.negativeControls.length) failures.push('negative-controls-unmeasured');
  if (truth.size) {
    if (precision === null || precision < input.precisionThreshold) failures.push('precision-below-threshold');
    if (recall! < input.recallThreshold) failures.push('recall-below-threshold');
  } else {
    if (truePositives) failures.push('negative-case-has-unexpected-valid-causes');
    if (falsePositives) failures.push('negative-case-has-false-positives');
  }
  return {
    project: input.project, runId: input.runId,
    basis: 'independently-adjudicated-causes' as const,
    truthCauses: truth.size, knownTruePositives: known.size, novelTruePositives: novel.size,
    falseNegatives: truth.size - known.size, falsePositives, duplicates, unresolved, invalidAccepted,
    precision, precisionLowerBound, recall, f1,
    missedCauseIds: [...truth].filter(id => !known.has(id)).sort(),
    negativeControls: { total: input.negativeControls.length, passed: input.negativeControls.filter(row => row.result === 'pass').length, failed: failedControls, unresolved: unresolvedControls },
    gate: { passed: failures.length === 0, failures, precisionThreshold: input.precisionThreshold, recallThreshold: input.recallThreshold },
    limitation: 'Known-cause recall on this frozen diagnostic set; not exhaustive vulnerability recall or a holdout generalization guarantee.',
  };
}
