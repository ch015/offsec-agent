import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { createRequire } from 'node:module';
import { load } from 'js-yaml';
import { readStandardFindings } from './finding-contract.js';
import type { ProviderRuntimeEvent } from './providers/provider-runtime.js';

const gate = createRequire(import.meta.url)('../../domains/offsec/hooks/report-gate-hook.js') as {
  runGate(input: { filePath: string; env: Record<string, string>; content: string }): {
    result?: { ok: boolean; errors?: unknown[] };
  };
};
const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;
const object = (value: unknown): Record<string, unknown> =>
  value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};

/** A review cannot retain a finding by rereading the analyzer's quotation alone. */
export function validateV2ReviewSourceReads(engagementDir: string, target: string, events: readonly ProviderRuntimeEvent[]): void {
  const records = readStandardFindings(engagementDir);
  if (!records.length) return;
  const review = object(JSON.parse(readFileSync(join(engagementDir, '03_review_result.json'), 'utf8')));
  const reviewed = new Map((Array.isArray(review.reviewedFindings) ? review.reviewedFindings : []).map(value => {
    const row = object(value); return [row.originalFindingId, row];
  }));
  const readPaths = new Set(events.filter(e => e.tool === 'Read' && e.decision === 'allow' && e.resource)
    .map(e => resolve(engagementDir, e.resource!)));
  for (const record of records) {
    const row = reviewed.get(record.id);
    if (!row && record.role !== 'reviewer') throw new Error(`v2 review did not classify ${record.id}`);
    if (row?.action === 'inconclusive') continue;
    for (const evidence of record.evidence) {
      const source = resolve(target, evidence.path);
      if (!readPaths.has(source)) throw new Error(`v2 review must Read the original source before accepting ${record.id}: ${source}`);
    }
  }
}

/** Validate downstream facts before accepting the model's evaluation artifacts. */
export function validateV2Evaluation(engagementDir: string): void {
  const records = readStandardFindings(engagementDir);
  const canonical = new Map<string, (typeof records)[number]>();
  for (const record of records) {
    if (!canonical.has(record.id) || record.role === 'reviewer') canonical.set(record.id, record);
  }
  // Empty assessments still pass the existing publication/coverage gate later.
  if (canonical.size === 0) return;
  const evaluation = object(JSON.parse(readFileSync(join(engagementDir, '04_evaluation.json'), 'utf8')));
  const classification = object(load(readFileSync(join(engagementDir, '04_evaluation_classification.yaml'), 'utf8')));
  if (!Array.isArray(classification.candidates)) throw new Error('v2 evaluation requires classification.candidates with id, final_status and canonical severity');
  const candidates = classification.candidates.map(object);
  const ids = candidates.map(candidate => candidate.id);
  if (new Set(ids).size !== ids.length || ids.length !== canonical.size || ids.some(id => typeof id !== 'string' || !canonical.has(id))) {
    throw new Error('v2 evaluation classification must account for every canonical finding ID exactly once');
  }
  const expected = Object.fromEntries(severities.map(severity => [severity, 0]));
  for (const candidate of candidates) {
    const record = canonical.get(candidate.id as string)!;
    if (candidate.severity !== record.severity) {
      throw new Error(`v2 evaluation severity mismatch for ${record.id}: expected ${record.severity}, got ${String(candidate.severity)}`);
    }
    if (['CONFIRMED', 'DOWNGRADED'].includes(String(candidate.final_status))) expected[record.severity]!++;
  }
  const actual = object(evaluation.severityDistribution);
  for (const severity of severities) {
    if (actual[severity] !== expected[severity]) throw new Error(`v2 evaluation severityDistribution.${severity} must equal canonical classified count ${expected[severity]}`);
  }
  const outcome = gate.runGate({
    filePath: join(engagementDir, '07_security_report.draft.md'),
    env: { AGENT_ENGAGEMENT_DIR: engagementDir, CH015_REPORT_GATE: 'on', CH015_REQUIRE_POC_BINDING: 'off' },
    content: '',
  });
  if (outcome.result?.ok !== true) throw new Error(`v2 evaluation publication prerequisites failed: ${JSON.stringify(outcome.result?.errors)}`);
}
