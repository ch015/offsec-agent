import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import type { SessionOutcome, SessionSpec } from '../../index.js';

export function syntheticOutcome(spec: SessionSpec, options: { cost?: number; subtype?: string; handoff?: boolean } = {}): SessionOutcome {
  const contract = JSON.parse(readFileSync(spec.contractPath!, 'utf8'));
  const phase = contract.phases.find((phase: { id: string }) => phase.id === spec.phase);
  const resources = dirname(dirname(spec.contractPath!));
  const artifacts: string[] = [...phase.requiredArtifacts];
  if (options.handoff && spec.workUnit?.ownedSourceFiles.some(file => file.endsWith('/a.ts'))) artifacts.push('02_analysis_handoff.yaml');
  for (const name of artifacts) {
    let body = spec.phase === 'report' ? '# Synthetic report\nNo confirmed findings.\n' : '{}\n';
    if (name === '02_analysis_handoff.yaml') body = JSON.stringify({ hypotheses: [{ question: 'Does package a cross a security boundary into package b?', impact: 'high', files: ['packages/a/a.ts', 'packages/b/b.ts'], observations: [{ path: 'packages/a/a.ts', lineStart: 1, lineEnd: 1, quote: 'export const a = 1;' }] }] });
    writeFileSync(join(spec.engagementDir, name), body);
  }
  return { texts: [], ledger: phase.requiredMethodFiles.map((file: string) => ({ at: new Date(0).toISOString(), event: 'PreToolUse', tool: 'Read', resource: resolve(resources, file), decision: 'allow' as const })),
    totalCostUsd: options.cost ?? 0.01, numTurns: 1, subtype: options.subtype ?? 'success', modelUsage: { [spec.model!]: { inputTokens: 1, outputTokens: 1 } },
    structuredOutput: { contractVersion: contract.version, phase: phase.id, role: phase.role, status: 'complete', artifacts, summary: 'fixture', metrics: { findingCount: 0 }, unresolved: [],
      ...(spec.workUnit ? { workUnit: { workUnitKey: spec.workUnit.unitKey, workPlanSha256: spec.workUnit.workPlanSha256, assignedSourceSha256: spec.workUnit.assignedSourceSha256 } } : {}) } };
}
