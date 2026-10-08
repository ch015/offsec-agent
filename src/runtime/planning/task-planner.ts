import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { OffsecWorkPlanV2 } from '../workflow/offsec-work-plan.js';
import type { ScannerPlan } from './scanner-contract.js';
import { sourceLines } from '../source-delivery.js';
import { createSecurityObligations, type SecurityObligation } from './security-obligations.js';

export type SourceRange = { path: string; sha256: string; lineStart: number; lineEnd: number; byteStart: number; byteEnd: number };
export type AnalysisTask = {
  unitKey: string;
  parentUnitKey: string;
  structuralUnitId: string;
  kind: 'source' | 'range-bridge';
  prerequisiteTaskIds?: string[];
  ownedSources: SourceRange[];
  contextRanges: Array<{ path: string; lineStart: number; lineEnd: number; byteStart?: number; byteEnd?: number }>;
  flowResponsibilities: ScannerPlan['crossUnitFlows'];
  securityObligations?: SecurityObligation[];
  limitations: string[];
};
const keyFor = (text: string) => `unit-${createHash('sha256').update(text).digest('hex').slice(0, 16)}`;

/** Capacity is bounded in bytes as well as lines, including one-line/minified files. */
export function partitionSource(path: string, sha256: string, raw: Buffer, maxBytes: number): SourceRange[] {
  const ranges: SourceRange[] = [];
  const newlines: number[] = [];
  for (let i = 0; i < raw.length; i++) if (raw[i] === 10) newlines.push(i);
  const lineAt = (offset: number) => {
    let low = 0, high = newlines.length;
    while (low < high) { const mid = (low + high) >>> 1; if (newlines[mid]! < offset) low = mid + 1; else high = mid; }
    return low + 1;
  };
  let start = 0;
  while (start < raw.length) {
    let end = Math.min(raw.length, start + maxBytes);
    if (end < raw.length) {
      const newline = raw.lastIndexOf(10, end - 1);
      if (newline >= start) end = newline + 1;
      else while (end < raw.length && (raw[end]! & 0xc0) === 0x80) end++;
    }
    ranges.push({ path, sha256, lineStart: lineAt(start), lineEnd: lineAt(end - (raw[end - 1] === 10 ? 1 : 0)), byteStart: start, byteEnd: end });
    start = end;
  }
  return ranges.length ? ranges : [{ path, sha256, lineStart: 1, lineEnd: 1, byteStart: 0, byteEnd: 0 }];
}

/** Scanner ownership stays semantic; sessions own exact ranges and explicit bridges. */
export function createAnalysisTasks(plan: OffsecWorkPlanV2, scanner: ScannerPlan, maxSourceTokens: number): AnalysisTask[] {
  const tasks: AnalysisTask[] = [];
  for (const unit of plan.units) {
    const base = { parentUnitKey: unit.unitKey, structuralUnitId: unit.sourceUnitId };
    if (unit.oversizedOwnedFiles?.length) {
      const file = unit.ownedFiles[0]!, raw = readFileSync(join(plan.targetRealpath, file.path));
      const ranges = partitionSource(file.path, file.sha256, raw, Math.max(4, maxSourceTokens * 4));
      const totalLines = Math.max(1, sourceLines(raw.toString('utf8')).length);
      const definitions = partitionSource(file.path, file.sha256, raw, Math.max(4, Math.min(4000, maxSourceTokens * 4)))[0]!;
      const prerequisiteTaskIds: string[] = [];
      for (const range of ranges) prerequisiteTaskIds.push(keyFor(`${unit.unitKey}:${range.byteStart}:${range.byteEnd}`));
      for (const range of ranges) tasks.push({ ...base, unitKey: keyFor(`${unit.unitKey}:${range.byteStart}:${range.byteEnd}`), kind: 'source', ownedSources: [range],
        contextRanges: [definitions, { path: file.path, lineStart: Math.max(1, range.lineStart - 3), lineEnd: Math.min(totalLines, range.lineEnd + 3) }],
        flowResponsibilities: [], limitations: ['Range partition uses line/byte boundaries; function semantics and shared state require the bridge task.'] });
      if (ranges.length > 1) tasks.push({ ...base, unitKey: keyFor(`${unit.unitKey}:range-bridge`), kind: 'range-bridge', ownedSources: [], prerequisiteTaskIds,
        contextRanges: [definitions],
        flowResponsibilities: [{ id: `BRIDGE-${unit.unitKey}`, fromUnit: unit.sourceUnitId, toUnit: unit.sourceUnitId, ownerUnit: unit.sourceUnitId,
          files: [file.path], question: 'Check shared definitions, state, guards and source-to-sink flows crossing every assigned range boundary; consult shared observations and record unresolved connections.' }],
        limitations: ['Bridge reviews cross-range semantics; full-file delivery belongs to the source tasks.'] });
    } else tasks.push({ ...base, unitKey: unit.unitKey, kind: 'source',
      ownedSources: unit.ownedFiles.map(file => {
        const raw = readFileSync(join(plan.targetRealpath, file.path));
        return { path: file.path, sha256: file.sha256, lineStart: 1, lineEnd: Math.max(1, sourceLines(raw.toString('utf8')).length), byteStart: 0, byteEnd: raw.length };
      }), contextRanges: [], flowResponsibilities: [], limitations: [] });
  }
  for (const flow of scanner.crossUnitFlows) {
    const eligible = tasks.filter(task => task.structuralUnitId === flow.ownerUnit);
    const owner = eligible.find(task => task.kind === 'range-bridge') ?? eligible.find(task => task.ownedSources.some(source => flow.files.includes(source.path))) ?? eligible[0];
    if (!owner) throw new Error(`Flow has no execution owner: ${flow.id}`);
    owner.flowResponsibilities.push(flow);
  }
  for (const task of tasks) task.securityObligations = createSecurityObligations(plan.targetRealpath, task.ownedSources, scanner.interfaces);
  return tasks;
}

export function analysisTaskRequest(task: AnalysisTask, input: { runId: string; snapshotId: string; planRevision: string; attempt: number; contextRefs: readonly string[]; toolPolicy: unknown }) {
  return { runId: input.runId, sourceSnapshotId: input.snapshotId, planRevision: input.planRevision,
    taskId: task.unitKey, taskRevision: 1, attemptId: `${task.unitKey}/${input.attempt}`, role: 'analyzer', kind: task.kind,
    unitId: task.structuralUnitId, objective: 'Analyze assigned source ranges, trace owned cross-unit flows, seek counterevidence, and retain explicit gaps.',
    ownedSources: task.ownedSources, contextRanges: task.contextRanges, limitations: task.limitations,
    contextRefs: input.contextRefs, flowResponsibilities: task.flowResponsibilities, securityObligations: task.securityObligations ?? [],
    requiredMethods: ['methods/analyze.md'], prerequisites: ['scanner-plan-validated', ...task.prerequisiteTaskIds ?? []], toolPolicy: input.toolPolicy,
    artifactContract: ['02_file_assessments.json'], completionCriteria: ['verified-source-delivery', 'file-analysis-evidence', 'owned-flow-assessments', 'security-control-case-assessments'], priorResultRefs: [],
  };
}
