import { existsSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { compareSourceRevision, mapEvidenceLines } from '../source-change-policy.js';
import { loadSourceSnapshot } from '../source-snapshot.js';
import { FileRunStateStore } from '../workflow/state-store.js';
import { assertRunInputsIntact } from '../workflow/host-integrity.js';
import { atomicPrivateWrite } from '../workflow/storage-files.js';
import { sourceRangeDelivered } from '../source-delivery.js';
import type { DependencyGraph } from '../workflow/offsec-dependency-graph.js';
import type { AnalysisTask } from './task-planner.js';
import type { ProviderPhaseOutcome, ProviderRuntimeEvent } from '../providers/provider-runtime.js';
import type { SessionOutcome } from '../session.js';
import { readAnalysisAssessments } from './analysis-assessments.js';
import { promoteStandardFindingRecords, readStandardFindingRecordReceipts } from '../finding-contract.js';

/** Change impact is file/dependency scoped; raw identity remains strict in each snapshot. */
export function planSourceRevision(oldRoot: string, newRoot: string, files: readonly string[], graph: DependencyGraph) {
  const before = loadSourceSnapshot(oldRoot), after = loadSourceSnapshot(newRoot);
  const changes = files.map(path => ({ path, ...(before.snapshot.files.some(file => file.path === path)
    ? compareSourceRevision(path, readFileSync(join(before.target, path)), readFileSync(join(after.target, path)))
    : { kind: 'analysis-relevant' as const, reuseAnalysis: false, reuseToolOutput: false, reason: 'New file' }) }));
  for (const change of changes) {
    const oldFile = before.snapshot.files.find(file => file.path === change.path), newFile = after.snapshot.files.find(file => file.path === change.path);
    if (oldFile && newFile && (oldFile.mode !== newFile.mode || oldFile.symlink !== newFile.symlink)) {
      change.kind = 'analysis-relevant'; change.reuseAnalysis = false; change.reuseToolOutput = false; change.reason = 'File permissions or type changed';
    }
  }
  const affected = new Set(changes.filter(change => !change.reuseAnalysis).map(change => change.path));
  for (const file of before.snapshot.files) if (!files.includes(file.path)) affected.add(file.path);
  let grew = true;
  const oldGraph: DependencyGraph = JSON.parse(readFileSync(join(oldRoot, '00_dependency_graph.json'), 'utf8'));
  while (grew) {
    grew = false;
    for (const edge of [...graph.edges, ...oldGraph.edges]) if (edge.resolvedTargets.some(path => affected.has(path)) && !affected.has(edge.from)) { affected.add(edge.from); grew = true; }
  }
  return { before, after, changes, affectedFiles: [...affected].sort(), comparisonProfile: 'source-format/1',
    tools: 'rerun-for-new-snapshot', allReusable: affected.size === 0 && files.length === before.snapshot.files.length };
}

export function openAnalysisReuse(oldRoot: string, newRoot: string, files: readonly string[], graph: DependencyGraph, contractVersion: string, scope?: string) {
  const snapshot = FileRunStateStore.open(oldRoot).read();
  if (snapshot.contractVersion !== contractVersion) throw new Error('Reuse requires a compatible assessment contract');
  assertRunInputsIntact(snapshot, oldRoot);
  const priorInput = JSON.parse(readFileSync(join(oldRoot, 'assess-v2-checkpoint-input.json'), 'utf8')).input;
  if ((priorInput.scope ?? '') !== (scope ?? '')) throw new Error('Reuse requires the same analysis objective/scope');
  const revision = planSourceRevision(oldRoot, newRoot, files, graph);
  atomicPrivateWrite(join(newRoot, '00_source_revision.json'), JSON.stringify({ sourceRun: oldRoot, previousSnapshot: revision.before.snapshot.id,
    currentSnapshot: revision.after.snapshot.id, changes: revision.changes, affectedFiles: revision.affectedFiles, comparisonProfile: revision.comparisonProfile, tools: revision.tools }, null, 2));
  const sealedResults = JSON.parse(readFileSync(join(oldRoot, '00_work_unit_results.json'), 'utf8'));
  const sealedTasks = sealedResults.tasks ?? [];
  const oldTasks: AnalysisTask[] = JSON.parse(readFileSync(join(oldRoot, '01_execution_tasks.json'), 'utf8'));
  const outcomes = Object.values(snapshot.attempts).filter(attempt => attempt.status === 'completed' && !attempt.superseded);
  const rangeIdentity = (target: string, task: AnalysisTask) => JSON.stringify(task.ownedSources.map(file => {
    const raw = readFileSync(join(target, file.path));
    const logicalOffset = (offset: number) => Buffer.byteLength(raw.subarray(0, offset).toString('utf8').replace(/\r\n/g, '\n'));
    return [file.path, file.lineStart, file.lineEnd, logicalOffset(file.byteStart), file.byteEnd === raw.length ? 'EOF' : logicalOffset(file.byteEnd)];
  }));
  const materialize = (phase: string, prior: typeof outcomes[number], directory: string, events: ProviderRuntimeEvent[]): ProviderPhaseOutcome<SessionOutcome> => {
    const stored = prior.result as { domainResult: any; recoveryOutcome: ProviderPhaseOutcome<SessionOutcome> };
    if (!stored.recoveryOutcome) throw new Error('Reuse result has no provenance');
    for (const artifact of prior.artifacts ?? []) atomicPrivateWrite(join(directory, artifact.name), readFileSync(artifact.path));
    const priorDirectory = prior.artifacts?.[0]?.path ? join(prior.artifacts[0].path, '..') : oldRoot;
    if (phase === 'analyze') {
      const task = sealedTasks.find((task: { taskId: string }) => task.taskId === prior.round);
      const sealed = sealedResults.units.find((unit: { unitKey: string }) => unit.unitKey === task?.parentUnitKey)?.findingReceipts ?? [];
      const observed = readStandardFindingRecordReceipts(priorDirectory);
      for (const receipt of observed) if (!sealed.some((known: typeof receipt) => JSON.stringify(known) === JSON.stringify(receipt))) throw new Error('Reuse finding differs from the sealed analysis checkpoint');
      promoteStandardFindingRecords({ fromEngagementDir: priorDirectory, toEngagementDir: directory, expected: observed });
    }
    const usage = { provider: 'host-validated-reuse', costUsd: 0, accountingComplete: true };
    return { provider: usage.provider, usage, texts: [], events,
      structuredOutput: structuredClone(stored.domainResult), raw: { texts: [], ledger: [], totalCostUsd: 0, costAccountingComplete: true } };
  };
  return {
    revision,
    scanner(directory: string) {
      const prior = outcomes.find(attempt => attempt.phase === 'recon');
      return prior && revision.allReusable ? materialize('recon', prior, directory, []) : undefined;
    },
    task(task: AnalysisTask, directory: string, dependencies: readonly string[]) {
      if (task.kind !== 'source' || !task.ownedSources.length) return undefined;
      const identity = rangeIdentity(revision.after.target, task);
      const oldTask = oldTasks.find(candidate => candidate.kind === task.kind && rangeIdentity(revision.before.target, candidate) === identity
        && JSON.stringify(candidate.flowResponsibilities) === JSON.stringify(task.flowResponsibilities));
      if (oldTask && !sealedTasks.some((record: { taskId: string; ownedSources: unknown }) => record.taskId === oldTask.unitKey && JSON.stringify(record.ownedSources) === JSON.stringify(oldTask.ownedSources))) throw new Error('Reuse task differs from the sealed analysis checkpoint');
      if (!oldTask || [...task.ownedSources.map(file => file.path), ...dependencies].some(file => revision.affectedFiles.includes(file))) return undefined;
      const obligationIdentity=(value:AnalysisTask)=>JSON.stringify((value.securityObligations ?? []).map(o=>({id:o.id,control:o.control,cases:o.cases,question:o.question})));
      if(obligationIdentity(oldTask)!==obligationIdentity(task)) return undefined;
      const prior = outcomes.find(attempt => attempt.phase === 'analyze' && attempt.round === oldTask.unitKey);
      if (!prior) return undefined;
      const previous = (prior.result as any)?.recoveryOutcome as ProviderPhaseOutcome<SessionOutcome> | undefined;
      if (!previous) return undefined;
      const observedDependencies = previous.events.filter(event => event.resource?.startsWith(revision.before.target + '/')).map(event => relative(revision.before.target, event.resource!));
      if (observedDependencies.some(file => revision.affectedFiles.includes(file))) return undefined;
      const priorDirectory = join(prior.artifacts![0]!.path, '..');
      const assessments = readAnalysisAssessments({ directory: priorDirectory, target: revision.before.target, files: oldTask.ownedSources.map(file => file.path), ranges: oldTask.ownedSources, flows: oldTask.flowResponsibilities, flowIds: oldTask.flowResponsibilities.map(flow => flow.id),
        securityObligations:oldTask.securityObligations,contextFiles:dependencies });
      if (!assessments.complete) return undefined;
      // Line-preserving normalization does not preserve raw byte offsets. Until
      // byte quotes have a validated mapping, reanalyze only this affected task.
      if (assessments.value.flows.some(flow => flow.evidence.some(evidence => evidence.byteStart !== undefined
        && revision.changes.find(change => change.path === evidence.path)?.kind !== 'identical'))) return undefined;
      const events: ProviderRuntimeEvent[] = [], mapping = [];
      for (const file of task.ownedSources) {
        const oldFile = oldTask.ownedSources.find(old => old.path === file.path)!;
        const path = join(revision.before.target, file.path), newPath = join(revision.after.target, file.path);
        const receipts = previous.events.filter(event => event.event === 'SourceDelivery' && event.resource === path && event.delivery).map(event => event.delivery!);
        if (!sourceRangeDelivered(path, receipts, oldFile.lineStart, oldFile.lineEnd, oldFile)) return undefined;
        const change = revision.changes.find(change => change.path === file.path)!;
        if (!change.reuseAnalysis) return undefined;
        const range = mapEvidenceLines(readFileSync(path, 'utf8'), readFileSync(newPath, 'utf8'), file.lineStart, file.lineEnd);
        if (!range) return undefined;
        mapping.push({ path: file.path, change, range });
        events.push({ at: new Date().toISOString(), event: 'ValidatedSourceReuse', resource: newPath,
          reason: `Reused ${oldRoot}/${oldTask.unitKey}; source-format/1; prior snapshot ${revision.before.snapshot.id}`,
          delivery: { toolCallId: `reuse:${oldTask.unitKey}:${file.path}`, sourceHash: file.sha256, totalLines: file.lineEnd, outputHash: oldFile.sha256,
            ranges: [], byteRanges: [{ start: file.byteStart, end: file.byteEnd }], status: 'verified' } });
      }
      const supportingEvidence: Array<{path:string;lineStart:number;lineEnd:number;byteStart?:number;byteEnd?:number}> = [
        ...assessments.value.flows.flatMap(flow=>flow.evidence),...assessments.security.rows.flatMap(row=>row.evidence)];
      for (const evidence of supportingEvidence) {
        const path = join(revision.before.target, evidence.path), newPath = join(revision.after.target, evidence.path);
        if (revision.affectedFiles.includes(evidence.path) || !revision.changes.find(change => change.path === evidence.path)?.reuseAnalysis) return undefined;
        const receipts = previous.events.filter(event => event.event === 'SourceDelivery' && event.resource === path && event.delivery).map(event => event.delivery!);
        const bytes = evidence.byteStart === undefined ? undefined : { byteStart: evidence.byteStart, byteEnd: evidence.byteEnd! };
        if (!sourceRangeDelivered(path, receipts, evidence.lineStart, evidence.lineEnd, bytes)) return undefined;
        const range = mapEvidenceLines(readFileSync(path, 'utf8'), readFileSync(newPath, 'utf8'), evidence.lineStart, evidence.lineEnd);
        if (!range) return undefined;
        const source = revision.after.snapshot.files.find(file => file.path === evidence.path)!;
        events.push({ at: new Date().toISOString(), event: 'ValidatedSourceReuse', resource: newPath, reason: `Validated prior flow evidence: ${oldTask.unitKey}`,
          delivery: { toolCallId: `reuse-flow:${oldTask.unitKey}:${evidence.path}`, sourceHash: source.sha256, outputHash: source.sha256, totalLines: evidence.lineEnd,
            ranges: bytes ? [] : [{ start: evidence.lineStart, end: evidence.lineEnd }],
            ...(bytes ? { byteRanges: [{ start: bytes.byteStart, end: bytes.byteEnd }] } : {}), status: 'verified' } });
      }
      atomicPrivateWrite(join(directory, '00_reuse_receipt.json'), JSON.stringify({ oldRun: oldRoot, oldTask: oldTask.unitKey, task: task.unitKey,
        previousSnapshot: revision.before.snapshot.id, currentSnapshot: revision.after.snapshot.id, comparisonProfile: revision.comparisonProfile,
        dependencyChecks: [...dependencies, ...observedDependencies], mapping, oldArtifacts: prior.artifacts, toolsReused: false }, null, 2));
      return materialize('analyze', prior, directory, events);
    },
  };
}
