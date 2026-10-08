import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import type { LedgerRow, SessionSpec } from '../session.js';
import { observeSourceDelivery } from '../source-delivery.js';
import { canonicalV2Findings } from '../v2-review-resolution.js';

/** A deterministic provider emulator. It explicitly emits model-facing read receipts. */
export function protocolFixture(spec: SessionSpec, options: { deliver?: boolean } = {}): LedgerRow[] {
  const ledger: LedgerRow[] = [];
  if (spec.phase === 'review' && spec.taskData?.independentCounting === true) {
    const path = join(spec.engagementDir, '03_review_result.json');
    if (existsSync(path)) {
      const review = JSON.parse(readFileSync(path,'utf8')), canonical = canonicalV2Findings(spec.engagementDir);
      review.countingSchemaVersion = 1;
      for (const row of review.reviewedFindings ?? []) {
        if (!['retained','corrected'].includes(row.action) || row.counting) continue;
        const finding = canonical.get(row.correctedFindingId ?? row.originalFindingId);
        if (finding) row.counting = {kind:'vulnerability',causeId:`VC-fixture-${finding.id.toLowerCase()}`,component: finding.id,
          rootCause:'Synthetic isolated control failure for the lifecycle fixture',fixBoundary:'Repair the isolated fixture control for this finding',primaryEvidence:finding.evidence.slice(0,1)};
      }
      writeFileSync(path,JSON.stringify(review));
    }
  }
  if (spec.phase === 'evaluate' && spec.taskData?.evaluationProjection) {
    const input = JSON.parse(readFileSync((spec.taskData.evaluationProjection as { path: string }).path, 'utf8'));
    const path = join(spec.engagementDir, '04_evaluation.json');
    const current = existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : {};
    writeFileSync(path, JSON.stringify({ ...current, severityDistribution: input.severityDistribution, actualToolCoverage: input.actualToolCoverage, vulnerabilityInventory: input.vulnerabilityInventory }));
  }
  if (spec.phase === 'recon') {
    const manifest = JSON.parse(readFileSync(join(spec.engagementDir, 'source_manifest.json'), 'utf8'));
    const graph = JSON.parse(readFileSync(join(spec.engagementDir, '00_inventory_graph.json'), 'utf8'));
    manifest.units = manifest.units.map((unit: { files: string[] }) => ({ ...unit, files: unit.files.filter(file => !(manifest.source_errors ?? []).some((error: { path: string }) => error.path === file)) }));
    const units = manifest.units.filter((unit: { files: string[] }) => unit.files.length).map((unit: { id: string; files: string[] }, index: number) => ({ id: `U-${index}`, files: unit.files,
      responsibility: 'Fixture module responsibility and trust boundary', rationale: 'Fixture structural grouping by module ownership', boundaryEvidence: [unit.files[0]], assumptions: [] }));
    const owner = new Map<string, string>(units.flatMap((unit: { id: string; files: string[] }) => unit.files.map(file => [file, unit.id] as [string, string])));
    const flows = new Map();
    for (const edge of graph.edges) for (const to of edge.resolvedTargets) {
      const fromUnit = owner.get(edge.from), toUnit = owner.get(to);
      if (fromUnit && toUnit && fromUnit !== toUnit) flows.set(`${fromUnit}->${toUnit}`, { id: `FLOW-${flows.size}`, fromUnit, toUnit, ownerUnit: fromUnit, files: [edge.from, to], question: 'Trace the fixture dependency across its assigned trust boundary' });
    }
    writeFileSync(join(spec.engagementDir, '00_scanner_plan.json'), JSON.stringify({ schemaVersion: '1', units,
      interfaces: [], prioritySurfaces: [], crossUnitFlows: [...flows.values()], unresolved: [] }));
  }
  if (spec.phase === 'analyze') {
    const owned = spec.workUnit?.ownedSourceFiles ?? [];
    const task = JSON.parse(/^inputs: (.+)$/m.exec(spec.prompt)?.[1] ?? '{}').taskRequest;
    let root = spec.engagementDir;
    while (!existsSync(join(root, '00_scanner_plan.json')) && dirname(root) !== root) root = dirname(root);
    const plan = existsSync(join(root, '00_scanner_plan.json')) ? JSON.parse(readFileSync(join(root, '00_scanner_plan.json'), 'utf8')) : { units: [], crossUnitFlows: [] };
    const unit = plan.units.find((unit: { files: string[] }) => owned.some(file => unit.files.includes(relative(spec.target, file))));
    writeFileSync(join(spec.engagementDir, '02_file_assessments.json'), JSON.stringify({
      files: owned.map(file => {
        const range = task?.ownedSources.find((source: { path: string }) => source.path === relative(spec.target, file));
        const text = readFileSync(file), first = text.subarray(range?.byteStart ?? 0, range?.byteEnd ?? text.length).toString('utf8').split(/\r?\n/)[0]!;
        return { path: relative(spec.target, file), status: 'analyzed', rationale: 'Fixture completed source analysis and counterevidence checks', evidence: first ? [{ lineStart: range?.lineStart ?? 1, lineEnd: range?.lineStart ?? 1, quote: first }] : [] };
      }),
      flows: (task?.flowResponsibilities ?? plan.crossUnitFlows.filter((flow: { ownerUnit: string }) => flow.ownerUnit === unit?.id)).map((flow: { id: string; files: string[] }) => ({ id: flow.id, status: 'analyzed', rationale: 'Fixture traced the source and dependency boundary', evidenceFiles: flow.files, evidence: flow.files.flatMap(path => { const quote = readFileSync(join(spec.target, path), 'utf8').split(/\r?\n/)[0]!; return quote ? [{ path, lineStart: 1, lineEnd: 1, quote }] : []; }) })),
      securityAssessments:(task?.securityObligations ?? []).map((o:any)=>({id:o.id,cases:o.cases.map((name:string)=>({case:name,result:'not-applicable',reason:'This deterministic lifecycle fixture has no deployed protected operation.'})),evidence:o.anchors,findingIds:[],conditions:[]})),
    }));
    if (options.deliver !== false) for (const file of [...new Set([...owned, ...(task?.contextRanges ?? []).map((range: { path: string }) => join(spec.target, range.path)), ...(task?.flowResponsibilities ?? []).flatMap((flow: { files: string[] }) => flow.files.map(file => join(spec.target, file)))])]) ledger.push(...deliveryFixture(spec, file));
  }
  return ledger;
}

export function deliveryFixture(spec: SessionSpec, file: string): LedgerRow[] {
  const text = readFileSync(file, 'utf8'), content = text.split(/\r?\n/).map((line, i) => `${i + 1}\t${line}`).join('\n');
  const observed = observeSourceDelivery({ target: spec.target, file, allowedFiles: [file], toolCallId: `fixture:${file}`, content });
  return observed ? [{ at: new Date(0).toISOString(), event: 'SourceDelivery', tool: 'Read', decision: 'allow', ...observed }] : [];
}
