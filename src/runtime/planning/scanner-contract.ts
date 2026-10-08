import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import type { DependencyGraph } from '../workflow/offsec-dependency-graph.js';
import { atomicPrivateWrite } from '../workflow/storage-files.js';

const Id = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$/);
const Text = z.string().trim().min(12);
export const ScannerPlanSchema = z.object({
  schemaVersion: z.literal('1'),
  units: z.array(z.object({ id: Id, responsibility: Text, rationale: Text,
    files: z.array(z.string().min(1)).min(1), boundaryEvidence: z.array(z.string().min(1)).min(1), assumptions: z.array(z.string()) }).strict()).min(1),
  interfaces: z.array(z.object({ id: Id, unitId: Id, file: z.string().min(1), kind: z.string().min(1), description: Text }).strict()),
  prioritySurfaces: z.array(z.object({ unitId: Id, files: z.array(z.string()).min(1), reason: Text }).strict()),
  crossUnitFlows: z.array(z.object({ id: Id, fromUnit: Id, toUnit: Id, ownerUnit: Id,
    files: z.array(z.string()).min(2), question: Text }).strict()),
  unresolved: z.array(z.string()),
}).strict();
export type ScannerPlan = z.infer<typeof ScannerPlanSchema>;

/** Compact, lossless resolved edges avoid making the Scanner page through
 * repeated parser metadata before it can assign directed responsibilities. */
export function writeScannerDependencies(root: string, graph: DependencyGraph) {
  const bySource = new Map<string, Set<string>>();
  for (const edge of graph.edges) for (const destination of edge.resolvedTargets) {
    if (!bySource.has(edge.from)) bySource.set(edge.from, new Set());
    bySource.get(edge.from)!.add(destination);
  }
  const path = join(root, '00_scanner_dependencies.json');
  const rows = [...bySource].sort(([a], [b]) => a.localeCompare(b)).map(([from, targets]) => ({ from, targets: [...targets].sort() }));
  atomicPrivateWrite(path, '[\n' + rows.map(row => JSON.stringify(row)).join(',\n') + '\n]\n');
  return path;
}

export function validateScannerPlan(value: unknown, sourceFiles: readonly string[], graph?: DependencyGraph): ScannerPlan {
  const plan = ScannerPlanSchema.parse(value), expected = new Set(sourceFiles), owners = new Map<string, string>();
  const errors = new Set<string>();
  const ids = new Set<string>();
  for (const unit of plan.units) {
    if (ids.has(unit.id)) errors.add(`Duplicate Scanner unit: ${unit.id}`);
    ids.add(unit.id);
    for (const file of unit.files) {
      if (!expected.has(file)) errors.add(`Scanner file outside inventory: ${file}`);
      if (owners.has(file)) errors.add(`Duplicate Scanner ownership: ${file}`);
      owners.set(file, unit.id);
    }
    for (const file of unit.boundaryEvidence) if (!unit.files.includes(file)) errors.add(`Boundary evidence outside unit ownership: ${unit.id}/${file}`);
  }
  const missing = sourceFiles.filter(file => !owners.has(file));
  if (missing.length) errors.add(`Scanner unassigned files (${missing.length}): ${missing.join(', ')}`);
  const local = (unitId: string, file: string) => {
    if (!ids.has(unitId) || owners.get(file) !== unitId) errors.add(`Scanner ownership mismatch: ${unitId}/${file}`);
  };
  if (new Set(plan.interfaces.map(item => item.id)).size !== plan.interfaces.length) errors.add('Duplicate Scanner interface ID');
  for (const item of plan.interfaces) local(item.unitId, item.file);
  for (const surface of plan.prioritySurfaces) for (const file of surface.files) local(surface.unitId, file);
  const flowIds = new Set<string>();
  for (const flow of plan.crossUnitFlows) {
    if (flowIds.has(flow.id)) errors.add(`Duplicate flow: ${flow.id}`); flowIds.add(flow.id);
    if (flow.fromUnit === flow.toUnit || !ids.has(flow.fromUnit) || !ids.has(flow.toUnit) || ![flow.fromUnit, flow.toUnit].includes(flow.ownerUnit)) errors.add(`Invalid Scanner flow owner: ${flow.id}`);
    if (flow.files.some(file => ![flow.fromUnit, flow.toUnit].includes(owners.get(file) ?? '')) || !flow.files.some(file => owners.get(file) === flow.fromUnit) || !flow.files.some(file => owners.get(file) === flow.toUnit)) errors.add(`Invalid Scanner flow evidence: ${flow.id}`);
  }
  const missingFlows = new Set<string>();
  for (const edge of graph?.edges ?? []) {
    for (const destination of edge.resolvedTargets) {
      const from = owners.get(edge.from), to = owners.get(destination);
      if (from && to && from !== to && !plan.crossUnitFlows.some(flow => flow.fromUnit === from && flow.toUnit === to)) {
        const pair = `${from} -> ${to}`;
        if (!missingFlows.has(pair)) errors.add(`Scanner missing cross-unit responsibility: ${pair} (${edge.from} -> ${destination})`);
        missingFlows.add(pair);
      }
    }
  }
  // A large plan must receive every correctable defect in one response, rather
  // than paying for a full rewrite once per missing file or boundary.
  if (errors.size) throw new Error([...errors].join('\n'));
  return plan;
}

export function readScannerPlan(engagementDir: string, files: readonly string[], graph?: DependencyGraph) {
  return validateScannerPlan(JSON.parse(readFileSync(join(engagementDir, '00_scanner_plan.json'), 'utf8')), files, graph);
}

export function saveScannerArtifacts(engagementDir: string, plan: ScannerPlan, sourceSnapshotId: string) {
  const artifacts = {
    'scan_manifest.json': { sourceSnapshotId, units: plan.units },
    'security_surface_map.json': { sourceSnapshotId, priorityOnly: true, surfaces: plan.prioritySurfaces },
    'interface_inventory.json': { sourceSnapshotId, interfaces: plan.interfaces },
    'scan_plan.json': { sourceSnapshotId, crossUnitFlows: plan.crossUnitFlows, unresolved: plan.unresolved },
  };
  for (const [name, value] of Object.entries(artifacts)) atomicPrivateWrite(join(engagementDir, name), JSON.stringify(value, null, 2) + '\n');
  return Object.keys(artifacts);
}
