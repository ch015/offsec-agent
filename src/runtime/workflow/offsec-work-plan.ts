import { createHash } from 'node:crypto';
import { readFileSync, realpathSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { dirname, extname, join, relative, resolve, sep } from 'node:path';

import { z } from 'zod';

import type { DependencyGraph, GraphEdge } from './offsec-dependency-graph.js';
import { assertDependencyGraphIntact } from './offsec-dependency-graph.js';

const Sha256Schema = z.string().regex(/^[a-f0-9]{64}$/);
// 정규화된 traversal-free POSIX manifest-relative 경로만 허용한다 — 접두사('../')뿐 아니라
// 중간(interior) '../' 세그먼트, 백슬래시, 빈/'.' 세그먼트(비정규화 경로)도 모두 거부한다.
// 실제 source-manifest 워커가 만드는 경로(예: 'packages/api/app.ts')는 항상 이 형태이므로
// 정상 레거시 sealed plan 호환에는 영향이 없다.
const RelativePathSchema = z.string().min(1).refine((value) => {
  if (value.includes('\0') || value.includes('\\')) return false;
  if (value.startsWith('/')) return false;
  const segments = value.split('/');
  return segments.every((segment) => segment !== '' && segment !== '.' && segment !== '..');
}, 'relative source path가 안전하지 않다(정규화된 traversal-free POSIX 경로여야 한다)');

const FileReceiptSchema = z.object({
  path: RelativePathSchema,
  bytes: z.number().int().nonnegative(),
  sha256: Sha256Schema,
}).strict();

const UnresolvedEdgeSchema = z.object({
  from: RelativePathSchema,
  specifier: z.string().min(1),
  reason: z.enum(['unresolved', 'context-cap']),
  // 신규 생성 context-cap 레코드는 항상 채워진다. 레거시 sealed plan(필드 부재)은 계속 파싱·재개된다.
  resolvedTarget: RelativePathSchema.optional(),
  budgetReason: z.enum(['file-cap', 'token-cap']).optional(),
}).strict();

const WorkUnitSchema = z.object({
  unitKey: z.string().regex(/^unit-[a-f0-9]{16}$/),
  sourceUnitId: z.string().min(1),
  ownedFiles: z.array(FileReceiptSchema).min(1),
  contextFiles: z.array(FileReceiptSchema),
  unresolvedEdges: z.array(UnresolvedEdgeSchema),
  assignedSourceSha256: Sha256Schema,
}).strict();

export const OffsecWorkPlanSchema = z.object({
  schemaVersion: z.literal('1.0.0'),
  targetRealpath: z.string().min(1),
  sourceManifestSha256: Sha256Schema,
  maxContextFilesPerUnit: z.number().int().nonnegative(),
  units: z.array(WorkUnitSchema).min(1),
  workPlanSha256: Sha256Schema,
  generatedAt: z.string().datetime(),
}).strict();

export type OffsecWorkPlan = z.infer<typeof OffsecWorkPlanSchema>;
export type OffsecWorkUnit = z.infer<typeof WorkUnitSchema>;

// ── V2 schemas ─────────────────────────────────────────────────────────────

const V2_RANKING_POLICY = 'ref-count-desc/tokens-asc/path-asc';

const ContextOmissionSchema = z.object({
  target: RelativePathSchema,
  reason: z.enum(['file-cap', 'token-cap']),
  estimatedTokens: z.number().int().nonnegative(),
  directReferenceCount: z.number().int().positive(),
}).strict();

const ContextSelectionReceiptSchema = z.object({
  ownedEstimatedTokens: z.number().int().nonnegative(),
  candidateCount: z.number().int().nonnegative(),
  selectedContextFiles: z.number().int().nonnegative(),
  selectedContextEstimatedTokens: z.number().int().nonnegative(),
  omitted: z.array(ContextOmissionSchema),
  rankingPolicy: z.literal(V2_RANKING_POLICY),
}).strict();

const PlanningPolicySchema = z.object({
  estimatedCharsPerToken: z.number().int().positive(),
  maxContextEstimatedTokensPerUnit: z.number().int().positive(),
  maxContextFilesPerUnit: z.number().int().nonnegative(),
  // Optional so existing sealed V2 plans retain their hash and resume unchanged.
  maxOwnedFilesPerUnit: z.number().int().positive().optional(),
  maxOwnedEstimatedTokensPerUnit: z.number().int().positive().optional(),
}).strict();

const WorkUnitV2Schema = WorkUnitSchema.extend({
  estimatedTokens: z.number().int().nonnegative(),
  contextSelectionReceipt: ContextSelectionReceiptSchema,
  // A file exceeding the source budget must be isolated and read in ranges.
  oversizedOwnedFiles: z.array(RelativePathSchema).optional(),
});

export const OffsecWorkPlanV2Schema = z.object({
  schemaVersion: z.literal('2.0.0'),
  targetRealpath: z.string().min(1),
  sourceManifestSha256: Sha256Schema,
  dependencyGraphSha256: Sha256Schema,
  planningPolicy: PlanningPolicySchema,
  maxContextFilesPerUnit: z.number().int().nonnegative(),
  units: z.array(WorkUnitV2Schema).min(1),
  workPlanSha256: Sha256Schema,
  generatedAt: z.string().datetime(),
}).strict();

export type OffsecWorkPlanV2 = z.infer<typeof OffsecWorkPlanV2Schema>;
export type OffsecWorkUnitV2 = z.infer<typeof WorkUnitV2Schema>;
export type ContextSelectionReceipt = z.infer<typeof ContextSelectionReceiptSchema>;
export type OffsecWorkPlanAny = OffsecWorkPlan | OffsecWorkPlanV2;
export type OffsecWorkUnitAny = OffsecWorkUnit | OffsecWorkUnitV2;

type SourceManifest = {
  target_realpath: string;
  hash: string;
  content_hash?: string;
  source_files: string[];
  units: Array<{ id: string; files: string[] }>;
};

export function createOffsecWorkPlan(input: {
  target: string;
  sourceManifest: unknown;
  maxContextFilesPerUnit?: number;
}): OffsecWorkPlan {
  const targetRealpath = realpathSync(input.target);
  const sourceManifest = parseSourceManifest(input.sourceManifest);
  if (realpathSync(sourceManifest.target_realpath) !== targetRealpath) {
    throw new Error('OffSec work plan target이 source manifest와 다르다');
  }
  const maxContextFilesPerUnit = input.maxContextFilesPerUnit ?? 50;
  if (!Number.isInteger(maxContextFilesPerUnit) || maxContextFilesPerUnit < 0) {
    throw new Error('OffSec work plan context cap이 잘못됐다');
  }

  const sourceFiles = [...new Set(sourceManifest.source_files)].sort();
  if (sourceFiles.length !== sourceManifest.source_files.length) {
    throw new Error('OffSec source manifest file이 중복됐다');
  }
  const receipts = new Map(sourceFiles.map((path) => [path, fileReceipt(targetRealpath, path)]));
  const owner = new Map<string, string>();
  for (const unit of sourceManifest.units) {
    for (const file of unit.files) {
      if (!receipts.has(file)) throw new Error(`OffSec unit file이 source manifest에 없다: ${file}`);
      if (owner.has(file)) throw new Error(`OffSec source file이 여러 unit에 배정됐다: ${file}`);
      owner.set(file, unit.id);
    }
  }
  const unassigned = sourceFiles.filter((file) => !owner.has(file));
  if (unassigned.length > 0) throw new Error(`OffSec source file이 unit에 배정되지 않았다: ${unassigned.join(',')}`);

  const units = sourceManifest.units
    .filter((unit) => unit.files.length > 0)
    .map((unit) => buildUnit({
      targetRealpath,
      unit,
      owner,
      receipts,
      sourceFiles,
      maxContextFilesPerUnit,
    }))
    .sort((left, right) => left.unitKey.localeCompare(right.unitKey));
  const unitKeys = new Set(units.map((unit) => unit.unitKey));
  if (unitKeys.size !== units.length) throw new Error('OffSec unitKey collision이 발생했다');
  const core = {
    schemaVersion: '1.0.0' as const,
    targetRealpath,
    sourceManifestSha256: sourceManifest.content_hash ?? sourceManifest.hash,
    maxContextFilesPerUnit,
    units,
  };
  return OffsecWorkPlanSchema.parse({
    ...core,
    workPlanSha256: digest(stableJson(core)),
    generatedAt: new Date().toISOString(),
  });
}

export function createOffsecWorkPlanV2(input: {
  target: string;
  sourceManifest: unknown;
  dependencyGraph: DependencyGraph;
  maxContextFilesPerUnit?: number;
  maxContextEstimatedTokensPerUnit?: number;
  maxOwnedFilesPerUnit?: number;
  maxOwnedEstimatedTokensPerUnit?: number;
  estimatedCharsPerToken?: number;
}): OffsecWorkPlanV2 {
  const targetRealpath = realpathSync(input.target);
  const sourceManifest = parseSourceManifest(input.sourceManifest);
  if (realpathSync(sourceManifest.target_realpath) !== targetRealpath) {
    throw new Error('OffSec work plan target이 source manifest와 다르다');
  }
  const charsPerToken = input.estimatedCharsPerToken ?? 4;
  const maxContextFilesPerUnit = input.maxContextFilesPerUnit ?? 75;
  const maxContextTokens = input.maxContextEstimatedTokensPerUnit ?? 98_304;
  for (const [name, value] of Object.entries({
    maxOwnedFilesPerUnit: input.maxOwnedFilesPerUnit,
    maxOwnedEstimatedTokensPerUnit: input.maxOwnedEstimatedTokensPerUnit,
  })) {
    if (value !== undefined && (!Number.isSafeInteger(value) || value < 1)) {
      throw new Error(`${name} must be a positive safe integer`);
    }
  }
  const graph = input.dependencyGraph;

  const sourceFiles = [...new Set(sourceManifest.source_files)].sort();
  if (sourceFiles.length !== sourceManifest.source_files.length) {
    throw new Error('OffSec source manifest file이 중복됐다');
  }
  const receipts = new Map(sourceFiles.map((p) => [p, fileReceipt(targetRealpath, p)]));
  const owner = new Map<string, string>();
  for (const unit of sourceManifest.units) {
    for (const file of unit.files) {
      if (!receipts.has(file)) throw new Error(`OffSec unit file이 source manifest에 없다: ${file}`);
      if (owner.has(file)) throw new Error(`OffSec source file이 여러 unit에 배정됐다: ${file}`);
      owner.set(file, unit.id);
    }
  }
  const unassigned = sourceFiles.filter((f) => !owner.has(f));
  if (unassigned.length > 0) throw new Error(`OffSec source file이 unit에 배정되지 않았다: ${unassigned.join(',')}`);

  const nodeMap = new Map(graph.nodes.map((n) => [n.path, n]));
  const edgesByFrom = new Map<string, GraphEdge[]>();
  for (const edge of graph.edges) {
    const list = edgesByFrom.get(edge.from) ?? [];
    list.push(edge);
    edgesByFrom.set(edge.from, list);
  }

  const units = sourceManifest.units
    .filter((unit) => unit.files.length > 0)
    .flatMap((unit) => partitionSourceUnit(unit, nodeMap, input.maxOwnedFilesPerUnit, input.maxOwnedEstimatedTokensPerUnit))
    .map((unit) => buildUnitV2({
      targetRealpath,
      unit,
      owner,
      receipts,
      nodeMap,
      edgesByFrom,
      maxContextFilesPerUnit,
      maxContextTokens,
      charsPerToken,
    }))
    .sort((l, r) => l.unitKey.localeCompare(r.unitKey));

  const unitKeys = new Set(units.map((u) => u.unitKey));
  if (unitKeys.size !== units.length) throw new Error('OffSec unitKey collision이 발생했다');

  const planningPolicy = {
    estimatedCharsPerToken: charsPerToken,
    maxContextEstimatedTokensPerUnit: maxContextTokens,
    maxContextFilesPerUnit,
    ...(input.maxOwnedFilesPerUnit !== undefined ? { maxOwnedFilesPerUnit: input.maxOwnedFilesPerUnit } : {}),
    ...(input.maxOwnedEstimatedTokensPerUnit !== undefined ? { maxOwnedEstimatedTokensPerUnit: input.maxOwnedEstimatedTokensPerUnit } : {}),
  };
  const core = {
    schemaVersion: '2.0.0' as const,
    targetRealpath,
    sourceManifestSha256: sourceManifest.content_hash ?? sourceManifest.hash,
    dependencyGraphSha256: graph.dependencyGraphSha256,
    planningPolicy,
    maxContextFilesPerUnit,
    units,
  };
  const result = OffsecWorkPlanV2Schema.parse({
    ...core,
    workPlanSha256: digest(stableJson(core)),
    generatedAt: new Date().toISOString(),
  });
  // Full graph/plan cross-validation before returning — not relying solely on assess
  assertPlanGraphIntegrity(result, graph);
  return result;
}

export function writeOffsecWorkPlan(engagementDir: string, plan: OffsecWorkPlanAny): string {
  const parsed = assertOffsecWorkPlanIntact(plan);
  const path = join(engagementDir, '00_work_plan.json');
  const temporary = `${path}.${process.pid}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(parsed, null, 2)}\n`, { mode: 0o600 });
  renameSync(temporary, path);
  return path;
}

export function assertOffsecWorkPlanIntact(value: unknown): OffsecWorkPlanAny {
  const raw = value as { schemaVersion?: string };
  if (raw?.schemaVersion === '2.0.0') {
    return assertPlanHashV2(value);
  }
  const plan = assertPlanHash(value);
  for (const unit of plan.units) {
    assertUnitAssignment(unit);
  }
  return plan;
}

export function assertOffsecWorkUnitIntact(value: unknown, unitKey: string): OffsecWorkUnitAny {
  const raw = value as { schemaVersion?: string };
  if (raw?.schemaVersion === '2.0.0') {
    const plan = assertPlanHashV2(value);
    const unit = plan.units.find((c) => c.unitKey === unitKey);
    if (!unit) throw new Error(`OffSec work unit이 sealed plan에 없다: ${unitKey}`);
    assertUnitAssignment(unit);
    return unit;
  }
  const plan = assertPlanHash(value);
  const unit = plan.units.find((candidate) => candidate.unitKey === unitKey);
  if (!unit) throw new Error(`OffSec work unit이 sealed plan에 없다: ${unitKey}`);
  assertUnitAssignment(unit);
  return unit;
}

export function assertOffsecWorkPlanComplete(planValue: unknown, completedUnitKeys: readonly string[]): void {
  const plan = assertOffsecWorkPlanIntact(planValue);
  const completed = new Set(completedUnitKeys);
  if (completed.size !== completedUnitKeys.length) throw new Error('OffSec completed unit key가 중복됐다');
  const expected = plan.units.map((unit) => unit.unitKey);
  const missing = expected.filter((unitKey) => !completed.has(unitKey));
  const unexpected = [...completed].filter((unitKey) => !expected.includes(unitKey));
  if (missing.length > 0 || unexpected.length > 0) {
    throw new Error(`OffSec work plan barrier 실패: missing=${missing.join(',') || '-'} unexpected=${unexpected.join(',') || '-'}`);
  }
}

export function getUnitTypedEdges(graph: DependencyGraph, unit: OffsecWorkUnitAny): GraphEdge[] {
  const ownedPaths = new Set(unit.ownedFiles.map((f) => f.path));
  return graph.edges.filter((e) => ownedPaths.has(e.from));
}

function buildUnit(input: {
  targetRealpath: string;
  unit: { id: string; files: string[] };
  owner: ReadonlyMap<string, string>;
  receipts: ReadonlyMap<string, z.infer<typeof FileReceiptSchema>>;
  sourceFiles: readonly string[];
  maxContextFilesPerUnit: number;
}): OffsecWorkUnit {
  const ownedFiles = [...input.unit.files].sort().map((file) => input.receipts.get(file)!);
  const context = new Set<string>();
  const unresolvedEdges: OffsecWorkUnit['unresolvedEdges'] = [];
  for (const file of input.unit.files) {
    for (const dependency of dependencySpecifiers(file, readFileSync(resolve(input.targetRealpath, file), 'utf8'))) {
      const { specifier } = dependency;
      if (!dependency.resolvable) {
        unresolvedEdges.push({ from: file, specifier, reason: 'unresolved' });
        continue;
      }
      const resolved = resolveDependency(file, specifier, input.sourceFiles, dependency.language);
      if (!resolved) {
        unresolvedEdges.push({ from: file, specifier, reason: 'unresolved' });
      } else if (input.owner.get(resolved) !== input.unit.id) {
        // 이미 포함된 context file을 다시 참조하는 경우 cap에 걸려도 새 cap 레코드를 만들지 않는다
        // (resolved-but-budget-excluded와 semantically-unresolved를 구분: 이미 포함된 target은 둘 다 아니다).
        if (context.has(resolved)) {
          // no-op — already included in this unit's context set
        } else if (context.size < input.maxContextFilesPerUnit) {
          context.add(resolved);
        } else {
          unresolvedEdges.push({ from: file, specifier, reason: 'context-cap', resolvedTarget: resolved });
        }
      }
    }
  }
  return WorkUnitSchema.parse({
    unitKey: `unit-${digest(input.unit.id).slice(0, 16)}`,
    sourceUnitId: input.unit.id,
    ownedFiles,
    contextFiles: [...context].sort().map((file) => input.receipts.get(file)!),
    unresolvedEdges,
    assignedSourceSha256: digest(stableJson(ownedFiles)),
  });
}

function dependencySpecifiers(
  file: string,
  content: string,
): Array<{ specifier: string; resolvable: boolean; language: 'js' | 'python' }> {
  const found = new Map<string, { specifier: string; resolvable: boolean; language: 'js' | 'python' }>();
  const add = (specifier: string, language: 'js' | 'python', resolvable: boolean): void => {
    found.set(`${language}:${specifier}`, { specifier, language, resolvable });
  };
  if (/\.(?:js|jsx|mjs|cjs|ts|tsx)$/i.test(file)) {
  const expressions = [
    /\b(?:import|export)\s+(?:[\s\S]*?\s+from\s+)?['"]([^'"]+)['"]/g,
    /\brequire\(\s*['"]([^'"]+)['"]\s*\)/g,
    /\bimport\(\s*['"]([^'"]+)['"]\s*\)/g,
  ];
  for (const expression of expressions) {
      for (const match of content.matchAll(expression)) {
        if (match[1]) add(match[1], 'js', match[1].startsWith('.'));
      }
    }
  } else if (/\.py$/i.test(file)) {
    for (const match of content.matchAll(/^\s*from\s+([.A-Za-z_][.\w]*)\s+import\s+/gm)) {
      if (match[1]) add(match[1], 'python', match[1].startsWith('.'));
    }
    for (const match of content.matchAll(/^\s*import\s+([A-Za-z_][.\w]*)/gm)) {
      if (match[1]) add(match[1], 'python', false);
    }
  } else if (/\.(?:go|java|kt|rs)$/i.test(file)) {
    const importLike = /\b(?:import|use)\s+(?:\([^)]*?\)|[^;\n]+)/g;
    for (const match of content.matchAll(importLike)) add(match[0], 'js', false);
  }
  return [...found.values()].sort((left, right) => left.specifier.localeCompare(right.specifier));
}

function resolveDependency(
  from: string,
  specifier: string,
  sourceFiles: readonly string[],
  language: 'js' | 'python',
): string | undefined {
  const sourceSet = new Set(sourceFiles);
  if (language === 'python') {
    const leadingDots = /^\.+/.exec(specifier)?.[0].length ?? 0;
    let baseDir = dirname(from);
    for (let index = 1; index < leadingDots; index += 1) baseDir = dirname(baseDir);
    const modulePath = specifier.slice(leadingDots).replaceAll('.', '/');
    const base = resolve('/', baseDir, modulePath).slice(1).replaceAll(sep, '/');
    return [`${base}.py`, `${base}/__init__.py`].find((candidate) => sourceSet.has(candidate));
  }
  const base = resolve('/', dirname(from), specifier).slice(1).replaceAll(sep, '/');
  const candidates = [base];
  if (!extname(base)) {
    for (const extension of ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py']) candidates.push(`${base}${extension}`);
    for (const extension of ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py']) {
      candidates.push(`${base}/index${extension}`);
    }
  }
  return candidates.find((candidate) => sourceSet.has(candidate));
}

function parseSourceManifest(value: unknown): SourceManifest {
  const schema = z.object({
    target_realpath: z.string().min(1),
    hash: Sha256Schema,
    content_hash: Sha256Schema.optional(),
    source_files: z.array(RelativePathSchema).min(1),
    units: z.array(z.object({
      id: z.string().min(1),
      files: z.array(RelativePathSchema),
    }).passthrough()).min(1),
  }).passthrough();
  return schema.parse(value);
}

function fileReceipt(targetRoot: string, relativePath: string) {
  const path = realpathSync(resolve(targetRoot, relativePath));
  if (!isWithin(targetRoot, path) || !statSync(path).isFile()) {
    throw new Error(`OffSec source file이 target 밖이다: ${relativePath}`);
  }
  const content = readFileSync(path);
  return FileReceiptSchema.parse({ path: relativePath, bytes: content.byteLength, sha256: digest(content) });
}

function partitionSourceUnit(
  unit: { id: string; files: string[] },
  nodes: ReadonlyMap<string, { estimatedTokenCount: number }>,
  maxFiles = Number.MAX_SAFE_INTEGER,
  maxTokens = Number.MAX_SAFE_INTEGER,
): Array<{ id: string; files: string[]; partitionKey?: string; oversizedOwnedFiles?: string[] }> {
  const chunks: string[][] = [];
  let files: string[] = [], tokens = 0;
  for (const path of [...unit.files].sort()) {
    const node = nodes.get(path);
    if (!node) throw new Error(`OffSec partition source file이 graph에 없다: ${path}`);
    if (files.length > 0 && (files.length >= maxFiles || tokens + node.estimatedTokenCount > maxTokens)) {
      chunks.push(files);
      files = [];
      tokens = 0;
    }
    files.push(path);
    tokens += node.estimatedTokenCount;
    if (tokens > maxTokens) {
      chunks.push(files);
      files = [];
      tokens = 0;
    }
  }
  if (files.length > 0) chunks.push(files);
  return chunks.map((part) => {
    const oversized = part.filter(path => nodes.get(path)!.estimatedTokenCount > maxTokens);
    return {
      id: unit.id,
      files: part,
      // Keep the graph's parent ownership; only the execution key changes.
      ...(chunks.length > 1 ? { partitionKey: stableJson([unit.id, part]) } : {}),
      ...(oversized.length > 0 ? { oversizedOwnedFiles: oversized } : {}),
    };
  });
}

function buildUnitV2(input: {
  targetRealpath: string;
  unit: { id: string; files: string[]; partitionKey?: string; oversizedOwnedFiles?: string[] };
  owner: ReadonlyMap<string, string>;
  receipts: ReadonlyMap<string, z.infer<typeof FileReceiptSchema>>;
  nodeMap: ReadonlyMap<string, { estimatedTokenCount: number }>;
  edgesByFrom: ReadonlyMap<string, GraphEdge[]>;
  maxContextFilesPerUnit: number;
  maxContextTokens: number;
  charsPerToken: number;
}): OffsecWorkUnitV2 {
  const ownedFiles = [...input.unit.files].sort().map((f) => input.receipts.get(f)!);
  const ownedFileSet = new Set(input.unit.files);
  // Explicit sorted owned path array — edge collection and provenance iterate this,
  // matching validation, independent of caller manifest order.
  const sortedOwnedPaths = [...input.unit.files].sort();
  const ownedEstimatedTokens = sortedOwnedPaths.reduce(
    (sum, f) => sum + (input.nodeMap.get(f)?.estimatedTokenCount ?? 0), 0);

  const unresolvedEdges: OffsecWorkUnitV2['unresolvedEdges'] = [];
  const candidateRefs = new Map<string, number>();
  // Track the deterministic first referencing edge for each candidate (for omission provenance)
  const candidateFirstEdge = new Map<string, { from: string; specifier: string }>();
  for (const file of sortedOwnedPaths) {
    const edges = input.edgesByFrom.get(file) ?? [];
    for (const edge of edges) {
      if (edge.classification === 'local-unresolved') {
        unresolvedEdges.push({ from: edge.from, specifier: edge.specifier, reason: 'unresolved' });
      } else if (edge.classification === 'local-resolved') {
        for (const target of edge.resolvedTargets) {
          if (ownedFileSet.has(target)) continue;
          const prevRefs = candidateRefs.get(target) ?? 0;
          candidateRefs.set(target, prevRefs + 1);
          // Record first referencing edge deterministically (first file in sorted order, first edge)
          if (!candidateFirstEdge.has(target)) {
            candidateFirstEdge.set(target, { from: edge.from, specifier: edge.specifier });
          }
        }
      }
    }
  }

  const candidates = [...candidateRefs.entries()].map(([target, refs]) => ({
    target,
    references: refs,
    estimatedTokens: input.nodeMap.get(target)?.estimatedTokenCount ?? 0,
  }));
  candidates.sort((a, b) => {
    if (a.references !== b.references) return b.references - a.references;
    if (a.estimatedTokens !== b.estimatedTokens) return a.estimatedTokens - b.estimatedTokens;
    return a.target.localeCompare(b.target);
  });

  let remainingFiles = input.maxContextFilesPerUnit;
  let remainingTokens = input.maxContextTokens;
  const selected: string[] = [];
  const omitted: Array<{ target: string; reason: 'file-cap' | 'token-cap'; estimatedTokens: number; directReferenceCount: number }> = [];

  for (const candidate of candidates) {
    const fitsFiles = remainingFiles > 0;
    const fitsTokens = candidate.estimatedTokens <= remainingTokens;
    if (fitsFiles && fitsTokens) {
      selected.push(candidate.target);
      remainingFiles -= 1;
      remainingTokens -= candidate.estimatedTokens;
    } else {
      const reason: 'file-cap' | 'token-cap' = !fitsFiles ? 'file-cap' : 'token-cap';
      omitted.push({
        target: candidate.target,
        reason,
        estimatedTokens: candidate.estimatedTokens,
        directReferenceCount: candidate.references,
      });
      // Use the deterministic first referencing edge for truthful provenance
      const firstEdge = candidateFirstEdge.get(candidate.target)!;
      unresolvedEdges.push({
        from: firstEdge.from,
        specifier: firstEdge.specifier,
        reason: 'context-cap',
        resolvedTarget: candidate.target,
        budgetReason: reason,
      });
    }
  }

  const contextFiles = selected.sort().map((f) => input.receipts.get(f)!);
  const selectedContextEstimatedTokens = selected.reduce(
    (sum, f) => sum + (input.nodeMap.get(f)?.estimatedTokenCount ?? 0), 0);

  const unitEstimatedTokens = ownedEstimatedTokens + selectedContextEstimatedTokens;

  return WorkUnitV2Schema.parse({
    unitKey: `unit-${digest(input.unit.partitionKey ?? input.unit.id).slice(0, 16)}`,
    sourceUnitId: input.unit.id,
    ownedFiles,
    contextFiles,
    unresolvedEdges,
    assignedSourceSha256: digest(stableJson(ownedFiles)),
    estimatedTokens: unitEstimatedTokens,
    ...(input.unit.oversizedOwnedFiles ? { oversizedOwnedFiles: input.unit.oversizedOwnedFiles } : {}),
    contextSelectionReceipt: {
      ownedEstimatedTokens,
      candidateCount: candidates.length,
      selectedContextFiles: selected.length,
      selectedContextEstimatedTokens,
      omitted,
      rankingPolicy: V2_RANKING_POLICY,
    },
  }) as OffsecWorkUnitV2;
}

function assertPlanHash(value: unknown): OffsecWorkPlan {
  const plan = OffsecWorkPlanSchema.parse(value);
  const { workPlanSha256: _hash, generatedAt: _generatedAt, ...core } = plan;
  if (digest(stableJson(core)) !== plan.workPlanSha256) throw new Error('OffSec work plan hash가 다르다');
  return plan;
}

function assertPlanHashV2(value: unknown): OffsecWorkPlanV2 {
  const plan = OffsecWorkPlanV2Schema.parse(value);
  const { workPlanSha256: _hash, generatedAt: _generatedAt, ...core } = plan;
  if (digest(stableJson(core)) !== plan.workPlanSha256) throw new Error('OffSec work plan v2 hash가 다르다');
  for (const unit of plan.units) {
    assertUnitAssignment(unit);
    const receipt = unit.contextSelectionReceipt;
    if (receipt.selectedContextFiles !== unit.contextFiles.length) {
      throw new Error(`OffSec v2 unit context file 수 불일치: ${unit.unitKey}`);
    }
  }
  // Plan-only structural integrity checks (no graph needed)
  assertPlanV2InternalIntegrity(plan);
  return plan;
}

/**
 * Plan-only structural validation: checks all V2 plan invariants that
 * can be validated without loading the dependency graph.
 */
function assertPlanV2InternalIntegrity(plan: OffsecWorkPlanV2): void {
  // No duplicate unitKeys
  const unitKeys = new Set<string>();
  for (const unit of plan.units) {
    if (unitKeys.has(unit.unitKey)) throw new Error(`OffSec v2 plan에 중복 unitKey: ${unit.unitKey}`);
    unitKeys.add(unit.unitKey);
  }

  // Source ownership: each owned file path appears in exactly one unit
  const ownedFileOwners = new Map<string, string>();
  for (const unit of plan.units) {
    for (const file of unit.ownedFiles) {
      if (ownedFileOwners.has(file.path)) {
        throw new Error(`OffSec v2 plan source file이 여러 unit에 배정됐다: ${file.path}`);
      }
      ownedFileOwners.set(file.path, unit.unitKey);
    }
  }

  for (const unit of plan.units) {
    const receipt = unit.contextSelectionReceipt;

    const sourceFileCap = plan.planningPolicy.maxOwnedFilesPerUnit;
    const sourceTokenCap = plan.planningPolicy.maxOwnedEstimatedTokensPerUnit;
    if (sourceFileCap !== undefined && unit.ownedFiles.length > sourceFileCap) {
      throw new Error(`OffSec v2 owned file cap 초과: ${unit.unitKey}`);
    }
    const oversized = unit.oversizedOwnedFiles ?? [];
    const exceedsTokens = sourceTokenCap !== undefined && receipt.ownedEstimatedTokens > sourceTokenCap;
    if (exceedsTokens) {
      if (unit.ownedFiles.length !== 1 || oversized.length !== 1 || oversized[0] !== unit.ownedFiles[0]!.path) {
        throw new Error(`OffSec v2 owned token cap 초과: oversized file은 단독 작업으로 표시해야 한다: ${unit.unitKey}`);
      }
    } else if (oversized.length > 0) {
      throw new Error(`OffSec v2 oversized file 표시가 token cap과 다르다: ${unit.unitKey}`);
    }

    // Context files must not be owned by this unit
    for (const cf of unit.contextFiles) {
      if (unit.ownedFiles.some((f) => f.path === cf.path)) {
        throw new Error(`OffSec v2 unit contextFile이 ownedFile이기도 하다: ${unit.unitKey}/${cf.path}`);
      }
    }

    // No duplicate context files
    const ctxPaths = new Set<string>();
    for (const cf of unit.contextFiles) {
      if (ctxPaths.has(cf.path)) throw new Error(`OffSec v2 unit에 중복 contextFile: ${unit.unitKey}/${cf.path}`);
      ctxPaths.add(cf.path);
    }

    // No duplicate omission targets
    const omittedPaths = new Set<string>();
    for (const om of receipt.omitted) {
      if (omittedPaths.has(om.target)) throw new Error(`OffSec v2 unit에 중복 omission: ${unit.unitKey}/${om.target}`);
      omittedPaths.add(om.target);
    }

    // Selected and omitted sets must be disjoint
    for (const om of receipt.omitted) {
      if (ctxPaths.has(om.target)) {
        throw new Error(`OffSec v2 unit omission이 selected에도 있다: ${unit.unitKey}/${om.target}`);
      }
    }

    // candidateCount must equal selected + omitted
    if (receipt.candidateCount !== receipt.selectedContextFiles + receipt.omitted.length) {
      throw new Error(`OffSec v2 unit candidate count 불일치: ${unit.unitKey} (expected ${receipt.selectedContextFiles + receipt.omitted.length}, got ${receipt.candidateCount})`);
    }

    // File and token caps respected
    if (receipt.selectedContextFiles > plan.maxContextFilesPerUnit) {
      throw new Error(`OffSec v2 unit이 file cap을 초과한다: ${unit.unitKey}`);
    }
    if (receipt.selectedContextEstimatedTokens > plan.planningPolicy.maxContextEstimatedTokensPerUnit) {
      throw new Error(`OffSec v2 unit이 token cap을 초과한다: ${unit.unitKey}`);
    }

    // Reference counts must be positive
    for (const om of receipt.omitted) {
      if (om.directReferenceCount <= 0) {
        throw new Error(`OffSec v2 omission directReferenceCount가 0 이하다: ${unit.unitKey}/${om.target}`);
      }
    }
  }
}

/**
 * Structural cross-validation of a V2 plan against its dependency graph.
 * Verifies §5.5: graph/plan hash equality, node/source ownership correspondence,
 * edge invariants, deterministic candidate ranking, selected/omitted partition,
 * file/token limits, context receipts vs graph targets, totals, and no duplicates.
 *
 * Throws on any inconsistency. This must be called at plan creation, resume, and
 * before publication for V2 plans.
 */
export function assertPlanGraphIntegrity(plan: OffsecWorkPlanV2, graph: DependencyGraph): void {
  assertPlanV2InternalIntegrity(plan);
  // 1. Full graph integrity validation (not merely hash recomputation)
  assertDependencyGraphIntact(graph);

  // 2. Plan dependencyGraphSha256 must match loaded graph
  if (plan.dependencyGraphSha256 !== graph.dependencyGraphSha256) {
    throw new Error('OffSec plan dependencyGraphSha256이 graph와 다르다');
  }

  // 3. Plan self-hash
  const { workPlanSha256: _planHash, generatedAt: _planTs, ...planCore } = plan;
  if (digest(stableJson(planCore)) !== plan.workPlanSha256) {
    throw new Error('OffSec plan/graph 교차 검증: plan hash가 다르다');
  }

  // 4. Planning policy cross-check
  if (plan.planningPolicy.estimatedCharsPerToken !== graph.estimatedCharsPerToken) {
    throw new Error('OffSec plan/graph 교차 검증: planningPolicy.estimatedCharsPerToken이 graph.estimatedCharsPerToken와 다르다');
  }
  if (plan.maxContextFilesPerUnit !== plan.planningPolicy.maxContextFilesPerUnit) {
    throw new Error('OffSec plan/graph 교차 검증: plan.maxContextFilesPerUnit이 plan.planningPolicy.maxContextFilesPerUnit와 다르다');
  }

  // 5. Node/source ownership correspondence
  const graphNodeMap = new Map(graph.nodes.map((n) => [n.path, n]));
  const allPlanFiles = new Set<string>();
  for (const unit of plan.units) {
    for (const file of unit.ownedFiles) {
      if (allPlanFiles.has(file.path)) {
        throw new Error(`OffSec plan/graph 교차 검증: 중복 owned file ${file.path}`);
      }
      allPlanFiles.add(file.path);
      const node = graphNodeMap.get(file.path);
      if (!node) {
        throw new Error(`OffSec plan/graph 교차 검증: owned file이 graph node에 없다: ${file.path}`);
      }
      if (node.ownerSourceUnitId !== unit.sourceUnitId) {
        throw new Error(`OffSec plan/graph 교차 검증: owner 불일치 ${file.path}: plan=${unit.sourceUnitId} graph=${node.ownerSourceUnitId}`);
      }
      // Verify every graph node's byteCount equals its canonical owned-file receipt bytes
      if (file.bytes !== node.byteCount) {
        throw new Error(`OffSec plan/graph 교차 검증: owned file bytes 불일치 ${file.path}: plan=${file.bytes} graph=${node.byteCount}`);
      }
    }
  }
  // Every graph node must appear in exactly one plan unit
  for (const node of graph.nodes) {
    if (!allPlanFiles.has(node.path)) {
      throw new Error(`OffSec plan/graph 교차 검증: graph node가 plan에 없다: ${node.path}`);
    }
  }

  // 6. Edge invariant verification
  const graphEdgesByFrom = new Map<string, GraphEdge[]>();
  for (const edge of graph.edges) {
    const list = graphEdgesByFrom.get(edge.from) ?? [];
    list.push(edge);
    graphEdgesByFrom.set(edge.from, list);
  }

  // Build canonical owned file receipts indexed by path for context verification
  const canonicalReceipts = new Map<string, { path: string; bytes: number; sha256: string }>();
  for (const unit of plan.units) {
    for (const file of unit.ownedFiles) {
      canonicalReceipts.set(file.path, { path: file.path, bytes: file.bytes, sha256: file.sha256 });
    }
  }

  // 7. For each unit: re-derive candidates and verify partition
  for (const unit of plan.units) {
    const ownedFileSet = new Set(unit.ownedFiles.map((f) => f.path));
    const receipt = unit.contextSelectionReceipt;

    // Re-derive expected candidates from graph edges (exact same logic as buildUnitV2)
    const candidateRefs = new Map<string, number>();
    const candidateFirstEdge = new Map<string, { from: string; specifier: string }>();
    for (const file of unit.ownedFiles) {
      const edges = graphEdgesByFrom.get(file.path) ?? [];
      for (const edge of edges) {
        if (edge.classification === 'local-resolved') {
          for (const target of edge.resolvedTargets) {
            if (!ownedFileSet.has(target)) {
              const prevRefs = candidateRefs.get(target) ?? 0;
              candidateRefs.set(target, prevRefs + 1);
              if (!candidateFirstEdge.has(target)) {
                candidateFirstEdge.set(target, { from: edge.from, specifier: edge.specifier });
              }
            }
          }
        }
      }
    }

    // Re-derive expected ranking (exact same sort as buildUnitV2)
    const expectedCandidates = [...candidateRefs.entries()].map(([target, refs]) => ({
      target,
      references: refs,
      estimatedTokens: graphNodeMap.get(target)?.estimatedTokenCount ?? 0,
    }));
    expectedCandidates.sort((a, b) => {
      if (a.references !== b.references) return b.references - a.references;
      if (a.estimatedTokens !== b.estimatedTokens) return a.estimatedTokens - b.estimatedTokens;
      return a.target.localeCompare(b.target);
    });

    // Verify candidate count
    if (receipt.candidateCount !== expectedCandidates.length) {
      throw new Error(`OffSec plan/graph 교차 검증: candidate count 불일치 ${unit.unitKey}: expected=${expectedCandidates.length} actual=${receipt.candidateCount}`);
    }

    // Re-derive selection (exact same algorithm as buildUnitV2)
    let remainingFiles = plan.maxContextFilesPerUnit;
    let remainingTokens = plan.planningPolicy.maxContextEstimatedTokensPerUnit;
    const expectedSelected: string[] = [];
    const expectedOmitted: Array<{ target: string; reason: 'file-cap' | 'token-cap'; estimatedTokens: number; directReferenceCount: number }> = [];
    const expectedUnresolvedEdges: Array<{ from: string; specifier: string; reason: string; resolvedTarget?: string; budgetReason?: string }> = [];

    // First collect local-unresolved edges from graph
    for (const file of unit.ownedFiles) {
      const edges = graphEdgesByFrom.get(file.path) ?? [];
      for (const edge of edges) {
        if (edge.classification === 'local-unresolved') {
          expectedUnresolvedEdges.push({ from: edge.from, specifier: edge.specifier, reason: 'unresolved' });
        }
      }
    }

    for (const candidate of expectedCandidates) {
      const fitsFiles = remainingFiles > 0;
      const fitsTokens = candidate.estimatedTokens <= remainingTokens;
      if (fitsFiles && fitsTokens) {
        expectedSelected.push(candidate.target);
        remainingFiles -= 1;
        remainingTokens -= candidate.estimatedTokens;
      } else {
        const reason: 'file-cap' | 'token-cap' = !fitsFiles ? 'file-cap' : 'token-cap';
        expectedOmitted.push({
          target: candidate.target,
          reason,
          estimatedTokens: candidate.estimatedTokens,
          directReferenceCount: candidate.references,
        });
        // Deterministic one-per-omitted-candidate context-cap record
        const firstEdge = candidateFirstEdge.get(candidate.target)!;
        expectedUnresolvedEdges.push({
          from: firstEdge.from,
          specifier: firstEdge.specifier,
          reason: 'context-cap',
          resolvedTarget: candidate.target,
          budgetReason: reason,
        });
      }
    }

    // Verify selected context files match exactly
    const actualSelected = [...unit.contextFiles].map((f) => f.path).sort();
    const expectedSelectedSorted = [...expectedSelected].sort();
    if (actualSelected.length !== expectedSelectedSorted.length ||
        actualSelected.some((p, i) => p !== expectedSelectedSorted[i])) {
      throw new Error(`OffSec plan/graph 교차 검증: selected context 불일치 ${unit.unitKey}`);
    }

    // Verify context file receipts match canonical owned receipts (path, bytes, sha256)
    for (const cf of unit.contextFiles) {
      const canonical = canonicalReceipts.get(cf.path);
      if (!canonical) {
        throw new Error(`OffSec plan/graph 교차 검증: context file이 canonical receipt에 없다: ${unit.unitKey}/${cf.path}`);
      }
      if (cf.bytes !== canonical.bytes || cf.sha256 !== canonical.sha256) {
        throw new Error(`OffSec plan/graph 교차 검증: context file receipt가 canonical과 다르다: ${unit.unitKey}/${cf.path}`);
      }
    }

    // Verify omitted array order/content against deterministic ranked selection (exact order, not merely set)
    if (receipt.omitted.length !== expectedOmitted.length) {
      throw new Error(`OffSec plan/graph 교차 검증: omitted count 불일치 ${unit.unitKey}: expected=${expectedOmitted.length} actual=${receipt.omitted.length}`);
    }
    for (let i = 0; i < expectedOmitted.length; i++) {
      const expected = expectedOmitted[i]!;
      const actual = receipt.omitted[i]!;
      if (actual.target !== expected.target) {
        throw new Error(`OffSec plan/graph 교차 검증: omitted[${i}] target 불일치 ${unit.unitKey}: expected=${expected.target} actual=${actual.target}`);
      }
      if (actual.reason !== expected.reason) {
        throw new Error(`OffSec plan/graph 교차 검증: omitted[${i}] reason 불일치 ${unit.unitKey}/${actual.target}`);
      }
      if (actual.estimatedTokens !== expected.estimatedTokens) {
        throw new Error(`OffSec plan/graph 교차 검증: omitted[${i}] tokens 불일치 ${unit.unitKey}/${actual.target}`);
      }
      if (actual.directReferenceCount !== expected.directReferenceCount) {
        throw new Error(`OffSec plan/graph 교차 검증: omitted[${i}] refCount 불일치 ${unit.unitKey}/${actual.target}`);
      }
    }

    // Verify unresolvedEdges exactly (reject missing, extra, duplicate, or altered)
    if (unit.unresolvedEdges.length !== expectedUnresolvedEdges.length) {
      throw new Error(`OffSec plan/graph 교차 검증: unresolvedEdges count 불일치 ${unit.unitKey}: expected=${expectedUnresolvedEdges.length} actual=${unit.unresolvedEdges.length}`);
    }
    for (let i = 0; i < expectedUnresolvedEdges.length; i++) {
      const expected = expectedUnresolvedEdges[i]!;
      const actual = unit.unresolvedEdges[i]!;
      if (actual.from !== expected.from || actual.specifier !== expected.specifier || actual.reason !== expected.reason) {
        throw new Error(`OffSec plan/graph 교차 검증: unresolvedEdges[${i}] 불일치 ${unit.unitKey}: expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`);
      }
      if (expected.resolvedTarget !== undefined && actual.resolvedTarget !== expected.resolvedTarget) {
        throw new Error(`OffSec plan/graph 교차 검증: unresolvedEdges[${i}] resolvedTarget 불일치 ${unit.unitKey}`);
      }
      if (expected.budgetReason !== undefined && actual.budgetReason !== expected.budgetReason) {
        throw new Error(`OffSec plan/graph 교차 검증: unresolvedEdges[${i}] budgetReason 불일치 ${unit.unitKey}`);
      }
    }

    // Verify owned estimated tokens (re-derive from graph)
    const expectedOwnedTokens = unit.ownedFiles.reduce(
      (sum, f) => sum + (graphNodeMap.get(f.path)?.estimatedTokenCount ?? 0), 0);
    if (receipt.ownedEstimatedTokens !== expectedOwnedTokens) {
      throw new Error(`OffSec plan/graph 교차 검증: ownedEstimatedTokens 불일치 ${unit.unitKey}`);
    }

    // Verify selectedContextEstimatedTokens
    const expectedSelectedTokens = expectedSelected.reduce(
      (sum, p) => sum + (graphNodeMap.get(p)?.estimatedTokenCount ?? 0), 0);
    if (receipt.selectedContextEstimatedTokens !== expectedSelectedTokens) {
      throw new Error(`OffSec plan/graph 교차 검증: selectedContextEstimatedTokens 불일치 ${unit.unitKey}`);
    }

    // Verify unit.estimatedTokens = owned + selected context
    const expectedUnitTokens = expectedOwnedTokens + expectedSelectedTokens;
    if (unit.estimatedTokens !== expectedUnitTokens) {
      throw new Error(`OffSec plan/graph 교차 검증: unit.estimatedTokens 불일치 ${unit.unitKey}: expected=${expectedUnitTokens} actual=${unit.estimatedTokens}`);
    }
  }
}

function assertUnitAssignment(unit: OffsecWorkUnit | OffsecWorkUnitV2): void {
  const assigned = digest(stableJson(unit.ownedFiles));
  if (assigned !== unit.assignedSourceSha256) {
    throw new Error(`OffSec unit source hash가 다르다: ${unit.unitKey}`);
  }
}

function isWithin(root: string, candidate: string): boolean {
  const rel = relative(realpathSync(root), realpathSync(candidate));
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !rel.startsWith('/'));
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function digest(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}
