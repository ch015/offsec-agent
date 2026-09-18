/**
 * GraphRAG module — dependency graph + call graph를 활용한 사전 분석 context 생성.
 *
 * 1. Taint path 계산: entry_point(source) → dangerous sink 경로 추출
 * 2. Community detection: 파일 클러스터링 + 역할 요약
 * 3. Centrality: 파일별 중요도 (in-degree 기반)
 *
 * 모든 계산은 로컬 그래프 탐색으로 LLM 호출 없이 수행.
 */

import { readFileSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';

// ─── Types ───

export interface DependencyGraph {
  nodes: Array<{ path: string; ownerSourceUnitId?: string; language?: string; byteCount?: number; estimatedTokenCount?: number }>;
  edges: Array<{ from: string; specifier?: string; classification: string; resolvedTargets?: string[] }>;
}

export interface CallGraph {
  [funcId: string]: { calls: string[]; called_by: string[] };
}

export interface DataFlow {
  entry: { file: string; line: number; type: string; handler: string };
  terminal: { file: string; line?: number; expr?: string };
}

export interface AstContext {
  entry_points?: Array<{ file: string; line: number; type: string; handler: string }>;
  call_graph?: CallGraph;
  data_flows?: DataFlow[];
}

export interface TaintPath {
  source: { file: string; function: string; line?: number; type: string };
  sink: { file: string; function: string; category: string };
  hops: string[]; // 함수 ID 경로
  hopCount: number;
}

export interface FileCommunity {
  id: number;
  files: string[];
  role: string; // 자동 추론된 역할 요약
  languages: string[];
}

export interface FileGraphContext {
  /** 이 파일을 경유하는 taint paths */
  taintPaths: TaintPath[];
  /** 이 파일이 속한 community */
  community: { id: number; role: string; memberCount: number };
  /** in-degree centrality (0~1) */
  centrality: number;
  /** 이 파일의 직접 호출자 (caller files) */
  callers: string[];
  /** 이 파일이 호출하는 대상 (callee files) */
  callees: string[];
}

export interface GraphRagResult {
  taintPaths: TaintPath[];
  communities: FileCommunity[];
  fileCentrality: Map<string, number>;
  fileContextMap: Map<string, FileGraphContext>;
}

// ─── Dangerous Sinks ───

const DANGEROUS_SINKS: Record<string, string> = {
  // SQL injection
  'query': 'sql_injection',
  'execute': 'sql_injection',
  'raw': 'sql_injection',
  'rawQuery': 'sql_injection',
  '$queryRaw': 'sql_injection',
  '$executeRaw': 'sql_injection',
  // Command injection
  'exec': 'command_injection',
  'execSync': 'command_injection',
  'spawn': 'command_injection',
  'spawnSync': 'command_injection',
  'execFile': 'command_injection',
  // File system
  'readFile': 'path_traversal',
  'readFileSync': 'path_traversal',
  'writeFile': 'path_traversal',
  'writeFileSync': 'path_traversal',
  'unlink': 'path_traversal',
  'createReadStream': 'path_traversal',
  // Eval / deserialization
  'eval': 'code_injection',
  'Function': 'code_injection',
  'deserialize': 'deserialization',
  'unserialize': 'deserialization',
  // Network
  'fetch': 'ssrf',
  'request': 'ssrf',
  'axios': 'ssrf',
  // Response (XSS)
  'innerHTML': 'xss',
  'dangerouslySetInnerHTML': 'xss',
  'document.write': 'xss',
  'res.send': 'xss',
  'res.write': 'xss',
};

// ─── Source identifiers (entry points) ───

const SOURCE_TYPES = new Set([
  'http_handler', 'express_route', 'api_route', 'sdk_export',
  'rpc_handler', 'websocket_handler', 'graphql_resolver',
  'cli_command', 'event_handler',
]);

// ─── Implementation ───

/**
 * 메인 함수: dependency graph + ast context를 받아 GraphRAG 결과를 생성.
 */
export function computeGraphRag(input: {
  dependencyGraph: DependencyGraph;
  astContext: AstContext;
  targetRoot?: string;
}): GraphRagResult {
  const { dependencyGraph, astContext } = input;

  // 1. 파일 간 adjacency (resolved import edges)
  const fileAdj = buildFileAdjacency(dependencyGraph);

  // 2. Call graph에서 함수→파일 매핑
  const funcToFile = buildFuncToFileMap(astContext.call_graph ?? {});

  // 3. Taint path 계산
  const taintPaths = computeTaintPaths(astContext, funcToFile);

  // 4. Community detection (label propagation)
  const communities = detectCommunities(dependencyGraph, fileAdj);

  // 5. Centrality (in-degree)
  const fileCentrality = computeCentrality(dependencyGraph, fileAdj);

  // 6. File context map 조합
  const fileContextMap = buildFileContextMap({
    dependencyGraph,
    astContext,
    taintPaths,
    communities,
    fileCentrality,
    fileAdj,
    funcToFile,
  });

  return { taintPaths, communities, fileCentrality, fileContextMap };
}

/**
 * engagement 디렉터리에서 graph 파일을 로드하여 computeGraphRag 실행.
 */
export async function loadAndComputeGraphRag(engagementDir: string): Promise<GraphRagResult | null> {
  const graphPath = join(engagementDir, '00_dependency_graph.json');
  const astPath = join(engagementDir, '00_ast_context.yaml');

  if (!existsSync(graphPath)) return null;

  const dependencyGraph: DependencyGraph = JSON.parse(readFileSync(graphPath, 'utf8'));

  let astContext: AstContext = {};
  if (existsSync(astPath)) {
    try {
      const { load } = await import('js-yaml');
      const yamlContent = readFileSync(astPath, 'utf8');
      const parsed = load(yamlContent) as Record<string, unknown>;
      astContext = {
        entry_points: parsed.entry_points as AstContext['entry_points'],
        call_graph: parsed.call_graph as CallGraph,
        data_flows: parsed.data_flows as DataFlow[],
      };
    } catch {
      // AST context 없이도 dependency graph만으로 community/centrality 계산 가능
    }
  }

  return computeGraphRag({ dependencyGraph, astContext });
}

// ─── Internal helpers ───

type FileAdjacency = Map<string, { importedBy: Set<string>; imports: Set<string> }>;

function buildFileAdjacency(graph: DependencyGraph): FileAdjacency {
  const adj: FileAdjacency = new Map();
  const ensureNode = (path: string) => {
    if (!adj.has(path)) adj.set(path, { importedBy: new Set(), imports: new Set() });
    return adj.get(path)!;
  };

  for (const node of graph.nodes) {
    ensureNode(node.path);
  }

  for (const edge of graph.edges) {
    if (edge.classification !== 'local-resolved' || !edge.resolvedTargets?.length) continue;
    const source = ensureNode(edge.from);
    for (const target of edge.resolvedTargets) {
      source.imports.add(target);
      ensureNode(target).importedBy.add(edge.from);
    }
  }

  return adj;
}

function buildFuncToFileMap(callGraph: CallGraph): Map<string, string> {
  const map = new Map<string, string>();
  for (const funcId of Object.keys(callGraph)) {
    // funcId format: "file/path.ts:functionName"
    const colonIdx = funcId.lastIndexOf(':');
    if (colonIdx > 0) {
      map.set(funcId, funcId.slice(0, colonIdx));
    }
  }
  return map;
}

function computeTaintPaths(astContext: AstContext, funcToFile: Map<string, string>): TaintPath[] {
  const callGraph = astContext.call_graph ?? {};
  const entryPoints = astContext.entry_points ?? [];
  const results: TaintPath[] = [];

  // entry point에서 시작하여 BFS로 dangerous sink까지 탐색
  for (const entry of entryPoints) {
    if (!SOURCE_TYPES.has(entry.type)) continue;

    const startFuncId = `${entry.file}:${entry.handler}`;
    if (!callGraph[startFuncId]) continue;

    // BFS
    const visited = new Set<string>();
    const queue: Array<{ funcId: string; path: string[] }> = [{ funcId: startFuncId, path: [startFuncId] }];
    visited.add(startFuncId);

    while (queue.length > 0) {
      const current = queue.shift()!;
      if (current.path.length > 8) continue; // max 8 hops

      const node = callGraph[current.funcId];
      if (!node) continue;

      for (const callee of node.calls) {
        // callee가 dangerous sink인지 확인
        const calleeName = callee.includes(':') ? callee.split(':').pop()! : callee;
        const sinkCategory = DANGEROUS_SINKS[calleeName];

        if (sinkCategory) {
          const sinkFile = funcToFile.get(callee) ?? entry.file;
          results.push({
            source: { file: entry.file, function: entry.handler, line: entry.line, type: entry.type },
            sink: { file: sinkFile, function: calleeName, category: sinkCategory },
            hops: [...current.path, callee],
            hopCount: current.path.length,
          });
          continue; // 이 경로는 완성
        }

        // callee를 키로 가진 call_graph 엔트리 찾기
        const fullCalleeId = findFullFuncId(callGraph, callee, current.funcId);
        if (fullCalleeId && !visited.has(fullCalleeId)) {
          visited.add(fullCalleeId);
          queue.push({ funcId: fullCalleeId, path: [...current.path, fullCalleeId] });
        }
      }
    }
  }

  return results;
}

function findFullFuncId(callGraph: CallGraph, callee: string, callerFuncId: string): string | null {
  // 정확한 키가 있으면 사용
  if (callGraph[callee]) return callee;

  // 같은 파일 내에서 찾기
  const callerFile = callerFuncId.slice(0, callerFuncId.lastIndexOf(':'));
  const sameFileKey = `${callerFile}:${callee}`;
  if (callGraph[sameFileKey]) return sameFileKey;

  // 부분 매칭 (끝이 :callee인 키)
  const suffix = `:${callee}`;
  for (const key of Object.keys(callGraph)) {
    if (key.endsWith(suffix)) return key;
  }

  return null;
}

function detectCommunities(graph: DependencyGraph, adj: FileAdjacency): FileCommunity[] {
  // Label Propagation Algorithm (간이 구현)
  const files = graph.nodes.map((n) => n.path);
  const labels = new Map<string, number>();
  files.forEach((f, i) => labels.set(f, i));

  // 5 iterations
  for (let iter = 0; iter < 5; iter++) {
    for (const file of files) {
      const neighbors = adj.get(file);
      if (!neighbors) continue;

      // 이웃들의 label 빈도 계산
      const labelCounts = new Map<number, number>();
      for (const neighbor of [...neighbors.imports, ...neighbors.importedBy]) {
        const l = labels.get(neighbor);
        if (l !== undefined) labelCounts.set(l, (labelCounts.get(l) ?? 0) + 1);
      }

      // 가장 빈번한 label 선택
      let maxCount = 0;
      let maxLabel = labels.get(file)!;
      for (const [l, count] of labelCounts) {
        if (count > maxCount) { maxCount = count; maxLabel = l; }
      }
      labels.set(file, maxLabel);
    }
  }

  // 같은 label로 그룹핑
  const groups = new Map<number, string[]>();
  for (const [file, label] of labels) {
    if (!groups.has(label)) groups.set(label, []);
    groups.get(label)!.push(file);
  }

  // 2개 이상 파일인 community만 유지
  const communities: FileCommunity[] = [];
  let id = 0;
  for (const [, members] of groups) {
    if (members.length < 2) continue;
    const languages = [...new Set(
      members.map((f) => graph.nodes.find((n) => n.path === f)?.language).filter(Boolean) as string[],
    )];
    communities.push({
      id: id++,
      files: members,
      role: inferCommunityRole(members),
      languages,
    });
  }

  return communities.sort((a, b) => b.files.length - a.files.length);
}

function inferCommunityRole(files: string[]): string {
  // 경로 패턴으로 역할 추론
  const patterns: Array<{ pattern: RegExp; role: string }> = [
    { pattern: /auth|login|session|jwt|token/i, role: 'Authentication & Session Management' },
    { pattern: /route|controller|handler|api|endpoint/i, role: 'API Routes & Request Handling' },
    { pattern: /model|schema|entity|migration|db/i, role: 'Data Models & Database' },
    { pattern: /middleware|interceptor|guard|filter/i, role: 'Middleware & Request Pipeline' },
    { pattern: /util|helper|lib|common|shared/i, role: 'Utilities & Shared Libraries' },
    { pattern: /test|spec|mock|fixture/i, role: 'Testing' },
    { pattern: /config|env|setting/i, role: 'Configuration' },
    { pattern: /component|view|page|layout|ui/i, role: 'UI Components' },
    { pattern: /service|provider|client/i, role: 'Service Layer' },
    { pattern: /hook|plugin|extension/i, role: 'Hooks & Plugins' },
    { pattern: /command|cli|script/i, role: 'CLI & Scripts' },
    { pattern: /channel|socket|stream|event/i, role: 'Communication & Events' },
    { pattern: /state|store|redux|context/i, role: 'State Management' },
  ];

  const joined = files.join(' ');
  for (const { pattern, role } of patterns) {
    if (pattern.test(joined)) return role;
  }

  // 공통 디렉토리로 추론
  const dirs = files.map((f) => f.split('/').slice(0, -1).join('/'));
  const commonDir = dirs[0] ?? '';
  if (commonDir) return `Module: ${commonDir.split('/').pop() ?? commonDir}`;

  return 'General Module';
}

function computeCentrality(graph: DependencyGraph, adj: FileAdjacency): Map<string, number> {
  const centrality = new Map<string, number>();
  let maxDegree = 0;

  for (const [file, neighbors] of adj) {
    const degree = neighbors.importedBy.size; // in-degree
    centrality.set(file, degree);
    if (degree > maxDegree) maxDegree = degree;
  }

  // normalize to 0~1
  if (maxDegree > 0) {
    for (const [file, degree] of centrality) {
      centrality.set(file, degree / maxDegree);
    }
  }

  return centrality;
}

function buildFileContextMap(input: {
  dependencyGraph: DependencyGraph;
  astContext: AstContext;
  taintPaths: TaintPath[];
  communities: FileCommunity[];
  fileCentrality: Map<string, number>;
  fileAdj: FileAdjacency;
  funcToFile: Map<string, string>;
}): Map<string, FileGraphContext> {
  const { taintPaths, communities, fileCentrality, fileAdj } = input;
  const map = new Map<string, FileGraphContext>();

  // community lookup
  const fileToCommunity = new Map<string, FileCommunity>();
  for (const community of communities) {
    for (const file of community.files) {
      fileToCommunity.set(file, community);
    }
  }

  for (const [file, neighbors] of fileAdj) {
    const community = fileToCommunity.get(file);
    const relatedTaintPaths = taintPaths.filter((tp) =>
      tp.source.file === file ||
      tp.sink.file === file ||
      tp.hops.some((h) => h.startsWith(file + ':')),
    );

    map.set(file, {
      taintPaths: relatedTaintPaths,
      community: community
        ? { id: community.id, role: community.role, memberCount: community.files.length }
        : { id: -1, role: 'Unclustered', memberCount: 1 },
      centrality: fileCentrality.get(file) ?? 0,
      callers: [...neighbors.importedBy],
      callees: [...neighbors.imports],
    });
  }

  return map;
}

// ─── Minimal YAML parser for AST context ───

function parseAstContextYaml(content: string): AstContext {
  // JSON으로 된 ast_context도 지원
  if (content.trim().startsWith('{')) {
    return JSON.parse(content);
  }

  // YAML은 js-yaml이 없으므로 구조만 추출 (best-effort)
  const result: AstContext = {};

  // entry_points 추출
  const entryMatch = content.match(/entry_points:\s*\n((?:\s+-[\s\S]*?)(?=\n\w|\n$|$))/);
  if (entryMatch) {
    result.entry_points = [];
    const entries = entryMatch[1].split(/\n\s+-\s/).filter(Boolean);
    for (const entry of entries) {
      const file = entry.match(/file:\s*(.+)/)?.[1]?.trim();
      const line = parseInt(entry.match(/line:\s*(\d+)/)?.[1] ?? '0', 10);
      const type = entry.match(/type:\s*(.+)/)?.[1]?.trim() ?? '';
      const handler = entry.match(/handler:\s*(.+)/)?.[1]?.trim() ?? '';
      if (file && handler) {
        result.entry_points.push({ file, line, type, handler });
      }
    }
  }

  // call_graph는 복잡한 nested 구조 — 간이 파싱
  const cgStart = content.indexOf('call_graph:');
  if (cgStart >= 0) {
    result.call_graph = {};
    const cgSection = content.slice(cgStart);
    // "  file:func:\n    calls:\n      - callee\n    called_by:\n      - caller"
    const funcRegex = /^\s{2}(\S+):\s*\n\s{4}calls:\s*\n((?:\s{6}-\s.+\n)*)\s{4}called_by:\s*\n((?:\s{6}-\s.+\n)*)/gm;
    let match;
    while ((match = funcRegex.exec(cgSection)) !== null) {
      const funcId = match[1];
      const calls = [...match[2].matchAll(/\s{6}-\s(.+)/g)].map((m) => m[1].trim());
      const calledBy = [...match[3].matchAll(/\s{6}-\s(.+)/g)].map((m) => m[1].trim());
      result.call_graph[funcId] = { calls, called_by: calledBy };
    }
  }

  return result;
}

// ─── Serialization for VA input ───

/**
 * unit의 파일 목록에 대한 graph context를 간결한 문자열로 변환.
 * VA agent의 inputs에 주입하기 위한 형태.
 */
export function serializeGraphContextForUnit(
  graphRag: GraphRagResult,
  unitFiles: string[],
): string {
  const lines: string[] = [];
  const unitFileSet = new Set(unitFiles);

  // 이 unit에 관련된 taint paths
  const relevantPaths = graphRag.taintPaths.filter((tp) =>
    unitFileSet.has(tp.source.file) || unitFileSet.has(tp.sink.file),
  );
  if (relevantPaths.length > 0) {
    lines.push('## Taint Paths (source → dangerous sink)');
    for (const tp of relevantPaths.slice(0, 10)) {
      lines.push(`- ${tp.source.file}:${tp.source.function} → ${tp.sink.function}() [${tp.sink.category}] (${tp.hopCount} hops)`);
    }
    lines.push('');
  }

  // Community 정보
  const communities = new Set<string>();
  for (const file of unitFiles) {
    const ctx = graphRag.fileContextMap.get(file);
    if (ctx && ctx.community.id >= 0) {
      communities.add(`${ctx.community.role} (${ctx.community.memberCount} files)`);
    }
  }
  if (communities.size > 0) {
    lines.push('## Module Role');
    for (const c of communities) lines.push(`- ${c}`);
    lines.push('');
  }

  // Top centrality files in this unit
  const ranked = unitFiles
    .map((f) => ({ file: f, centrality: graphRag.fileCentrality.get(f) ?? 0 }))
    .filter((f) => f.centrality > 0)
    .sort((a, b) => b.centrality - a.centrality);
  if (ranked.length > 0) {
    lines.push('## High-Centrality Files (most imported)');
    for (const r of ranked.slice(0, 5)) {
      lines.push(`- ${r.file} (centrality: ${r.centrality.toFixed(2)})`);
    }
    lines.push('');
  }

  // Cross-unit callers (외부에서 이 unit을 호출하는 파일)
  const externalCallers = new Set<string>();
  for (const file of unitFiles) {
    const ctx = graphRag.fileContextMap.get(file);
    if (ctx) {
      for (const caller of ctx.callers) {
        if (!unitFileSet.has(caller)) externalCallers.add(`${caller} → ${file}`);
      }
    }
  }
  if (externalCallers.size > 0) {
    lines.push('## External Callers (cross-unit dependencies)');
    for (const c of [...externalCallers].slice(0, 10)) lines.push(`- ${c}`);
    lines.push('');
  }

  return lines.length > 0 ? lines.join('\n') : '';
}
