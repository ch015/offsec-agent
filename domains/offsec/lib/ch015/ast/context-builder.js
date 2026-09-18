'use strict';

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const { parseFiles, getSupportedExtensions } = require('./parser');
const { runSemgrep } = require('./semgrep');
const { extractCallGraph } = require('./call-graph');
const { extractDataFlows } = require('./data-flow');
const { computeTaintPaths } = require('./taint');

const DEFAULT_SOURCE_DIRS = [
  'src', 'lib', 'app', 'components', 'pages', 'features', 'services', 'api', 'server', 'backend',
  'routes', 'controllers', 'middleware', 'handlers', 'frontend', 'views', 'endpoints',
  'functions', 'lambdas', 'workers', 'jobs', 'contracts', 'hooks', 'mcp-server', 'harness',
];
const MAX_FILES = 500;
const MAX_DATA_FLOWS = 200;
const MAX_TAINT_PATHS = 50;
const MAX_SEMGREP_FINDINGS = 100;
// data-flow.js의 기존 하드코딩 MAX_DEPTH(8)와 동일 — config/options 미지정 시 현행 동작 유지
const DEFAULT_CALL_GRAPH_DEPTH = 8;

async function buildAstContext(targetPath, options = {}) {
  const config = loadConfig(targetPath, options);
  const startTime = Date.now();

  const log = options.logger || console.error.bind(console);
  log('[AST] Starting analysis...');

  // Step 1: Collect source files
  const files = collectSourceFiles(targetPath, config);
  log(`[AST] Found ${files.length} source files`);

  if (files.length === 0) {
    return { ok: false, error: 'No source files found', stats: {} };
  }

  // Step 2: Parse with tree-sitter
  const parseResult = parseFiles(files);
  log(`[AST] Parsed: ${parseResult.parsed.length} ok, ${parseResult.failed.length} failed`);

  // Step 3: Extract call graph
  const callGraph = extractCallGraph(parseResult.parsed, targetPath);
  log(`[AST] Call graph: ${callGraph.stats.total_functions} functions, ${callGraph.stats.total_calls} calls, ${callGraph.stats.total_entry_points} entry points`);

  // Step 4: Extract structural data flows
  // config 키 배선: ch015.analysisMode.ast.{maxDataFlows,callGraphDepth} → 실제 탐색 상한
  const dataFlows = extractDataFlows(callGraph, {
    maxFlows: config.maxDataFlows,
    maxDepth: config.callGraphDepth,
  });
  log(`[AST] Data flows: ${dataFlows.length} found`);

  // Step 5: Extract source-to-sink taint candidates for verifier re-check
  const taintPaths = computeTaintPaths(callGraph, {
    dataFlows,
    maxPaths: config.maxTaintPaths,
  });
  log(`[AST] Taint candidates: ${taintPaths.length} found`);

  // Step 6: Run semgrep (optional)
  let semgrepResult = { ok: false, status: 'disabled', findings: [], stats: {} };
  if (config.runSemgrep) {
    log('[AST] Running Semgrep...');
    const semgrepFiles = [...new Set([...files, ...(options.semgrepFiles || [])])];
    semgrepResult = await runSemgrep(targetPath, {
      manifestPath: config.semgrepManifest,
      files: semgrepFiles,
      maxFindings: config.maxSemgrepFindings,
      timeout: (config.timeout || 120) * 1000,
    });
    log(`[AST] Semgrep: ${semgrepResult.findings.length} findings`);
  } else {
    log('[AST] Semgrep disabled by host assurance mode');
  }

  // Step 7: Assemble context
  const context = assembleContext({
    callGraph,
    dataFlows,
    taintPaths,
    semgrepResult,
    parseResult,
    config,
    elapsed: Date.now() - startTime,
  });

  if (context.stats.truncated) {
    log(`[AST] WARNING: analysis caps reached — results truncated (recall may be reduced): ${JSON.stringify(context.stats.truncation)}`);
  }

  // Step 8: Write to file
  const outputPath = path.resolve(options.outputPath || path.join(targetPath, '.ch015', 'ast-context.yaml'));
  const outputDir = path.dirname(outputPath);
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true, mode: 0o700 });
  }
  fs.writeFileSync(outputPath, yaml.dump(context, { lineWidth: 120, noRefs: true }), { encoding: 'utf8', mode: 0o600 });
  log(`[AST] Context written to ${outputPath}`);

  return {
    ok: true,
    outputPath,
    stats: context.stats,
    semgrep: {
      status: semgrepResult.status,
      error: semgrepResult.error,
      receipt: semgrepResult.receipt,
    },
  };
}

function loadConfig(targetPath, options) {
  let projectConfig = {};
  const configPath = path.join(targetPath, 'ch015.config.json');
  if (fs.existsSync(configPath)) {
    try {
      projectConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    } catch { /* use defaults */ }
  }

  const astConfig = projectConfig.ch015?.analysisMode?.ast || {};

  return {
    sourceDirs: projectConfig.sourceDirectories || DEFAULT_SOURCE_DIRS,
    extensions: getSupportedExtensions(),
    codeExtensions: projectConfig.codeExtensions || [],
    maxFiles: options.maxFiles || MAX_FILES,
    maxDataFlows: astConfig.maxDataFlows || options.maxDataFlows || MAX_DATA_FLOWS,
    maxTaintPaths: astConfig.maxTaintPaths || options.maxTaintPaths || MAX_TAINT_PATHS,
    maxSemgrepFindings: astConfig.maxSemgrepFindings || options.maxSemgrepFindings || MAX_SEMGREP_FINDINGS,
    semgrepManifest: options.semgrepManifest
      || path.resolve(__dirname, '../../../rules/semgrep/manifest.json'),
    runSemgrep: options.runSemgrep ?? astConfig.runSemgrep ?? true,
    callGraphDepth: astConfig.callGraphDepth || options.callGraphDepth || DEFAULT_CALL_GRAPH_DEPTH,
    timeout: astConfig.timeout || options.timeout || 120,
  };
}

function collectSourceFiles(targetPath, config) {
  const files = [];
  const supportedExts = new Set(config.extensions);

  function walk(dir, depth) {
    if (depth > 10) return;
    if (files.length >= config.maxFiles) return;

    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true })
        .sort((left, right) => left.name.localeCompare(right.name));
    } catch {
      return;
    }

    for (const entry of entries) {
      if (files.length >= config.maxFiles) return;
      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        if (shouldSkipDir(entry.name)) continue;
        walk(fullPath, depth + 1);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (supportedExts.has(ext)) {
          files.push(fullPath);
        }
      }
    }
  }

  // Walk source directories first, then root
  const sourceDirs = config.sourceDirs
    .map(d => path.join(targetPath, d))
    .filter(d => fs.existsSync(d));

  if (sourceDirs.length > 0) {
    for (const dir of sourceDirs) {
      walk(dir, 0);
    }
    // 루트에 배치된 엔트리포인트(server.js/app.js/index.py 등)가 source dir 밖에
    // 있어 통째로 누락되던 문제 방지 — 루트 파일만 1-depth로 추가 수집한다.
    try {
      for (const entry of fs.readdirSync(targetPath, { withFileTypes: true })
        .sort((left, right) => left.name.localeCompare(right.name))) {
        if (files.length >= config.maxFiles) break;
        if (!entry.isFile()) continue;
        const ext = path.extname(entry.name).toLowerCase();
        if (supportedExts.has(ext)) {
          const full = path.join(targetPath, entry.name);
          if (!files.includes(full)) files.push(full);
        }
      }
    } catch { /* 루트 읽기 실패는 무시 */ }
  } else {
    walk(targetPath, 0);
  }

  return files.sort();
}

function shouldSkipDir(name) {
  return [
    'node_modules', '.git', '.svn', 'vendor', '__pycache__', '.venv', 'venv',
    'dist', 'build', 'out', '.next', '.nuxt', 'coverage', '.ch015',
    '.claude', '.cursor', 'test', 'tests', '__tests__',
  ].includes(name);
}

function assembleContext(data) {
  const { callGraph, dataFlows, taintPaths, semgrepResult, parseResult, elapsed, config } = data;

  // 캡에 도달하면 recall이 조용히 잘렸다는 신호 — 소비자가 상한 상향을 결정할 수 있게 노출.
  const cfg = config || {};
  const collectedFiles = parseResult.parsed.length + parseResult.failed.length;
  const truncation = {
    files: cfg.maxFiles ? collectedFiles >= cfg.maxFiles : false,
    data_flows: cfg.maxDataFlows ? dataFlows.length >= cfg.maxDataFlows : false,
    taint_paths: cfg.maxTaintPaths ? taintPaths.length >= cfg.maxTaintPaths : false,
    semgrep_findings: Boolean(semgrepResult.stats?.truncated),
  };

  return {
    meta: {
      generated_at: new Date().toISOString(),
      analysis_time_ms: elapsed,
      mode: 'ast',
    },
    stats: {
      files_parsed: parseResult.parsed.length,
      files_failed: parseResult.failed.length,
      functions: callGraph.stats.total_functions,
      calls: callGraph.stats.total_calls,
      entry_points: callGraph.stats.total_entry_points,
      data_flows: dataFlows.length,
      taint_paths: taintPaths.length,
      semgrep_findings: semgrepResult.findings.length,
      semgrep_status: semgrepResult.status,
      semgrep_raw_findings: semgrepResult.stats?.raw_total_findings || 0,
      semgrep_files_requested: semgrepResult.stats?.files_requested || 0,
      semgrep_files_scanned: semgrepResult.stats?.files_scanned || 0,
      truncation,
      truncated: Object.values(truncation).some(Boolean),
    },
    entry_points: callGraph.entryPoints.map(ep => ({
      file: ep.file,
      line: ep.line,
      type: ep.type,
      method: ep.method,
      route: ep.route,
      handler: ep.handler,
    })),
    call_graph: summarizeCallGraph(callGraph),
    data_flows: dataFlows.map(df => ({
      entry: df.entry,
      terminal: df.terminal,
      via: df.via,
      hops: df.hops,
    })),
    taint_paths: taintPaths.map(tp => ({
      source: tp.source,
      sink: tp.sink,
      via: tp.via,
      sanitizers: tp.sanitizers,
      hops: tp.hops,
      confidence: tp.confidence,
      potential_cwe: tp.potential_cwe,
      tainted_arguments: tp.tainted_arguments,
    })),
    semgrep_findings: semgrepResult.findings.map(f => ({
      rule: f.rule_id,
      file: f.file,
      line: f.line,
      severity: f.severity,
      message: f.message,
      cwe: f.cwe,
    })),
    semgrep_receipt: semgrepResult.receipt || null,
    parse_failures: parseResult.failed.map(f => ({
      file: f.filePath,
      error: f.error,
    })),
  };
}

function summarizeCallGraph(callGraph) {
  const summary = {};
  const nodeKeys = Object.keys(callGraph.nodes);

  // Only include nodes with edges (callers or callees)
  const nodesWithEdges = new Set();
  for (const edge of callGraph.edges) {
    const callerKey = `${edge.file}:${findEnclosingFunction(edge, callGraph) || '<module>'}`;
    nodesWithEdges.add(callerKey);
  }

  for (const key of nodeKeys) {
    const node = callGraph.nodes[key];
    const calledBy = callGraph.edges
      .filter(e => e.callee === node.name && e.file !== node.file)
      .map(e => `${e.file}:${e.line}`);

    const calls = callGraph.edges
      .filter(e => e.file === node.file && e.line >= node.line && e.line <= (node.endLine || node.line + 100))
      .map(e => e.callee);

    if (calls.length > 0 || calledBy.length > 0) {
      summary[key] = {
        calls: [...new Set(calls)].slice(0, 20),
        called_by: calledBy.slice(0, 10),
      };
    }
  }

  return summary;
}

function findEnclosingFunction(edge, callGraph) {
  for (const [key, node] of Object.entries(callGraph.nodes)) {
    if (node.file === edge.file && edge.line >= node.line && edge.line <= (node.endLine || node.line + 500)) {
      return node.name;
    }
  }
  return null;
}

// CLI entry point
if (require.main === module) {
  const targetPath = process.argv[2] || process.cwd();
  buildAstContext(targetPath).then(result => {
    if (result.ok) {
      console.log(JSON.stringify(result.stats, null, 2));
    } else {
      console.error('AST analysis failed:', result.error);
      process.exit(1);
    }
  });
}

module.exports = {
  buildAstContext,
  collectSourceFiles,
};
