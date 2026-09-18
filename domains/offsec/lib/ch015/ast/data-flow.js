'use strict';

const MAX_FLOWS = 200;
const MAX_DEPTH = 8;

/**
 * @param {Object} callGraph
 * @param {Object} [options] - { maxFlows, maxDepth }
 *   maxFlows: 추출할 flow 상한 (config: ch015.analysisMode.ast.maxDataFlows, 기본 50)
 *   maxDepth: 호출 추적 깊이 상한 (config: ch015.analysisMode.ast.callGraphDepth, 기본 8)
 */
function extractDataFlows(callGraph, options = {}) {
  const maxFlows = Number.isFinite(options.maxFlows) && options.maxFlows > 0
    ? options.maxFlows : MAX_FLOWS;
  const maxDepth = Number.isFinite(options.maxDepth) && options.maxDepth > 0
    ? options.maxDepth : MAX_DEPTH;
  const flows = [];
  const entryPoints = callGraph.entryPoints || [];

  for (const ep of entryPoints) {
    if (flows.length >= maxFlows) break;

    const scope = getHandlerScope(ep, entryPoints, callGraph);
    const callsInScope = getCallsInRange(ep.file, scope.start, scope.end, callGraph.edges);

    for (const call of callsInScope) {
      if (flows.length >= maxFlows) break;

      const terminals = traceToTerminals(call, callGraph, new Set(), 0, maxDepth);
      for (const term of terminals) {
        if (flows.length >= maxFlows) break;
        flows.push({
          entry: {
            file: ep.file,
            line: ep.line,
            type: ep.type,
            method: ep.method,
            route: ep.route,
            handler: ep.handler,
          },
          terminal: term.terminal,
          via: term.via,
          hops: term.hops,
        });
      }
    }
  }

  return flows;
}

function getHandlerScope(ep, allEntryPoints, callGraph) {
  if (ep.handler) {
    const funcNode = findNodeByName(ep.handler, ep.file, callGraph);
    if (funcNode) {
      return { start: funcNode.line, end: funcNode.endLine || funcNode.line + 200 };
    }
  }

  const sameFileEps = allEntryPoints
    .filter(e => e.file === ep.file && e.line > ep.line)
    .sort((a, b) => a.line - b.line);

  const nextEpLine = sameFileEps.length > 0 ? sameFileEps[0].line - 1 : ep.line + 200;
  return { start: ep.line, end: nextEpLine };
}

function getCallsInRange(file, startLine, endLine, edges) {
  return edges.filter(e =>
    e.file === file && e.line >= startLine && e.line <= endLine
  );
}

function traceToTerminals(call, callGraph, visited, depth, maxDepth = MAX_DEPTH) {
  if (depth >= maxDepth) {
    return [makeTerminal(call, depth)];
  }

  const visitKey = `${call.file}:${call.line}:${call.callee}`;
  if (visited.has(visitKey)) return [];
  visited.add(visitKey);

  const target = resolveTarget(call.callee, call.file, callGraph);

  if (!target) {
    visited.delete(visitKey);
    return [makeTerminal(call, depth)];
  }

  const innerCalls = getCallsInRange(
    target.file,
    target.line,
    target.endLine || target.line + 200,
    callGraph.edges
  );

  if (innerCalls.length === 0) {
    visited.delete(visitKey);
    return [makeTerminal(call, depth)];
  }

  const results = [];
  const viaStep = formatViaStep(call);

  for (const inner of innerCalls) {
    const innerTerminals = traceToTerminals(inner, callGraph, visited, depth + 1, maxDepth);
    for (const t of innerTerminals) {
      results.push({
        terminal: t.terminal,
        via: [viaStep, ...t.via],
        hops: t.hops + 1,
      });
    }
  }

  visited.delete(visitKey);

  if (results.length === 0) {
    return [makeTerminal(call, depth)];
  }

  return results;
}

function makeTerminal(call, depth) {
  return {
    terminal: {
      file: call.file,
      line: call.line,
      expr: call.callee,
      arguments: (call.arguments || []).map(a => a.expr),
    },
    via: [],
    hops: depth,
  };
}

function formatViaStep(call) {
  const args = (call.arguments || []).map(a => a.expr).join(', ');
  return `${call.file}:${call.line} ${call.callee}(${args})`;
}

function resolveTarget(callee, callerFile, callGraph) {
  const simpleName = callee.split('.').pop();

  let node = findNodeByName(callee, callerFile, callGraph)
          || findNodeByName(simpleName, callerFile, callGraph);
  if (node) return node;

  const fileImports = callGraph.imports[callerFile] || [];
  for (const imp of fileImports) {
    if (!imp.resolvedFile) continue;
    node = findNodeByName(callee, imp.resolvedFile, callGraph)
        || findNodeByName(simpleName, imp.resolvedFile, callGraph);
    if (node) return node;
  }

  return null;
}

function findNodeByName(name, file, callGraph) {
  const nodes = callGraph.nodes || {};
  const key = `${file}:${name}`;
  if (nodes[key]) return { ...nodes[key], file };

  for (const [, node] of Object.entries(nodes)) {
    if (node.name === name && node.file === file) {
      return { ...node, file };
    }
  }

  return null;
}

module.exports = { extractDataFlows };
