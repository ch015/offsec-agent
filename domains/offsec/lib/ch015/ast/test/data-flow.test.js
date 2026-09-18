'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { parseFiles } = require('../parser');
const { extractCallGraph } = require('../call-graph');
const { extractDataFlows } = require('../data-flow');

const FIXTURES = path.join(__dirname, 'fixtures', 'simple-express');

function getFlows() {
  const files = [
    path.join(FIXTURES, 'index.js'),
    path.join(FIXTURES, 'db.js'),
    path.join(FIXTURES, 'auth.js'),
  ];
  const { parsed } = parseFiles(files);
  const callGraph = extractCallGraph(parsed, FIXTURES);
  return extractDataFlows(callGraph);
}

describe('data-flow', () => {
  describe('extractDataFlows', () => {
    it('finds data flows from entry points', () => {
      const flows = getFlows();
      assert.ok(flows.length > 0, 'should find at least one data flow');
    });

    it('flows have required structural fields', () => {
      const flows = getFlows();
      for (const f of flows) {
        assert.ok(f.entry, 'should have entry');
        assert.ok(f.entry.file, 'entry should have file');
        assert.ok(f.entry.line, 'entry should have line');
        assert.ok(f.terminal, 'should have terminal');
        assert.ok(f.terminal.file, 'terminal should have file');
        assert.ok(f.terminal.line, 'terminal should have line');
        assert.ok(f.terminal.expr, 'terminal should have expr');
        assert.ok(Array.isArray(f.via), 'should have via array');
        assert.ok(typeof f.hops === 'number', 'should have hops count');
      }
    });

    it('traces cross-file flows through imports', () => {
      const flows = getFlows();
      const crossFile = flows.filter(f =>
        f.entry.file !== f.terminal.file
      );
      assert.ok(crossFile.length > 0, 'should find cross-file data flows');
    });

    it('cross-file flows have via steps', () => {
      const flows = getFlows();
      const crossFile = flows.filter(f =>
        f.entry.file !== f.terminal.file && f.via.length > 0
      );
      assert.ok(crossFile.length > 0, 'cross-file flows should have via steps');
    });

    it('captures terminal call arguments', () => {
      const flows = getFlows();
      const withArgs = flows.filter(f =>
        f.terminal.arguments && f.terminal.arguments.length > 0
      );
      assert.ok(withArgs.length > 0, 'some terminals should have arguments');
    });

    it('does not contain security judgments', () => {
      const flows = getFlows();
      for (const f of flows) {
        assert.equal(f.confidence, undefined, 'should not have confidence score');
        assert.equal(f.potential_cwe, undefined, 'should not have CWE mapping');
        assert.equal(f.source, undefined, 'should not label sources');
        assert.equal(f.sink, undefined, 'should not label sinks');
        assert.equal(f.sanitizers, undefined, 'should not label sanitizers');
      }
    });

    it('respects maxFlows option', () => {
      const files = [
        path.join(FIXTURES, 'index.js'),
        path.join(FIXTURES, 'db.js'),
        path.join(FIXTURES, 'auth.js'),
      ];
      const { parsed } = parseFiles(files);
      const callGraph = extractCallGraph(parsed, FIXTURES);

      const unlimited = extractDataFlows(callGraph);
      assert.ok(unlimited.length >= 1);

      const limited = extractDataFlows(callGraph, { maxFlows: 1 });
      assert.equal(limited.length, 1);
    });

    it('respects maxDepth option (callGraphDepth wiring)', () => {
      const files = [
        path.join(FIXTURES, 'index.js'),
        path.join(FIXTURES, 'db.js'),
        path.join(FIXTURES, 'auth.js'),
      ];
      const { parsed } = parseFiles(files);
      const callGraph = extractCallGraph(parsed, FIXTURES);

      // hops는 (재귀 종단 depth) + (via 래핑 단계)로 계산되므로 maxDepth=1이면 최대 2.
      // 핵심은 재귀 탐색이 maxDepth에서 끊겨 기본값(8)보다 얕은 flow만 나온다는 것.
      const shallow = extractDataFlows(callGraph, { maxDepth: 1 });
      for (const f of shallow) {
        assert.ok(f.hops <= 2, `flow should not exceed maxDepth=1 traversal (hops<=2), got hops=${f.hops}`);
        assert.ok(f.via.length <= 1, `via steps should be capped by maxDepth=1, got ${f.via.length}`);
      }
    });

    it('invalid options fall back to defaults', () => {
      const files = [path.join(FIXTURES, 'index.js'), path.join(FIXTURES, 'db.js')];
      const { parsed } = parseFiles(files);
      const callGraph = extractCallGraph(parsed, FIXTURES);

      const flows = extractDataFlows(callGraph, { maxFlows: 0, maxDepth: -1 });
      assert.deepEqual(flows, extractDataFlows(callGraph));
    });

    it('returns empty array for empty call graph', () => {
      const flows = extractDataFlows({
        nodes: {}, edges: [], entryPoints: [], imports: {},
        stats: { total_functions: 0, total_calls: 0, total_entry_points: 0 },
      });
      assert.equal(flows.length, 0);
    });
  });
});
