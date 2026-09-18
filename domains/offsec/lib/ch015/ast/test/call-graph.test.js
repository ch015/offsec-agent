'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { parseFiles } = require('../parser');
const { extractCallGraph } = require('../call-graph');

const FIXTURES = path.join(__dirname, 'fixtures', 'simple-express');

function getGraph() {
  const files = [
    path.join(FIXTURES, 'index.js'),
    path.join(FIXTURES, 'db.js'),
    path.join(FIXTURES, 'auth.js'),
  ];
  const { parsed } = parseFiles(files);
  return extractCallGraph(parsed, FIXTURES);
}

describe('call-graph', () => {
  describe('extractCallGraph', () => {
    it('extracts functions from all files', () => {
      const graph = getGraph();
      assert.ok(graph.stats.total_functions > 0, 'should find functions');

      const nodeNames = Object.values(graph.nodes).map(n => n.name);
      assert.ok(nodeNames.includes('getUser'), 'should find getUser');
      assert.ok(nodeNames.includes('createUser'), 'should find createUser');
      assert.ok(nodeNames.includes('checkAuth'), 'should find checkAuth');
    });

    it('extracts call edges', () => {
      const graph = getGraph();
      assert.ok(graph.stats.total_calls > 0, 'should find calls');

      const callees = graph.edges.map(e => e.callee);
      assert.ok(callees.some(c => c.includes('getUser')), 'should find getUser call');
      assert.ok(callees.some(c => c.includes('createUser')), 'should find createUser call');
    });

    it('identifies HTTP entry points', () => {
      const graph = getGraph();
      assert.ok(graph.entryPoints.length > 0, 'should find entry points');

      const methods = graph.entryPoints.map(ep => ep.method);
      assert.ok(methods.includes('get'), 'should find GET route');
      assert.ok(methods.includes('post'), 'should find POST route');
    });

    it('extracts call arguments', () => {
      const graph = getGraph();
      const callsWithArgs = graph.edges.filter(e => e.arguments && e.arguments.length > 0);
      assert.ok(callsWithArgs.length > 0, 'should find calls with arguments');
    });

    it('extracts imports', () => {
      const graph = getGraph();
      const indexImports = graph.imports['index.js'] || [];
      assert.ok(indexImports.length > 0, 'should find imports in index.js');

      const modules = indexImports.map(i => i.module);
      assert.ok(modules.some(m => m.includes('./db')), 'should find ./db import');
      assert.ok(modules.some(m => m.includes('./auth')), 'should find ./auth import');
    });

    it('returns stats', () => {
      const graph = getGraph();
      assert.ok(typeof graph.stats.total_functions === 'number');
      assert.ok(typeof graph.stats.total_calls === 'number');
      assert.ok(typeof graph.stats.total_entry_points === 'number');
      assert.ok(typeof graph.stats.total_entry_points === 'number');
    });
  });

  describe('GraphQL / WebSocket entry points', () => {
    const BOOST = path.join(__dirname, 'fixtures', 'detection-boost');
    const epsOf = (file) => {
      const { parsed } = parseFiles([path.join(BOOST, file)]);
      return extractCallGraph(parsed, BOOST).entryPoints;
    };

    it('detects GraphQL @Query/@Mutation resolvers', () => {
      const eps = epsOf('graphql.ts').filter(e => e.type === 'graphql');
      const methods = eps.map(e => e.method);
      assert.ok(methods.includes('query'), 'should detect @Query');
      assert.ok(methods.includes('mutation'), 'should detect @Mutation');
    });

    it('detects WebSocket connection/message handlers', () => {
      const eps = epsOf('websocket.js').filter(e => e.type === 'websocket');
      const events = eps.map(e => e.route);
      assert.ok(events.includes('connection'), 'should detect io.on(connection)');
      assert.ok(events.includes('message'), 'should detect socket.on(message)');
    });

    it('does NOT treat config.get/cache.get/Map.get as routes (source-model precision)', () => {
      const http = epsOf('routes-precision.js').filter(e => e.type === 'http');
      assert.ok(http.some(e => e.route === '/real'), 'real app.get route should be detected');
      // config.get('feature.enabled') / cache.get / Map.get must not appear as routes.
      const bogus = http.filter(e => /feature\.enabled|somekey|^k$/.test(String(e.route)));
      assert.equal(bogus.length, 0, 'lookup calls must not become HTTP entry points');
    });
  });
});
