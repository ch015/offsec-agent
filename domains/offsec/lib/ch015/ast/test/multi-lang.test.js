'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { parseFile, parseFiles } = require('../parser');
const { extractCallGraph } = require('../call-graph');

const FIXTURES = path.join(__dirname, 'fixtures', 'multi-lang');

describe('multi-lang extractors', () => {
  describe('Java', () => {
    const file = path.join(FIXTURES, 'App.java');

    it('parses Java file', () => {
      const result = parseFile(file);
      assert.ok(result.ok, `parse should succeed: ${result.error}`);
      assert.equal(result.language, 'java');
    });

    it('extracts methods and calls', () => {
      const { parsed } = parseFiles([file]);
      const graph = extractCallGraph(parsed, FIXTURES);
      const funcs = Object.values(graph.nodes).map(n => n.name);
      assert.ok(funcs.includes('getUser'), 'should find getUser');
      assert.ok(funcs.includes('createUser'), 'should find createUser');
      assert.ok(funcs.includes('deleteUser'), 'should find deleteUser');
      assert.ok(graph.stats.total_calls > 0, 'should find calls');
    });

    it('detects Spring Boot entry points', () => {
      const { parsed } = parseFiles([file]);
      const graph = extractCallGraph(parsed, FIXTURES);
      const methods = graph.entryPoints.map(ep => ep.method);
      assert.ok(methods.includes('get'), 'should find GET mapping');
      assert.ok(methods.includes('post'), 'should find POST mapping');
      assert.ok(methods.includes('delete'), 'should find DELETE mapping');
    });

    it('extracts imports', () => {
      const { parsed } = parseFiles([file]);
      const graph = extractCallGraph(parsed, FIXTURES);
      const fileImports = graph.imports['App.java'] || [];
      assert.ok(fileImports.length > 0, 'should find imports');
    });
  });

  describe('Rust', () => {
    const file = path.join(FIXTURES, 'main.rs');

    it('parses Rust file', () => {
      const result = parseFile(file);
      assert.ok(result.ok, `parse should succeed: ${result.error}`);
      assert.equal(result.language, 'rust');
    });

    it('extracts functions and calls', () => {
      const { parsed } = parseFiles([file]);
      const graph = extractCallGraph(parsed, FIXTURES);
      const funcs = Object.values(graph.nodes).map(n => n.name);
      assert.ok(funcs.includes('get_user'), 'should find get_user');
      assert.ok(funcs.includes('create_user'), 'should find create_user');
      assert.ok(funcs.includes('configure_routes'), 'should find configure_routes');
      assert.ok(graph.stats.total_calls > 0, 'should find calls');
    });

    it('detects Actix route attributes', () => {
      const { parsed } = parseFiles([file]);
      const graph = extractCallGraph(parsed, FIXTURES);
      assert.ok(graph.entryPoints.length > 0, 'should find entry points');
      const methods = graph.entryPoints.map(ep => ep.method);
      assert.ok(methods.includes('get'), 'should find GET route');
      assert.ok(methods.includes('post'), 'should find POST route');
    });

    it('extracts use declarations', () => {
      const { parsed } = parseFiles([file]);
      const graph = extractCallGraph(parsed, FIXTURES);
      const fileImports = graph.imports['main.rs'] || [];
      assert.ok(fileImports.length > 0, 'should find use declarations');
    });
  });

  describe('C', () => {
    const file = path.join(FIXTURES, 'server.c');

    it('parses C file', () => {
      const result = parseFile(file);
      assert.ok(result.ok, `parse should succeed: ${result.error}`);
      assert.equal(result.language, 'c');
    });

    it('extracts functions and calls', () => {
      const { parsed } = parseFiles([file]);
      const graph = extractCallGraph(parsed, FIXTURES);
      const funcs = Object.values(graph.nodes).map(n => n.name);
      assert.ok(funcs.includes('main'), 'should find main');
      assert.ok(funcs.includes('handle_request'), 'should find handle_request');
      assert.ok(funcs.includes('execute_query'), 'should find execute_query');
      assert.ok(graph.stats.total_calls > 0, 'should find calls');
    });

    it('detects main as CLI entry point', () => {
      const { parsed } = parseFiles([file]);
      const graph = extractCallGraph(parsed, FIXTURES);
      const cliEntries = graph.entryPoints.filter(ep => ep.type === 'cli');
      assert.ok(cliEntries.length > 0, 'should find main entry point');
      assert.equal(cliEntries[0].handler, 'main');
    });

    it('extracts includes', () => {
      const { parsed } = parseFiles([file]);
      const graph = extractCallGraph(parsed, FIXTURES);
      const fileImports = graph.imports['server.c'] || [];
      assert.ok(fileImports.length > 0, 'should find #include directives');
      const modules = fileImports.map(i => i.module);
      assert.ok(modules.includes('stdio.h'), 'should find stdio.h');
    });
  });

  describe('Kotlin', () => {
    const file = path.join(FIXTURES, 'App.kt');

    it('parses Kotlin file', () => {
      const result = parseFile(file);
      assert.ok(result.ok, `parse should succeed: ${result.error}`);
      assert.equal(result.language, 'kotlin');
    });

    it('extracts functions and calls', () => {
      const { parsed } = parseFiles([file]);
      const graph = extractCallGraph(parsed, FIXTURES);
      assert.ok(graph.stats.total_functions > 0, 'should find functions');
      assert.ok(graph.stats.total_calls > 0, 'should find calls');
    });
  });

  describe('Swift', () => {
    const file = path.join(FIXTURES, 'ViewController.swift');

    it('parses Swift file', () => {
      const result = parseFile(file);
      assert.ok(result.ok, `parse should succeed: ${result.error}`);
      assert.equal(result.language, 'swift');
    });

    it('extracts functions', () => {
      const { parsed } = parseFiles([file]);
      const graph = extractCallGraph(parsed, FIXTURES);
      assert.ok(graph.stats.total_functions > 0, 'should find functions');
    });
  });

  describe('Objective-C++', () => {
    const file = path.join(FIXTURES, 'Bridge.mm');

    it('parses .mm (Obj-C++) file as objc', () => {
      const result = parseFile(file);
      assert.ok(result.ok, `parse should succeed: ${result.error}`);
      assert.equal(result.language, 'objc');
    });

    it('extracts keyword selectors, class methods, and C functions', () => {
      const { parsed } = parseFiles([file]);
      const graph = extractCallGraph(parsed, FIXTURES);
      const funcs = Object.values(graph.nodes).map(n => n.name);
      assert.ok(funcs.includes('signIn:error:'), 'should build keyword selector');
      assert.ok(funcs.includes('openOAuth:error:'), 'should find openOAuth:error:');
      assert.ok(funcs.includes('initialize'), 'should find class method initialize');
      assert.ok(funcs.includes('helper'), 'should find C-style function');
    });

    it('extracts Obj-C message sends and C calls', () => {
      const { parsed } = parseFiles([file]);
      const graph = extractCallGraph(parsed, FIXTURES);
      const callees = graph.edges.map(e => e.callee);
      assert.ok(callees.includes('objectForKey:'), 'should capture message send selector');
      assert.ok(callees.includes('openOAuth:error:'), 'should capture self message send');
      assert.ok(callees.includes('URLWithString:'), 'should capture framework message send');
      assert.ok(callees.includes('logEvent'), 'should capture C-style call');
    });

    it('detects iOS lifecycle entry points', () => {
      const { parsed } = parseFiles([file]);
      const graph = extractCallGraph(parsed, FIXTURES);
      const handlers = graph.entryPoints.map(ep => ep.handler);
      assert.ok(handlers.includes('initialize'), 'should flag initialize as entry point');
    });

    it('extracts #import directives', () => {
      const { parsed } = parseFiles([file]);
      const graph = extractCallGraph(parsed, FIXTURES);
      const fileImports = graph.imports['Bridge.mm'] || [];
      assert.ok(fileImports.length >= 2, 'should find #import directives');
    });
  });

  describe('C#', () => {
    const file = path.join(FIXTURES, 'Controller.cs');

    it('parses C# file', () => {
      const result = parseFile(file);
      assert.ok(result.ok, `parse should succeed: ${result.error}`);
      assert.equal(result.language, 'c_sharp');
    });

    it('extracts methods and calls', () => {
      const { parsed } = parseFiles([file]);
      const graph = extractCallGraph(parsed, FIXTURES);
      const funcs = Object.values(graph.nodes).map(n => n.name);
      assert.ok(funcs.includes('GetUser'), 'should find GetUser');
      assert.ok(funcs.includes('CreateUser'), 'should find CreateUser');
      assert.ok(graph.stats.total_calls > 0, 'should find calls');
    });

    it('detects ASP.NET entry points', () => {
      const { parsed } = parseFiles([file]);
      const graph = extractCallGraph(parsed, FIXTURES);
      assert.ok(graph.entryPoints.length > 0, 'should find entry points');
      const methods = graph.entryPoints.map(ep => ep.method);
      assert.ok(methods.includes('get'), 'should find HttpGet');
      assert.ok(methods.includes('post'), 'should find HttpPost');
    });

    it('extracts using directives', () => {
      const { parsed } = parseFiles([file]);
      const graph = extractCallGraph(parsed, FIXTURES);
      const fileImports = graph.imports['Controller.cs'] || [];
      assert.ok(fileImports.length > 0, 'should find using directives');
    });
  });

  describe('Ruby', () => {
    const file = path.join(FIXTURES, 'users_controller.rb');

    it('parses Ruby file', () => {
      const result = parseFile(file);
      assert.ok(result.ok, `parse should succeed: ${result.error}`);
      assert.equal(result.language, 'ruby');
    });

    it('extracts methods', () => {
      const { parsed } = parseFiles([file]);
      const graph = extractCallGraph(parsed, FIXTURES);
      const funcs = Object.values(graph.nodes).map(n => n.name);
      assert.ok(funcs.includes('index'), 'should find index');
      assert.ok(funcs.includes('show'), 'should find show');
      assert.ok(funcs.includes('create'), 'should find create');
      assert.ok(funcs.includes('user_params'), 'should find user_params');
    });

    it('detects Rails controller actions (excludes private)', () => {
      const { parsed } = parseFiles([file]);
      const graph = extractCallGraph(parsed, FIXTURES);
      const actions = graph.entryPoints
        .filter(ep => ep.type === 'http' && ep.method === 'rails_action')
        .map(ep => ep.handler);
      assert.ok(actions.includes('index'), 'should find index action');
      assert.ok(actions.includes('show'), 'should find show action');
      assert.ok(actions.includes('create'), 'should find create action');
      assert.ok(!actions.includes('user_params'), 'should NOT include private method');
    });

    it('extracts calls', () => {
      const { parsed } = parseFiles([file]);
      const graph = extractCallGraph(parsed, FIXTURES);
      assert.ok(graph.stats.total_calls > 0, 'should find calls');
    });
  });

  describe('PHP', () => {
    const file = path.join(FIXTURES, 'UserController.php');

    it('parses PHP file', () => {
      const result = parseFile(file);
      assert.ok(result.ok, `parse should succeed: ${result.error}`);
      assert.equal(result.language, 'php');
    });

    it('extracts methods', () => {
      const { parsed } = parseFiles([file]);
      const graph = extractCallGraph(parsed, FIXTURES);
      const funcs = Object.values(graph.nodes).map(n => n.name);
      assert.ok(funcs.includes('index'), 'should find index');
      assert.ok(funcs.includes('store'), 'should find store');
      assert.ok(funcs.includes('show'), 'should find show');
    });

    it('detects Laravel controller methods', () => {
      const { parsed } = parseFiles([file]);
      const graph = extractCallGraph(parsed, FIXTURES);
      const actions = graph.entryPoints
        .filter(ep => ep.method === 'laravel_action')
        .map(ep => ep.handler);
      assert.ok(actions.includes('index'), 'should find index action');
      assert.ok(actions.includes('store'), 'should find store action');
    });

    it('extracts imports', () => {
      const { parsed } = parseFiles([file]);
      const graph = extractCallGraph(parsed, FIXTURES);
      const fileImports = graph.imports['UserController.php'] || [];
      assert.ok(fileImports.length > 0, 'should find use declarations');
    });
  });

  describe('Elixir', () => {
    const file = path.join(FIXTURES, 'router.ex');

    it('parses Elixir file', () => {
      const result = parseFile(file);
      assert.ok(result.ok, `parse should succeed: ${result.error}`);
      assert.equal(result.language, 'elixir');
    });

    it('detects Phoenix routes', () => {
      const { parsed } = parseFiles([file]);
      const graph = extractCallGraph(parsed, FIXTURES);
      const httpEntries = graph.entryPoints.filter(ep =>
        ep.type === 'http' || ep.type === 'http_resource'
      );
      assert.ok(httpEntries.length >= 3, 'should find at least 3 route entries');
      const methods = httpEntries.map(ep => ep.method);
      assert.ok(methods.includes('restful'), 'should find resources route');
      assert.ok(methods.includes('get'), 'should find GET route');
      assert.ok(methods.includes('post'), 'should find POST route');
    });
  });
});
