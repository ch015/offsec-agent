'use strict';

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const yaml = require('js-yaml');
const { buildAstContext, collectSourceFiles } = require('../context-builder');

const FIXTURES = path.join(__dirname, 'fixtures', 'simple-express');
const OUTPUT_DIR = path.join(FIXTURES, '.ch015');

afterEach(() => {
  if (fs.existsSync(OUTPUT_DIR)) {
    fs.rmSync(OUTPUT_DIR, { recursive: true, force: true });
  }
});

describe('context-builder', () => {
  it('T15 parses every one of 622 supported files and explicitly lists unsupported inputs', async () => {
    const root = fs.mkdtempSync(path.join(require('os').tmpdir(), 'ast-complete-scope-'));
    try {
      const files = Array.from({ length: 622 }, (_, i) => path.join(root, `source-${i}.js`));
      for (const file of files) fs.writeFileSync(file, 'module.exports = 1;\n');
      const unsupported = path.join(root, 'config.unknown'); fs.writeFileSync(unsupported, 'configuration');
      const outputPath = path.join(root, 'result.yaml');
      const result = await buildAstContext(root, { sourceFiles: [...files, unsupported], runSemgrep: false, outputPath, logger: () => {} });
      assert.equal(result.ok, true);
      const context = yaml.load(fs.readFileSync(outputPath, 'utf8'));
      assert.equal(context.scope.parsed_files.length, 622);
      assert.ok(context.scope.parsed_files.includes('source-621.js'));
      assert.deepEqual(context.scope.skipped_files, []); assert.deepEqual(context.scope.unsupported_files, ['config.unknown']);
      assert.equal(context.stats.truncation.files, false);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  });
  describe('collectSourceFiles', () => {
    it('finds source files in fixture directory', () => {
      const { getSupportedExtensions } = require('../parser');
      const config = {
        sourceDirs: [],
        extensions: getSupportedExtensions(),
        maxFiles: 100,
      };
      const files = collectSourceFiles(FIXTURES, config);
      assert.ok(files.length >= 3, `should find at least 3 files, found ${files.length}`);
      assert.ok(files.some(f => f.endsWith('index.js')));
      assert.ok(files.some(f => f.endsWith('db.js')));
    });

    it('respects maxFiles limit', () => {
      const { getSupportedExtensions } = require('../parser');
      const config = {
        sourceDirs: [],
        extensions: getSupportedExtensions(),
        maxFiles: 1,
      };
      const files = collectSourceFiles(FIXTURES, config);
      assert.equal(files.length, 1);
    });

    it('does not skip directories named ch015 under source roots', () => {
      const tmp = fs.mkdtempSync(path.join(__dirname, 'tmp-ch015-src-'));
      try {
        fs.mkdirSync(path.join(tmp, 'lib', 'ch015'), { recursive: true });
        fs.writeFileSync(path.join(tmp, 'lib', 'ch015', 'engine.js'), 'module.exports = {};\n');
        const { getSupportedExtensions } = require('../parser');
        const files = collectSourceFiles(tmp, {
          sourceDirs: ['lib'],
          extensions: getSupportedExtensions(),
          maxFiles: 100,
        });
        assert.ok(files.some(f => f.endsWith(path.join('lib', 'ch015', 'engine.js'))));
      } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
      }
    });
  });

  describe('buildAstContext', () => {
    it('generates ast-context.yaml', async () => {
      const result = await buildAstContext(FIXTURES, { logger: () => {} });
      assert.ok(result.ok, `should succeed: ${result.error}`);

      const outputPath = path.join(OUTPUT_DIR, 'ast-context.yaml');
      assert.ok(fs.existsSync(outputPath), 'should create output file');
      if (process.platform !== 'win32') {
        assert.equal(fs.statSync(OUTPUT_DIR).mode & 0o777, 0o700);
        assert.equal(fs.statSync(outputPath).mode & 0o777, 0o600);
      }

      const content = yaml.load(fs.readFileSync(outputPath, 'utf8'));
      assert.ok(content.meta);
      assert.equal(content.meta.mode, 'ast');
      assert.ok(content.stats);
      assert.ok(content.stats.files_parsed > 0);
    });

    it('writes to an explicit engagement output without touching the source tree', async () => {
      const engagement = fs.mkdtempSync(path.join(require('os').tmpdir(), 'ch015-ast-eng-'));
      const outputPath = path.join(engagement, '00_ast_context.yaml');
      try {
        const result = await buildAstContext(FIXTURES, {
          logger: () => {},
          outputPath,
          runSemgrep: false,
        });
        assert.ok(result.ok, `should succeed: ${result.error}`);
        assert.equal(result.outputPath, outputPath);
        assert.ok(fs.existsSync(outputPath));
      } finally {
        fs.rmSync(engagement, { recursive: true, force: true });
      }
    });

    it('context contains entry points', async () => {
      const result = await buildAstContext(FIXTURES, { logger: () => {} });
      assert.ok(result.ok);

      const content = yaml.load(fs.readFileSync(path.join(OUTPUT_DIR, 'ast-context.yaml'), 'utf8'));
      assert.ok(content.entry_points.length > 0, 'should find entry points');
    });

    it('context contains data flows', async () => {
      const result = await buildAstContext(FIXTURES, { logger: () => {} });
      assert.ok(result.ok);

      const content = yaml.load(fs.readFileSync(path.join(OUTPUT_DIR, 'ast-context.yaml'), 'utf8'));
      assert.ok(content.data_flows.length > 0, 'should find data flows');

      const flow = content.data_flows[0];
      assert.ok(flow.entry, 'flow should have entry');
      assert.ok(flow.terminal, 'flow should have terminal');
      assert.ok(Array.isArray(flow.via), 'flow should have via array');
    });

    it('context contains taint candidate paths', async () => {
      const result = await buildAstContext(FIXTURES, { logger: () => {} });
      assert.ok(result.ok);

      const content = yaml.load(fs.readFileSync(path.join(OUTPUT_DIR, 'ast-context.yaml'), 'utf8'));
      assert.ok(content.taint_paths.length > 0, 'should find taint candidates');

      const taintPath = content.taint_paths[0];
      assert.ok(taintPath.source, 'taint candidate should have source');
      assert.ok(taintPath.sink, 'taint candidate should have sink');
      assert.ok(typeof taintPath.confidence === 'number', 'taint candidate should have confidence');
    });

    it('context does not contain final security findings', async () => {
      const result = await buildAstContext(FIXTURES, { logger: () => {} });
      assert.ok(result.ok);

      const content = yaml.load(fs.readFileSync(path.join(OUTPUT_DIR, 'ast-context.yaml'), 'utf8'));
      assert.equal(content.findings, undefined, 'should not emit final findings');
    });

    it('context contains call graph', async () => {
      const result = await buildAstContext(FIXTURES, { logger: () => {} });
      assert.ok(result.ok);

      const content = yaml.load(fs.readFileSync(path.join(OUTPUT_DIR, 'ast-context.yaml'), 'utf8'));
      assert.ok(content.call_graph, 'should have call graph');
      assert.ok(Object.keys(content.call_graph).length > 0, 'call graph should have entries');
    });

    it('returns stats', async () => {
      const result = await buildAstContext(FIXTURES, { logger: () => {} });
      assert.ok(result.ok);
      assert.ok(result.stats.files_parsed > 0);
      assert.ok(typeof result.stats.functions === 'number');
      assert.ok(typeof result.stats.entry_points === 'number');
      assert.ok(typeof result.stats.data_flows === 'number');
      assert.ok(typeof result.stats.taint_paths === 'number');
    });

    it('wires ch015.analysisMode.ast.maxDataFlows/callGraphDepth from target config', async () => {
      // fixture를 임시 디렉터리로 복사하고 maxDataFlows=1 config를 둔다
      const tmp = fs.mkdtempSync(path.join(__dirname, 'tmp-ch015-cfg-'));
      try {
        for (const f of ['index.js', 'db.js', 'auth.js']) {
          const src = path.join(FIXTURES, f);
          if (fs.existsSync(src)) fs.copyFileSync(src, path.join(tmp, f));
        }
        fs.writeFileSync(path.join(tmp, 'ch015.config.json'), JSON.stringify({
          ch015: { analysisMode: { ast: { maxDataFlows: 1, callGraphDepth: 1 } } },
        }));

        const result = await buildAstContext(tmp, { logger: () => {} });
        assert.ok(result.ok, `should succeed: ${result.error}`);
        assert.ok(result.stats.data_flows <= 1, `maxDataFlows=1 should cap flows, got ${result.stats.data_flows}`);

        const content = yaml.load(fs.readFileSync(path.join(tmp, '.ch015', 'ast-context.yaml'), 'utf8'));
        // hops = 재귀 종단 depth + via 래핑 단계 → callGraphDepth=1이면 최대 2
        for (const flow of content.data_flows) {
          assert.ok(flow.hops <= 2, `callGraphDepth=1 should cap traversal (hops<=2), got ${flow.hops}`);
          assert.ok(flow.via.length <= 1, `via steps should be capped, got ${flow.via.length}`);
        }
      } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
      }
    });
  });
});
