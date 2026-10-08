'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { parseFile, parseFiles, detectLanguage, isSupported, getSupportedExtensions } = require('../parser');

const FIXTURES = path.join(__dirname, 'fixtures', 'simple-express');

describe('parser', () => {
  describe('detectLanguage', () => {
    it('detects JavaScript', () => {
      const result = detectLanguage('test.js');
      assert.equal(result.name, 'javascript');
    });

    it('detects TypeScript', () => {
      const result = detectLanguage('test.ts');
      assert.equal(result.name, 'typescript');
    });

    it('detects TSX', () => {
      const result = detectLanguage('test.tsx');
      assert.equal(result.name, 'tsx');
    });

    it('detects Python', () => {
      const result = detectLanguage('test.py');
      assert.equal(result.name, 'python');
    });

    it('detects Go', () => {
      const result = detectLanguage('test.go');
      assert.equal(result.name, 'go');
    });

    it('detects Ruby', () => {
      const result = detectLanguage('test.rb');
      assert.equal(result.name, 'ruby');
    });

    it('returns null for unsupported extension', () => {
      assert.equal(detectLanguage('test.txt'), null);
      assert.equal(detectLanguage('test.md'), null);
    });
  });

  describe('isSupported', () => {
    it('returns true for supported files', () => {
      assert.ok(isSupported('src/app.js'));
      assert.ok(isSupported('src/main.py'));
      assert.ok(isSupported('main.go'));
    });

    it('returns false for unsupported files', () => {
      assert.ok(!isSupported('readme.md'));
      assert.ok(!isSupported('config.yaml'));
      assert.ok(!isSupported('screen.dart'), 'incompatible grammar must not be advertised as supported');
    });
  });

  describe('getSupportedExtensions', () => {
    it('includes common extensions', () => {
      const exts = getSupportedExtensions();
      assert.ok(exts.includes('.js'));
      assert.ok(exts.includes('.ts'));
      assert.ok(exts.includes('.py'));
      assert.ok(exts.includes('.go'));
    });
  });

  describe('parseFile', () => {
    it('parses JavaScript file successfully', () => {
      const result = parseFile(path.join(FIXTURES, 'index.js'));
      assert.ok(result.ok);
      assert.equal(result.language, 'javascript');
      assert.ok(result.tree);
      assert.ok(result.source.length > 0);
      assert.ok(result.lineCount > 0);
    });

    it('parses all fixture files', () => {
      const files = ['index.js', 'db.js', 'auth.js'];
      for (const file of files) {
        const result = parseFile(path.join(FIXTURES, file));
        assert.ok(result.ok, `Failed to parse ${file}: ${result.error}`);
      }
    });

    it('returns error for non-existent file', () => {
      const result = parseFile('/nonexistent/file.js');
      assert.ok(!result.ok);
      assert.ok(result.error.includes('read failed'));
    });

    it('returns error for unsupported extension', () => {
      const result = parseFile('test.txt');
      assert.ok(!result.ok);
      assert.ok(result.error.includes('unsupported extension'));
    });

    it('loads every advertised installed grammar with the pinned Tree-sitter ABI', () => {
      const root = fs.mkdtempSync(path.join(os.tmpdir(), 'grammar-abi-'));
      try {
        for (const ext of getSupportedExtensions()) {
          const file = path.join(root, `empty${ext}`); fs.writeFileSync(file, '');
          const result = parseFile(file);
          assert.ok(result.ok, `${ext}: ${result.error}`);
          assert.ok(result.tree.rootNode);
        }
        const file = path.join(root, 'contract.sol');
        fs.writeFileSync(file, 'pragma solidity ^0.8.0; contract Example { function value() public pure returns(uint) { return 1; } }');
        const result = parseFile(file);
        assert.ok(result.ok, result.error); assert.equal(result.hasSyntaxErrors, false);
        assert.ok(result.tree.rootNode.toString().includes('function_definition'));
        const invalid = path.join(root, 'fragment.ts'); fs.writeFileSync(invalid, 'export function incomplete(');
        const fragment = parseFile(invalid); assert.ok(fragment.ok); assert.equal(fragment.hasSyntaxErrors, true);
      } finally { fs.rmSync(root, { recursive: true, force: true }); }
    });
  });

  describe('parseFiles', () => {
    it('parses multiple files and separates successes from failures', () => {
      const files = [
        path.join(FIXTURES, 'index.js'),
        path.join(FIXTURES, 'db.js'),
        '/nonexistent.js',
      ];
      const results = parseFiles(files);
      assert.equal(results.parsed.length, 2);
      assert.equal(results.failed.length, 1);
    });
  });
});
