'use strict';

const fs = require('fs');
const path = require('path');

const LANGUAGE_MAP = {
  '.js':   { pkg: 'tree-sitter-javascript', name: 'javascript' },
  '.jsx':  { pkg: 'tree-sitter-javascript', name: 'javascript' },
  '.mjs':  { pkg: 'tree-sitter-javascript', name: 'javascript' },
  '.cjs':  { pkg: 'tree-sitter-javascript', name: 'javascript' },
  '.ts':   { pkg: 'tree-sitter-typescript', name: 'typescript', sub: 'typescript' },
  '.tsx':  { pkg: 'tree-sitter-typescript', name: 'tsx', sub: 'tsx' },
  '.py':   { pkg: 'tree-sitter-python', name: 'python' },
  '.go':   { pkg: 'tree-sitter-go', name: 'go' },
  '.java': { pkg: 'tree-sitter-java', name: 'java' },
  '.rs':   { pkg: 'tree-sitter-rust', name: 'rust' },
  '.c':    { pkg: 'tree-sitter-c', name: 'c' },
  '.cpp':  { pkg: 'tree-sitter-cpp', name: 'cpp' },
  '.h':    { pkg: 'tree-sitter-c', name: 'c' },
  '.hpp':  { pkg: 'tree-sitter-cpp', name: 'cpp' },
  '.cc':   { pkg: 'tree-sitter-cpp', name: 'cpp' },
  '.kt':   { pkg: '@tree-sitter-grammars/tree-sitter-kotlin', name: 'kotlin' },
  '.kts':  { pkg: '@tree-sitter-grammars/tree-sitter-kotlin', name: 'kotlin' },
  '.swift': { pkg: 'tree-sitter-swift', name: 'swift' },
  '.m':    { pkg: 'tree-sitter-objc', name: 'objc' },
  '.mm':   { pkg: 'tree-sitter-objc', name: 'objc' },
  '.cs':   { pkg: 'tree-sitter-c-sharp', name: 'c_sharp' },
  '.rb':   { pkg: 'tree-sitter-ruby', name: 'ruby' },
  '.php':  { pkg: 'tree-sitter-php', name: 'php', sub: 'php' },
  '.dart': { pkg: 'tree-sitter-dart', name: 'dart' },
  '.sol':  { pkg: 'tree-sitter-solidity', name: 'solidity' },
  '.ex':   { pkg: 'tree-sitter-elixir', name: 'elixir' },
  '.exs':  { pkg: 'tree-sitter-elixir', name: 'elixir' },
  // .tf/.hcl (HCL/Terraform) disabled: the only published grammar
  // (@tree-sitter-grammars/tree-sitter-hcl@1.2.0) requires tree-sitter ^0.25,
  // whose ABI breaks the swift/objc grammars (pinned to ^0.22.x). No 0.22-compatible
  // HCL grammar exists. The extractHCL extractor in call-graph.js is kept so re-adding
  // is a one-line map entry once a compatible grammar ships.
};

const loadedLanguages = new Map();
let Parser = null;

function getParser() {
  if (!Parser) {
    try {
      Parser = require('tree-sitter');
    } catch {
      return null;
    }
  }
  return Parser;
}

function loadLanguage(ext) {
  const spec = LANGUAGE_MAP[ext];
  if (!spec) return null;

  const key = `${spec.pkg}:${spec.sub || ''}`;
  if (loadedLanguages.has(key)) return loadedLanguages.get(key);

  try {
    let lang = require(spec.pkg);
    if (spec.sub) lang = lang[spec.sub];
    loadedLanguages.set(key, lang);
    return lang;
  } catch {
    loadedLanguages.set(key, null);
    return null;
  }
}

function detectLanguage(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const spec = LANGUAGE_MAP[ext];
  return spec ? { ext, ...spec } : null;
}

function parseFile(filePath) {
  const TreeSitter = getParser();
  if (!TreeSitter) return { ok: false, error: 'tree-sitter not installed', filePath };

  const langSpec = detectLanguage(filePath);
  if (!langSpec) return { ok: false, error: `unsupported extension: ${path.extname(filePath)}`, filePath };

  const lang = loadLanguage(langSpec.ext);
  if (!lang) return { ok: false, error: `language package not installed: ${langSpec.pkg}`, filePath };

  let source;
  try {
    source = fs.readFileSync(filePath, 'utf8');
  } catch (e) {
    return { ok: false, error: `read failed: ${e.message}`, filePath };
  }

  try {
    const parser = new TreeSitter();
    parser.setLanguage(lang);
    const tree = parser.parse(source);
    return {
      ok: true,
      filePath,
      language: langSpec.name,
      tree,
      source,
      lineCount: source.split('\n').length,
    };
  } catch (e) {
    return { ok: false, error: `parse failed: ${e.message}`, filePath };
  }
}

function parseFiles(filePaths) {
  const results = { parsed: [], failed: [] };
  for (const fp of filePaths) {
    const result = parseFile(fp);
    if (result.ok) {
      results.parsed.push(result);
    } else {
      results.failed.push(result);
    }
  }
  return results;
}

function getSupportedExtensions() {
  return Object.keys(LANGUAGE_MAP);
}

function isSupported(filePath) {
  return detectLanguage(filePath) !== null;
}

module.exports = {
  parseFile,
  parseFiles,
  detectLanguage,
  getSupportedExtensions,
  isSupported,
  LANGUAGE_MAP,
};
