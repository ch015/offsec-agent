import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  assertDependencyGraphIntact,
  createDependencyGraph,
  DEFAULT_ESTIMATED_CHARS_PER_TOKEN,
  GRAPH_DISCLAIMER,
  writeDependencyGraph,
  readDependencyGraph,
} from '../workflow/offsec-dependency-graph.js';

function testStableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(testStableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) =>
      `${JSON.stringify(key)}:${testStableJson(record[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}
function testDigest(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function tsFixture() {
  const target = mkdtempSync(join(tmpdir(), 'nunchi-dep-graph-ts-'));
  mkdirSync(join(target, 'src', 'lib'), { recursive: true });
  mkdirSync(join(target, 'src', 'components'), { recursive: true });
  writeFileSync(join(target, 'src', 'lib', 'auth.ts'),
    'export const authorize = true;\n');
  writeFileSync(join(target, 'src', 'components', 'login.tsx'),
    "import { authorize } from '../lib/auth';\nexport const Login = authorize;\n");
  writeFileSync(join(target, 'tsconfig.json'), JSON.stringify({
    compilerOptions: {
      baseUrl: '.',
      paths: { '@/*': ['src/*'] },
    },
  }));
  writeFileSync(join(target, 'src', 'components', 'dashboard.tsx'),
    "import { authorize } from '@/lib/auth';\nexport const Dashboard = authorize;\n");
  return {
    target,
    manifest: {
      target_realpath: realpathSync(target),
      hash: 'a'.repeat(64),
      source_files: [
        'src/components/dashboard.tsx',
        'src/components/login.tsx',
        'src/lib/auth.ts',
      ],
      units: [
        { id: 'src/components', files: ['src/components/dashboard.tsx', 'src/components/login.tsx'] },
        { id: 'src/lib', files: ['src/lib/auth.ts'] },
      ],
    },
  };
}

describe('OffSec dependency graph — P1', () => {
  it('resolves JS/TS relative imports', () => {
    const { target, manifest } = tsFixture();
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const relEdge = graph.edges.find(
      (e) => e.from === 'src/components/login.tsx' && e.specifier === '../lib/auth',
    );
    expect(relEdge).toBeDefined();
    expect(relEdge!.classification).toBe('local-resolved');
    expect(relEdge!.resolutionKind).toBe('relative-import');
    expect(relEdge!.resolvedTargets).toEqual(['src/lib/auth.ts']);
  });

  it('resolves root referenced tsconfig alias like @/lib/auth', () => {
    const { target, manifest } = tsFixture();
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const aliasEdge = graph.edges.find(
      (e) => e.from === 'src/components/dashboard.tsx' && e.specifier === '@/lib/auth',
    );
    expect(aliasEdge).toBeDefined();
    expect(aliasEdge!.classification).toBe('local-resolved');
    expect(aliasEdge!.resolutionKind).toBe('tsconfig-paths');
    expect(aliasEdge!.resolvedTargets).toEqual(['src/lib/auth.ts']);
  });

  it('resolves local workspace package root and exported subpath to source files', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-dep-graph-ws-'));
    mkdirSync(join(target, 'packages', 'ui', 'src'), { recursive: true });
    mkdirSync(join(target, 'packages', 'app', 'src'), { recursive: true });
    writeFileSync(join(target, 'packages', 'ui', 'package.json'), JSON.stringify({
      name: '@acme/ui',
      exports: { '.': './src/index.ts', './button': './src/button.ts' },
    }));
    writeFileSync(join(target, 'packages', 'ui', 'src', 'index.ts'), 'export const UI = true;\n');
    writeFileSync(join(target, 'packages', 'ui', 'src', 'button.ts'), 'export const Button = true;\n');
    writeFileSync(join(target, 'packages', 'app', 'src', 'main.ts'),
      "import { UI } from '@acme/ui';\nimport { Button } from '@acme/ui/button';\n");
    writeFileSync(join(target, 'package.json'), JSON.stringify({ name: 'root', private: true }));
    const manifest = {
      target_realpath: realpathSync(target),
      hash: 'c'.repeat(64),
      source_files: [
        'packages/app/src/main.ts',
        'packages/ui/src/button.ts',
        'packages/ui/src/index.ts',
      ],
      units: [
        { id: 'packages/app', files: ['packages/app/src/main.ts'] },
        { id: 'packages/ui', files: ['packages/ui/src/button.ts', 'packages/ui/src/index.ts'] },
      ],
    };
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const rootImport = graph.edges.find(
      (e) => e.from === 'packages/app/src/main.ts' && e.specifier === '@acme/ui',
    );
    expect(rootImport).toBeDefined();
    expect(rootImport!.classification).toBe('local-resolved');
    expect(rootImport!.resolutionKind).toBe('workspace-package');
    expect(rootImport!.resolvedTargets).toContain('packages/ui/src/index.ts');

    const subpathImport = graph.edges.find(
      (e) => e.from === 'packages/app/src/main.ts' && e.specifier === '@acme/ui/button',
    );
    expect(subpathImport).toBeDefined();
    expect(subpathImport!.classification).toBe('local-resolved');
    expect(subpathImport!.resolvedTargets).toContain('packages/ui/src/button.ts');
  });

  it('classifies unknown bare packages as external, not local-unresolved', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-dep-graph-ext-'));
    mkdirSync(join(target, 'src'), { recursive: true });
    writeFileSync(join(target, 'src', 'app.ts'),
      "import express from 'express';\nimport lodash from 'lodash';\n");
    const manifest = {
      target_realpath: realpathSync(target),
      hash: 'd'.repeat(64),
      source_files: ['src/app.ts'],
      units: [{ id: 'src', files: ['src/app.ts'] }],
    };
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const expressEdge = graph.edges.find((e) => e.specifier === 'express');
    expect(expressEdge).toBeDefined();
    expect(expressEdge!.classification).toBe('external');
    const lodashEdge = graph.edges.find((e) => e.specifier === 'lodash');
    expect(lodashEdge).toBeDefined();
    expect(lodashEdge!.classification).toBe('external');
    expect(graph.edges.filter((e) => e.classification === 'local-unresolved')).toHaveLength(0);
  });

  it('resolves Python relative and local absolute imports; external remains external', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-dep-graph-py-'));
    mkdirSync(join(target, 'myapp'), { recursive: true });
    mkdirSync(join(target, 'myapp', 'utils'), { recursive: true });
    writeFileSync(join(target, 'myapp', '__init__.py'), '');
    writeFileSync(join(target, 'myapp', 'utils', '__init__.py'), '');
    writeFileSync(join(target, 'myapp', 'utils', 'helpers.py'), 'def helper(): pass\n');
    writeFileSync(join(target, 'myapp', 'main.py'),
      'from .utils.helpers import helper\nimport myapp.utils.helpers\nimport flask\n');
    const manifest = {
      target_realpath: realpathSync(target),
      hash: 'e'.repeat(64),
      source_files: [
        'myapp/__init__.py',
        'myapp/main.py',
        'myapp/utils/__init__.py',
        'myapp/utils/helpers.py',
      ],
      units: [
        { id: 'myapp', files: ['myapp/__init__.py', 'myapp/main.py', 'myapp/utils/__init__.py', 'myapp/utils/helpers.py'] },
      ],
    };
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const relImport = graph.edges.find(
      (e) => e.from === 'myapp/main.py' && e.specifier === '.utils.helpers',
    );
    expect(relImport).toBeDefined();
    expect(relImport!.classification).toBe('local-resolved');
    expect(relImport!.resolutionKind).toBe('python-relative');

    const absImport = graph.edges.find(
      (e) => e.from === 'myapp/main.py' && e.specifier === 'myapp.utils.helpers',
    );
    expect(absImport).toBeDefined();
    expect(absImport!.classification).toBe('local-resolved');
    expect(absImport!.resolutionKind).toBe('python-local-absolute');

    const flaskImport = graph.edges.find(
      (e) => e.from === 'myapp/main.py' && e.specifier === 'flask',
    );
    expect(flaskImport).toBeDefined();
    expect(flaskImport!.classification).toBe('external');
  });

  it('resolves Rust crate::, super::, and mod name; external crate remains external', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-dep-graph-rs-'));
    mkdirSync(join(target, 'src'), { recursive: true });
    mkdirSync(join(target, 'src', 'handlers'), { recursive: true });
    writeFileSync(join(target, 'Cargo.toml'), '[package]\nname = "myapp"\n');
    writeFileSync(join(target, 'src', 'lib.rs'),
      'mod handlers;\nuse crate::handlers::api;\n');
    writeFileSync(join(target, 'src', 'handlers', 'mod.rs'),
      'mod api;\nuse super::lib;\nuse serde::Deserialize;\n');
    writeFileSync(join(target, 'src', 'handlers', 'api.rs'),
      'use crate::handlers::api;\nuse super::api;\n');
    const manifest = {
      target_realpath: realpathSync(target),
      hash: 'f'.repeat(64),
      source_files: [
        'src/handlers/api.rs',
        'src/handlers/mod.rs',
        'src/lib.rs',
      ],
      units: [
        { id: 'src', files: ['src/handlers/api.rs', 'src/handlers/mod.rs', 'src/lib.rs'] },
      ],
    };
    const graph = createDependencyGraph({ target, sourceManifest: manifest });

    const modDecl = graph.edges.find(
      (e) => e.from === 'src/lib.rs' && e.specifier === 'mod:handlers',
    );
    expect(modDecl).toBeDefined();
    expect(modDecl!.classification).toBe('local-resolved');
    expect(modDecl!.resolutionKind).toBe('rust-mod-decl');

    const crateUse = graph.edges.find(
      (e) => e.from === 'src/lib.rs' && e.specifier === 'crate::handlers::api',
    );
    expect(crateUse).toBeDefined();
    expect(crateUse!.classification).toBe('local-resolved');
    expect(crateUse!.resolutionKind).toBe('rust-crate-path');

    const serdeEdge = graph.edges.find((e) => e.specifier === 'serde::Deserialize');
    expect(serdeEdge).toBeDefined();
    expect(serdeEdge!.classification).toBe('external');

    const superUse = graph.edges.find(
      (e) => e.from === 'src/handlers/mod.rs' && e.specifier.startsWith('super::'),
    );
    expect(superUse).toBeDefined();
  });

  it('resolves Go local module imports to sorted package files; external remains external', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-dep-graph-go-'));
    mkdirSync(join(target, 'cmd'), { recursive: true });
    mkdirSync(join(target, 'pkg', 'handler'), { recursive: true });
    writeFileSync(join(target, 'go.mod'), 'module github.com/example/myapp\n\ngo 1.21\n');
    writeFileSync(join(target, 'cmd', 'main.go'),
      'package main\n\nimport (\n\t"github.com/example/myapp/pkg/handler"\n\t"fmt"\n)\n');
    writeFileSync(join(target, 'pkg', 'handler', 'handler.go'),
      'package handler\n\nfunc Handle() {}\n');
    writeFileSync(join(target, 'pkg', 'handler', 'utils.go'),
      'package handler\n\nfunc Util() {}\n');
    const manifest = {
      target_realpath: realpathSync(target),
      hash: '1'.repeat(64),
      source_files: [
        'cmd/main.go',
        'pkg/handler/handler.go',
        'pkg/handler/utils.go',
      ],
      units: [
        { id: 'cmd', files: ['cmd/main.go'] },
        { id: 'pkg/handler', files: ['pkg/handler/handler.go', 'pkg/handler/utils.go'] },
      ],
    };
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const localImport = graph.edges.find(
      (e) => e.from === 'cmd/main.go' && e.specifier === 'github.com/example/myapp/pkg/handler',
    );
    expect(localImport).toBeDefined();
    expect(localImport!.classification).toBe('local-resolved');
    expect(localImport!.resolutionKind).toBe('go-local-module');
    expect(localImport!.resolvedTargets).toEqual([
      'pkg/handler/handler.go',
      'pkg/handler/utils.go',
    ]);

    const fmtImport = graph.edges.find((e) => e.specifier === 'fmt');
    expect(fmtImport).toBeDefined();
    expect(fmtImport!.classification).toBe('external');
  });

  it('rejects target traversal in source paths', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-dep-graph-trav-'));
    mkdirSync(join(target, 'src'), { recursive: true });
    writeFileSync(join(target, 'src', 'app.ts'), 'export const x = 1;\n');
    const manifest = {
      target_realpath: realpathSync(target),
      hash: '2'.repeat(64),
      source_files: ['src/app.ts', 'src/../../../etc/passwd'],
      units: [
        { id: 'src', files: ['src/app.ts', 'src/../../../etc/passwd'] },
      ],
    };
    expect(() => createDependencyGraph({ target, sourceManifest: manifest })).toThrow();
  });

  it('produces deterministic hash on re-generation', () => {
    const { target, manifest } = tsFixture();
    const g1 = createDependencyGraph({ target, sourceManifest: manifest });
    const g2 = createDependencyGraph({ target, sourceManifest: manifest });
    const { generatedAt: _ts1, dependencyGraphSha256: h1, ...core1 } = g1;
    const { generatedAt: _ts2, dependencyGraphSha256: h2, ...core2 } = g2;
    expect(testDigest(testStableJson(core1))).toBe(h1);
    expect(testDigest(testStableJson(core2))).toBe(h2);
    expect(h1).toBe(h2);
    expect(testStableJson(core1)).toBe(testStableJson(core2));
  });

  it('fails closed on graph tampering', () => {
    const { target, manifest } = tsFixture();
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    expect(() => assertDependencyGraphIntact(graph)).not.toThrow();

    const tampered = { ...graph, nodes: [...graph.nodes, {
      path: 'src/lib/auth.ts',
      ownerSourceUnitId: 'src/lib',
      language: 'typescript',
      byteCount: 999,
      estimatedTokenCount: 250,
    }] };
    expect(() => assertDependencyGraphIntact(tampered)).toThrow(/hash/);
  });

  it('reports unsupported-language accounting explicitly', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-dep-graph-unsup-'));
    mkdirSync(join(target, 'src'), { recursive: true });
    writeFileSync(join(target, 'src', 'app.ts'), 'export const x = 1;\n');
    writeFileSync(join(target, 'src', 'config.yaml'), 'key: value\n');
    writeFileSync(join(target, 'src', 'styles.css'), 'body { margin: 0; }\n');
    const manifest = {
      target_realpath: realpathSync(target),
      hash: '3'.repeat(64),
      source_files: ['src/app.ts', 'src/config.yaml', 'src/styles.css'],
      units: [
        { id: 'src', files: ['src/app.ts', 'src/config.yaml', 'src/styles.css'] },
      ],
    };
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    expect(graph.metadata.unsupportedFileCount).toBe(2);
    expect(graph.metadata.unsupportedLanguageCounts['yaml']).toBe(1);
    expect(graph.metadata.unsupportedLanguageCounts['css']).toBe(1);
    expect(graph.metadata.supportedParsers).toContain('typescript');
    expect(graph.metadata.disclaimer).toBe(GRAPH_DISCLAIMER);
  });

  it('writes and reads graph with integrity round-trip', () => {
    const { target, manifest } = tsFixture();
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const engagementDir = mkdtempSync(join(tmpdir(), 'nunchi-dep-graph-write-'));
    writeDependencyGraph(engagementDir, graph);
    const raw = readDependencyGraph(engagementDir);
    const restored = assertDependencyGraphIntact(raw);
    expect(restored.dependencyGraphSha256).toBe(graph.dependencyGraphSha256);
  });

  it('produces correct token estimates at default chars-per-token', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-dep-graph-tokens-'));
    mkdirSync(join(target, 'src'), { recursive: true });
    const content = 'x'.repeat(100);
    writeFileSync(join(target, 'src', 'app.ts'), content);
    const manifest = {
      target_realpath: realpathSync(target),
      hash: '4'.repeat(64),
      source_files: ['src/app.ts'],
      units: [{ id: 'src', files: ['src/app.ts'] }],
    };
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const node = graph.nodes.find((n) => n.path === 'src/app.ts')!;
    expect(node.byteCount).toBe(100);
    expect(node.estimatedTokenCount).toBe(Math.ceil(100 / DEFAULT_ESTIMATED_CHARS_PER_TOKEN));
    expect(graph.estimatedCharsPerToken).toBe(DEFAULT_ESTIMATED_CHARS_PER_TOKEN);
  });

  it('validates every local-resolved target exists in node set', () => {
    const { target, manifest } = tsFixture();
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const nodePathSet = new Set(graph.nodes.map((n) => n.path));
    for (const edge of graph.edges) {
      if (edge.classification === 'local-resolved') {
        for (const t of edge.resolvedTargets) {
          expect(nodePathSet.has(t)).toBe(true);
        }
      }
      if (edge.classification === 'local-unresolved' || edge.classification === 'external') {
        expect(edge.resolvedTargets).toHaveLength(0);
      }
    }
  });
});

describe('OffSec dependency graph — correction fixtures', () => {
  it('F1: resolves alias from referenced tsconfig.app.json with JSONC comments', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-dep-graph-ref-tsconfig-'));
    mkdirSync(join(target, 'src', 'lib'), { recursive: true });
    mkdirSync(join(target, 'src', 'app'), { recursive: true });
    writeFileSync(join(target, 'src', 'lib', 'auth.ts'), 'export const auth = true;\n');
    writeFileSync(join(target, 'src', 'app', 'main.ts'),
      "import { auth } from '@/lib/auth';\nimport { auth as a2 } from '@davinci/lib/auth';\n");
    // Root tsconfig references tsconfig.app.json
    writeFileSync(join(target, 'tsconfig.json'), JSON.stringify({
      references: [{ path: './tsconfig.app.json' }],
    }));
    // tsconfig.app.json with JSONC comments
    writeFileSync(join(target, 'tsconfig.app.json'), [
      '// This is a JSONC config',
      '{',
      '  /* compiler settings */',
      '  "compilerOptions": {',
      '    "baseUrl": ".",',
      '    "paths": {',
      '      "@/*": ["src/*"],',
      '      "@davinci/*": ["src/*"]',
      '    }',
      '  },',
      '  "include": ["src/**/*"]',
      '}',
    ].join('\n'));
    const manifest = {
      target_realpath: realpathSync(target),
      hash: 'f1'.repeat(32),
      source_files: ['src/app/main.ts', 'src/lib/auth.ts'],
      units: [
        { id: 'src/app', files: ['src/app/main.ts'] },
        { id: 'src/lib', files: ['src/lib/auth.ts'] },
      ],
    };
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const atEdge = graph.edges.find(
      (e) => e.from === 'src/app/main.ts' && e.specifier === '@/lib/auth',
    );
    expect(atEdge).toBeDefined();
    expect(atEdge!.classification).toBe('local-resolved');
    expect(atEdge!.resolvedTargets).toEqual(['src/lib/auth.ts']);

    const davinciEdge = graph.edges.find(
      (e) => e.from === 'src/app/main.ts' && e.specifier === '@davinci/lib/auth',
    );
    expect(davinciEdge).toBeDefined();
    expect(davinciEdge!.classification).toBe('local-resolved');
    expect(davinciEdge!.resolvedTargets).toEqual(['src/lib/auth.ts']);
  });

  it('F2: resolves Go imports against nearest parent go.mod per source file', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-dep-graph-nested-gomod-'));
    mkdirSync(join(target, 'account-pool-server', 'pkg', 'handler'), { recursive: true });
    mkdirSync(join(target, 'account-pool-server', 'cmd'), { recursive: true });
    mkdirSync(join(target, 'cmd'), { recursive: true });
    // Root go.mod (different module)
    writeFileSync(join(target, 'go.mod'), 'module github.com/example/root\n\ngo 1.21\n');
    writeFileSync(join(target, 'cmd', 'main.go'),
      'package main\n\nimport "github.com/example/root/cmd/util"\n');
    // Nested go.mod
    writeFileSync(join(target, 'account-pool-server', 'go.mod'),
      'module github.com/example/account-pool\n\ngo 1.21\n');
    writeFileSync(join(target, 'account-pool-server', 'cmd', 'main.go'),
      'package main\n\nimport "github.com/example/account-pool/pkg/handler"\n');
    writeFileSync(join(target, 'account-pool-server', 'pkg', 'handler', 'handler.go'),
      'package handler\n\nfunc Handle() {}\n');
    const manifest = {
      target_realpath: realpathSync(target),
      hash: 'f2'.repeat(32),
      source_files: [
        'account-pool-server/cmd/main.go',
        'account-pool-server/pkg/handler/handler.go',
        'cmd/main.go',
      ],
      units: [
        { id: 'account-pool-server/cmd', files: ['account-pool-server/cmd/main.go'] },
        { id: 'account-pool-server/pkg/handler', files: ['account-pool-server/pkg/handler/handler.go'] },
        { id: 'cmd', files: ['cmd/main.go'] },
      ],
    };
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    // Nested go.mod resolves correctly
    const nestedImport = graph.edges.find(
      (e) => e.from === 'account-pool-server/cmd/main.go' &&
             e.specifier === 'github.com/example/account-pool/pkg/handler',
    );
    expect(nestedImport).toBeDefined();
    expect(nestedImport!.classification).toBe('local-resolved');
    expect(nestedImport!.resolvedTargets).toEqual(['account-pool-server/pkg/handler/handler.go']);
    // Root cmd/main.go import is unresolved (no matching dir in root module)
    const rootImport = graph.edges.find(
      (e) => e.from === 'cmd/main.go' && e.specifier === 'github.com/example/root/cmd/util',
    );
    expect(rootImport).toBeDefined();
    expect(rootImport!.classification).toBe('local-unresolved');
  });

  it('Rust: handles repeated super::super:: and brace forms', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-dep-graph-rust-super-'));
    mkdirSync(join(target, 'src', 'net', 'handlers'), { recursive: true });
    writeFileSync(join(target, 'Cargo.toml'), '[package]\nname = "myapp"\n');
    writeFileSync(join(target, 'src', 'lib.rs'), 'mod net;\n');
    writeFileSync(join(target, 'src', 'net', 'mod.rs'), 'mod handlers;\npub fn shell_quote() {}\npub struct SshConnection;\n');
    writeFileSync(join(target, 'src', 'net', 'handlers', 'mod.rs'),
      'use super::super::net;\nuse super::{shell_quote, SshConnection};\nuse crate::net as net_alias;\n');
    const manifest = {
      target_realpath: realpathSync(target),
      hash: 'r1'.repeat(32),
      source_files: [
        'src/lib.rs',
        'src/net/handlers/mod.rs',
        'src/net/mod.rs',
      ],
      units: [{ id: 'src', files: ['src/lib.rs', 'src/net/handlers/mod.rs', 'src/net/mod.rs'] }],
    };
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    // super::super::net from src/net/handlers/mod.rs should resolve to src/net (mod.rs or net.rs)
    const superSuperEdge = graph.edges.find(
      (e) => e.from === 'src/net/handlers/mod.rs' && e.specifier === 'super::super::net',
    );
    expect(superSuperEdge).toBeDefined();
    expect(superSuperEdge!.classification).toBe('local-resolved');
    expect(superSuperEdge!.resolvedTargets).toContain('src/net/mod.rs');

    // Brace form: super::{shell_quote, SshConnection} expands to two separate edges
    const braceEdge1 = graph.edges.find(
      (e) => e.from === 'src/net/handlers/mod.rs' && e.specifier === 'super::shell_quote',
    );
    expect(braceEdge1).toBeDefined();
    // super::shell_quote from handlers/mod.rs resolves via rustModuleDir(handlers/mod.rs)=net/handlers,
    // parent=net, then searches net/shell_quote.rs or net/shell_quote/mod.rs.
    // Since shell_quote is a function in net/mod.rs (not a separate file), this is local-unresolved.
    expect(braceEdge1!.classification).toMatch(/local-/);
    const braceEdge2 = graph.edges.find(
      (e) => e.from === 'src/net/handlers/mod.rs' && e.specifier === 'super::SshConnection',
    );
    expect(braceEdge2).toBeDefined();
    expect(braceEdge2!.classification).toMatch(/local-/);

    // crate::net as net_alias — alias form with `as`
    const aliasEdge = graph.edges.find(
      (e) => e.from === 'src/net/handlers/mod.rs' && e.specifier === 'crate::net',
    );
    expect(aliasEdge).toBeDefined();
    expect(aliasEdge!.classification).toBe('local-resolved');
    expect(aliasEdge!.resolvedTargets).toContain('src/net/mod.rs');
  });

  it('fails closed on duplicate source paths', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-dep-graph-dup-'));
    mkdirSync(join(target, 'src'), { recursive: true });
    writeFileSync(join(target, 'src', 'app.ts'), 'export const x = 1;\n');
    const manifest = {
      target_realpath: realpathSync(target),
      hash: 'dd'.repeat(32),
      source_files: ['src/app.ts', 'src/app.ts'],
      units: [{ id: 'src', files: ['src/app.ts'] }],
    };
    expect(() => createDependencyGraph({ target, sourceManifest: manifest })).toThrow(/중복/);
  });

  it('fails closed on missing source file', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-dep-graph-missing-'));
    mkdirSync(join(target, 'src'), { recursive: true });
    writeFileSync(join(target, 'src', 'app.ts'), 'export const x = 1;\n');
    const manifest = {
      target_realpath: realpathSync(target),
      hash: 'mm'.repeat(32),
      source_files: ['src/app.ts', 'src/missing.ts'],
      units: [{ id: 'src', files: ['src/app.ts', 'src/missing.ts'] }],
    };
    expect(() => createDependencyGraph({ target, sourceManifest: manifest })).toThrow(/없다/);
  });

  it('assertDependencyGraphIntact fails on duplicate nodes', () => {
    const { target, manifest } = tsFixture();
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    // Inject duplicate node
    const tampered = JSON.parse(JSON.stringify(graph));
    tampered.nodes.push(tampered.nodes[0]);
    // Rehash to bypass hash check
    const { dependencyGraphSha256: _, generatedAt: __, ...core } = tampered;
    tampered.dependencyGraphSha256 = testDigest(testStableJson(core));
    expect(() => assertDependencyGraphIntact(tampered)).toThrow(/중복|정렬/);
  });

  it('assertDependencyGraphIntact fails on out-of-order edges', () => {
    const { target, manifest } = tsFixture();
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const tampered = JSON.parse(JSON.stringify(graph));
    if (tampered.edges.length >= 2) {
      // Reverse edges
      tampered.edges.reverse();
      const { dependencyGraphSha256: _, generatedAt: __, ...core } = tampered;
      tampered.dependencyGraphSha256 = testDigest(testStableJson(core));
      expect(() => assertDependencyGraphIntact(tampered)).toThrow(/정렬/);
    }
  });

  it('JSONC strip handles trailing commas and block comments', async () => {
    const { stripJsonc } = await import('../workflow/offsec-dependency-graph.js');
    const input = '{\n  // comment\n  "a": 1, /* block */\n  "b": 2,\n}';
    const result = JSON.parse(stripJsonc(input));
    expect(result).toEqual({ a: 1, b: 2 });
  });

  it('Go resolver rejects prefix collision — modulePath is prefix of another module', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-dep-graph-go-prefix-'));
    mkdirSync(join(target, 'cmd'), { recursive: true });
    mkdirSync(join(target, 'pkg', 'api'), { recursive: true });
    writeFileSync(join(target, 'go.mod'), 'module github.com/example/app\n\ngo 1.21\n');
    // Import "github.com/example/app-worker/pkg" should be external, not local —
    // "github.com/example/app" is a prefix but not an exact match or exact + '/'
    writeFileSync(join(target, 'cmd', 'main.go'),
      'package main\n\nimport (\n\t"github.com/example/app-worker/pkg"\n\t"github.com/example/app/pkg/api"\n)\n');
    writeFileSync(join(target, 'pkg', 'api', 'handler.go'), 'package api\n\nfunc Handle() {}\n');
    const manifest = {
      target_realpath: realpathSync(target),
      hash: 'gp'.repeat(32),
      source_files: ['cmd/main.go', 'pkg/api/handler.go'],
      units: [
        { id: 'cmd', files: ['cmd/main.go'] },
        { id: 'pkg/api', files: ['pkg/api/handler.go'] },
      ],
    };
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    // The colliding prefix should be external
    const collisionEdge = graph.edges.find(
      (e) => e.specifier === 'github.com/example/app-worker/pkg',
    );
    expect(collisionEdge).toBeDefined();
    expect(collisionEdge!.classification).toBe('external');
    // The exact module + subpath should still resolve
    const localEdge = graph.edges.find(
      (e) => e.specifier === 'github.com/example/app/pkg/api',
    );
    expect(localEdge).toBeDefined();
    expect(localEdge!.classification).toBe('local-resolved');
  });

  it('Go resolver resolves exact module-root import to sorted non-test .go files in modDir', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-dep-graph-go-root-'));
    mkdirSync(join(target, 'cmd'), { recursive: true });
    writeFileSync(join(target, 'go.mod'), 'module github.com/example/lib\n\ngo 1.21\n');
    writeFileSync(join(target, 'cmd', 'main.go'),
      'package main\n\nimport "github.com/example/lib"\n');
    writeFileSync(join(target, 'lib.go'), 'package lib\n\nfunc Init() {}\n');
    writeFileSync(join(target, 'helper.go'), 'package lib\n\nfunc Help() {}\n');
    writeFileSync(join(target, 'lib_test.go'), 'package lib\n\nfunc TestInit(t *testing.T) {}\n');
    const manifest = {
      target_realpath: realpathSync(target),
      hash: 'gr'.repeat(32),
      source_files: ['cmd/main.go', 'helper.go', 'lib.go', 'lib_test.go'],
      units: [
        { id: 'cmd', files: ['cmd/main.go'] },
        { id: 'root', files: ['helper.go', 'lib.go', 'lib_test.go'] },
      ],
    };
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const rootImport = graph.edges.find(
      (e) => e.from === 'cmd/main.go' && e.specifier === 'github.com/example/lib',
    );
    expect(rootImport).toBeDefined();
    expect(rootImport!.classification).toBe('local-resolved');
    expect(rootImport!.resolutionKind).toBe('go-local-module');
    // Should resolve to non-test files only, sorted
    expect(rootImport!.resolvedTargets).toEqual(['helper.go', 'lib.go']);
  });

  it('JS/TS edge language equals source node language, not hardcoded javascript', () => {
    const { target, manifest } = tsFixture();
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    // login.tsx is typescript
    const loginEdge = graph.edges.find(
      (e) => e.from === 'src/components/login.tsx' && e.specifier === '../lib/auth',
    );
    expect(loginEdge).toBeDefined();
    expect(loginEdge!.language).toBe('typescript');
    // Verify the node is actually typescript
    const loginNode = graph.nodes.find((n) => n.path === 'src/components/login.tsx');
    expect(loginNode!.language).toBe('typescript');
  });

  it('assertDependencyGraphIntact rejects tampered edge language inconsistent with source node', () => {
    const { target, manifest } = tsFixture();
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const tampered = JSON.parse(JSON.stringify(graph));
    // Tamper an edge language to differ from node language
    if (tampered.edges.length > 0) {
      tampered.edges[0].language = 'python';
      const { dependencyGraphSha256: _, generatedAt: __, ...core } = tampered;
      tampered.dependencyGraphSha256 = testDigest(testStableJson(core));
      expect(() => assertDependencyGraphIntact(tampered)).toThrow(/language.*source node/);
    }
  });

  it('assertDependencyGraphIntact rejects tampered metadata unsupported counts', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-dep-graph-meta-'));
    mkdirSync(join(target, 'src'), { recursive: true });
    writeFileSync(join(target, 'src', 'app.ts'), 'export const x = 1;\n');
    writeFileSync(join(target, 'src', 'config.yaml'), 'key: value\n');
    const manifest = {
      target_realpath: realpathSync(target),
      hash: 'mt'.repeat(32),
      source_files: ['src/app.ts', 'src/config.yaml'],
      units: [{ id: 'src', files: ['src/app.ts', 'src/config.yaml'] }],
    };
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    // Tamper unsupportedFileCount
    const tampered = JSON.parse(JSON.stringify(graph));
    tampered.metadata.unsupportedFileCount = 99;
    const { dependencyGraphSha256: _, generatedAt: __, ...core } = tampered;
    tampered.dependencyGraphSha256 = testDigest(testStableJson(core));
    expect(() => assertDependencyGraphIntact(tampered)).toThrow(/unsupportedFileCount/);
  });

  it('assertDependencyGraphIntact rejects unsorted resolvedTargets', () => {
    const { target, manifest } = tsFixture();
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const tampered = JSON.parse(JSON.stringify(graph));
    // Find an edge with resolvedTargets and reverse them
    const edgeWithTargets = tampered.edges.find((e: { resolvedTargets: string[] }) => e.resolvedTargets.length > 1);
    if (edgeWithTargets) {
      edgeWithTargets.resolvedTargets.reverse();
      const { dependencyGraphSha256: _, generatedAt: __, ...core } = tampered;
      tampered.dependencyGraphSha256 = testDigest(testStableJson(core));
      expect(() => assertDependencyGraphIntact(tampered)).toThrow(/정렬.*중복/);
    }
  });

  it('assertDependencyGraphIntact enforces one edge per from+specifier', () => {
    const { target, manifest } = tsFixture();
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const tampered = JSON.parse(JSON.stringify(graph));
    if (tampered.edges.length > 0) {
      // Duplicate first edge with different classification
      const dup = { ...tampered.edges[0], classification: 'external', resolvedTargets: [] };
      tampered.edges.push(dup);
      tampered.edges.sort((a: { from: string; specifier: string; classification: string },
                           b: { from: string; specifier: string; classification: string }) =>
        `${a.from}|${a.specifier}|${a.classification}`.localeCompare(
          `${b.from}|${b.specifier}|${b.classification}`));
      const { dependencyGraphSha256: _, generatedAt: __, ...core } = tampered;
      tampered.dependencyGraphSha256 = testDigest(testStableJson(core));
      expect(() => assertDependencyGraphIntact(tampered)).toThrow(/동일 from\+specifier/);
    }
  });

  it('assertDependencyGraphIntact enforces deterministic supportedParsers', () => {
    const { target, manifest } = tsFixture();
    const graph = createDependencyGraph({ target, sourceManifest: manifest });
    const tampered = JSON.parse(JSON.stringify(graph));
    tampered.metadata.supportedParsers = ['python', 'go', 'rust', 'javascript', 'typescript'];
    const { dependencyGraphSha256: _, generatedAt: __, ...core } = tampered;
    tampered.dependencyGraphSha256 = testDigest(testStableJson(core));
    expect(() => assertDependencyGraphIntact(tampered)).toThrow(/supportedParsers.*표준/);
  });

  it('createDependencyGraph rejects unit files not in source_files', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-dep-graph-unit-nosrc-'));
    mkdirSync(join(target, 'src'), { recursive: true });
    writeFileSync(join(target, 'src', 'app.ts'), 'export const x = 1;\n');
    writeFileSync(join(target, 'src', 'extra.ts'), 'export const y = 2;\n');
    const manifest = {
      target_realpath: realpathSync(target),
      hash: 'un'.repeat(32),
      source_files: ['src/app.ts'], // extra.ts missing from source_files
      units: [{ id: 'src', files: ['src/app.ts', 'src/extra.ts'] }],
    };
    expect(() => createDependencyGraph({ target, sourceManifest: manifest })).toThrow(/source_files에 없다/);
  });

  it('createDependencyGraph rejects duplicate unit IDs', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-dep-graph-dupid-'));
    mkdirSync(join(target, 'src'), { recursive: true });
    writeFileSync(join(target, 'src', 'a.ts'), 'export const a = 1;\n');
    writeFileSync(join(target, 'src', 'b.ts'), 'export const b = 2;\n');
    const manifest = {
      target_realpath: realpathSync(target),
      hash: 'di'.repeat(32),
      source_files: ['src/a.ts', 'src/b.ts'],
      units: [
        { id: 'shared', files: ['src/a.ts'] },
        { id: 'shared', files: ['src/b.ts'] },
      ],
    };
    expect(() => createDependencyGraph({ target, sourceManifest: manifest })).toThrow(/중복 unit ID/);
  });
});
