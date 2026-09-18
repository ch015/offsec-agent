import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, realpathSync, renameSync, writeFileSync } from 'node:fs';
import { basename, dirname, extname, join, relative, resolve, sep } from 'node:path';

import { z } from 'zod';

// ── Shared helpers ─────────────────────────────────────────────────────────

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function digest(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}

function isWithin(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !rel.startsWith('/'));
}

function toPosix(p: string): string {
  return p.split(sep).join('/');
}

/**
 * Shared deterministic edge comparator — used by both generation (sort)
 * and validation (ordering check). Uses codepoint comparison (< / >)
 * for locale-independent determinism.
 */
function edgeKey(edge: { from: string; specifier: string; classification: string }): string {
  return `${edge.from}\0${edge.specifier}\0${edge.classification}`;
}
function compareEdges(
  a: { from: string; specifier: string; classification: string },
  b: { from: string; specifier: string; classification: string },
): number {
  const ka = edgeKey(a);
  const kb = edgeKey(b);
  if (ka < kb) return -1;
  if (ka > kb) return 1;
  return 0;
}

function safeReadFile(target: string, relPath: string): string | null {
  const abs = resolve(target, relPath);
  if (!isWithin(target, abs) || !existsSync(abs)) return null;
  try { return readFileSync(abs, 'utf8'); } catch { return null; }
}

/**
 * Strip JSONC (JSON with Comments) to plain JSON without external dependencies.
 * Strips line comments and block comments outside strings.
 */
function stripJsonc(text: string): string {
  let result = '';
  let i = 0;
  while (i < text.length) {
    // String literal — copy verbatim
    if (text[i] === '"') {
      let j = i + 1;
      while (j < text.length) {
        if (text[j] === '\\') { j += 2; continue; }
        if (text[j] === '"') { j++; break; }
        j++;
      }
      result += text.slice(i, j);
      i = j;
      continue;
    }
    // Line comment
    if (text[i] === '/' && text[i + 1] === '/') {
      i += 2;
      while (i < text.length && text[i] !== '\n') i++;
      continue;
    }
    // Block comment
    if (text[i] === '/' && text[i + 1] === '*') {
      i += 2;
      while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i++;
      i += 2;
      continue;
    }
    result += text[i]!;
    i++;
  }
  // Strip trailing commas before } or ]
  return result.replace(/,\s*([}\]])/g, '$1');
}

function safeReadJsonc(target: string, relPath: string): unknown {
  const text = safeReadFile(target, relPath);
  if (text === null) return null;
  try { return JSON.parse(stripJsonc(text)); } catch { return null; }
}

// ── Schemas ────────────────────────────────────────────────────────────────

const Sha256Schema = z.string().regex(/^[a-f0-9]{64}$/);
const RelativePathSchema = z.string().min(1).refine((value) => {
  if (value.includes('\0') || value.includes('\\')) return false;
  if (value.startsWith('/')) return false;
  const segments = value.split('/');
  return segments.every((s) => s !== '' && s !== '.' && s !== '..');
});

export const DEFAULT_ESTIMATED_CHARS_PER_TOKEN = 4;
export const GRAPH_DISCLAIMER =
  'This dependency graph is a syntactic planning aid. ' +
  'It is not semantic or security-analysis completeness evidence.';

const GraphNodeSchema = z.object({
  path: RelativePathSchema,
  ownerSourceUnitId: z.string().min(1),
  language: z.string().min(1),
  byteCount: z.number().int().nonnegative(),
  estimatedTokenCount: z.number().int().nonnegative(),
}).strict();

const GraphEdgeSchema = z.object({
  from: RelativePathSchema,
  specifier: z.string().min(1),
  language: z.string().min(1),
  classification: z.enum(['local-resolved', 'local-unresolved', 'external']),
  resolutionKind: z.string().min(1),
  resolvedTargets: z.array(RelativePathSchema),
}).strict();

const GraphMetadataSchema = z.object({
  supportedParsers: z.array(z.string()),
  unsupportedFileCount: z.number().int().nonnegative(),
  unsupportedLanguageCounts: z.record(z.string(), z.number().int().nonnegative()),
  disclaimer: z.literal(GRAPH_DISCLAIMER),
}).strict();

export const DependencyGraphSchema = z.object({
  version: z.literal('1.0.0'),
  estimatedCharsPerToken: z.number().int().positive(),
  nodes: z.array(GraphNodeSchema),
  edges: z.array(GraphEdgeSchema),
  metadata: GraphMetadataSchema,
  generatedAt: z.string().datetime(),
  dependencyGraphSha256: Sha256Schema,
}).strict();

export type DependencyGraph = z.infer<typeof DependencyGraphSchema>;
export type GraphNode = z.infer<typeof GraphNodeSchema>;
export type GraphEdge = z.infer<typeof GraphEdgeSchema>;

// ── Language detection ─────────────────────────────────────────────────────

const SUPPORTED_LANGUAGES = new Set(['javascript', 'typescript', 'python', 'rust', 'go']);
const LANGUAGE_MAP: Record<string, string> = {
  '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
  '.ts': 'typescript', '.tsx': 'typescript',
  '.py': 'python',
  '.rs': 'rust',
  '.go': 'go',
  '.java': 'java', '.kt': 'kotlin', '.kts': 'kotlin',
  '.rb': 'ruby',
  '.c': 'c', '.h': 'c-header',
  '.cpp': 'cpp', '.hpp': 'cpp-header', '.cc': 'cpp', '.cxx': 'cpp',
  '.cs': 'csharp',
  '.swift': 'swift',
  '.php': 'php',
  '.scala': 'scala',
  '.ex': 'elixir', '.exs': 'elixir',
  '.sh': 'shell', '.bash': 'shell', '.zsh': 'shell',
  '.yaml': 'yaml', '.yml': 'yaml',
  '.json': 'json', '.toml': 'toml',
  '.md': 'markdown', '.mdx': 'markdown',
  '.sql': 'sql', '.graphql': 'graphql', '.gql': 'graphql',
  '.html': 'html', '.htm': 'html', '.css': 'css', '.scss': 'scss',
};

function detectLanguage(filePath: string): string {
  const ext = extname(filePath).toLowerCase();
  return LANGUAGE_MAP[ext] ?? 'unknown';
}

// ── Config readers ─────────────────────────────────────────────────────────

type TsPathConfig = {
  baseUrl: string | undefined;
  paths: Record<string, string[]>;
  configDir: string;
  /** Include patterns from tsconfig — determines source applicability */
  include: string[] | undefined;
};

type TsConfigWithReferences = {
  /** Main config (may have paths/baseUrl from own or extended tsconfig) */
  configs: TsPathConfig[];
};

/**
 * Read tsconfig.json, follow `extends`, and follow root `references` to
 * referenced configs (e.g. tsconfig.app.json). Each referenced config carries
 * its own include/paths so that aliases apply only to files matching that config's
 * include patterns, preventing leakage into unrelated nested template/projects.
 */
function readTsConfigWithReferences(target: string): TsConfigWithReferences {
  const configs: TsPathConfig[] = [];
  const seen = new Set<string>();

  function read(configRelPath: string): TsPathConfig | null {
    const configPath = resolve(target, configRelPath);
    if (!isWithin(target, configPath) || seen.has(configPath)) return null;
    seen.add(configPath);
    const raw = safeReadJsonc(target, configRelPath) as {
      extends?: string;
      compilerOptions?: { baseUrl?: string; paths?: Record<string, string[]> };
      references?: Array<{ path: string }>;
      include?: string[];
    } | null;
    if (!raw || typeof raw !== 'object') return null;
    const configDir = toPosix(dirname(configRelPath));
    let result: TsPathConfig = {
      baseUrl: raw.compilerOptions?.baseUrl,
      paths: raw.compilerOptions?.paths ?? {},
      configDir,
      include: Array.isArray(raw.include) ? raw.include : undefined,
    };
    if (typeof raw.extends === 'string') {
      const extendedRel = toPosix(relative(target, resolve(target, configDir, raw.extends)));
      const extendedTsConfig = extendedRel.endsWith('.json') ? extendedRel : `${extendedRel}.json`;
      const parent = read(existsSync(resolve(target, extendedTsConfig)) ? extendedTsConfig : extendedRel);
      if (parent) {
        result = {
          baseUrl: result.baseUrl ?? parent.baseUrl,
          paths: { ...parent.paths, ...result.paths },
          configDir: result.configDir,
          include: result.include ?? parent.include,
        };
      }
    }
    // Follow root references only from the root tsconfig
    if (configRelPath === 'tsconfig.json' && Array.isArray(raw.references)) {
      for (const ref of raw.references) {
        if (ref && typeof ref.path === 'string') {
          const refRel = toPosix(relative(target, resolve(target, configDir, ref.path)));
          const refPath = refRel.endsWith('.json') ? refRel : `${refRel}/tsconfig.json`;
          const refConfig = read(refPath);
          if (refConfig && (Object.keys(refConfig.paths).length > 0 || refConfig.baseUrl)) {
            configs.push(refConfig);
          }
        }
      }
    }
    return result;
  }

  const root = read('tsconfig.json');
  if (root) {
    configs.unshift(root);
  }
  return { configs };
}

/**
 * Check if a source file is covered by a tsconfig's include patterns.
 * Uses simple glob matching: src/** matches src/anything/deep.
 */
function fileMatchesInclude(filePath: string, config: TsPathConfig): boolean {
  if (!config.include) return true; // no include means global
  const fileRelToConfig = config.configDir === '.'
    ? filePath
    : (filePath.startsWith(`${config.configDir}/`) ? filePath.slice(config.configDir.length + 1) : filePath);
  for (const pattern of config.include) {
    if (simpleGlobMatch(pattern, fileRelToConfig) || simpleGlobMatch(pattern, filePath)) {
      return true;
    }
  }
  return false;
}

function simpleGlobMatch(pattern: string, path: string): boolean {
  // Handle common tsconfig include patterns: "src/**/*", "src", "**/*.ts"
  const normalized = pattern.replace(/\\/g, '/');
  if (normalized === path) return true;
  if (normalized.endsWith('/**/*') || normalized.endsWith('/**')) {
    const prefix = normalized.replace(/\/\*\*\/?(\*)?$/, '');
    return path.startsWith(`${prefix}/`) || path === prefix;
  }
  if (normalized.includes('*')) {
    const re = new RegExp('^' + normalized
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*\*/g, '§§')
      .replace(/\*/g, '[^/]*')
      .replace(/§§/g, '.*') + '$');
    return re.test(path);
  }
  return path.startsWith(`${normalized}/`);
}

/**
 * Given a source file path, find the applicable TsPathConfig from referenced configs.
 * Returns the most specific matching config (by include patterns), or the root config.
 */
function findApplicableTsConfig(filePath: string, tsConfigs: TsConfigWithReferences): TsPathConfig | null {
  if (tsConfigs.configs.length === 0) return null;
  // Try referenced configs (non-root) first — they have more specific include patterns
  for (let i = 1; i < tsConfigs.configs.length; i++) {
    const cfg = tsConfigs.configs[i]!;
    if (cfg.include && fileMatchesInclude(filePath, cfg)) return cfg;
  }
  // Fallback to root
  return tsConfigs.configs[0] ?? null;
}

type WorkspacePackage = {
  name: string;
  root: string;
  entryPoints: Map<string, string[]>;
};

function readWorkspacePackages(target: string, sealedFiles: ReadonlySet<string>): Map<string, WorkspacePackage> {
  const registry = new Map<string, WorkspacePackage>();
  const visited = new Set<string>();
  function walk(dir: string): void {
    const abs = resolve(target, dir);
    if (!isWithin(target, abs) || visited.has(abs)) return;
    visited.add(abs);
    const pkgJsonRel = dir === '.' ? 'package.json' : `${dir}/package.json`;
    const raw = safeReadJsonc(target, pkgJsonRel) as {
      name?: string;
      exports?: Record<string, unknown>;
      types?: string;
      module?: string;
      main?: string;
    } | null;
    if (raw && typeof raw.name === 'string' && raw.name.length > 0) {
      const entryPoints = new Map<string, string[]>();
      if (raw.exports && typeof raw.exports === 'object') {
        for (const [subpath, target_] of Object.entries(raw.exports)) {
          const candidates = resolveExportTarget(target_, dir, sealedFiles, target);
          if (candidates.length > 0) entryPoints.set(subpath, candidates);
        }
      }
      if (!entryPoints.has('.')) {
        const fallback = resolveFallbackEntryPoint(raw, dir, sealedFiles, target);
        if (fallback.length > 0) entryPoints.set('.', fallback);
      }
      registry.set(raw.name, { name: raw.name, root: dir, entryPoints });
    }
    let entries: string[];
    try {
      entries = readdirSync(abs, { withFileTypes: true })
        .filter((e) => e.isDirectory() && !e.isSymbolicLink())
        .filter((e) => !['node_modules', '.git', 'dist', 'build', 'coverage', '.next', '.cache', 'target'].includes(e.name))
        .map((e) => e.name);
    } catch { return; }
    for (const entry of entries) {
      walk(dir === '.' ? entry : `${dir}/${entry}`);
    }
  }
  walk('.');
  return registry;
}

function resolveExportTarget(value: unknown, pkgRoot: string, sealedFiles: ReadonlySet<string>, target: string): string[] {
  if (typeof value === 'string') {
    return resolveEntryToSealedFiles(value, pkgRoot, sealedFiles, target);
  }
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const obj = value as Record<string, unknown>;
    for (const key of ['types', 'import', 'require', 'default']) {
      if (typeof obj[key] === 'string') {
        const found = resolveEntryToSealedFiles(obj[key] as string, pkgRoot, sealedFiles, target);
        if (found.length > 0) return found;
      }
    }
  }
  return [];
}

function resolveEntryToSealedFiles(entry: string, pkgRoot: string, sealedFiles: ReadonlySet<string>, target: string): string[] {
  const rel = toPosix(relative(target, resolve(target, pkgRoot, entry)));
  if (sealedFiles.has(rel)) return [rel];
  const sourceEquivalents = [
    rel.replace(/^dist\//, 'src/').replace(/\.(?:js|mjs|cjs|d\.ts)$/, '.ts'),
    rel.replace(/^dist\//, 'src/').replace(/\.(?:js|mjs|cjs|d\.ts)$/, '.tsx'),
    rel.replace(/\.(?:js|mjs|cjs)$/, '.ts'),
    rel.replace(/\.(?:js|mjs|cjs)$/, '.tsx'),
  ];
  for (const candidate of sourceEquivalents) {
    if (sealedFiles.has(candidate)) return [candidate];
  }
  for (const ext of ['.ts', '.tsx', '.js', '.jsx']) {
    const idx = `${pkgRoot === '.' ? '' : `${pkgRoot}/`}src/index${ext}`;
    if (sealedFiles.has(idx)) return [idx];
  }
  for (const ext of ['.ts', '.tsx', '.js', '.jsx']) {
    const idx = `${pkgRoot === '.' ? '' : `${pkgRoot}/`}index${ext}`;
    if (sealedFiles.has(idx)) return [idx];
  }
  return [];
}

function resolveFallbackEntryPoint(
  raw: { types?: string; module?: string; main?: string },
  pkgRoot: string,
  sealedFiles: ReadonlySet<string>,
  target: string,
): string[] {
  for (const field of [raw.types, raw.module, raw.main]) {
    if (typeof field === 'string') {
      const found = resolveEntryToSealedFiles(field, pkgRoot, sealedFiles, target);
      if (found.length > 0) return found;
    }
  }
  return [];
}

/**
 * Find the nearest go.mod for a given Go source file and return its module path
 * and the directory relative path (relative to target root) it lives in.
 */
function findNearestGoMod(filePath: string, target: string): { modulePath: string; modDir: string } | null {
  let dir = dirname(filePath);
  const seen = new Set<string>();
  while (dir && !seen.has(dir)) {
    seen.add(dir);
    const goModPath = dir === '.' ? 'go.mod' : `${dir}/go.mod`;
    const content = safeReadFile(target, goModPath);
    if (content) {
      const match = /^module\s+(\S+)/m.exec(content);
      if (match?.[1]) return { modulePath: match[1], modDir: dir };
    }
    if (dir === '.') break;
    dir = dirname(dir);
  }
  return null;
}

type CrateRoot = { cargoDir: string; srcDir: string };

function findCrateRoot(filePath: string, target: string): CrateRoot | null {
  let dir = dirname(filePath);
  const seen = new Set<string>();
  while (dir && !seen.has(dir)) {
    seen.add(dir);
    const cargoPath = dir === '.' ? 'Cargo.toml' : `${dir}/Cargo.toml`;
    if (existsSync(resolve(target, cargoPath))) {
      const srcDir = dir === '.' ? 'src' : `${dir}/src`;
      return { cargoDir: dir, srcDir };
    }
    if (dir === '.') break;
    dir = dirname(dir);
  }
  return null;
}

// ── Import specifier extraction ────────────────────────────────────────────

type ExtractedSpecifier = {
  specifier: string;
  language: string;
  kind: string;
};

function extractJsTsSpecifiers(content: string, sourceLanguage: string): ExtractedSpecifier[] {
  const found = new Map<string, ExtractedSpecifier>();
  const add = (specifier: string, kind: string) => {
    const key = `${sourceLanguage}:${specifier}`;
    if (!found.has(key)) found.set(key, { specifier, language: sourceLanguage, kind });
  };
  const patterns = [
    /\b(?:import|export)\s+(?:[\s\S]*?\s+from\s+)?['"]([^'"]+)['"]/g,
    /\brequire\(\s*['"]([^'"]+)['"]\s*\)/g,
    /\bimport\(\s*['"]([^'"]+)['"]\s*\)/g,
  ];
  for (const pattern of patterns) {
    for (const match of content.matchAll(pattern)) {
      if (match[1]) {
        const kind = match[1].startsWith('.') ? 'relative' : 'non-relative';
        add(match[1], kind);
      }
    }
  }
  return [...found.values()].sort((a, b) => a.specifier.localeCompare(b.specifier));
}

function extractPythonSpecifiers(content: string): ExtractedSpecifier[] {
  const found = new Map<string, ExtractedSpecifier>();
  const add = (specifier: string, kind: string) => {
    if (!found.has(specifier)) found.set(specifier, { specifier, language: 'python', kind });
  };
  for (const match of content.matchAll(/^\s*from\s+([.A-Za-z_][\w.]*)\s+import\s+/gm)) {
    if (match[1]) add(match[1], match[1].startsWith('.') ? 'relative' : 'absolute');
  }
  for (const match of content.matchAll(/^\s*import\s+([A-Za-z_][\w.]*)/gm)) {
    if (match[1]) add(match[1], 'absolute');
  }
  return [...found.values()].sort((a, b) => a.specifier.localeCompare(b.specifier));
}

function extractRustSpecifiers(content: string): ExtractedSpecifier[] {
  const found = new Map<string, ExtractedSpecifier>();
  const add = (specifier: string, kind: string) => {
    if (!found.has(specifier)) found.set(specifier, { specifier, language: 'rust', kind });
  };

  // Match `use crate::path::to::item;`, `use super::super::item;`,
  // `use self::thing;`, including brace forms `use super::{a, b}`
  // and alias forms `use crate::x as y;`
  const usePattern = /\buse\s+((?:crate|self|super)(?:::\w+|::\{[^}]*\}|::super)*(?:::\w+|::\{[^}]*\})?)/g;
  for (const match of content.matchAll(usePattern)) {
    if (match[1]) {
      const stmt = match[1];
      // Handle brace expansions: use super::{a, b} → super::a, super::b
      const braceMatch = /^((?:crate|self|super)(?:::\w+|::super)*)(?:::)?\{([^}]*)\}$/.exec(stmt);
      if (braceMatch && braceMatch[1] && braceMatch[2]) {
        const prefix = braceMatch[1];
        const items = braceMatch[2].split(',').map((s) => s.trim().replace(/\s+as\s+\w+$/, '')).filter(Boolean);
        for (const item of items) {
          const full = `${prefix}::${item}`;
          const kind = classifyRustPathKind(full);
          add(full, kind);
        }
      } else {
        // Strip `as alias` suffix
        const stripped = stmt.replace(/\s+as\s+\w+$/, '');
        const kind = classifyRustPathKind(stripped);
        add(stripped, kind);
      }
    }
  }

  // Match mod declarations: `mod name;`
  for (const match of content.matchAll(/^\s*mod\s+(\w+)\s*;/gm)) {
    if (match[1]) add(`mod:${match[1]}`, 'mod-decl');
  }

  // External crate use — matches `use something::...` where something is not crate/self/super
  for (const match of content.matchAll(/\buse\s+(\w[\w:]*)/g)) {
    if (match[1] && !match[1].startsWith('crate') && !match[1].startsWith('self') && !match[1].startsWith('super')) {
      // Only add if not already captured as a more specific form
      const key = match[1];
      if (!found.has(key)) add(key, 'external-use');
    }
  }

  return [...found.values()].sort((a, b) => a.specifier.localeCompare(b.specifier));
}

function classifyRustPathKind(path: string): string {
  if (path.startsWith('crate::')) return 'crate-path';
  if (path.startsWith('self::')) return 'self-path';
  if (path.startsWith('super')) return 'super-path';
  return 'external-use';
}

function extractGoSpecifiers(content: string): ExtractedSpecifier[] {
  const found = new Map<string, ExtractedSpecifier>();
  const add = (specifier: string) => {
    if (!found.has(specifier)) found.set(specifier, { specifier, language: 'go', kind: 'import' });
  };
  for (const match of content.matchAll(/import\s+"([^"]+)"/g)) {
    if (match[1]) add(match[1]);
  }
  for (const match of content.matchAll(/import\s+\w+\s+"([^"]+)"/g)) {
    if (match[1]) add(match[1]);
  }
  for (const match of content.matchAll(/import\s+\(([\s\S]*?)\)/g)) {
    if (match[1]) {
      for (const line of match[1].matchAll(/"([^"]+)"/g)) {
        if (line[1]) add(line[1]);
      }
    }
  }
  return [...found.values()].sort((a, b) => a.specifier.localeCompare(b.specifier));
}

function extractSpecifiers(filePath: string, content: string, language: string): ExtractedSpecifier[] {
  switch (language) {
    case 'javascript':
    case 'typescript':
      return extractJsTsSpecifiers(content, language);
    case 'python':
      return extractPythonSpecifiers(content);
    case 'rust':
      return extractRustSpecifiers(content);
    case 'go':
      return extractGoSpecifiers(content);
    default:
      return [];
  }
}

// ── Resolution ─────────────────────────────────────────────────────────────

type ResolveResult = {
  classification: 'local-resolved' | 'local-unresolved' | 'external';
  resolutionKind: string;
  resolvedTargets: string[];
};

const JS_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'];

function resolveJsRelative(from: string, specifier: string, sealedFiles: ReadonlySet<string>): string | undefined {
  const base = toPosix(resolve('/', dirname(from), specifier).slice(1));
  const candidates = [base];
  if (!extname(base)) {
    for (const ext of JS_EXTENSIONS) candidates.push(`${base}${ext}`);
    for (const ext of JS_EXTENSIONS) candidates.push(`${base}/index${ext}`);
  }
  return candidates.find((c) => sealedFiles.has(c));
}

function resolveJsTsSpecifier(
  from: string,
  spec: ExtractedSpecifier,
  sealedFiles: ReadonlySet<string>,
  tsConfigs: TsConfigWithReferences,
  workspacePackages: ReadonlyMap<string, WorkspacePackage>,
): ResolveResult {
  if (spec.kind === 'relative') {
    const resolved = resolveJsRelative(from, spec.specifier, sealedFiles);
    return resolved
      ? { classification: 'local-resolved', resolutionKind: 'relative-import', resolvedTargets: [resolved] }
      : { classification: 'local-unresolved', resolutionKind: 'relative-import', resolvedTargets: [] };
  }

  // Find the applicable tsconfig for this source file
  const tsConfig = findApplicableTsConfig(from, tsConfigs);
  if (tsConfig) {
    for (const [pattern, mappings] of Object.entries(tsConfig.paths)) {
      const starIndex = pattern.indexOf('*');
      if (starIndex === -1) {
        if (spec.specifier === pattern) {
          for (const mapping of mappings) {
            const baseDir = tsConfig.baseUrl
              ? toPosix(relative('.', resolve(tsConfig.configDir, tsConfig.baseUrl)))
              : tsConfig.configDir;
            const resolved = toPosix(resolve('/', baseDir === '.' ? '' : baseDir, mapping).slice(1));
            const found = resolveJsRelative('.', resolved, sealedFiles);
            if (found) return { classification: 'local-resolved', resolutionKind: 'tsconfig-paths', resolvedTargets: [found] };
          }
        }
        continue;
      }
      const prefix = pattern.slice(0, starIndex);
      const suffix = pattern.slice(starIndex + 1);
      if (spec.specifier.startsWith(prefix) && spec.specifier.endsWith(suffix) &&
          spec.specifier.length >= prefix.length + suffix.length) {
        const captured = spec.specifier.slice(prefix.length, spec.specifier.length - suffix.length);
        for (const mapping of mappings) {
          const baseDir = tsConfig.baseUrl
            ? toPosix(relative('.', resolve(tsConfig.configDir, tsConfig.baseUrl)))
            : tsConfig.configDir;
          const mappedPath = mapping.replace('*', captured);
          const resolved = toPosix(resolve('/', baseDir === '.' ? '' : baseDir, mappedPath).slice(1));
          const found = resolveJsRelative('.', resolved, sealedFiles);
          if (found) return { classification: 'local-resolved', resolutionKind: 'tsconfig-paths', resolvedTargets: [found] };
        }
      }
    }
  }

  const pkgParts = parsePackageSpecifier(spec.specifier);
  if (pkgParts) {
    const pkg = workspacePackages.get(pkgParts.name);
    if (pkg) {
      const subpath = pkgParts.subpath ? `./${pkgParts.subpath}` : '.';
      const targets = pkg.entryPoints.get(subpath);
      if (targets && targets.length > 0) {
        return { classification: 'local-resolved', resolutionKind: 'workspace-package', resolvedTargets: [...targets].sort() };
      }
      if (pkgParts.subpath) {
        const subpathBase = `${pkg.root}/${pkgParts.subpath}`;
        const found = resolveJsRelative('.', subpathBase, sealedFiles);
        if (found) return { classification: 'local-resolved', resolutionKind: 'workspace-package', resolvedTargets: [found] };
      }
      return { classification: 'local-unresolved', resolutionKind: 'workspace-package', resolvedTargets: [] };
    }
  }
  return { classification: 'external', resolutionKind: 'bare-specifier', resolvedTargets: [] };
}

function parsePackageSpecifier(specifier: string): { name: string; subpath: string | null } | null {
  if (specifier.startsWith('.') || specifier.startsWith('/')) return null;
  if (specifier.startsWith('@')) {
    const slashIndex = specifier.indexOf('/');
    if (slashIndex === -1) return null;
    const secondSlash = specifier.indexOf('/', slashIndex + 1);
    if (secondSlash === -1) return { name: specifier, subpath: null };
    return { name: specifier.slice(0, secondSlash), subpath: specifier.slice(secondSlash + 1) };
  }
  const slashIndex = specifier.indexOf('/');
  if (slashIndex === -1) return { name: specifier, subpath: null };
  return { name: specifier.slice(0, slashIndex), subpath: specifier.slice(slashIndex + 1) };
}

function resolvePythonSpecifier(
  from: string,
  spec: ExtractedSpecifier,
  sealedFiles: ReadonlySet<string>,
): ResolveResult {
  if (spec.kind === 'relative') {
    const leadingDots = /^\.+/.exec(spec.specifier)?.[0].length ?? 0;
    let baseDir = dirname(from);
    for (let i = 1; i < leadingDots; i++) baseDir = dirname(baseDir);
    const modulePath = spec.specifier.slice(leadingDots).replaceAll('.', '/');
    const base = toPosix(resolve('/', baseDir, modulePath).slice(1));
    const candidates = [`${base}.py`, `${base}/__init__.py`];
    const found = candidates.filter((c) => sealedFiles.has(c));
    return found.length > 0
      ? { classification: 'local-resolved', resolutionKind: 'python-relative', resolvedTargets: found.sort() }
      : { classification: 'local-unresolved', resolutionKind: 'python-relative', resolvedTargets: [] };
  }
  const parts = spec.specifier.split('.');
  const topLevel = parts[0]!;
  const topDirInit = `${topLevel}/__init__.py`;
  const topFile = `${topLevel}.py`;
  const isLocalPackage = sealedFiles.has(topDirInit) || sealedFiles.has(topFile);
  if (!isLocalPackage) {
    return { classification: 'external', resolutionKind: 'external-python-module', resolvedTargets: [] };
  }
  const modulePath = parts.join('/');
  const candidates = [`${modulePath}.py`, `${modulePath}/__init__.py`];
  const found = candidates.filter((c) => sealedFiles.has(c));
  return found.length > 0
    ? { classification: 'local-resolved', resolutionKind: 'python-local-absolute', resolvedTargets: found.sort() }
    : { classification: 'local-unresolved', resolutionKind: 'python-local-absolute', resolvedTargets: [] };
}

function resolveRustSpecifier(
  from: string,
  spec: ExtractedSpecifier,
  sealedFiles: ReadonlySet<string>,
  crateRoot: CrateRoot | null,
): ResolveResult {
  if (spec.kind === 'external-use') {
    return { classification: 'external', resolutionKind: 'external-crate', resolvedTargets: [] };
  }
  if (!crateRoot) {
    return { classification: 'local-unresolved', resolutionKind: `rust-${spec.kind}`, resolvedTargets: [] };
  }
  if (spec.kind === 'mod-decl') {
    const modName = spec.specifier.slice(4); // strip 'mod:'
    const moduleDir = rustModuleDir(from);
    const candidates = [
      `${moduleDir}/${modName}.rs`,
      `${moduleDir}/${modName}/mod.rs`,
    ];
    const found = candidates.filter((c) => sealedFiles.has(c));
    return found.length > 0
      ? { classification: 'local-resolved', resolutionKind: 'rust-mod-decl', resolvedTargets: found.sort() }
      : { classification: 'local-unresolved', resolutionKind: 'rust-mod-decl', resolvedTargets: [] };
  }

  // Handle crate-path, self-path, super-path (including repeated super::super::)
  const segments = spec.specifier.split('::');
  let base: string;
  let itemSegments: string[];

  if (spec.kind === 'crate-path') {
    base = crateRoot.srcDir;
    itemSegments = segments.slice(1); // skip 'crate'
  } else if (spec.kind === 'self-path') {
    base = rustModuleDir(from);
    itemSegments = segments.slice(1); // skip 'self'
  } else {
    // super-path — handle repeated super:: prefixes
    base = dirname(rustModuleDir(from));
    if (base === '.') base = crateRoot.srcDir;
    let superCount = 0;
    for (let i = 0; i < segments.length; i++) {
      if (segments[i] === 'super') {
        superCount++;
      } else {
        break;
      }
    }
    // First super already goes up one from rustModuleDir's parent
    for (let i = 1; i < superCount; i++) {
      base = dirname(base);
      if (base === '.') base = crateRoot.srcDir;
    }
    itemSegments = segments.slice(superCount);
  }

  for (let depth = itemSegments.length; depth >= 1; depth--) {
    const pathSegments = itemSegments.slice(0, depth).join('/');
    const candidates = [
      `${base}/${pathSegments}.rs`,
      `${base}/${pathSegments}/mod.rs`,
    ];
    const found = candidates.filter((c) => sealedFiles.has(c));
    if (found.length > 0) {
      const kind = spec.kind === 'crate-path' ? 'rust-crate-path' :
        spec.kind === 'self-path' ? 'rust-self-path' : 'rust-super-path';
      return { classification: 'local-resolved', resolutionKind: kind, resolvedTargets: found.sort() };
    }
  }
  const kind = spec.kind === 'crate-path' ? 'rust-crate-path' :
    spec.kind === 'self-path' ? 'rust-self-path' : 'rust-super-path';
  return { classification: 'local-unresolved', resolutionKind: kind, resolvedTargets: [] };
}

function rustModuleDir(filePath: string): string {
  const base = basename(filePath, '.rs');
  if (base === 'mod' || base === 'lib' || base === 'main') {
    return dirname(filePath);
  }
  return `${dirname(filePath)}/${base}`;
}

function resolveGoSpecifier(
  from: string,
  spec: ExtractedSpecifier,
  sealedFiles: ReadonlySet<string>,
  target: string,
): ResolveResult {
  // Find nearest go.mod for this source file
  const goMod = findNearestGoMod(from, target);
  // Require exact module path prefix: specifier must be exactly modulePath or modulePath + '/'
  // to avoid false local classification when modulePath is a prefix of an unrelated module
  if (!goMod || (spec.specifier !== goMod.modulePath && !spec.specifier.startsWith(`${goMod.modulePath}/`))) {
    return { classification: 'external', resolutionKind: 'external-go-module', resolvedTargets: [] };
  }
  const suffix = spec.specifier.slice(goMod.modulePath.length);
  const relPkgDir = suffix.startsWith('/') ? suffix.slice(1) : '';
  if (!relPkgDir) {
    // Exact module-root import (e.g. "github.com/example/myapp") — resolve to sorted non-test
    // .go files in the module directory itself
    const modDir = goMod.modDir;
    const targets = [...sealedFiles]
      .filter((f) => {
        if (!f.endsWith('.go') || f.endsWith('_test.go')) return false;
        const fileDir = dirname(f);
        return fileDir === modDir;
      })
      .sort();
    return targets.length > 0
      ? { classification: 'local-resolved', resolutionKind: 'go-local-module', resolvedTargets: targets }
      : { classification: 'local-unresolved', resolutionKind: 'go-local-module', resolvedTargets: [] };
  }
  // Resolve pkgDir relative to the go.mod directory
  const pkgDir = goMod.modDir === '.' ? relPkgDir : `${goMod.modDir}/${relPkgDir}`;
  const targets = [...sealedFiles]
    .filter((f) => {
      if (!f.endsWith('.go') || f.endsWith('_test.go')) return false;
      const fileDir = dirname(f);
      return fileDir === pkgDir;
    })
    .sort();
  return targets.length > 0
    ? { classification: 'local-resolved', resolutionKind: 'go-local-module', resolvedTargets: targets }
    : { classification: 'local-unresolved', resolutionKind: 'go-local-module', resolvedTargets: [] };
}

// ── Graph construction ─────────────────────────────────────────────────────

type SourceManifestInput = {
  target_realpath: string;
  source_files: string[];
  units: Array<{ id: string; files: string[] }>;
};

function parseManifestInput(value: unknown): SourceManifestInput {
  const schema = z.object({
    target_realpath: z.string().min(1),
    source_files: z.array(z.string().min(1)),
    units: z.array(z.object({
      id: z.string().min(1),
      files: z.array(z.string()),
    }).passthrough()),
  }).passthrough();
  return schema.parse(value);
}

export function createDependencyGraph(input: {
  target: string;
  sourceManifest: unknown;
  estimatedCharsPerToken?: number;
}): DependencyGraph {
  const targetRealpath = realpathSync(input.target);
  const manifest = parseManifestInput(input.sourceManifest);
  const charsPerToken = input.estimatedCharsPerToken ?? DEFAULT_ESTIMATED_CHARS_PER_TOKEN;
  const sourceFiles = [...new Set(manifest.source_files)].sort();

  // Fail closed: reject duplicate source paths in input
  if (sourceFiles.length !== manifest.source_files.length) {
    const counts = new Map<string, number>();
    for (const f of manifest.source_files) counts.set(f, (counts.get(f) ?? 0) + 1);
    const dups = [...counts.entries()].filter(([, c]) => c > 1).map(([f]) => f);
    throw new Error(`graph에 중복 source path가 있다: ${dups.join(', ')}`);
  }

  const sealedFiles = new Set(sourceFiles);
  const ownerMap = new Map<string, string>();
  const unitIds = new Set<string>();
  for (const unit of manifest.units) {
    if (unitIds.has(unit.id)) {
      throw new Error(`graph에 중복 unit ID가 있다: ${unit.id}`);
    }
    unitIds.add(unit.id);
    for (const file of unit.files) {
      if (!sealedFiles.has(file)) {
        throw new Error(`graph unit file이 source_files에 없다: ${file}`);
      }
      if (ownerMap.has(file)) {
        throw new Error(`graph node에 여러 owner가 있다: ${file}`);
      }
      ownerMap.set(file, unit.id);
    }
  }

  // Verify every source file has an owner
  for (const file of sourceFiles) {
    if (!ownerMap.has(file)) {
      throw new Error(`graph node에 owner가 없다: ${file}`);
    }
  }

  // Verify target_realpath match
  if (realpathSync(manifest.target_realpath) !== targetRealpath) {
    throw new Error('graph target_realpath가 input target과 다르다');
  }

  const tsConfigs = readTsConfigWithReferences(targetRealpath);
  const workspacePackages = readWorkspacePackages(targetRealpath, sealedFiles);
  const crateRootCache = new Map<string, CrateRoot | null>();

  const unsupportedCounts: Record<string, number> = {};
  let unsupportedTotal = 0;
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  for (const filePath of sourceFiles) {
    const abs = resolve(targetRealpath, filePath);
    if (!isWithin(targetRealpath, abs)) {
      throw new Error(`graph node가 target 밖이다: ${filePath}`);
    }
    // Fail closed: source file must exist
    if (!existsSync(abs)) {
      throw new Error(`graph source file이 없다: ${filePath}`);
    }
    let byteCount = 0;
    try { byteCount = readFileSync(abs).byteLength; } catch {
      throw new Error(`graph source file을 읽을 수 없다: ${filePath}`);
    }
    const language = detectLanguage(filePath);
    const estimatedTokenCount = Math.ceil(byteCount / charsPerToken);
    const owner = ownerMap.get(filePath)!;
    nodes.push({ path: filePath, ownerSourceUnitId: owner, language, byteCount, estimatedTokenCount });

    if (!SUPPORTED_LANGUAGES.has(language)) {
      unsupportedCounts[language] = (unsupportedCounts[language] ?? 0) + 1;
      unsupportedTotal += 1;
      continue;
    }

    let content: string;
    try { content = readFileSync(abs, 'utf8'); } catch { continue; }

    const specifiers = extractSpecifiers(filePath, content, language);
    const edgeDedup = new Set<string>();
    for (const spec of specifiers) {
      const edgeKey = `${filePath}|${spec.specifier}`;
      if (edgeDedup.has(edgeKey)) continue;
      edgeDedup.add(edgeKey);

      let result: ResolveResult;
      switch (language) {
        case 'javascript':
        case 'typescript':
          result = resolveJsTsSpecifier(filePath, spec, sealedFiles, tsConfigs, workspacePackages);
          break;
        case 'python':
          result = resolvePythonSpecifier(filePath, spec, sealedFiles);
          break;
        case 'rust': {
          const dir = dirname(filePath);
          let crateRoot = crateRootCache.get(dir);
          if (crateRoot === undefined) {
            crateRoot = findCrateRoot(filePath, targetRealpath);
            crateRootCache.set(dir, crateRoot);
          }
          result = resolveRustSpecifier(filePath, spec, sealedFiles, crateRoot);
          break;
        }
        case 'go':
          result = resolveGoSpecifier(filePath, spec, sealedFiles, targetRealpath);
          break;
        default:
          continue;
      }

      for (const t of result.resolvedTargets) {
        if (!sealedFiles.has(t)) {
          throw new Error(`local-resolved target이 sealed node set에 없다: ${t}`);
        }
      }
      if (result.classification === 'local-unresolved' && result.resolvedTargets.length > 0) {
        throw new Error(`local-unresolved edge에 resolvedTargets가 있다`);
      }
      if (result.classification === 'external' && result.resolvedTargets.length > 0) {
        throw new Error(`external edge에 resolvedTargets가 있다`);
      }

      edges.push({
        from: filePath,
        specifier: spec.specifier,
        language: spec.language,
        classification: result.classification,
        resolutionKind: result.resolutionKind,
        resolvedTargets: result.resolvedTargets,
      });
    }
  }

  edges.sort(compareEdges);

  const supportedParsers = ['javascript', 'typescript', 'python', 'rust', 'go'];
  const metadata = {
    supportedParsers,
    unsupportedFileCount: unsupportedTotal,
    unsupportedLanguageCounts: unsupportedCounts,
    disclaimer: GRAPH_DISCLAIMER,
  };

  const core = {
    version: '1.0.0' as const,
    estimatedCharsPerToken: charsPerToken,
    nodes,
    edges,
    metadata,
  };

  return DependencyGraphSchema.parse({
    ...core,
    generatedAt: new Date().toISOString(),
    dependencyGraphSha256: digest(stableJson(core)),
  });
}

// ── Write and verify ───────────────────────────────────────────────────────

export function writeDependencyGraph(engagementDir: string, graph: DependencyGraph): string {
  const parsed = assertDependencyGraphIntact(graph);
  const filePath = join(engagementDir, '00_dependency_graph.json');
  const temporary = `${filePath}.${process.pid}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(parsed, null, 2)}\n`, { mode: 0o600 });
  renameSync(temporary, filePath);
  return filePath;
}

export function assertDependencyGraphIntact(value: unknown): DependencyGraph {
  const graph = DependencyGraphSchema.parse(value);

  // Self-hash verification: only exclude generatedAt and dependencyGraphSha256
  const { dependencyGraphSha256: _sealed, generatedAt: _ts, ...core } = graph;
  if (digest(stableJson(core)) !== graph.dependencyGraphSha256) {
    throw new Error('OffSec dependency graph hash가 다르다');
  }

  // Enforce deterministic supportedParsers value and order
  const expectedSupportedParsers = ['javascript', 'typescript', 'python', 'rust', 'go'];
  if (graph.metadata.supportedParsers.length !== expectedSupportedParsers.length ||
      graph.metadata.supportedParsers.some((p, i) => p !== expectedSupportedParsers[i])) {
    throw new Error('graph metadata.supportedParsers가 표준 값/순서와 다르다');
  }

  // Node path uniqueness and ordering
  const nodeSet = new Set<string>();
  const nodeByPath = new Map<string, GraphNode>();
  let prevNodePath = '';
  for (const node of graph.nodes) {
    if (nodeSet.has(node.path)) {
      throw new Error(`graph에 중복 node가 있다: ${node.path}`);
    }
    if (node.path < prevNodePath) {
      throw new Error(`graph node 정렬 위반: ${node.path} < ${prevNodePath}`);
    }
    prevNodePath = node.path;
    nodeSet.add(node.path);
    nodeByPath.set(node.path, node);

    // Token/byte consistency check where derivable
    const expectedTokens = Math.ceil(node.byteCount / graph.estimatedCharsPerToken);
    if (node.estimatedTokenCount !== expectedTokens) {
      throw new Error(`graph node token 불일치: ${node.path} (expected ${expectedTokens}, got ${node.estimatedTokenCount})`);
    }
  }

  // Edge ordering, duplicate check, and invariant enforcement
  let prevEdge: { from: string; specifier: string; classification: string } = { from: '', specifier: '', classification: '' };
  const edgeFromSpecKeys = new Set<string>();
  let computedUnsupportedTotal = 0;
  const computedUnsupportedCounts: Record<string, number> = {};
  for (const node of graph.nodes) {
    if (!SUPPORTED_LANGUAGES.has(node.language)) {
      computedUnsupportedTotal += 1;
      computedUnsupportedCounts[node.language] = (computedUnsupportedCounts[node.language] ?? 0) + 1;
    }
  }

  // Verify exact metadata unsupported counts/total
  if (graph.metadata.unsupportedFileCount !== computedUnsupportedTotal) {
    throw new Error(`graph metadata.unsupportedFileCount 불일치: expected ${computedUnsupportedTotal}, got ${graph.metadata.unsupportedFileCount}`);
  }
  const metaCounts = graph.metadata.unsupportedLanguageCounts;
  const computedKeys = Object.keys(computedUnsupportedCounts).sort();
  const metaKeys = Object.keys(metaCounts).sort();
  if (computedKeys.length !== metaKeys.length || computedKeys.some((k, i) => k !== metaKeys[i])) {
    throw new Error('graph metadata.unsupportedLanguageCounts 키 불일치');
  }
  for (const key of computedKeys) {
    if (metaCounts[key] !== computedUnsupportedCounts[key]) {
      throw new Error(`graph metadata.unsupportedLanguageCounts[${key}] 불일치`);
    }
  }

  for (const edge of graph.edges) {
    if (!nodeSet.has(edge.from)) {
      throw new Error(`edge source가 node set에 없다: ${edge.from}`);
    }
    // Enforce one edge per from+specifier (same comparator as generation edgeDedup)
    const fromSpecKey = `${edge.from}|${edge.specifier}`;
    if (edgeFromSpecKeys.has(fromSpecKey)) {
      throw new Error(`graph에 동일 from+specifier edge가 중복됐다: ${fromSpecKey}`);
    }
    edgeFromSpecKeys.add(fromSpecKey);

    // Enforce sort order (same comparator as generation)
    if (compareEdges(edge, prevEdge) < 0) {
      throw new Error(`graph edge 정렬 위반: ${edge.from}|${edge.specifier}|${edge.classification}`);
    }
    prevEdge = edge;

    // Edge language must be consistent with the source node's language
    const sourceNode = nodeByPath.get(edge.from)!;
    if (edge.language !== sourceNode.language) {
      throw new Error(`edge language가 source node language와 다르다: ${edge.from} edge=${edge.language} node=${sourceNode.language}`);
    }

    // resolvedTargets must be unique and sorted
    if (edge.resolvedTargets.length > 1) {
      for (let i = 1; i < edge.resolvedTargets.length; i++) {
        if (edge.resolvedTargets[i]! <= edge.resolvedTargets[i - 1]!) {
          throw new Error(`edge resolvedTargets가 정렬/중복 위반: ${edge.from} → ${edge.specifier}`);
        }
      }
    }

    // Classification/target-shape validation
    if (edge.classification === 'local-resolved') {
      if (edge.resolvedTargets.length === 0) {
        throw new Error(`local-resolved edge에 resolvedTargets가 없다: ${edge.from} → ${edge.specifier}`);
      }
      for (const t of edge.resolvedTargets) {
        if (!nodeSet.has(t)) {
          throw new Error(`local-resolved target이 node set에 없다: ${t}`);
        }
      }
    }
    if (edge.classification === 'local-unresolved' && edge.resolvedTargets.length > 0) {
      throw new Error(`local-unresolved edge에 resolvedTargets가 있다: ${edge.from} → ${edge.specifier}`);
    }
    if (edge.classification === 'external' && edge.resolvedTargets.length > 0) {
      throw new Error(`external edge에 resolvedTargets가 있다: ${edge.from} → ${edge.specifier}`);
    }
  }
  return graph;
}

export function readDependencyGraph(engagementDir: string): unknown {
  return JSON.parse(readFileSync(join(engagementDir, '00_dependency_graph.json'), 'utf8'));
}

// Export helpers for test usage
export { stripJsonc };
