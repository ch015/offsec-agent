import { afterEach, describe, expect, it } from 'vitest';
import { createRequire } from 'node:module';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { dump, load } from 'js-yaml';
import { computeGraphRag, serializeGraphContextForUnit } from '../workflow/graph-rag.js';
import { loadPreanalysisEvidence, writeUnitEvidence } from '../workflow/preanalysis-evidence.js';
import { coverageAppendix } from '../missions/analysis-checkpoint.js';

const { buildAstContext } = createRequire(import.meta.url)('../../../domains/offsec/lib/ch015/ast/context-builder.js');
const dirs: string[] = [];
function fixture() {
  const target = realpathSync(mkdtempSync(join(tmpdir(), 'offsec-evidence-'))); dirs.push(target);
  const put = (file: string, source: string) => { mkdirSync(dirname(join(target, file)), { recursive: true }); writeFileSync(join(target, file), source); return join(target, file); };
  return { target, put, outputPath: join(target, 'context.yaml') };
}
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

describe('native preanalysis → AI evidence', () => {
  it('retains partial parser/tool evidence per unit and discloses it even in a completed report', async () => {
    const f = fixture(), source = f.put('fragment.ts', 'export function incomplete('), unsupported = f.put('contract.sol', 'contract Example {}');
    const semgrepExecFile = (_command: string, args: string[], _options: unknown, callback: (error: unknown, stdout: string, stderr: string) => void) => {
      callback(null, args[0] === '--version' ? '1.157.0\n' : JSON.stringify({ results: [], paths: { scanned: [source] }, errors: [{ path: source, code: 3, level: 'warn', type: 'Syntax error', message: 'incomplete fragment' }] }), '');
    };
    const result = await buildAstContext(f.target, { outputPath: f.outputPath, sourceFiles: [source, unsupported], runSemgrep: true, semgrepExecFile, logger() {} });
    expect(result.semgrep.status).toBe('complete');
    const evidence = loadPreanalysisEvidence(f.outputPath, f.target, [source, unsupported]);
    const refs = writeUnitEvidence(f.target, ['fragment.ts'], evidence), details = JSON.parse(readFileSync(refs.detailPath, 'utf8'));
    expect(details.parseWarnings).toHaveLength(1); expect(details.semgrepDiagnostics).toHaveLength(1);
    expect(details.semgrepFileCoverage).toEqual([expect.objectContaining({ file: 'fragment.ts', status: 'partial' })]);
    const appendix = coverageAppendix({ complete: true, uncoveredFiles: [], preanalysisLimitations: evidence.limitations });
    expect(appendix).toContain('Semgrep reported 1'); expect(appendix).toContain('no applicable pinned rules for 1');
    expect(appendix).toContain('AST syntax warnings');
  });
  it('scans exactly the manifest with Semgrep even when AST caps or legacy hints differ', async () => {
    const f = fixture();
    const a = f.put('src/a.js', 'function a() { return 1; }'), b = f.put('packages/b.js', 'function b() { return 2; }');
    const excluded = f.put('src/excluded.js', 'function secret() { return 3; }');
    let scanArgs: string[] = [];
    const semgrepExecFile = (_command: string, args: string[], _options: unknown, callback: (error: unknown, stdout: string, stderr: string) => void) => {
      if (args[0] === '--version') callback(null, '1.157.0\n', '');
      else { scanArgs = args; callback(null, JSON.stringify({ results: [], paths: { scanned: [a, b] } }), ''); }
    };
    const result = await buildAstContext(f.target, { outputPath: f.outputPath, sourceFiles: [a, b], semgrepFiles: [excluded], maxFiles: 1, runSemgrep: true, semgrepExecFile, logger() {} });
    expect(result.semgrep.status).toBe('complete');
    expect(scanArgs).toContain(a);
    expect(scanArgs).toContain(b);
    expect(scanArgs).not.toContain(excluded);
    expect(result.stats.files_parsed).toBe(1);
    expect(result.stats.semgrep_files_scanned).toBe(2);
  });
  it('keeps manifest files across project layouts and never rediscovers excluded source', async () => {
    const f = fixture();
    const api = f.put('src/api.js', "function search(req) { query(req.query.term); }\napp.get('/search', search);\n");
    const payment = f.put('packages/payment/handler.js', 'export function payment(input) { query(input); }\n');
    f.put('src/excluded/internal.js', 'function excluded() { query("constant"); }\n');
    const result = await buildAstContext(f.target, { outputPath: f.outputPath, sourceFiles: [api, payment], runSemgrep: false, logger() {} });
    expect(result.ok).toBe(true);
    const ast = load(readFileSync(f.outputPath, 'utf8')) as any;
    expect(ast.scope.parsed_files).toEqual(['packages/payment/handler.js', 'src/api.js']);
    expect(Object.keys(ast.call_graph).some(key => key.includes('excluded'))).toBe(false);
    expect(ast.taint_paths).toHaveLength(1);
    const graph = computeGraphRag({ dependencyGraph: { nodes: [{ path: 'src/api.js' }], edges: [] }, astContext: ast });
    expect(graph.taintPaths).toHaveLength(1);
    expect(graph.taintPaths[0].evidence).toEqual(ast.taint_paths[0]);
    expect(serializeGraphContextForUnit(graph, ['src/api.js'])).toContain('query');
    const evidence = loadPreanalysisEvidence(f.outputPath, f.target, [api, payment]);
    const refs = writeUnitEvidence(f.target, ['src/api.js'], evidence);
    const detail = JSON.parse(readFileSync(refs.detailPath, 'utf8'));
    expect(detail.taintPaths).toEqual(ast.taint_paths);
    expect(detail.parsedFiles).toEqual(['src/api.js']);
  });

  it('discloses skipped and unsupported files without calling them parsed', async () => {
    const f = fixture();
    const a = f.put('src/a.js', 'function a() { return 1; }');
    const b = f.put('other/b.js', 'function b() { return 2; }');
    const hcl = f.put('infra/main.tf', 'resource "example" "test" {}');
    await buildAstContext(f.target, { outputPath: f.outputPath, sourceFiles: [a, b, hcl], maxFiles: 1, runSemgrep: false, logger() {} });
    const ast = load(readFileSync(f.outputPath, 'utf8')) as any;
    expect(ast.scope.parsed_files).toEqual(['other/b.js']);
    expect(ast.scope.skipped_files).toEqual(['src/a.js']);
    expect(ast.scope.unsupported_files).toEqual(['infra/main.tf']);
    expect(ast.stats.truncation.files).toBe(true);
    await buildAstContext(f.target, { outputPath: f.outputPath, sourceFiles: [hcl], runSemgrep: false, logger() {} });
    const unsupported = loadPreanalysisEvidence(f.outputPath, f.target, [hcl]);
    expect(unsupported.available).toBe(true);
    expect(unsupported.parsedFiles).toEqual([]);
    expect(unsupported.unsupportedFiles).toEqual(['infra/main.tf']);
  });

  it('rejects escaping paths and symlinks before parsing', async () => {
    const f = fixture(), outside = fixture();
    const secret = outside.put('other.js', 'privateValue');
    symlinkSync(secret, join(f.target, 'linked.js'));
    await expect(buildAstContext(f.target, { sourceFiles: [secret], runSemgrep: false })).rejects.toThrow('outside');
    await expect(buildAstContext(f.target, { sourceFiles: [join(f.target, 'linked.js')], runSemgrep: false })).rejects.toThrow('outside');
  });

  it('preserves Semgrep, sanitizers and intermediate-file evidence on demand', () => {
    const f = fixture();
    const files = ['api.ts', 'service.ts', 'db.ts'].map(name => f.put(name, 'source'));
    const taint = { source: { file: 'api.ts', expr: 'input' }, sink: { file: 'db.ts', function: 'db.query', category: 'sql' }, via: [{ file: 'service.ts', line: 3 }], sanitizers: [{ file: 'service.ts', function: 'validate' }], tainted_arguments: ['value'] };
    writeFileSync(f.outputPath, dump({ scope: { parsed_files: ['api.ts', 'service.ts', 'db.ts'] }, taint_paths: [taint], semgrep_findings: [{ file: 'service.ts', line: 3, rule: 'candidate' }], stats: { semgrep_status: 'complete' } }));
    const refs = writeUnitEvidence(f.target, ['service.ts'], loadPreanalysisEvidence(f.outputPath, f.target, files));
    const detail = JSON.parse(readFileSync(refs.detailPath, 'utf8'));
    expect(detail.taintPaths[0].sanitizers).toEqual(taint.sanitizers);
    expect(detail.semgrepFindings).toHaveLength(1);
    const graph = computeGraphRag({ dependencyGraph: { nodes: files.map(path => ({ path })), edges: [] }, astContext: { taint_paths: [taint] } });
    expect(serializeGraphContextForUnit(graph, ['service.ts'])).toContain('db.ts');
  });

  it('filters out-of-scope references even from a custom parser', () => {
    const f = fixture();
    const file = f.put('api.ts', 'source');
    writeFileSync(f.outputPath, dump({ taint_paths: [{ source: { file: 'api.ts' }, sink: { file: '../excluded.ts' } }], semgrep_findings: [{ file: 'api.ts', rule: 'ok' }, { file: '/excluded.ts' }] }));
    const result = loadPreanalysisEvidence(f.outputPath, f.target, [file]);
    expect(result.taintPaths).toEqual([]);
    expect(result.semgrepFindings).toHaveLength(1);
    expect(result.limitations.some(message => message.includes('2 malformed'))).toBe(true);
  });

  it('reports unavailable preanalysis and does not manufacture a clean assessment', () => {
    const f = fixture();
    const result = loadPreanalysisEvidence(f.outputPath, f.target, []);
    expect(result.available).toBe(false);
    expect(result.limitations.join()).toContain('unavailable');
  });

  it('supports legacy HTTP candidates and qualified sinks, but avoids ambiguous symbol resolution', () => {
    const graph = { nodes: [{ path: 'api.ts' }, { path: 'a.ts' }, { path: 'b.ts' }], edges: [] };
    const ast = { entry_points: [{ file: 'api.ts', line: 1, type: 'http', handler: 'handler' }], call_graph: { 'api.ts:handler': { calls: ['db.query'], called_by: [] } } };
    expect(computeGraphRag({ dependencyGraph: graph, astContext: ast }).taintPaths).toHaveLength(1);
    const ambiguous = { ...ast, call_graph: { 'api.ts:handler': { calls: ['service'], called_by: [] }, 'a.ts:service': { calls: ['db.query'], called_by: [] }, 'b.ts:service': { calls: [], called_by: [] } } };
    expect(computeGraphRag({ dependencyGraph: graph, astContext: ambiguous }).taintPaths).toEqual([]);
  });
});
