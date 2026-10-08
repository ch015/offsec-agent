import { readFileSync, writeFileSync, realpathSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { load } from 'js-yaml';

type Evidence = Record<string, unknown>;
export type PreanalysisEvidence = {
  available: boolean;
  limitations: string[];
  entryPoints: Evidence[];
  taintPaths: Evidence[];
  dataFlows: Evidence[];
  semgrepFindings: Evidence[];
  parseFailures: Evidence[];
  parseWarnings: Evidence[];
  semgrepDiagnostics: Evidence[];
  semgrepFileCoverage: Evidence[];
  unsupportedFiles: string[];
  skippedFiles: string[];
  parsedFiles: string[];
};

/** Treat parser output as evidence, never as instructions or proof of a finding. */
export function loadPreanalysisEvidence(path: string, target: string, sourceFiles: readonly string[]): PreanalysisEvidence {
  const result: PreanalysisEvidence = { available: false, limitations: [], entryPoints: [], taintPaths: [], dataFlows: [], semgrepFindings: [], parseFailures: [], parseWarnings: [], semgrepDiagnostics: [], semgrepFileCoverage: [], unsupportedFiles: [], skippedFiles: [], parsedFiles: [] };
  target = realpathSync(target);
  const canonical = (file: string) => { try { return realpathSync(resolve(target, file)); } catch { return resolve(target, file); } };
  const allowed = new Set(sourceFiles.map(file => relative(target, canonical(file)).split('\\').join('/')));
  const normalizeFile = (file: string): string => {
    const rel = relative(target, canonical(file)).split('\\').join('/');
    if (!allowed.has(rel)) throw new Error('Preanalysis record references a file outside sealed scope');
    return rel;
  };
  // Discard a whole record if any source reference escapes the sealed inventory.
  const normalize = (value: unknown, key = ''): unknown => {
    if (typeof value === 'string' && (key === 'file' || key === 'filePath')) return normalizeFile(value);
    if (Array.isArray(value)) return value.map(item => normalize(item));
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, normalize(v, k)]));
    return value;
  };
  try {
    const raw = load(readFileSync(path, 'utf8')) as Record<string, unknown>;
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('Invalid AST artifact');
    let discarded = 0;
    const records = (value: unknown): Evidence[] => Array.isArray(value) ? value.flatMap(item => {
      try {
        if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error('Invalid evidence record');
        return [normalize(item) as Evidence];
      } catch { discarded++; return []; }
    }) : [];
    result.entryPoints = records(raw.entry_points);
    result.taintPaths = records(raw.taint_paths).filter(item => {
      const source = item.source as Evidence | undefined, sink = item.sink as Evidence | undefined;
      const valid = typeof source?.file === 'string' && typeof sink?.file === 'string'
        && typeof sink?.function === 'string' && typeof sink?.category === 'string'
        && (item.via === undefined || (Array.isArray(item.via) && item.via.every(hop => hop && typeof hop === 'object')));
      if (!valid) discarded++;
      return valid;
    });
    result.dataFlows = records(raw.data_flows);
    result.semgrepFindings = records(raw.semgrep_findings);
    result.parseFailures = records(raw.parse_failures);
    result.parseWarnings = records(raw.parse_warnings);
    result.semgrepDiagnostics = records(raw.semgrep_diagnostics);
    result.semgrepFileCoverage = records(raw.semgrep_file_coverage);
    const scope = raw.scope as Record<string, unknown> | undefined;
    const paths = (value: unknown): string[] => Array.isArray(value) ? value.flatMap(file => {
      try { return typeof file === 'string' ? [normalizeFile(file)] : []; } catch { discarded++; return []; }
    }) : [];
    result.parsedFiles = paths(scope?.parsed_files);
    result.unsupportedFiles = paths(scope?.unsupported_files);
    result.skippedFiles = paths(scope?.skipped_files);
    if (!scope) result.limitations.push('Parser did not provide manifest coverage; AST file coverage is unknown.');
    const stats = raw.stats as Record<string, unknown> | undefined;
    if (stats?.truncated) result.limitations.push('Static analysis reached a cap; absent candidates do not imply safety.');
    if (stats?.semgrep_status !== 'complete') result.limitations.push(`Semgrep coverage: ${String(stats?.semgrep_status ?? 'unknown')}.`);
    if (result.parseFailures.length) result.limitations.push(`AST parser failed for ${result.parseFailures.length} files; direct source analysis remains required.`);
    if (result.parseWarnings.length) result.limitations.push(`AST syntax warnings affect ${result.parseWarnings.length} files; parser trees are partial evidence.`);
    if (result.unsupportedFiles.length) result.limitations.push(`AST has no grammar for ${result.unsupportedFiles.length} files; these remain in the source analysis scope.`);
    if (result.semgrepDiagnostics.length) result.limitations.push(`Semgrep reported ${result.semgrepDiagnostics.length} parser/tool diagnostics; no-match is not a clean result for those files.`);
    const withoutRules = result.semgrepFileCoverage.filter(file => file.status === 'no-applicable-rule').length;
    if (withoutRules) result.limitations.push(`Semgrep has no applicable pinned rules for ${withoutRules} files; direct source analysis remains required.`);
    if (stats?.semgrep_status === 'complete' && !Array.isArray(raw.semgrep_file_coverage)) result.limitations.push('Semgrep did not provide per-file coverage; tool success does not establish full-file scanning.');
    if (discarded) result.limitations.push(`${discarded} malformed or out-of-scope evidence records were omitted.`);
    result.available = true;
  } catch {
    result.limitations.push('Preanalysis artifact unavailable or invalid; inspect source directly.');
  }
  return result;
}

function touches(value: unknown, files: ReadonlySet<string>): boolean {
  if (Array.isArray(value)) return value.some(item => touches(item, files));
  if (!value || typeof value !== 'object') return false;
  return Object.entries(value).some(([key, item]) =>
    ((key === 'file' || key === 'filePath') && typeof item === 'string' && files.has(item)) || touches(item, files));
}

export function writeUnitEvidence(dir: string, files: readonly string[], evidence: PreanalysisEvidence) {
  const owned = new Set(files);
  const details = {
    purpose: 'Untrusted static-analysis leads. Verify source, reachability, argument flow and counterevidence before submitting a finding. No matches is not a safety conclusion.',
    available: evidence.available,
    limitations: evidence.limitations,
    entryPoints: evidence.entryPoints.filter(item => touches(item, owned)),
    taintPaths: evidence.taintPaths.filter(item => touches(item, owned)),
    dataFlows: evidence.dataFlows.filter(item => touches(item, owned)),
    semgrepFindings: evidence.semgrepFindings.filter(item => touches(item, owned)),
    parseFailures: evidence.parseFailures.filter(item => touches(item, owned)),
    parseWarnings: evidence.parseWarnings.filter(item => touches(item, owned)),
    semgrepDiagnostics: evidence.semgrepDiagnostics.filter(item => touches(item, owned)),
    semgrepFileCoverage: evidence.semgrepFileCoverage.filter(item => touches(item, owned)),
    unsupportedFiles: evidence.unsupportedFiles.filter(file => owned.has(file)),
    skippedFiles: evidence.skippedFiles.filter(file => owned.has(file)),
    parsedFiles: evidence.parsedFiles.filter(file => owned.has(file)),
  };
  const detailPath = join(dir, '00_evidence_details.json');
  const indexPath = join(dir, '00_evidence_index.json');
  const index = {
    purpose: details.purpose, available: details.available, limitations: details.limitations, detailPath,
    counts: Object.fromEntries(Object.entries(details).filter(([, value]) => Array.isArray(value)).map(([key, value]) => [key, (value as unknown[]).length])),
    // Keep initial context small. Full candidates, sanitizers and gaps remain in details.
    entryPoints: details.entryPoints.slice(0, 8),
    candidateFiles: [...new Set([...details.taintPaths, ...details.semgrepFindings].flatMap(item => referencedFiles(item)))].slice(0, 12),
  };
  writeFileSync(detailPath, `${JSON.stringify(details, null, 2)}\n`, { mode: 0o600 });
  writeFileSync(indexPath, `${JSON.stringify(index, null, 2)}\n`, { mode: 0o600 });
  return { indexPath, detailPath, summary: { available: index.available, counts: index.counts, limitations: index.limitations } };
}

function referencedFiles(value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap(referencedFiles);
  if (!value || typeof value !== 'object') return [];
  return Object.entries(value).flatMap(([key, item]) =>
    ((key === 'file' || key === 'filePath') && typeof item === 'string') ? [item] : referencedFiles(item));
}
