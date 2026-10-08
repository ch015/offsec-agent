'use strict';

const { execFile } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const DEFAULT_TIMEOUT = 120_000;
const MAX_FINDINGS = 100;

function isSemgrepInstalled(options = {}) {
  return new Promise((resolve) => {
    const runner = options.execFileImpl || execFile;
    runner(options.executable || 'semgrep', ['--version'], processOptions(5000), (err) => {
      resolve(!err);
    });
  });
}

function runSemgrepChunk(targetPath, options = {}) {
  const {
    severity,
    timeout = DEFAULT_TIMEOUT,
    maxFindings = MAX_FINDINGS,
    executable = 'semgrep',
    manifestPath,
    files = [],
    execFileImpl = execFile,
  } = options;

  return new Promise((resolve) => {
    let prepared;
    try {
      prepared = prepareRun(targetPath, manifestPath, files);
    } catch (error) {
      resolve(failure('invalid-input', error.message));
      return;
    }

    execFileImpl(executable, ['--version'], processOptions(5000), (versionError, versionStdout) => {
      if (versionError) {
        resolve(failure('unavailable', versionError.code === 'ENOENT' ? 'semgrep not installed' : versionError.message));
        return;
      }
      const version = String(versionStdout).trim().split(/\s+/).find(part => /^\d+\.\d+\.\d+$/.test(part));
      if (version !== prepared.manifest.semgrepVersion) {
        resolve(failure('version-mismatch', `semgrep version mismatch: ${version || 'unknown'} != ${prepared.manifest.semgrepVersion}`));
        return;
      }

      const args = ['scan', '--metrics=off', '--json', '--no-git-ignore', '--max-target-bytes=0'];
      for (const config of prepared.rulePaths) args.push('--config', config);
      if (severity) args.push('--severity', severity);
      args.push(...prepared.files);

      execFileImpl(executable, args, processOptions(timeout), (err, stdout, stderr) => {
        if (err && !stdout) {
          resolve(failure(err.killed ? 'timeout' : 'execution-failed', String(stderr || err.code || 'Semgrep process failed').trim().slice(-2000), {
            version,
            exitCode: typeof err.code === 'number' ? err.code : null,
            stderrSha256: digest(String(stderr || '')),
          }));
          return;
        }

        try {
          const raw = JSON.parse(stdout);
          if (!Array.isArray(raw.results)) throw new Error('results array가 없다');
          const normalized = raw.results
            .map(result => normalizeFinding(result, prepared))
            .sort(compareFindings);
          const findings = normalized.slice(0, maxFindings);
          const scanned = Array.isArray(raw.paths?.scanned)
            ? raw.paths.scanned.map(value => normalizeScannedPath(value, prepared)).sort()
            : [];
          if (!Array.isArray(raw.paths?.scanned) || new Set(scanned).size !== scanned.length) throw new Error('Semgrep scanned file receipt is missing or duplicated');
          if (raw.errors !== undefined && !Array.isArray(raw.errors)) throw new Error('Semgrep diagnostics must be an array');
          const diagnostics = (raw.errors || []).map(error => ({
            ...(error.path ? { file: normalizeScannedPath(error.path, prepared) } : {}),
            level: String(error.level || 'error'), type: String(error.type || 'unknown'), code: error.code,
            message: String(error.message || '').slice(0, 4000),
          }));
          const skipped = new Map((raw.paths.skipped || []).map(item => [normalizeScannedPath(item.path, prepared), String(item.reason || 'unspecified')]));
          const fileCoverage = prepared.relativeFiles.map(file => {
            const issues = diagnostics.filter(error => error.file === file);
            if (issues.length) return { file, status: 'partial', reason: issues.map(error => error.type).join(', ') };
            if (scanned.includes(file)) return { file, status: 'scanned' };
            if (ruleApplies(file, prepared.ruleProfiles) === false) return { file, status: 'no-applicable-rule', reason: 'Pinned rule manifest has no matching language/path rule for this file' };
            return { file, status: 'unaccounted', reason: skipped.get(file) || 'No scanned receipt for an applicable or unclassified file' };
          });
          // Recoverable syntax warnings describe partial parser evidence, not
          // process failure. Every other error, timeout or missing target is a
          // failed required-tool run even when stdout contains valid findings.
          const fatalDiagnostics = diagnostics.filter(error => !(error.level === 'warn' && error.code === 3 && error.file
            && ['Syntax error', 'Partial parsing'].includes(error.type)));
          const complete = !err && fatalDiagnostics.length === 0 && fileCoverage.every(file => file.status !== 'unaccounted');

          const stats = {
            files_requested: prepared.files.length,
            files_scanned: scanned.length,
            rules_applied: new Set(normalized.map(f => f.rule_id)).size,
            raw_total_findings: normalized.length,
            retained_findings: findings.length,
            truncated: normalized.length > findings.length,
          };

          resolve({
            ok: complete,
            status: complete ? 'complete' : 'incomplete',
            ...(!complete ? { error: `Semgrep execution/coverage incomplete: exit=${err?.code ?? 0}; fatal diagnostics=${fatalDiagnostics.length}; unaccounted files=${fileCoverage.filter(file => file.status === 'unaccounted').length}` } : {}),
            findings,
            stats,
            diagnostics,
            fileCoverage,
            receipt: {
              version,
              executable,
              manifestSha256: prepared.manifestSha256,
              ruleSha256: prepared.manifest.rules.map(rule => rule.sha256),
              requestedFilesSha256: digest(prepared.relativeFiles.join('\n')),
              requestedContentSha256: prepared.requestedContentSha256,
              requestedFiles: prepared.fileReceipts,
              fileCoverage,
              diagnostics,
              matchedRuleIds: [...new Set(normalized.map(finding => finding.rule_id))].sort(),
              stdoutSha256: digest(String(stdout)),
              stderrSha256: digest(String(stderr || '')),
              exitCode: err ? (typeof err.code === 'number' ? err.code : null) : 0,
            },
          });
        } catch (error) {
          resolve(failure('invalid-output', error.message, {
            version,
            stdoutSha256: digest(String(stdout || '')),
            stderrSha256: digest(String(stderr || '')),
          }));
        }
      });
    });
  });
}

async function runSemgrep(targetPath, options = {}) {
  let prepared;
  try { prepared = prepareRun(targetPath, options.manifestPath, options.files || []); }
  catch (error) { return failure('invalid-input', error.message); }
  const batches = []; let current = [], bytes = 0;
  for (const file of prepared.files) {
    const size = Buffer.byteLength(file) + 3;
    if (current.length && (current.length >= 128 || bytes + size > 24_000)) { batches.push(current); current = []; bytes = 0; }
    current.push(file); bytes += size;
  }
  if (current.length) batches.push(current);
  if (batches.length === 1) return runSemgrepChunk(targetPath, options);
  const results = [];
  for (const files of batches) {
    const result = await runSemgrepChunk(targetPath, { ...options, files });
    results.push(result);
    if (!result.ok) break;
  }
  const failed = results.find(result => !result.ok);
  const expected = new Map(prepared.fileReceipts.map(file => [file.path, file]));
  const changed = results.some(result => (result.receipt?.requestedFiles || []).some(file => JSON.stringify(expected.get(file.path)) !== JSON.stringify(file)));
  const known = results.flatMap(result => result.fileCoverage || []);
  const covered = new Map(known.map(file => [file.file, file]));
  const fileCoverage = prepared.relativeFiles.map(file => covered.get(file) || { file, status: 'unaccounted', reason: 'Batch was not completed' });
  const diagnostics = results.flatMap(result => result.diagnostics || []);
  const maxFindings = options.maxFindings ?? MAX_FINDINGS;
  const findings = results.flatMap(result => result.findings).sort(compareFindings).slice(0, maxFindings);
  const rawTotal = results.reduce((sum, result) => sum + (result.stats?.raw_total_findings || 0), 0);
  const batchReceipts = results.map((result, index) => ({ index, files: batches[index].map(file => relativePath(prepared.targetRoot, file)), status: result.status, receipt: result.receipt || null }));
  const matchedRuleIds = [...new Set(results.flatMap(result => result.receipt?.matchedRuleIds || []))].sort();
  const ok = !failed && !changed && covered.size === prepared.files.length;
  return {
    ok, status: ok ? 'complete' : 'incomplete',
    ...(!ok ? { error: changed ? 'Source bytes changed between Semgrep batches' : failed?.error || 'Semgrep batch coverage incomplete' } : {}),
    findings, diagnostics, fileCoverage,
    stats: { files_requested: prepared.files.length, files_scanned: results.reduce((sum, result) => sum + (result.stats?.files_scanned || 0), 0),
      rules_applied: matchedRuleIds.length,
      raw_total_findings: rawTotal, retained_findings: findings.length, truncated: rawTotal > findings.length },
    receipt: { version: prepared.manifest.semgrepVersion, executable: options.executable || 'semgrep', manifestSha256: prepared.manifestSha256,
      ruleSha256: prepared.manifest.rules.map(rule => rule.sha256), requestedFilesSha256: digest(prepared.relativeFiles.join('\n')),
      requestedContentSha256: prepared.requestedContentSha256, requestedFiles: prepared.fileReceipts,
      outputFormat: 'batch-receipts/1', stdoutSha256: digest(stableJson(batchReceipts.map(batch => batch.receipt?.stdoutSha256 || null))),
      stderrSha256: digest(stableJson(batchReceipts.map(batch => batch.receipt?.stderrSha256 || null))),
      exitCode: ok ? 0 : null, fileCoverage, diagnostics, matchedRuleIds, batches: batchReceipts },
  };
}

function prepareRun(targetPath, manifestPath, files) {
  if (!manifestPath) throw new Error('local Semgrep manifest가 필요하다');
  if (!Array.isArray(files) || files.length === 0) throw new Error('Semgrep explicit file list가 필요하다');
  const targetRoot = fs.realpathSync(targetPath);
  const manifestFile = fs.realpathSync(manifestPath);
  const manifestContent = fs.readFileSync(manifestFile);
  const manifest = JSON.parse(manifestContent.toString('utf8'));
  if (!/^\d+\.\d+\.\d+$/.test(manifest.semgrepVersion) || !Array.isArray(manifest.rules) || manifest.rules.length === 0) {
    throw new Error('Semgrep manifest schema가 잘못됐다');
  }
  const ruleRoot = path.dirname(manifestFile);
  const rulePaths = manifest.rules.map(rule => {
    if (!rule || typeof rule.path !== 'string' || !/^[a-f0-9]{64}$/.test(rule.sha256)) {
      throw new Error('Semgrep rule manifest entry가 잘못됐다');
    }
    const rulePath = fs.realpathSync(path.resolve(ruleRoot, rule.path));
    if (!isWithin(ruleRoot, rulePath) || digest(fs.readFileSync(rulePath)) !== rule.sha256) {
      throw new Error(`Semgrep rule hash 또는 경계가 잘못됐다: ${rule.path}`);
    }
    return rulePath;
  });
  const ruleProfiles = rulePaths.flatMap(file => {
    const rules = yaml.load(fs.readFileSync(file, 'utf8'))?.rules;
    if (!Array.isArray(rules)) throw new Error('Semgrep rule document has no rules array');
    return rules.flatMap(rule => {
      if (!Array.isArray(rule.languages)) throw new Error('Semgrep rule has no language profile');
      return { languages: new Set(rule.languages), paths: rule.paths || {} };
    });
  });
  const canonicalFiles = files.map(file => fs.realpathSync(path.resolve(file)));
  if (new Set(canonicalFiles).size !== canonicalFiles.length) throw new Error('Semgrep file list가 중복됐다');
  for (const file of canonicalFiles) {
    if (!isWithin(targetRoot, file) || !fs.statSync(file).isFile()) throw new Error(`Semgrep file이 target 밖이다: ${file}`);
  }
  canonicalFiles.sort((left, right) =>
    relativePath(targetRoot, left).localeCompare(relativePath(targetRoot, right)));
  const fileReceipts = canonicalFiles.map(file => {
    const content = fs.readFileSync(file);
    return { path: relativePath(targetRoot, file), bytes: content.byteLength, sha256: digest(content) };
  });
  return {
    targetRoot,
    manifest,
    manifestSha256: digest(manifestContent),
    rulePaths,
    files: canonicalFiles,
    relativeFiles: fileReceipts.map(file => file.path),
    fileReceipts,
    requestedContentSha256: digest(stableJson(fileReceipts)),
    allowedFiles: new Set(canonicalFiles),
    ruleProfiles,
  };
}

function ruleApplies(file, profiles) {
  let uncertain = false;
  // Only prove path exclusion for simple patterns whose Semgrep and glob
  // semantics coincide. Future complex filters remain conservatively unknown.
  const matches = pattern => /^\*\.[a-z0-9]+$/i.test(pattern) ? file.endsWith(pattern.slice(1)) : undefined;
  for (const profile of profiles) {
    const includes = profile.paths.include || [], excludes = profile.paths.exclude || [];
    if (excludes.some(pattern => matches(pattern) === true)) continue;
    if (includes.length && includes.every(pattern => matches(pattern) === false)) continue;
    const applies = languageApplies(file, profile.languages);
    if (applies === true) return true;
    if (applies === undefined) uncertain = true;
  }
  return uncertain ? undefined : false;
}

function languageApplies(file, languages) {
  if (languages.has('generic') || languages.has('regex')) return true;
  const profiles = {
    '.js': ['javascript'], '.jsx': ['javascript'], '.mjs': ['javascript'], '.cjs': ['javascript'],
    '.ts': ['typescript', 'javascript'], '.tsx': ['typescript', 'javascript'], '.py': ['python'],
    '.yaml': ['yaml'], '.yml': ['yaml'], '.json': ['json'], '.sql': ['sql'], '.sol': ['solidity'], '.sh': ['bash'],
    '.go': ['go'], '.java': ['java'], '.rs': ['rust'], '.c': ['c'], '.h': ['c', 'cpp'], '.cpp': ['cpp'], '.hpp': ['cpp'], '.cc': ['cpp'],
    '.kt': ['kotlin'], '.kts': ['kotlin'], '.swift': ['swift'], '.m': ['objc'], '.mm': ['objc'], '.cs': ['csharp'],
    '.rb': ['ruby'], '.php': ['php'], '.dart': ['dart'], '.ex': ['elixir'], '.exs': ['elixir'], '.tf': ['terraform', 'hcl'], '.hcl': ['hcl'],
    '.html': ['html'], '.htm': ['html'], '.xhtml': ['html'], '.vue': ['vue'], '.xml': ['xml'],
    '.svelte': ['svelte'], '.astro': ['astro'], '.pug': ['pug'], '.jade': ['pug'], '.hbs': ['handlebars'], '.handlebars': ['handlebars'],
    '.ejs': ['ejs'], '.erb': ['erb'], '.haml': ['haml'], '.slim': ['slim'], '.mustache': ['mustache'], '.twig': ['twig'], '.liquid': ['liquid'],
    '.jinja': ['jinja'], '.jinja2': ['jinja'], '.j2': ['jinja'], '.njk': ['nunjucks'], '.nunjucks': ['nunjucks'], '.tpl': ['template'],
    '.jsp': ['jsp'], '.jspx': ['jsp'], '.cshtml': ['razor'], '.razor': ['razor'], '.aspx': ['aspx'], '.ascx': ['aspx'],
    '.toml': ['toml'], '.ini': ['ini'], '.properties': ['properties'], '.conf': ['config'], '.config': ['config'],
    '.key': ['pem'], '.pem': ['pem'], '.pub': ['pem'], '.npmrc': ['config'], '.yarnrc': ['config'],
  };
  const base = path.basename(file).toLowerCase();
  const profile = base === 'composer.lock' ? ['json']
    : /^(dockerfile|containerfile)(\..+)?$/.test(base) ? ['dockerfile']
    : /^\.env(?:\.|$)/.test(base) || ['.npmrc', '.yarnrc', '.htaccess'].includes(base) ? ['config'] : profiles[path.extname(file).toLowerCase()];
  return profile ? profile.some(language => languages.has(language)) : undefined;
}

function compareFindings(left, right) {
  return left.file.localeCompare(right.file)
    || left.line - right.line
    || left.end_line - right.end_line
    || left.rule_id.localeCompare(right.rule_id)
    || left.message.localeCompare(right.message);
}

function relativePath(root, file) {
  return path.relative(root, file).replaceAll(path.sep, '/');
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function normalizeFinding(result, prepared) {
  const file = normalizeResultFile(result?.path, prepared);
  const start = result?.start?.line;
  const end = result?.end?.line ?? start;
  const lineCount = fs.readFileSync(file, 'utf8').split(/\r?\n/).length;
  if (!Number.isInteger(start) || !Number.isInteger(end) || start < 1 || end < start || end > lineCount) {
    throw new Error(`Semgrep finding line range가 잘못됐다: ${result?.path}:${start}-${end}`);
  }
  return {
    rule_id: String(result.check_id || ''),
    file: path.relative(prepared.targetRoot, file).replaceAll(path.sep, '/'),
    line: start,
    end_line: end,
    severity: normalizeSeverity(result.extra?.severity),
    message: String(result.extra?.message || ''),
    cwe: extractCwe(result),
  };
}

function normalizeScannedPath(value, prepared) {
  if (typeof value !== 'string') throw new Error('Semgrep scanned path가 문자열이 아니다');
  return path.relative(prepared.targetRoot, normalizeResultFile(value, prepared)).replaceAll(path.sep, '/');
}

function normalizeResultFile(value, prepared) {
  if (typeof value !== 'string' || value.length === 0) throw new Error('Semgrep result path가 없다');
  const candidate = fs.realpathSync(path.isAbsolute(value) ? value : path.resolve(prepared.targetRoot, value));
  if (!isWithin(prepared.targetRoot, candidate) || !prepared.allowedFiles.has(candidate)) {
    throw new Error(`Semgrep result path가 allow-list 밖이다: ${value}`);
  }
  return candidate;
}

function isWithin(root, candidate) {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

function processOptions(timeout) {
  return {
    timeout,
    maxBuffer: 10 * 1024 * 1024,
    env: { ...process.env, SEMGREP_SEND_METRICS: 'off', SEMGREP_ENABLE_VERSION_CHECK: '0' },
  };
}

function failure(status, error, receipt) {
  return { ok: false, status, error, findings: [], stats: {}, ...(receipt ? { receipt } : {}) };
}

function digest(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function normalizeSeverity(sev) {
  if (!sev) return 'INFO';
  const upper = sev.toUpperCase();
  if (upper === 'ERROR') return 'HIGH';
  if (upper === 'WARNING') return 'MEDIUM';
  if (upper === 'INFO') return 'LOW';
  return upper;
}

function extractCwe(result) {
  const metadata = result.extra?.metadata || {};
  if (metadata.cwe) {
    const cwes = Array.isArray(metadata.cwe) ? metadata.cwe : [metadata.cwe];
    return cwes.map(c => typeof c === 'string' ? c.match(/CWE-\d+/)?.[0] : null).filter(Boolean);
  }
  return [];
}

module.exports = {
  runSemgrep,
  isSemgrepInstalled,
};
