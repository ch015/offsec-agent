'use strict';

const { execFile } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

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

function runSemgrep(targetPath, options = {}) {
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

      const args = ['scan', '--metrics=off', '--json'];
      for (const config of prepared.rulePaths) args.push('--config', config);
      if (severity) args.push('--severity', severity);
      args.push(...prepared.files);

      execFileImpl(executable, args, processOptions(timeout), (err, stdout, stderr) => {
        if (err && !stdout) {
          resolve(failure(err.killed ? 'timeout' : 'execution-failed', err.message, {
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

          const stats = {
            files_requested: prepared.files.length,
            files_scanned: scanned.length,
            rules_applied: new Set(normalized.map(f => f.rule_id)).size,
            raw_total_findings: normalized.length,
            retained_findings: findings.length,
            truncated: normalized.length > findings.length,
          };

          resolve({
            ok: true,
            status: 'complete',
            findings,
            stats,
            receipt: {
              version,
              executable,
              manifestSha256: prepared.manifestSha256,
              ruleSha256: prepared.manifest.rules.map(rule => rule.sha256),
              requestedFilesSha256: digest(prepared.relativeFiles.join('\n')),
              requestedContentSha256: prepared.requestedContentSha256,
              requestedFiles: prepared.fileReceipts,
              stdoutSha256: digest(String(stdout)),
              stderrSha256: digest(String(stderr || '')),
              exitCode: err && typeof err.code === 'number' ? err.code : 0,
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
  };
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
    env: { ...process.env, SEMGREP_SEND_METRICS: 'off' },
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
