'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { describe, it } = require('node:test');

const { runSemgrep } = require('../semgrep');

const MANIFEST = path.resolve(__dirname, '../../../../rules/semgrep/manifest.json');

function fixture() {
  const target = fs.mkdtempSync(path.join(os.tmpdir(), 'nunchi-semgrep-'));
  const source = path.join(target, 'app.js');
  fs.writeFileSync(source, 'eval(input);\n', 'utf8');
  return { target, source };
}

function runner(output, version = '1.157.0') {
  const calls = [];
  const execFileImpl = (command, args, options, callback) => {
    calls.push({ command, args, options });
    if (args[0] === '--version') callback(null, `${version}\n`, '');
    else callback(null, JSON.stringify(output), 'diagnostic');
  };
  return { calls, execFileImpl };
}

describe('trusted Semgrep runner', () => {
  it('accounts for syntax warnings and files without rules without claiming clean scanning', async () => {
    const { target, source } = fixture(), solidity = path.join(target, 'contract.sol'); fs.writeFileSync(solidity, 'contract Example {}');
    const mock = runner({ results: [], paths: { scanned: [source] }, errors: [{ path: source, code: 3, level: 'warn', type: 'Syntax error', message: 'incomplete fragment' }] });
    const result = await runSemgrep(target, { manifestPath: MANIFEST, files: [source, solidity], execFileImpl: mock.execFileImpl });
    assert.equal(result.status, 'complete');
    assert.deepEqual(result.fileCoverage.map(file => [file.file, file.status]), [['app.js', 'partial'], ['contract.sol', 'no-applicable-rule']]);
    assert.equal(result.receipt.diagnostics.length, 1);
    assert.deepEqual(result.receipt.fileCoverage, result.fileCoverage);
  });

  it('does not accept fatal diagnostics, timeouts with JSON stdout, or missing applicable targets', async () => {
    const { target, source } = fixture();
    for (const defect of ['fatal', 'timeout', 'missing']) {
      const output = { results: [], paths: { scanned: defect === 'missing' ? [] : [source] }, errors: defect === 'fatal' ? [{ path: source, code: 2, level: 'error', type: 'Timeout', message: 'failed' }] : [] };
      const mock = runner(output);
      const run = (command, args, options, callback) => {
        if (defect === 'timeout' && args[0] !== '--version') return callback(Object.assign(new Error('timed out'), { killed: true, code: 'ETIMEDOUT' }), JSON.stringify(output), '');
        mock.execFileImpl(command, args, options, callback);
      };
      const result = await runSemgrep(target, { manifestPath: MANIFEST, files: [source], execFileImpl: run });
      assert.equal(result.ok, false, defect); assert.equal(result.status, 'incomplete', defect);
      if (defect === 'timeout') assert.equal(result.receipt.exitCode, null);
    }
  });

  it('accounts for templates and configuration without matching pinned rules', async () => {
    const { target } = fixture();
    const files = ['component.html', 'view.pug', 'view.hbs', 'App.vue', 'App.svelte', '.npmrc', 'nginx.conf', 'secret.key'].map(name => {
      const file = path.join(target, name); fs.writeFileSync(file, 'text'); return file;
    });
    const mock = runner({ results: [], paths: { scanned: [] } });
    const result = await runSemgrep(target, { manifestPath: MANIFEST, files, execFileImpl: mock.execFileImpl });
    assert.equal(result.ok, true);
    assert.ok(result.fileCoverage.every(file => file.status === 'no-applicable-rule'));
  });

  it('accounts for SQL migrations and Composer lockfiles without claiming they were scanned', async () => {
    const { target } = fixture();
    const files = ['schema.sql', 'composer.lock'].map(name => {
      const file = path.join(target, name); fs.writeFileSync(file, name.endsWith('.sql') ? 'SELECT 1;' : '{"packages": []}'); return file;
    });
    const mock = runner({ results: [], paths: { scanned: [] } });
    const result = await runSemgrep(target, { manifestPath: MANIFEST, files, execFileImpl: mock.execFileImpl });
    assert.equal(result.ok, true);
    assert.equal(result.stats.files_scanned, 0);
    assert.ok(result.fileCoverage.every(file => file.status === 'no-applicable-rule'));
    // Unknown extensions must remain unresolved, including other .lock formats.
    const unknown = path.join(target, 'unknown.lock'); fs.writeFileSync(unknown, 'unknown content');
    const uncertain = await runSemgrep(target, { manifestPath: MANIFEST, files: [unknown], execFileImpl: mock.execFileImpl });
    assert.equal(uncertain.ok, false);
    assert.equal(uncertain.fileCoverage[0].status, 'unaccounted');
    fs.rmSync(target, { recursive: true, force: true });
  });

  it('batches large file lists, merges before the global cap, and accounts for every requested file', async () => {
    const { target } = fixture();
    const files = Array.from({ length: 300 }, (_, index) => {
      const file = path.join(target, `source-${String(index).padStart(3, '0')}.js`); fs.writeFileSync(file, 'eval(input);\n'); return file;
    });
    const batches = [];
    const execFileImpl = (_command, args, _options, callback) => {
      if (args[0] === '--version') return callback(null, '1.157.0', '');
      const sources = args.filter(arg => files.map(file => fs.realpathSync(file)).includes(arg)); batches.push(sources);
      callback(null, JSON.stringify({ results: sources.map((file, index) => ({ check_id: `rule-${index}`, path: file, start: { line: 1 }, extra: {} })), paths: { scanned: sources } }), '');
    };
    const result = await runSemgrep(target, { manifestPath: MANIFEST, files: files.reverse(), maxFindings: 2, execFileImpl });
    assert.equal(result.ok, true); assert.equal(batches.length, 3);
    assert.ok(batches.every(batch => batch.length <= 128));
    assert.equal(result.stats.raw_total_findings, 300); assert.equal(result.findings.length, 2);
    assert.equal(result.stats.rules_applied, 128); assert.equal(result.stats.truncated, true);
    assert.equal(result.fileCoverage.length, 300); assert.ok(result.fileCoverage.every(file => file.status === 'scanned'));
    assert.equal(result.receipt.batches.length, 3); assert.equal(result.receipt.requestedFiles.length, 300);
    assert.equal(result.findings[0].file, 'source-000.js');
    fs.rmSync(target, { recursive: true, force: true });
  });

  it('bounds command argument bytes and preserves failure plus unexecuted batch coverage', async () => {
    const { target } = fixture(), nested = path.join(target, 'directory-'.repeat(22)); fs.mkdirSync(nested);
    const files = Array.from({ length: 210 }, (_, index) => {
      const file = path.join(nested, `${'source-'.repeat(20)}${index}.js`); fs.writeFileSync(file, 'eval(input);'); return file;
    });
    let scans = 0;
    const execFileImpl = (_command, args, _options, callback) => {
      if (args[0] === '--version') return callback(null, '1.157.0', '');
      const sources = args.filter(arg => arg.endsWith('.js'));
      assert.ok(sources.reduce((sum, file) => sum + Buffer.byteLength(file) + 3, 0) <= 24_000);
      scans++;
      if (scans === 2) return callback(Object.assign(new Error('tool failed'), { code: 2 }), '', 'tool failed');
      callback(null, JSON.stringify({ results: [], paths: { scanned: sources } }), '');
    };
    const result = await runSemgrep(target, { manifestPath: MANIFEST, files, execFileImpl });
    assert.equal(result.ok, false); assert.equal(scans, 2);
    assert.equal(result.fileCoverage.length, 210); assert.ok(result.fileCoverage.some(file => file.status === 'unaccounted'));
    assert.equal(result.receipt.batches[1].receipt.exitCode, 2); assert.match(result.error, /tool failed/);
    fs.rmSync(target, { recursive: true, force: true });
  });

  it('uses hash-pinned local rules, explicit files, and preserves raw totals', async () => {
    const { target, source } = fixture();
    const resultEntry = {
      check_id: 'nunchi.code.dynamic-evaluation',
      path: source,
      start: { line: 1 },
      end: { line: 1 },
      extra: { severity: 'ERROR', message: 'candidate', metadata: { cwe: ['CWE-95'] } },
    };
    const mock = runner({ results: [resultEntry, resultEntry], paths: { scanned: [source] } });
    const result = await runSemgrep(target, {
      manifestPath: MANIFEST,
      files: [source],
      maxFindings: 1,
      execFileImpl: mock.execFileImpl,
    });
    assert.equal(result.ok, true);
    assert.deepEqual(result.stats, {
      files_requested: 1,
      files_scanned: 1,
      rules_applied: 1,
      raw_total_findings: 2,
      retained_findings: 1,
      truncated: true,
    });
    assert.equal(result.receipt.version, '1.157.0');
    const scan = mock.calls[1];
    assert.ok(scan.args.includes('--metrics=off'));
    assert.ok(scan.args.includes(fs.realpathSync(source)));
    assert.ok(scan.args.every(arg => !String(arg).startsWith('p/')));
    assert.equal(scan.options.env.SEMGREP_SEND_METRICS, 'off');
    assert.equal(scan.options.env.SEMGREP_ENABLE_VERSION_CHECK, '0');
  });

  it('rejects findings outside the sealed explicit file list', async () => {
    const { target, source } = fixture();
    const sibling = path.join(target, 'sibling.js');
    fs.writeFileSync(sibling, 'eval(other);\n', 'utf8');
    const mock = runner({
      results: [{
        check_id: 'rule', path: sibling, start: { line: 1 }, end: { line: 1 }, extra: {},
      }],
      paths: { scanned: [source] },
    });
    const result = await runSemgrep(target, {
      manifestPath: MANIFEST,
      files: [source],
      execFileImpl: mock.execFileImpl,
    });
    assert.equal(result.status, 'invalid-output');
    assert.match(result.error, /allow-list/);
  });

  it('fails closed on executable version drift', async () => {
    const { target, source } = fixture();
    const mock = runner({ results: [], paths: { scanned: [source] } }, '1.999.0');
    const result = await runSemgrep(target, {
      manifestPath: MANIFEST,
      files: [source],
      execFileImpl: mock.execFileImpl,
    });
    assert.equal(result.status, 'version-mismatch');
    assert.match(result.error, /1\.999\.0/);
    assert.equal(mock.calls.length, 1);
  });

  it('sorts inputs and findings before truncation and binds source bytes in the receipt', async () => {
    const { target, source } = fixture();
    const second = path.join(target, 'z.js');
    fs.writeFileSync(second, 'eval(other);\n', 'utf8');
    const entries = [second, source, second].map((file, index) => ({
      check_id: `rule-${index}`,
      path: file,
      start: { line: 1 },
      end: { line: 1 },
      extra: { severity: 'WARNING', message: `candidate-${index}`, metadata: {} },
    }));
    const firstMock = runner({ results: entries, paths: { scanned: [second, source] } });
    const secondMock = runner({ results: entries.slice().reverse(), paths: { scanned: [source, second] } });
    const options = { manifestPath: MANIFEST, files: [second, source], maxFindings: 2 };
    const first = await runSemgrep(target, { ...options, execFileImpl: firstMock.execFileImpl });
    const secondRun = await runSemgrep(target, { ...options, files: [source, second], execFileImpl: secondMock.execFileImpl });
    assert.deepEqual(first.findings, secondRun.findings);
    assert.deepEqual(first.receipt.requestedFiles, secondRun.receipt.requestedFiles);
    assert.equal(first.receipt.requestedContentSha256, secondRun.receipt.requestedContentSha256);
    assert.deepEqual(firstMock.calls[1].args.slice(-2), [fs.realpathSync(source), fs.realpathSync(second)]);

    fs.writeFileSync(second, 'eval(changed);\n', 'utf8');
    const changedMock = runner({ results: [], paths: { scanned: [source, second] } });
    const changed = await runSemgrep(target, { ...options, execFileImpl: changedMock.execFileImpl });
    assert.notEqual(changed.receipt.requestedContentSha256, first.receipt.requestedContentSha256);
  });
});
