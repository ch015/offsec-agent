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
