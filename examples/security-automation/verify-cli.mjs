import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import locations from './paths.cjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const read = file => JSON.parse(fs.readFileSync(file, 'utf8'));
const sha = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const cli = (...args) => execFileSync('bash', [path.join(here, 'demo.sh'), ...args], { encoding: 'utf8', timeout: 10000, env: { ...process.env, ANTHROPIC_API_KEY: '' } });
const checks = [];
assert.match(cli(), /CLI 시연/); checks.push('default command shows CLI help without launching a UI');
assert.match(cli('prompt'), /\$ch015-va/); checks.push('code-pentester native skill prompt is available');
assert.match(cli('status'), /offsec/); checks.push('CLI status command');

const recordings = read(path.join(here, 'recordings/index.json'));
for (const kind of ['code', 'web', 'offsec', 'soc']) {
  const latest = JSON.parse(cli('show', kind, '--json'));
  assert.equal(latest.status, 'completed', `${kind} live result`);
  const saved = JSON.parse(cli('show', kind, '--recorded', '--json'));
  assert.equal(saved.status, 'completed');
  assert.equal(saved.source, 'recording');
  assert.equal(saved.directory, latest.directory);
  assert.match(cli('show', kind, '--recorded'), /저장된 실제 실행 기록/);
  if (saved.artifactSha256) assert.equal(saved.artifactSha256, sha(saved.artifact));
}
checks.push('four actual completed runs can be shown as JSON and labeled recordings without an API key');

assert(recordings.code.contextAvailable);
assert.equal(recordings.code.stats.files_parsed, 2);
checks.push('code-pentester real AST context and two parsed source files');
assert.deepEqual(recordings.web.requests.map(r => r.status), [200, 200, 403]);
assert.equal(recordings.web.requests[1].body.owner, 'bob');
checks.push('real HTTP evidence: own invoice 200, other invoice 200, fixed route 403');

const soc = recordings.soc;
assert(soc.modelCalls > 0 && soc.calls.length > 0);
assert(soc.assessment.summary.startsWith(soc.countSentence));
assert.deepEqual(soc.counts, { total: 3, own: 1, other: 2, otherSuccess: 1, otherDenied: 1 });
assert.deepEqual(soc.assessment.mitreTactics, []);
for (const text of [soc.assessment.title, soc.assessment.summary, ...soc.assessment.findings.map(f => f.description), ...Object.values(soc.assessment.recommendation).filter(Boolean)]) assert.match(text, /[가-힣]/);
const evidence = new Set([`signal:${soc.signal.signalId}`, ...soc.observations.filter(o => o.ok && !o.truncated).map(o => o.evidenceId)]);
for (const finding of soc.assessment.findings) for (const id of finding.evidence) assert(evidence.has(id));
checks.push('real SOC model: Korean assessment, observed counts, valid evidence IDs, no unsupported ATT&CK mapping');

const offsec = recordings.offsec;
assert.equal(offsec.publicationStatus, 'published');
assert(offsec.findings.some(f => f.evidence.some(e => e.path === 'server.mjs')));
assert.match(cli('show', 'offsec', '--recorded'), /송장|IDOR/);
const engagement = path.join(offsec.directory, 'engagement');
const state = read(path.join(engagement, 'run-state.json'));
const attempts = Object.values(state.attempts);
for (const phase of ['analyze', 'review', 'evaluate', 'report']) {
  assert(attempts.some(a => a.phase === phase && a.status === 'completed' && a.usage.accountingComplete && a.usage.modelIdentityVerified), `${phase}: complete real provider receipt`);
}
const events = fs.readFileSync(path.join(engagement, 'run-events.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
const reviewEnd = events.findLast(e => e.phase === 'review' && e.type === 'phase.completed');
const reviewStart = events.findLast(e => e.phase === 'review' && e.type === 'phase.started' && e.attempt === reviewEnd.attempt);
const ledger = fs.readFileSync(path.join(engagement, 'host-ledger.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
const canonicalPath = file => fs.realpathSync(file);
const sourceReads = ledger.filter(e => e.at >= reviewStart.at && e.at <= reviewEnd.at && e.tool === 'Read' && e.decision === 'allow' && e.resource && fs.existsSync(e.resource) && canonicalPath(e.resource).startsWith(canonicalPath(path.join(here, 'fixture')) + path.sep)).map(e => e.resource);
assert(sourceReads.some(file => canonicalPath(file) === canonicalPath(path.join(here, 'fixture/server.mjs'))));
checks.push('OffSec: four actual model phases, publication gate passed, reviewer source Read in the review interval');

const evaluation = read(path.join(engagement, '04_evaluation.json'));
for (const severity of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']) {
  assert.equal(evaluation.severityDistribution[severity], offsec.findings.filter(f => f.severity === severity).length);
}
checks.push('OffSec canonical finding severities match the published evaluation counts');

const revisions = {};
for (const [kind, cwd] of Object.entries(locations.repos)) {
  revisions[kind] = {
    baseCommit: execFileSync('git', ['rev-parse', 'HEAD'], { cwd, encoding: 'utf8' }).trim(),
    worktreeChanges: execFileSync('git', ['status', '--porcelain'], { cwd, encoding: 'utf8' }).trim().split('\n').filter(Boolean),
  };
}
const result = { passed: true, at: new Date().toISOString(), checks, revisions,
  runs: Object.fromEntries(Object.entries(recordings).map(([kind, r]) => [kind, { started: r.started, finished: r.finished, directory: r.directory, source: 'actual execution', artifactSha256: r.artifactSha256 }])),
  offsec: { publicationStatus: offsec.publicationStatus, sourceReads: [...new Set(sourceReads)], findings: offsec.findings.length, totalCostUsd: state.totalCostUsd },
  soc: { modelCalls: soc.modelCalls, toolCalls: soc.calls.length, counts: soc.counts },
  scope: ['Code: AST preprocessing; native agent invocation is supplied separately.', 'Web: loopback HTTP replay; actual Electron/Rust app proof is in .runtime/web-demo-proof.json.', 'OffSec: real model API and publication gate with local fixes.', 'SOC: real model with local synthetic data adapter; no production SIEM or messaging.'],
};
fs.writeFileSync(path.join(here, 'verification.json'), JSON.stringify(result, null, 2));
console.log(JSON.stringify({ passed: true, checks, report: path.join(here, 'verification.json') }, null, 2));
