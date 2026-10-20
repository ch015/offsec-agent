import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { manualReviewFixture } from './fixtures/manual-review.js';
import { appendReviewNote, appendReviewNoteBatch, REVIEW_NOTES_FILE } from '../review-notes.js';
import { mediationFor, opinionFor, writeIntake } from './fixtures/review-intake.js';
const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
const script = resolve(import.meta.dirname, '../../../scripts/results-admin.ts');
const run = (...args: string[]) => spawnSync(process.execPath, ['--import', 'tsx', script, ...args], { encoding: 'utf8' });
function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'results-admin-')); roots.push(root);
  const input = join(root, 'quality.json'), output = join(root, 'score.json');
  const value = { project: 'synthetic', runId: 'fixture', truthCauseIds: [], predictionIds: [], judgments: [],
    negativeControls: [{ id: 'negative', result: 'pass', rationale: 'Human-authored fixture has no protected operation.' }],
    executionComplete: true, sourceDeliveryComplete: true, independentCountingComplete: true, frozenTruthVerified: true };
  writeFileSync(input, JSON.stringify(value));
  return { input, output, value };
}
it('scores supplied adjudication offline with distinct gate and input failure exits', () => {
  const f = fixture();
  const passed = run('quality', `--input=${f.input}`, `--output=${f.output}`);
  expect(passed.status, passed.stderr).toBe(0);
  expect(JSON.parse(readFileSync(f.output, 'utf8'))).toMatchObject({ inputSha256: expect.stringMatching(/^[a-f0-9]{64}$/), gate: { passed: true } });
  writeFileSync(f.input, JSON.stringify({ ...f.value, executionComplete: false }));
  const failed = run('quality', `--input=${f.input}`);
  expect(failed.status).toBe(2);
  expect(JSON.parse(failed.stdout).gate.failures).toContain('execution-incomplete');
  writeFileSync(f.input, '{}');
  expect(run('quality', `--input=${f.input}`).status).toBe(1);
});
it('refuses existing exports and unknown or duplicate CLI options', () => {
  const f = fixture(); writeFileSync(f.output, 'preserved');
  expect(run('quality', `--input=${f.input}`, `--output=${f.output}`).status).toBe(1);
  expect(readFileSync(f.output, 'utf8')).toBe('preserved');
  expect(run('quality', `--input=${f.input}`, '--resume=true').status).toBe(1);
  expect(run('quality', `--input=${f.input}`, `--input=${f.input}`).status).toBe(1);
});

it('previews and atomically registers a manual review plan without a provider or database', () => {
  const base = realpathSync(mkdtempSync(join(tmpdir(), 'manual-review-cli-'))); roots.push(base);
  const f = manualReviewFixture(base), input = join(base, 'plan-input.json'), output = join(base, 'plan.json'), config = join(base, 'config.json');
  writeFileSync(input, JSON.stringify(f.input)); writeFileSync(config, '{"version":1}');
  const plan = run('review-plan', `--input=${input}`, `--output=${output}`);
  expect(plan.status, plan.stderr).toBe(0);
  expect(JSON.parse(readFileSync(output, 'utf8'))).toEqual(f.batch);
  const saved = run('note-batch', `--input=${output}`, `--engagement=${f.root}`, `--config=${config}`, '--expected-head=empty');
  expect(saved.status, saved.stderr).toBe(0); expect(JSON.parse(saved.stdout).insertedCount).toBe(2);
  const retry = run('note-batch', `--input=${output}`, `--engagement=${f.root}`, `--config=${config}`, '--expected-head=empty');
  expect(retry.status).toBe(0); expect(JSON.parse(retry.stdout).insertedCount).toBe(0);
  const audit = run('inspect', `--engagement=${f.root}`, `--config=${config}`);
  expect(audit.status).toBe(2); expect(JSON.parse(audit.stdout).notes.manualReviews).toMatchObject({ assignmentCount: 2, openCount: 2 });
});

it('exports filtered status and an editable response packet without modifying the engagement', () => {
  const base = realpathSync(mkdtempSync(join(tmpdir(), 'manual-view-cli-'))); roots.push(base);
  const f = manualReviewFixture(base), config = join(base, 'config.json'); writeFileSync(config, '{"version":1}');
  const first = appendReviewNoteBatch(f.root, f.batch, 'empty'), before = readFileSync(join(f.root, REVIEW_NOTES_FILE));
  const flags = [`--engagement=${f.root}`, `--config=${config}`];
  const status = run('review-status', ...flags, '--assignee=reader-a');
  expect(status.status, status.stderr).toBe(0);
  expect(JSON.parse(status.stdout)).toMatchObject({ global: { assignmentCount: 2, openCount: 2 }, selected: { assignmentCount: 1, openCount: 1 } });
  const empty = run('review-status', ...flags, '--assignee=unknown');
  expect(empty.status).toBe(0); expect(JSON.parse(empty.stdout).selected.allAccepted).toBeNull();
  const markdown = run('review-status', ...flags, '--format=markdown');
  expect(markdown.status).toBe(0); expect(markdown.stdout).toContain('미종결 2건');
  expect(run('review-status', ...flags, '--format=html').status).toBe(1);
  const output = join(base, 'packet.json');
  const packetFlags = ['review-response-template', ...flags, '--assignment=DOC-0001', '--note-id=NEW-REPLY'];
  const exported = run(...packetFlags, `--output=${output}`);
  expect(exported.status, exported.stderr).toBe(0);
  const packet = JSON.parse(readFileSync(output, 'utf8'));
  expect(packet).toMatchObject({ expectedHead: first.head, note: { kind: 'review-response', results: [{ status: 'not-reviewed' }, { status: 'not-reviewed' }] } });
  expect(run(...packetFlags, `--output=${output}`).status).toBe(1);
  const inside = join(f.root, 'draft.json');
  expect(run(...packetFlags, `--output=${inside}`).status).toBe(1); expect(existsSync(inside)).toBe(false);
  expect(readFileSync(join(f.root, REVIEW_NOTES_FILE))).toEqual(before);
  // The metadata envelope is not accepted as a note by accident.
  expect(run('note', ...flags, `--input=${output}`, `--expected-head=${packet.expectedHead}`).status).toBe(1);
  const notePath = join(base, 'reply.json'); writeFileSync(notePath, JSON.stringify(packet.note));
  const saved = run('note', ...flags, `--input=${notePath}`, `--expected-head=${packet.expectedHead}`);
  expect(saved.status, saved.stderr).toBe(0);
});

it('finishes unattended intake with unresolved receipts and requires explicit mediation', () => {
  const base = realpathSync(mkdtempSync(join(tmpdir(), 'review-intake-cli-'))); roots.push(base);
  const f = manualReviewFixture(base), config = join(base, 'config.json'); writeFileSync(config, '{"version":1}');
  const a = appendReviewNote(f.root, opinionFor(f.input.files[0]!, 'A', 'support'), 'empty');
  const b = appendReviewNote(f.root, opinionFor(f.input.files[0]!, 'B', 'oppose'), a.head);
  const intake = writeIntake(f.root, join(base, 'inputs'), b.head, [opinionFor(f.input.files[0]!, 'C', 'uncertain'), '{']);
  const flags = [`--engagement=${f.root}`, `--config=${config}`], before = readFileSync(join(f.root, REVIEW_NOTES_FILE));
  const output = join(base, 'intake.json');
  const collected = run('review-collect', ...flags, `--input=${intake.input}`, '--mode=unattended', '--concurrency=2', `--output=${output}`);
  expect(collected.status, collected.stderr).toBe(2);
  expect(JSON.parse(readFileSync(output, 'utf8'))).toMatchObject({ processingComplete: true, persisted: false,
    decisionRouting: 'deferred', counts: { validated: 1, invalid: 1 } });
  expect(readFileSync(join(f.root, REVIEW_NOTES_FILE))).toEqual(before);
  const pending = run('review-conflicts', ...flags, '--mode=unattended');
  expect(pending.status).toBe(2); expect(JSON.parse(pending.stdout).pending).toHaveLength(1);
  expect(run('review-collect', ...flags, `--input=${intake.input}`, '--mode=auto').status).toBe(1);
  expect(run('review-collect', ...flags, `--input=${intake.input}`, '--concurrency=17').status).toBe(1);
  expect(run('review-collect', ...flags, `--input=${intake.input}`, `--output=${output}`).status).toBe(1);
  const decision = join(base, 'decision.json'); writeFileSync(decision, JSON.stringify(mediationFor([a.entry, b.entry], 'adopt')));
  const saved = run('note', ...flags, `--input=${decision}`, `--expected-head=${b.head}`);
  expect(saved.status, saved.stderr).toBe(0);
  const after = run('review-conflicts', ...flags);
  expect(after.status).toBe(0); expect(JSON.parse(after.stdout)).toMatchObject({ openCount: 0, conflictingGroupCount: 1 });
});
