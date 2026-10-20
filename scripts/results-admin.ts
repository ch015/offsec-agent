import { closeSync, constants, fsyncSync, mkdirSync, openSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { auditResultRecords, renderResultAudit } from '../src/runtime/result-audit.js';
import { appendReviewNote, appendReviewNoteBatch } from '../src/runtime/review-notes.js';
import { planManualReview } from '../src/runtime/manual-review.js';
import { createManualResponseTemplate, readManualReviewStatus, renderManualReviewStatus } from '../src/runtime/manual-review-view.js';
import { collectReviewSubmissions, readReviewConflicts, ReviewCollectionOptionsSchema } from '../src/runtime/review-intake.js';
import { contentHash } from '../src/runtime/result-records.js';
import { scoreDiagnosticQuality } from '../src/runtime/diagnostic-quality.js';
import { managedPath } from '../src/runtime/workflow/storage-files.js';
import { loadConfig } from '../src/runtime/config.js';
import { createPostgresPool } from '../src/runtime/workflow/database.js';
import { PostgresResultStore, type ResultStateSource } from '../src/runtime/postgres-results.js';

const usage = 'Usage: pnpm results:admin <inspect|note|note-batch|notes-import|review-plan|review-status|review-response-template|review-collect|review-conflicts|quality> --engagement=<dir> | --input=<json> [--config=<file>] [--state-backend=file|postgres --run-id=<id>] [--expected-head=<hash|empty>] [--assignee=<label>] [--assignment=<id> --note-id=<new-id>] [--mode=human|unattended] [--concurrency=1..16] [--format=json|markdown] [--output=<new-file-outside-engagement>]';
export async function runResultAdmin(argv: readonly string[]): Promise<number> {
  const [command, ...rest] = argv;
  const allowed: Record<string, string[]> = {
    inspect: ['engagement', 'format', 'output', 'config', 'state-backend', 'run-id'],
    note: ['engagement', 'input', 'expected-head', 'config', 'state-backend', 'run-id'],
    'note-batch': ['engagement', 'input', 'expected-head', 'config', 'state-backend', 'run-id'],
    'review-plan': ['input', 'output'],
    'review-status': ['engagement', 'assignee', 'format', 'output', 'config', 'state-backend', 'run-id'],
    'review-response-template': ['engagement', 'assignment', 'note-id', 'output', 'config', 'state-backend', 'run-id'],
    'review-collect': ['engagement', 'input', 'mode', 'concurrency', 'output', 'config', 'state-backend', 'run-id'],
    'review-conflicts': ['engagement', 'mode', 'output', 'config', 'state-backend', 'run-id'],
    'notes-import': ['engagement', 'config', 'state-backend', 'run-id'], quality: ['input', 'output'],
  };
  if (!command || !allowed[command]) throw new Error(usage);
  const flags = new Map<string, string>();
  for (const arg of rest) {
    const match = /^--([^=]+)=(.+)$/.exec(arg);
    if (!match || !allowed[command]!.includes(match[1]!) || flags.has(match[1]!)) throw new Error(usage);
    flags.set(match[1]!, match[2]!);
  }
  const required = (name: string) => { const value = flags.get(name); if (!value) throw new Error(`--${name} is required. ${usage}`); return value; };
  let body: string, exitCode = 0, engagement: string | undefined;
  if (command === 'review-plan') {
    body = JSON.stringify(planManualReview(JSON.parse(readFileSync(resolve(required('input')), 'utf8'))), null, 2) + '\n';
  } else if (command === 'quality') {
    const bytes = readFileSync(resolve(required('input'))), result = scoreDiagnosticQuality(JSON.parse(bytes.toString('utf8')));
    body = JSON.stringify({ schemaVersion: 1, inputSha256: contentHash(bytes), ...result,
      inputNotice: 'Judgments and provenance flags are supplied by the input author, not independently verified by this command.' }, null, 2) + '\n';
    exitCode = result.gate.passed ? 0 : 2;
  } else {
    engagement = realpathSync(resolve(required('engagement')));
    const config = loadConfig(flags.get('config'));
    const backend = flags.get('state-backend') ?? config.runtime.backend;
    if (!['file', 'postgres'].includes(backend)) throw new Error('--state-backend must be file or postgres');
    if (backend === 'file' && flags.has('run-id')) throw new Error('--run-id requires --state-backend=postgres');
    const source: ResultStateSource = backend === 'postgres' ? { backend, runId: required('run-id') } : { backend: 'file' };
    if (config.results.backend === 'file' && (source.backend === 'postgres' || command === 'notes-import')) throw new Error('Set results.backend to postgres in the config for PostgreSQL results or notes-import');
    const pool = config.results.backend === 'postgres' ? createPostgresPool(process.env, config.database) : undefined;
    pool?.on('error', () => undefined);
    const store = pool ? new PostgresResultStore(pool) : undefined;
    try {
      if (command === 'note' || command === 'note-batch') {
        const input = JSON.parse(readFileSync(resolve(required('input')), 'utf8')), head = required('expected-head');
        const result = command === 'note-batch'
          ? store ? await store.appendBatch(engagement, input, head, source) : appendReviewNoteBatch(engagement, input, head)
          : store ? await store.append(engagement, input, head, source) : appendReviewNote(engagement, input, head);
        body = JSON.stringify(result, null, 2) + '\n';
      } else if (command === 'notes-import') {
        body = JSON.stringify(await store!.importNotes(engagement, source), null, 2) + '\n';
      } else if (command === 'review-collect' || command === 'review-conflicts') {
        const rawConcurrency = flags.get('concurrency');
        if (rawConcurrency !== undefined && !/^[1-9][0-9]*$/.test(rawConcurrency)) throw new Error('--concurrency must be an integer from 1 to 16');
        const options = ReviewCollectionOptionsSchema.parse({ mode: flags.get('mode'), concurrency: rawConcurrency === undefined ? undefined : Number(rawConcurrency) });
        if (command === 'review-collect') {
          const input = resolve(required('input'));
          const result = store ? await store.collect(engagement, input, options, source) : await collectReviewSubmissions(engagement, input, options);
          body = JSON.stringify(result, null, 2) + '\n'; exitCode = result.requiresAction ? 2 : 0;
        } else {
          const result = store ? await store.conflicts(engagement, options.mode, source) : readReviewConflicts(engagement, options.mode);
          body = JSON.stringify(result, null, 2) + '\n'; exitCode = result.openCount ? 2 : 0;
        }
      } else if (command === 'review-response-template') {
        const assignment = required('assignment'), noteId = required('note-id');
        const packet = store ? await store.responseTemplate(engagement, assignment, noteId, source)
          : createManualResponseTemplate(engagement, assignment, noteId);
        body = JSON.stringify(packet, null, 2) + '\n';
      } else if (command === 'review-status') {
        const format = flags.get('format') ?? 'json';
        if (!['json', 'markdown'].includes(format)) throw new Error('--format must be json or markdown');
        const view = store ? await store.reviewStatus(engagement, flags.get('assignee'), source)
          : readManualReviewStatus(engagement, flags.get('assignee'));
        body = format === 'markdown' ? renderManualReviewStatus(view) : JSON.stringify(view, null, 2) + '\n';
        // Status is a successful read even when work remains. It is not a quality gate.
      } else {
        const format = flags.get('format') ?? 'json';
        if (!['json', 'markdown'].includes(format)) throw new Error('--format must be json or markdown');
        const audit = store ? await store.inspect(engagement, source) : auditResultRecords(engagement);
        body = format === 'markdown' ? renderResultAudit(audit) : JSON.stringify(audit, null, 2) + '\n';
        exitCode = audit.issues.length || audit.coverage.finalRecordedComplete !== true ? 2 : 0;
      }
    } finally { await pool?.end(); }
  }
  const output = flags.get('output');
  if (output) {
    const path = resolve(output);
    managedPath(dirname(path), path);
    if (engagement) {
      const rel = relative(engagement, path);
      if (!isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${sep}`)) throw new Error('Audit export must be outside the engagement; sealed artifacts cannot be overwritten');
    }
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    const fd = openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    try { writeFileSync(fd, body); fsyncSync(fd); } finally { closeSync(fd); }
    process.stdout.write(`Written: ${path}\n`);
  } else process.stdout.write(body);
  return exitCode;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { process.exitCode = await runResultAdmin(process.argv.slice(2)); }
  catch (error) { console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 1; }
}
