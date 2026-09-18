import { randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  closeSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  writeFileSync,
  renameSync,
} from 'node:fs';
import { basename, dirname, join, relative, resolve } from 'node:path';
import { spawn, type ChildProcess } from 'node:child_process';

import { z } from 'zod';

import {
  assertBenchmarkCorpusIntact,
  assertBenchmarkNormalizationIntact,
  assertBenchmarkRunArtifactsIntact,
  assertBenchmarkSourceManifestIntact,
  benchmarkSha256,
  benchmarkStableJson,
  BenchmarkRunRecordSchema,
  NormalizedBenchmarkFindingSchema,
  type BenchmarkCorpus,
  type BenchmarkRunRecord,
  type BenchmarkSourceManifest,
  assertNoBenchmarkLeak,
  validateNormalizedBenchmarkFindings,
} from '../../src/runtime/offsec-benchmark.js';
import { normalizeCh015MarkdownFindings } from './adapters/ch015.js';
import { normalizeCurrentOffsecFindings } from './adapters/current.js';

const ExecutableArmSchema = z.enum(['ch015', 'current-sequential', 'current-parallel']);
const ExactModelSchema = z.string().min(1).refine(
  (value) => !['default', 'haiku', 'sonnet', 'opus', 'inherit'].includes(value.toLowerCase()),
  'benchmark model은 alias가 아닌 고정 model ID여야 한다',
);

export const BenchmarkRunnerOptionsSchema = z.object({
  corpusPath: z.string().min(1),
  sourceManifestPath: z.string().min(1),
  caseId: z.string().min(1),
  target: z.string().min(1),
  outputRoot: z.string().min(1),
  arms: z.array(ExecutableArmSchema).min(2),
  repetitions: z.number().int().positive(),
  provider: z.literal('anthropic'),
  model: ExactModelSchema,
  effort: z.enum(['low', 'medium', 'high', 'xhigh', 'max']),
  maxTurns: z.number().int().positive(),
  randomizationSeed: z.number().int().nonnegative(),
  semgrepMode: z.enum(['required', 'best-effort', 'off']),
  maxConcurrency: z.number().int().positive(),
  currentRoot: z.string().min(1),
  ch015PluginRoot: z.string().min(1),
  dryRun: z.boolean(),
}).strict().superRefine((value, context) => {
  const unique = new Set(value.arms);
  if (unique.size !== value.arms.length) {
    context.addIssue({ code: 'custom', path: ['arms'], message: 'benchmark arm은 중복될 수 없다' });
  }
  if (!unique.has('current-parallel') || (!unique.has('ch015') && !unique.has('current-sequential'))) {
    context.addIssue({
      code: 'custom', path: ['arms'],
      message: 'benchmark에는 current-parallel과 최소 하나의 사전 등록 baseline이 필요하다',
    });
  }
});

export type BenchmarkRunnerOptions = z.infer<typeof BenchmarkRunnerOptionsSchema>;

export type PlannedBenchmarkRun = Readonly<{
  caseId: string;
  repetition: number;
  arm: z.infer<typeof ExecutableArmSchema>;
  executionOrder: number;
}>;

const TASK_TEMPLATE = [
  'Perform a read-only, comprehensive source security assessment of the supplied repository.',
  'Analyze all source files in scope and use available static-analysis tools.',
  'Report only findings supported by exact source evidence; state uncertainty instead of guessing.',
  'Do not modify target source. Write assessment artifacts only to the supplied engagement directory.',
].join(' ');

export function planBenchmarkRuns(options: BenchmarkRunnerOptions): PlannedBenchmarkRun[] {
  const parsed = BenchmarkRunnerOptionsSchema.parse(options);
  const random = xorshift32(parsed.randomizationSeed);
  const planned: PlannedBenchmarkRun[] = [];
  let executionOrder = 0;
  for (let repetition = 1; repetition <= parsed.repetitions; repetition += 1) {
    const arms = [...new Set(parsed.arms)];
    for (let index = arms.length - 1; index > 0; index -= 1) {
      const selected = Math.floor(random() * (index + 1));
      [arms[index], arms[selected]] = [arms[selected]!, arms[index]!];
    }
    for (const arm of arms) {
      planned.push({ caseId: parsed.caseId, repetition, arm, executionOrder });
      executionOrder += 1;
    }
  }
  return planned;
}

export function buildArmCommand(input: {
  options: BenchmarkRunnerOptions;
  arm: PlannedBenchmarkRun['arm'];
  target: string;
  engagementDir: string;
}): { executable: string; args: string[]; cwd: string; prompt: string } {
  const { options, arm, target, engagementDir } = input;
  const prompt = `${TASK_TEMPLATE} Target: ${target}. Engagement directory: ${engagementDir}.`;
  if (arm === 'ch015') {
    return {
      executable: 'claude',
      cwd: target,
      prompt,
      args: [
        '--print',
        '--plugin-dir', options.ch015PluginRoot,
        '--model', options.model,
        '--effort', options.effort,
        '--max-turns', String(options.maxTurns),
        '--output-format', 'text',
        '--no-session-persistence',
        '--strict-mcp-config',
        '--setting-sources', '',
        '--dangerously-skip-permissions',
        '--add-dir', engagementDir,
        '--',
        `/ch015:va --target ${target} --mode ast\n\n${prompt}`,
      ],
    };
  }
  return {
    executable: 'pnpm',
    cwd: options.currentRoot,
    prompt,
    args: [
      '--dir', options.currentRoot,
      'assess', target, prompt,
      `--model=${options.model}`,
      `--effort=${options.effort}`,
      `--max-turns=${options.maxTurns}`,
      `--engagement-dir=${engagementDir}`,
      '--verification-mode=VA_ONLY',
      `--semgrep=${options.semgrepMode}`,
      `--work-units=${arm === 'current-parallel' ? 'force' : 'off'}`,
      `--max-concurrency=${arm === 'current-parallel' ? options.maxConcurrency : 1}`,
    ],
  };
}

export async function runBenchmark(optionsValue: BenchmarkRunnerOptions): Promise<{
  planned: PlannedBenchmarkRun[];
  records: BenchmarkRunRecord[];
}> {
  const options = BenchmarkRunnerOptionsSchema.parse(optionsValue);
  const corpus = readCorpus(options.corpusPath);
  const sourceManifest = readManifest(options.sourceManifestPath, options.target);
  const benchmarkCase = corpus.cases.find((entry) => entry.caseId === options.caseId);
  if (!benchmarkCase) throw new Error(`benchmark case가 corpus에 없다: ${options.caseId}`);
  if (benchmarkCase.sourceManifestSha256 !== sourceManifest.manifestSha256 ||
      benchmarkCase.vulnerableRevision !== sourceManifest.revision) {
    throw new Error('benchmark case와 source manifest binding이 다르다');
  }
  assertNoBenchmarkLeak(TASK_TEMPLATE, corpus);
  const planned = planBenchmarkRuns(options);
  if (options.dryRun) return { planned, records: [] };
  assertBenchmarkOutputIsolation(options.outputRoot);
  const campaignPath = join(options.outputRoot, 'campaign-manifest.json');
  const optionsSha256 = benchmarkSha256(benchmarkStableJson({ ...options, dryRun: false }));
  type CampaignEntry = { identity: string; runDir: string; record: BenchmarkRunRecord };
  type Campaign = { schemaVersion: '1.0.0'; optionsSha256: string; planned: PlannedBenchmarkRun[]; completed: CampaignEntry[] };
  let campaign: Campaign;
  if (existsSync(options.outputRoot)) {
    if (!existsSync(campaignPath)) throw new Error(`benchmark resume manifest가 없다: ${campaignPath}`);
    campaign = JSON.parse(readFileSync(campaignPath, 'utf8')) as Campaign;
    if (campaign.schemaVersion !== '1.0.0' || campaign.optionsSha256 !== optionsSha256 ||
        benchmarkStableJson(campaign.planned) !== benchmarkStableJson(planned)) {
      throw new Error('benchmark resume plan/options binding이 다르다');
    }
  } else {
    mkdirSync(options.outputRoot, { recursive: true });
    campaign = { schemaVersion: '1.0.0', optionsSha256, planned, completed: [] };
    writeJson(campaignPath, campaign);
  }

  const records: BenchmarkRunRecord[] = [];
  for (const item of planned) {
    const identity = `${item.caseId}:${item.repetition}:${item.arm}`;
    const prior = campaign.completed.find((entry) => entry.identity === identity);
    if (prior) {
      const runDir = resolve(options.outputRoot, prior.runDir);
      const record = assertBenchmarkRunArtifactsIntact(prior.record, runDir);
      if (record.caseId !== item.caseId || record.repetition !== item.repetition ||
          record.arm !== item.arm || record.executionOrder !== item.executionOrder ||
          record.corpusSha256 !== corpus.corpusSha256 ||
          record.sourceManifestSha256 !== sourceManifest.manifestSha256) {
        throw new Error(`benchmark resume run identity가 plan과 다르다: ${identity}`);
      }
      const normalizedFile = readFileSync(join(runDir, 'normalized-findings.json'));
      assertBenchmarkNormalizationIntact({
        record: JSON.parse(readFileSync(join(runDir, 'normalization-record.json'), 'utf8')),
        findings: NormalizedBenchmarkFindingSchema.array().parse(JSON.parse(normalizedFile.toString('utf8'))),
        normalizedFile, run: record, sourceManifest,
      });
      records.push(record);
      continue;
    }
    const record = await executePlannedRun({ options, corpus, sourceManifest, item });
    records.push(record);
    if (record.exitCode === 0) {
      const runDir = readdirSync(options.outputRoot).find((name) => name.endsWith(record.runId));
      if (!runDir) throw new Error(`benchmark run directory를 찾을 수 없다: ${record.runId}`);
      campaign.completed.push({ identity, runDir, record });
      writeJsonReplacing(campaignPath, campaign);
    }
  }
  const failed = records.filter((record) => record.exitCode !== 0);
  if (failed.length > 0) {
    throw new Error(`benchmark arm 실행 실패: ${failed.map((record) => `${record.arm}:${record.exitCode}`).join(', ')}`);
  }
  return { planned, records };
}

export function assertBenchmarkOutputIsolation(outputRoot: string): void {
  let existingParent = dirname(resolve(outputRoot));
  while (!existsSync(existingParent)) {
    const parent = dirname(existingParent);
    if (parent === existingParent) break;
    existingParent = parent;
  }
  try {
    const gitRoot = execFileSync('git', ['-C', existingParent, 'rev-parse', '--show-toplevel'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    if (gitRoot) {
      throw new Error(`benchmark output은 Git 작업트리 밖이어야 한다: ${gitRoot}`);
    }
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('benchmark output은')) throw error;
  }
}

async function executePlannedRun(input: {
  options: BenchmarkRunnerOptions;
  corpus: BenchmarkCorpus;
  sourceManifest: BenchmarkSourceManifest;
  item: PlannedBenchmarkRun;
}): Promise<BenchmarkRunRecord> {
  const { options, corpus, sourceManifest, item } = input;
  const runId = `run-${randomBytes(10).toString('hex')}`;
  const nonce = randomBytes(16).toString('hex');
  const runDir = join(options.outputRoot, `${String(item.executionOrder).padStart(3, '0')}-${item.arm}-${runId}`);
  const target = join(runDir, 'target');
  const engagementDir = join(runDir, 'engagement');
  mkdirSync(target, { recursive: true });
  mkdirSync(engagementDir, { recursive: true });
  copySealedSource(options.target, target, sourceManifest);
  assertBenchmarkSourceManifestIntact(sourceManifest, target);

  const command = buildArmCommand({ options, arm: item.arm, target, engagementDir });
  assertNoBenchmarkLeak(command.prompt, corpus);
  const stdoutPath = join(runDir, 'stdout.log');
  const stderrPath = join(runDir, 'stderr.log');
  const startedAt = new Date();
  const started = Date.now();
  let exitCode = await spawnToFiles(command, stdoutPath, stderrPath, engagementDir);
  try {
    assertBenchmarkSourceManifestIntact(sourceManifest, target);
  } catch (error) {
    exitCode = exitCode === 0 ? 86 : exitCode;
    writeFileSync(stderrPath, `\nsource integrity failure: ${errorMessage(error)}\n`, { flag: 'a' });
  }
  const finishedAt = new Date();
  const artifacts = artifactReceipts(runDir, ['stdout.log', 'stderr.log', ...walkRelative(engagementDir)
    .map((path) => `engagement/${path}`)]);
  const contractPath = item.arm === 'ch015'
    ? join(options.ch015PluginRoot, 'ch015.config.json')
    : join(options.currentRoot, 'domains/offsec/contracts/offsec-contract.v1.json');
  const resourceRoot = item.arm === 'ch015'
    ? options.ch015PluginRoot
    : join(options.currentRoot, 'domains/offsec');
  const core = {
    schemaVersion: '1.0.0' as const,
    runId,
    nonce,
    caseId: item.caseId,
    repetition: item.repetition,
    arm: item.arm,
    split: corpus.split,
    capability: corpus.cases.find((entry) => entry.caseId === item.caseId)!.capability,
    corpusSha256: corpus.corpusSha256,
    sourceManifestSha256: sourceManifest.manifestSha256,
    // Pairing uses the semantic task, not per-run opaque target/output paths.
    promptSha256: benchmarkSha256(TASK_TEMPLATE),
    contractSha256: benchmarkSha256(readFileSync(contractPath)),
    resourceManifestSha256: treeSha256(resourceRoot),
    entrypoint: item.arm === 'ch015' ? 'claude-plugin' as const : 'nunchi-assess' as const,
    commandSha256: benchmarkSha256(benchmarkStableJson({
      executable: command.executable,
      args: command.args,
      cwd: command.cwd,
    })),
    provider: options.provider,
    model: options.model,
    effort: options.effort,
    maxTurns: options.maxTurns,
    randomizationSeed: options.randomizationSeed,
    executionOrder: item.executionOrder,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    elapsedMs: Date.now() - started,
    exitCode,
    artifacts,
  };
  const run = BenchmarkRunRecordSchema.parse({
    ...core,
    runSha256: benchmarkSha256(benchmarkStableJson(core)),
  });
  writeJson(join(runDir, 'run-record.json'), run);
  if (exitCode === 0) writeNormalizedFindings({ item, run, runDir, target, engagementDir, sourceManifest });
  return run;
}

function writeNormalizedFindings(input: {
  item: PlannedBenchmarkRun;
  run: BenchmarkRunRecord;
  runDir: string;
  target: string;
  engagementDir: string;
  sourceManifest: BenchmarkSourceManifest;
}): void {
  const findings = input.item.arm === 'ch015'
    ? normalizeCh015Outputs(input)
    : normalizeCurrentOffsecFindings({ engagementDir: input.engagementDir, run: input.run });
  const validated = validateNormalizedBenchmarkFindings({
    findings,
    run: input.run,
    sourceManifest: input.sourceManifest,
    target: input.target,
  });
  const normalizedPath = join(input.runDir, 'normalized-findings.json');
  writeJson(normalizedPath, validated);
  const normalizationCore = {
    schemaVersion: '1.0.0',
    runSha256: input.run.runSha256,
    sourceManifestSha256: input.sourceManifest.manifestSha256,
    adapter: input.item.arm === 'ch015' ? 'ch015-markdown-v1' : 'current-standard-finding-v1',
    normalizedSha256: benchmarkSha256(benchmarkStableJson(validated)),
    normalizedFileSha256: benchmarkSha256(readFileSync(normalizedPath)),
  };
  writeJson(join(input.runDir, 'normalization-record.json'), {
    ...normalizationCore,
    recordSha256: benchmarkSha256(benchmarkStableJson(normalizationCore)),
  });
}

function normalizeCh015Outputs(input: {
  run: BenchmarkRunRecord;
  runDir: string;
  target: string;
  engagementDir: string;
  sourceManifest: BenchmarkSourceManifest;
}) {
  const markdown = walkRelative(input.engagementDir).filter((path) => path.endsWith('.md'));
  const finalReports = markdown.filter((path) =>
    /(?:^|\/)(?:10_)?final[_-]security[_-]report\.md$|(?:^|\/)security[_-]report\.md$/i.test(path));
  const reportPaths = finalReports.length > 0
    ? finalReports.map((path) => join(input.engagementDir, path))
    : [join(input.runDir, 'stdout.log')];
  const findings = reportPaths.flatMap((reportPath) => normalizeCh015MarkdownFindings({
    reportPath,
    target: input.target,
    sourceManifest: input.sourceManifest,
    run: input.run,
  }));
  const unique = new Map(findings.map((finding) => [`${finding.findingId}\0${finding.title}`, finding]));
  return [...unique.values()];
}

export function spawnToFiles(
  command: { executable: string; args: string[]; cwd: string },
  stdoutPath: string,
  stderrPath: string,
  engagementDir: string,
  timings: { timeoutMs: number; killGraceMs: number } = { timeoutMs: 30 * 60 * 1000, killGraceMs: 10_000 },
): Promise<number> {
  const stdout = openSync(stdoutPath, 'w');
  const stderr = openSync(stderrPath, 'w');
  return new Promise((resolvePromise, reject) => {
    let closed = false;
    const closeFiles = (): void => {
      if (closed) return;
      closed = true;
      closeSync(stdout);
      closeSync(stderr);
    };
    const child = spawn(command.executable, command.args, {
      cwd: command.cwd,
      env: { ...process.env, AGENT_ENGAGEMENT_DIR: engagementDir },
      stdio: ['ignore', stdout, stderr],
      detached: process.platform !== 'win32',
    });
    let killTimeout: NodeJS.Timeout | undefined;
    let timedOut = false;
    let closedCode: number | null = null;
    let settled = false;
    const finish = (code: number): void => {
      if (settled) return;
      settled = true;
      closeFiles();
      resolvePromise(code);
    };
    const timeout = setTimeout(() => {
      timedOut = true;
      signalProcessTree(child, 'SIGTERM');
      killTimeout = setTimeout(() => {
        signalProcessTree(child, 'SIGKILL');
        finish(closedCode ?? 124);
      }, timings.killGraceMs);
    }, timings.timeoutMs);
    child.once('error', (error) => {
      clearTimeout(timeout);
      if (killTimeout) clearTimeout(killTimeout);
      closeFiles();
      reject(error);
    });
    child.once('close', (code) => {
      clearTimeout(timeout);
      closedCode = code;
      if (!timedOut || !processTreeExists(child)) {
        if (killTimeout) clearTimeout(killTimeout);
        finish(code ?? 124);
      } else {
        closeFiles();
      }
    });
  });
}

export function signalProcessTree(child: ChildProcess, signal: NodeJS.Signals): void {
  if (child.pid === undefined) return;
  if (process.platform === 'win32') {
    child.kill(signal);
    return;
  }
  try {
    process.kill(-child.pid, signal);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ESRCH') throw error;
  }
}

function processTreeExists(child: ChildProcess): boolean {
  if (child.pid === undefined || process.platform === 'win32') return false;
  try {
    process.kill(-child.pid, 0);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ESRCH') return false;
    throw error;
  }
}

function copySealedSource(sourceRoot: string, targetRoot: string, manifest: BenchmarkSourceManifest): void {
  for (const file of manifest.files) {
    const destination = join(targetRoot, file.path);
    mkdirSync(dirname(destination), { recursive: true });
    copyFileSync(join(sourceRoot, file.path), destination);
  }
}

function artifactReceipts(root: string, paths: readonly string[]) {
  return [...new Set(paths)].sort().map((path) => {
    const content = readFileSync(join(root, path));
    return { path, bytes: content.byteLength, sha256: benchmarkSha256(content) };
  });
}

function treeSha256(root: string): string {
  return benchmarkSha256(benchmarkStableJson(walkRelative(root).map((path) => {
    const content = readFileSync(join(root, path));
    return { path, bytes: content.byteLength, sha256: benchmarkSha256(content) };
  })));
}

function walkRelative(root: string): string[] {
  const paths: string[] = [];
  const visit = (directory: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const absolute = join(directory, entry.name);
      if (entry.isDirectory()) visit(absolute);
      else if (entry.isFile()) paths.push(relative(root, absolute).split('\\').join('/'));
    }
  };
  visit(root);
  return paths;
}

function readCorpus(path: string): BenchmarkCorpus {
  return assertBenchmarkCorpusIntact(JSON.parse(readFileSync(resolve(path), 'utf8')));
}

function readManifest(path: string, target: string): BenchmarkSourceManifest {
  return assertBenchmarkSourceManifestIntact(JSON.parse(readFileSync(resolve(path), 'utf8')), resolve(target));
}

function writeJson(path: string, value: unknown): void {
  if (existsSync(path)) throw new Error(`benchmark output이 이미 존재한다: ${path}`);
  const temporary = `${path}.tmp-${process.pid}-${randomBytes(4).toString('hex')}`;
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx' });
  renameSync(temporary, path);
}

function writeJsonReplacing(path: string, value: unknown): void {
  const temporary = `${path}.tmp-${process.pid}-${randomBytes(4).toString('hex')}`;
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx' });
  renameSync(temporary, path);
}

function xorshift32(seed: number): () => number {
  let state = seed || 0x9e3779b9;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 0x1_0000_0000;
  };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function defaultRunnerRoots(currentRoot: string): Pick<BenchmarkRunnerOptions, 'currentRoot' | 'ch015PluginRoot'> {
  return {
    currentRoot,
    ch015PluginRoot: resolve(currentRoot, '../../ch015-pentester/plugins/ch015'),
  };
}

export function displayRunPlan(options: BenchmarkRunnerOptions, planned: readonly PlannedBenchmarkRun[]) {
  return {
    dryRun: options.dryRun,
    outputRoot: resolve(options.outputRoot),
    targetName: basename(resolve(options.target)),
    sourceManifestSha256: benchmarkSha256(readFileSync(resolve(options.sourceManifestPath))),
    corpusFileSha256: benchmarkSha256(readFileSync(resolve(options.corpusPath))),
    model: options.model,
    effort: options.effort,
    maxTurns: options.maxTurns,
    semgrepMode: options.semgrepMode,
    randomizationSeed: options.randomizationSeed,
    runs: planned,
  };
}
