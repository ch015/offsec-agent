import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  BenchmarkRunnerOptionsSchema,
  defaultRunnerRoots,
  displayRunPlan,
  runBenchmark,
} from '../evals/offsec/runner.js';

function parseArgs(argv: readonly string[]): Map<string, string> {
  const allowed = new Set([
    'corpus', 'source-manifest', 'case', 'target', 'output-root', 'arms', 'repetitions', 'provider',
    'model', 'effort', 'max-turns', 'seed', 'semgrep', 'max-concurrency', 'current-root',
    'ch015-plugin-root', 'dry-run',
  ]);
  const values = new Map<string, string>();
  for (const arg of argv) {
    if (arg === '--') continue;
    const match = /^--([a-z-]+)=(.*)$/.exec(arg);
    if (!match?.[1] || !allowed.has(match[1])) throw new Error(`알 수 없는 benchmark 인수다: ${arg}`);
    values.set(match[1], match[2] ?? '');
  }
  return values;
}

function required(values: Map<string, string>, key: string): string {
  const value = values.get(key);
  if (!value) throw new Error(`benchmark 인수가 필요하다: --${key}`);
  return value;
}

function positiveInteger(values: Map<string, string>, key: string, fallback: number): number {
  const raw = values.get(key);
  const value = raw === undefined ? fallback : Number(raw);
  if (!Number.isInteger(value) || value <= 0) throw new Error(`--${key}는 양의 정수여야 한다`);
  return value;
}

async function main(): Promise<void> {
  const values = parseArgs(process.argv.slice(2));
  const scriptRoot = resolve(fileURLToPath(new URL('..', import.meta.url)));
  const roots = defaultRunnerRoots(scriptRoot);
  const randomizationSeed = Number(values.get('seed') ?? '20260806');
  if (!Number.isInteger(randomizationSeed) || randomizationSeed < 0) {
    throw new Error('--seed는 0 이상의 정수여야 한다');
  }
  const options = BenchmarkRunnerOptionsSchema.parse({
    corpusPath: resolve(required(values, 'corpus')),
    sourceManifestPath: resolve(required(values, 'source-manifest')),
    caseId: required(values, 'case'),
    target: resolve(required(values, 'target')),
    outputRoot: resolve(required(values, 'output-root')),
    arms: (values.get('arms') ?? 'ch015,current-sequential,current-parallel').split(','),
    repetitions: positiveInteger(values, 'repetitions', 1),
    provider: values.get('provider') ?? 'anthropic',
    model: required(values, 'model'),
    effort: values.get('effort') ?? 'high',
    maxTurns: positiveInteger(values, 'max-turns', 120),
    randomizationSeed,
    semgrepMode: values.get('semgrep') ?? 'required',
    maxConcurrency: positiveInteger(values, 'max-concurrency', 4),
    currentRoot: resolve(values.get('current-root') ?? roots.currentRoot),
    ch015PluginRoot: resolve(values.get('ch015-plugin-root') ?? roots.ch015PluginRoot),
    dryRun: (values.get('dry-run') ?? 'false') === 'true',
  });
  const result = await runBenchmark(options);
  console.log(JSON.stringify({ ...displayRunPlan(options, result.planned), records: result.records }, null, 2));
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
