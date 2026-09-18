import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { z } from 'zod';

import {
  assertBenchmarkCorpusIntact,
  benchmarkSha256,
  benchmarkStableJson,
  createBenchmarkSourceManifest,
} from '../src/runtime/offsec-benchmark.js';

const AnchorSeedSchema = z.object({
  path: z.string().min(1),
  lineStart: z.number().int().positive(),
  lineEnd: z.number().int().positive(),
}).strict();

const SeedSchema = z.object({
  schemaVersion: z.literal('1.0.0'),
  revision: z.string().regex(/^[a-f0-9]{40}$/),
  caseId: z.string().min(1),
  capability: z.literal('large-repository'),
  labels: z.array(z.object({
    labelId: z.string().min(1),
    rootCauseId: z.string().min(1),
    title: z.string().min(1),
    cwes: z.array(z.string()).min(1),
    modality: z.literal('static'),
    anchors: z.array(AnchorSeedSchema).min(1),
  }).strict()).min(1),
}).strict();

const SOURCE_EXTENSIONS = new Set(['.cjs', '.html', '.js', '.json', '.mjs', '.sol', '.ts', '.yaml', '.yml']);
const ROOT_FILES = new Set(['Dockerfile', 'package.json', 'pnpm-lock.yaml', 'tsconfig.json']);
const SOURCE_PREFIXES = ['build/', 'config/', 'data/', 'frontend/src/app/', 'lib/', 'models/', 'routes/'];
const EXCLUDED_PREFIXES = [
  'data/static/i18n/',
  'data/static/codefixes/',
  'data/static/code-snippets/',
  'frontend/src/app/code-snippet/',
];

function extension(path: string): string {
  const index = path.lastIndexOf('.');
  return index < 0 ? '' : path.slice(index);
}

function sourceFiles(target: string): string[] {
  const tracked = execFileSync('git', ['ls-files'], { cwd: target, encoding: 'utf8' })
    .split('\n').filter(Boolean);
  return tracked.filter((path) =>
    ROOT_FILES.has(path) || path === 'app.ts' || path === 'server.ts' ||
    (SOURCE_PREFIXES.some((prefix) => path.startsWith(prefix)) &&
      SOURCE_EXTENSIONS.has(extension(path)) &&
      !EXCLUDED_PREFIXES.some((prefix) => path.startsWith(prefix))));
}

function quote(target: string, path: string, lineStart: number, lineEnd: number): string {
  const lines = readFileSync(resolve(target, path), 'utf8').split(/\r?\n/);
  if (lineEnd > lines.length || lineEnd < lineStart) throw new Error(`ground truth anchor가 잘못됐다: ${path}`);
  return lines.slice(lineStart - 1, lineEnd).join('\n');
}

function main(): void {
  const projectRoot = resolve(fileURLToPath(new URL('..', import.meta.url)));
  const args = process.argv.slice(2).filter((value) => value !== '--');
  const target = resolve(args[0] ?? '../benchmarks/juice-shop');
  const outputDir = resolve(args[1] ?? resolve(projectRoot, 'evals/offsec/corpora/juice-shop-pilot'));
  const seedPath = resolve(outputDir, 'ground-truth.seed.json');
  if (!existsSync(seedPath)) throw new Error(`ground truth seed가 없다: ${seedPath}`);
  const seed = SeedSchema.parse(JSON.parse(readFileSync(seedPath, 'utf8')));
  const dirtyTracked = execFileSync('git', ['status', '--porcelain', '--untracked-files=no'], {
    cwd: target,
    encoding: 'utf8',
  }).trim();
  if (dirtyTracked) throw new Error('benchmark target에 커밋되지 않은 tracked 변경이 있다');
  const revision = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: target, encoding: 'utf8' }).trim();
  if (revision !== seed.revision) throw new Error(`Juice Shop revision drift: ${revision} != ${seed.revision}`);
  const manifest = createBenchmarkSourceManifest({ target, revision, files: sourceFiles(target) });
  const manifestPaths = new Set(manifest.files.map((file) => file.path));
  for (const anchor of seed.labels.flatMap((label) => label.anchors)) {
    if (!manifestPaths.has(anchor.path)) throw new Error(`ground truth anchor가 source manifest 밖이다: ${anchor.path}`);
  }
  const labels = seed.labels.map((label) => ({
    ...label,
    anchors: label.anchors.map((anchor) => ({
      ...anchor,
      quote: quote(target, anchor.path, anchor.lineStart, anchor.lineEnd),
    })),
  }));
  const core = {
    schemaVersion: '1.0.0' as const,
    corpusId: 'corpus-juice-shop-pilot-v1',
    split: 'validation' as const,
    claimAuthority: 'pilot-only' as const,
    cases: [{
      caseId: seed.caseId,
      capability: seed.capability,
      sourceManifestSha256: manifest.manifestSha256,
      repositoryPseudonym: `repo-${benchmarkSha256(`pilot:${revision}`).slice(0, 12)}`,
      vulnerableRevision: revision,
      labels,
    }],
  };
  const corpus = assertBenchmarkCorpusIntact({
    ...core,
    corpusSha256: benchmarkSha256(benchmarkStableJson(core)),
  });
  mkdirSync(outputDir, { recursive: true });
  writeFileSync(resolve(outputDir, 'source-manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  writeFileSync(resolve(outputDir, 'corpus.json'), `${JSON.stringify(corpus, null, 2)}\n`);
  console.log(JSON.stringify({
    revision,
    files: manifest.files.length,
    bytes: manifest.files.reduce((sum, file) => sum + file.bytes, 0),
    labels: labels.length,
    manifestSha256: manifest.manifestSha256,
    corpusSha256: corpus.corpusSha256,
  }, null, 2));
}

main();
