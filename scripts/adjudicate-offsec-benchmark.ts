import { randomBytes } from 'node:crypto';
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

import {
  assertBenchmarkNormalizationIntact,
  assertBenchmarkCorpusIntact,
  assertBenchmarkSourceManifestIntact,
  benchmarkSha256,
  benchmarkStableJson,
  BlindReviewPacketSchema,
  BenchmarkJudgmentSchema,
  BenchmarkRunRecordSchema,
  createBlindReviewPackets,
  NormalizedBenchmarkFindingSchema,
  resolveBenchmarkJudgments,
  validateNormalizedBenchmarkFindings,
} from '../src/runtime/offsec-benchmark.js';
import { scoreAdjudicatedBenchmarkRun } from '../evals/offsec/scoring.js';

type Flags = Map<string, string>;

export function prepareReviewArtifacts(input: {
  runDir: string;
  sourceManifestPath: string;
  outputDir: string;
  salt?: string;
}): { packetCount: number; packetsPath: string; mappingPath: string; manifestPath: string } {
  const runDir = resolve(input.runDir);
  const run = BenchmarkRunRecordSchema.parse(readJson(join(runDir, 'run-record.json')));
  const target = join(runDir, 'target');
  const sourceManifest = assertBenchmarkSourceManifestIntact(readJson(input.sourceManifestPath), target);
  const normalizedPath = join(runDir, 'normalized-findings.json');
  const normalizedFile = readFileSync(normalizedPath);
  const findings = validateNormalizedBenchmarkFindings({
    findings: NormalizedBenchmarkFindingSchema.array().parse(JSON.parse(normalizedFile.toString('utf8'))),
    run,
    sourceManifest,
    target,
  });
  const normalization = assertBenchmarkNormalizationIntact({
    record: readJson(join(runDir, 'normalization-record.json')),
    findings,
    normalizedFile,
    run,
    sourceManifest,
  });
  const salt = input.salt ?? randomBytes(32).toString('hex');
  const { packets, privateMapping } = createBlindReviewPackets({
    findings,
    salt,
  });
  const outputDir = resolve(input.outputDir);
  mkdirSync(outputDir, { recursive: true, mode: 0o700 });
  chmodSync(outputDir, 0o700);
  const packetsPath = join(outputDir, 'review-packets.json');
  const mappingPath = join(outputDir, 'private-mapping.json');
  const manifestPath = join(outputDir, 'review-manifest.json');
  writeJson(packetsPath, packets, 0o600);
  const mapping = [...privateMapping].map(([packetId, finding]) => ({ packetId, finding }));
  writeJson(mappingPath, mapping, 0o600);
  const manifestCore = {
    schemaVersion: '1.0.0', runSha256: run.runSha256,
    normalizationRecordSha256: normalization.recordSha256,
    salt,
    packetsSha256: benchmarkSha256(readFileSync(packetsPath)),
    mappingSha256: benchmarkSha256(readFileSync(mappingPath)),
    packetIds: packets.map((packet) => packet.packetId).sort(),
  };
  writeJson(manifestPath, {
    ...manifestCore, manifestSha256: benchmarkSha256(benchmarkStableJson(manifestCore)),
  }, 0o600);
  return { packetCount: packets.length, packetsPath, mappingPath, manifestPath };
}

export function scoreReviewArtifacts(input: {
  runDir: string;
  corpusPath: string;
  sourceManifestPath: string;
  mappingPath: string;
  judgmentsPath: string;
  usagePath?: string;
  toolVersionsPath?: string;
  outputPath: string;
}) {
  const runDir = resolve(input.runDir);
  const run = BenchmarkRunRecordSchema.parse(readJson(join(runDir, 'run-record.json')));
  const sourceManifest = assertBenchmarkSourceManifestIntact(readJson(input.sourceManifestPath), join(runDir, 'target'));
  const normalizedPath = join(runDir, 'normalized-findings.json');
  const normalizedFile = readFileSync(normalizedPath);
  const normalized = NormalizedBenchmarkFindingSchema.array().parse(JSON.parse(normalizedFile.toString('utf8')));
  const normalization = assertBenchmarkNormalizationIntact({
    record: readJson(join(runDir, 'normalization-record.json')),
    findings: normalized,
    normalizedFile,
    run,
    sourceManifest,
  });
  const reviewDir = dirname(resolve(input.mappingPath));
  const packetsPath = join(reviewDir, 'review-packets.json');
  const manifestPath = join(reviewDir, 'review-manifest.json');
  const manifest = readJson(manifestPath) as Record<string, unknown>;
  const { manifestSha256, ...manifestCore } = manifest;
  if (typeof manifestSha256 !== 'string' || benchmarkSha256(benchmarkStableJson(manifestCore)) !== manifestSha256 ||
      manifest.runSha256 !== run.runSha256 ||
      manifest.normalizationRecordSha256 !== normalization.recordSha256 ||
      manifest.packetsSha256 !== benchmarkSha256(readFileSync(packetsPath)) ||
      manifest.mappingSha256 !== benchmarkSha256(readFileSync(input.mappingPath)) ||
      typeof manifest.salt !== 'string') {
    throw new Error('review manifest binding이 다르다');
  }
  const mappingEntries = (readJson(input.mappingPath) as unknown[]).map((value) => {
    const entry = value as { packetId?: unknown; finding?: unknown };
    if (typeof entry.packetId !== 'string') throw new Error('private mapping packetId가 없다');
    return [entry.packetId, NormalizedBenchmarkFindingSchema.parse(entry.finding)] as const;
  });
  const findings = validateNormalizedBenchmarkFindings({
    findings: mappingEntries.map(([, finding]) => finding),
    run,
    sourceManifest,
    target: join(runDir, 'target'),
  });
  const packetMapping = new Map(mappingEntries.map(([packetId], index) => [packetId, findings[index]!]));
  if (packetMapping.size !== mappingEntries.length) throw new Error('private mapping packetId가 중복됐다');
  const recreated = createBlindReviewPackets({ findings: normalized, salt: manifest.salt });
  const packets = BlindReviewPacketSchema.array().parse(readJson(packetsPath));
  const recreatedMapping = [...recreated.privateMapping].map(([packetId, finding]) => ({ packetId, finding }));
  if (benchmarkStableJson(recreated.packets) !== benchmarkStableJson(packets) ||
      benchmarkStableJson(recreatedMapping) !== benchmarkStableJson(mappingEntries.map(([packetId, finding]) => ({ packetId, finding })))) {
    throw new Error('review packet/private mapping이 normalized Finding seal과 다르다');
  }
  const judgments = resolveBenchmarkJudgments(
    [...packetMapping.keys()],
    BenchmarkJudgmentSchema.array().parse(readJson(input.judgmentsPath)),
  );
  if (Boolean(input.usagePath) !== Boolean(input.toolVersionsPath)) {
    throw new Error('usage와 toolVersions provenance는 함께 제공해야 한다');
  }
  const measurement = input.usagePath && input.toolVersionsPath
    ? {
        measurementStatus: 'available' as const,
        usage: usage(attestedJson(input.usagePath, runDir, run)),
        toolVersions: toolVersions(attestedJson(input.toolVersionsPath, runDir, run)),
      }
    : {
        measurementStatus: 'unavailable' as const,
        usage: { inputTokens: 0, outputTokens: 0 },
        toolVersions: { 'benchmark-measurement': 'unavailable' },
      };
  const result = scoreAdjudicatedBenchmarkRun({
    run,
    runDir,
    corpus: assertBenchmarkCorpusIntact(readJson(input.corpusPath)),
    packetMapping,
    judgments,
    ...measurement,
  });
  mkdirSync(dirname(resolve(input.outputPath)), { recursive: true, mode: 0o700 });
  const judgmentFile = readFileSync(resolve(input.judgmentsPath));
  const scoreCore = {
    schemaVersion: '1.0.0',
    runSha256: run.runSha256,
    reviewManifestSha256: manifestSha256,
    judgmentsSha256: benchmarkSha256(judgmentFile),
    corpusSha256: assertBenchmarkCorpusIntact(readJson(input.corpusPath)).corpusSha256,
    ...result,
  };
  const scoreRecord = { ...scoreCore, scoreSha256: benchmarkSha256(benchmarkStableJson(scoreCore)) };
  writeJson(resolve(input.outputPath), scoreRecord, 0o600);
  return scoreRecord;
}

export function collectScoreRecords(input: {
  campaignPath: string;
  scorePaths: readonly string[];
  outputPath: string;
}): { observationCount: number; collectionManifestPath: string } {
  const campaign = readJson(input.campaignPath) as {
    planned?: Array<{ caseId: string; repetition: number; arm: string }>;
    completed?: Array<{ identity: string; record: { runSha256: string } }>;
  };
  if (!Array.isArray(campaign.planned) || !Array.isArray(campaign.completed)) {
    throw new Error('benchmark campaign manifest가 잘못됐다');
  }
  const expected = new Set(campaign.planned.map((item) => `${item.caseId}:${item.repetition}:${item.arm}`));
  const completedByRun = new Map(campaign.completed.map((entry) => [entry.record.runSha256, entry.identity]));
  const observations: unknown[] = [];
  const scoreSha256: string[] = [];
  const seen = new Set<string>();
  for (const path of input.scorePaths) {
    const score = readJson(path) as Record<string, unknown>;
    const scoreSha = score.scoreSha256;
    const { scoreSha256: _scoreSha256, ...core } = score;
    if (typeof scoreSha !== 'string' || benchmarkSha256(benchmarkStableJson(core)) !== scoreSha) {
      throw new Error(`benchmark score record hash가 다르다: ${path}`);
    }
    const identity = completedByRun.get(String(score.runSha256));
    if (!identity || !expected.has(identity) || !seen.add(identity)) {
      throw new Error(`benchmark score campaign identity가 잘못됐다: ${identity ?? 'unknown'}`);
    }
    observations.push(score.observation);
    scoreSha256.push(scoreSha);
  }
  if (seen.size !== expected.size || [...expected].some((identity) => !seen.has(identity))) {
    throw new Error(`benchmark score collection이 불완전하다: ${seen.size}/${expected.size}`);
  }
  const outputPath = resolve(input.outputPath);
  mkdirSync(dirname(outputPath), { recursive: true, mode: 0o700 });
  writeFileSync(outputPath, `${observations.map((value) => JSON.stringify(value)).join('\n')}\n`, { flag: 'wx', mode: 0o600 });
  const collectionCore = {
    schemaVersion: '1.0.0', campaignSha256: benchmarkSha256(readFileSync(input.campaignPath)),
    scoreSha256: scoreSha256.sort(), observationsSha256: benchmarkSha256(readFileSync(outputPath)),
  };
  const collectionManifestPath = `${outputPath}.manifest.json`;
  writeJson(collectionManifestPath, {
    ...collectionCore, collectionSha256: benchmarkSha256(benchmarkStableJson(collectionCore)),
  }, 0o600);
  return { observationCount: observations.length, collectionManifestPath };
}

function parseArgs(argv: string[]): { command: string; flags: Flags } {
  const [command = '', ...rest] = argv.filter((value) => value !== '--');
  const flags = new Map<string, string>();
  for (const arg of rest) {
    const match = /^--([a-z-]+)=(.*)$/.exec(arg);
    if (!match?.[1]) throw new Error(`잘못된 인수다: ${arg}`);
    flags.set(match[1], match[2] ?? '');
  }
  return { command, flags };
}

function required(flags: Flags, name: string): string {
  const value = flags.get(name);
  if (!value) throw new Error(`--${name}가 필요하다`);
  return value;
}

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(resolve(path), 'utf8'));
}

function attestedJson(path: string, runDir: string, run: { artifacts: Array<{ path: string; sha256: string }> }): unknown {
  const absolute = resolve(path);
  const receipt = run.artifacts.find((artifact) => resolve(runDir, artifact.path) === absolute);
  const content = readFileSync(absolute);
  if (!receipt || benchmarkSha256(content) !== receipt.sha256) {
    throw new Error(`measurement artifact가 run receipt에 봉인되지 않았다: ${path}`);
  }
  return JSON.parse(content.toString('utf8'));
}

function writeJson(path: string, value: unknown, mode: number): void {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx', mode });
}

function usage(value: unknown): { inputTokens: number; outputTokens: number } {
  const record = value as Record<string, unknown>;
  const inputTokens = Number(record.inputTokens);
  const outputTokens = Number(record.outputTokens);
  if (!Number.isInteger(inputTokens) || inputTokens < 0 || !Number.isInteger(outputTokens) || outputTokens < 0) {
    throw new Error('usage token 값이 잘못됐다');
  }
  return { inputTokens, outputTokens };
}

function toolVersions(value: unknown): Record<string, string> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('toolVersions가 객체가 아니다');
  const entries = Object.entries(value).map(([key, item]) => {
    if (!key || typeof item !== 'string' || !item) throw new Error('toolVersions 항목이 잘못됐다');
    return [key, item] as const;
  });
  return Object.fromEntries(entries);
}

async function main(): Promise<void> {
  const { command, flags } = parseArgs(process.argv.slice(2));
  if (command === 'prepare') {
    console.log(JSON.stringify(prepareReviewArtifacts({
      runDir: required(flags, 'run-dir'),
      sourceManifestPath: required(flags, 'source-manifest'),
      outputDir: required(flags, 'output-dir'),
    }), null, 2));
    return;
  }
  if (command === 'score') {
    console.log(JSON.stringify(scoreReviewArtifacts({
      runDir: required(flags, 'run-dir'),
      corpusPath: required(flags, 'corpus'),
      sourceManifestPath: required(flags, 'source-manifest'),
      mappingPath: required(flags, 'mapping'),
      judgmentsPath: required(flags, 'judgments'),
      usagePath: flags.get('usage'),
      toolVersionsPath: flags.get('tool-versions'),
      outputPath: required(flags, 'output'),
    }), null, 2));
    return;
  }
  if (command === 'collect') {
    console.log(JSON.stringify(collectScoreRecords({
      campaignPath: required(flags, 'campaign'),
      scorePaths: required(flags, 'scores').split(',').filter(Boolean),
      outputPath: required(flags, 'output'),
    }), null, 2));
    return;
  }
  throw new Error('사용: adjudicate-offsec-benchmark <prepare|score|collect> --...');
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  });
}
