import { createHash, randomBytes } from 'node:crypto';
import { existsSync, lstatSync, readFileSync, realpathSync } from 'node:fs';
import { isAbsolute, relative, resolve, sep } from 'node:path';

import { z } from 'zod';

import { OffsecEvaluationArmSchema, OffsecCapabilitySchema } from './offsec-evaluation.js';

const Sha256Schema = z.string().regex(/^[a-f0-9]{64}$/);
const RelativePathSchema = z.string().min(1).refine(
  (value) => !isAbsolute(value) && !value.includes('\\') &&
    value.split('/').every((part) => part !== '' && part !== '.' && part !== '..'),
  'benchmark path는 정규화된 상대 경로여야 한다',
);

const SourceFileSchema = z.object({
  path: RelativePathSchema,
  bytes: z.number().int().nonnegative(),
  sha256: Sha256Schema,
}).strict();

const SourceManifestCoreSchema = z.object({
  schemaVersion: z.literal('1.0.0'),
  revision: z.string().regex(/^[a-f0-9]{40}$/),
  files: z.array(SourceFileSchema).min(1),
}).strict();

export const BenchmarkSourceManifestSchema = SourceManifestCoreSchema.extend({
  manifestSha256: Sha256Schema,
}).strict();
export type BenchmarkSourceManifest = z.infer<typeof BenchmarkSourceManifestSchema>;

const SourceAnchorSchema = z.object({
  path: RelativePathSchema,
  lineStart: z.number().int().positive(),
  lineEnd: z.number().int().positive(),
  quote: z.string().min(1).max(65_536),
}).strict().refine((value) => value.lineEnd >= value.lineStart, 'benchmark line 범위가 역전됐다');

const FindingEvidenceSchema = z.object({
  path: RelativePathSchema,
  lineStart: z.number().int().positive(),
  lineEnd: z.number().int().positive(),
  quote: z.string().min(1).max(65_536),
  origin: z.enum(['reported', 'adapter-resolved']),
}).strict().refine((value) => value.lineEnd >= value.lineStart, 'benchmark line 범위가 역전됐다');

const BlindFindingEvidenceSchema = z.object({
  path: RelativePathSchema,
  lineStart: z.number().int().positive(),
  lineEnd: z.number().int().positive(),
  quote: z.string().min(1).max(65_536),
}).strict().refine((value) => value.lineEnd >= value.lineStart, 'benchmark line 범위가 역전됐다');

export const BenchmarkGroundTruthLabelSchema = z.object({
  labelId: z.string().regex(/^GT-[A-Z0-9][A-Z0-9._-]{0,63}$/),
  rootCauseId: z.string().regex(/^RC-[A-Z0-9][A-Z0-9._-]{0,63}$/),
  title: z.string().min(1).max(512),
  cwes: z.array(z.string().regex(/^CWE-\d+$/)).min(1),
  modality: z.enum(['static', 'mixed', 'live']),
  anchors: z.array(SourceAnchorSchema).min(1),
  dynamicOracleId: z.string().regex(/^ORACLE-[A-Z0-9][A-Z0-9._-]{0,63}$/).optional(),
}).strict().superRefine((value, context) => {
  if (value.modality === 'live' && !value.dynamicOracleId) {
    context.addIssue({ code: 'custom', message: 'live ground truth에는 dynamicOracleId가 필요하다' });
  }
});

const BenchmarkCaseSchema = z.object({
  caseId: z.string().regex(/^case-[a-z0-9]{8,64}$/),
  capability: OffsecCapabilitySchema,
  sourceManifestSha256: Sha256Schema,
  repositoryPseudonym: z.string().regex(/^repo-[a-f0-9]{12}$/),
  vulnerableRevision: z.string().regex(/^[a-f0-9]{40}$/),
  fixedRevision: z.string().regex(/^[a-f0-9]{40}$/).optional(),
  labels: z.array(BenchmarkGroundTruthLabelSchema).min(1),
}).strict();

const BenchmarkCorpusCoreSchema = z.object({
  schemaVersion: z.literal('1.0.0'),
  corpusId: z.string().regex(/^corpus-[a-z0-9][a-z0-9._-]{0,63}$/),
  split: z.enum(['validation', 'holdout']),
  claimAuthority: z.enum(['pilot-only', 'diagnostic-only', 'final-holdout']),
  cases: z.array(BenchmarkCaseSchema).min(1),
}).strict();

export const BenchmarkCorpusSchema = BenchmarkCorpusCoreSchema.extend({
  corpusSha256: Sha256Schema,
}).strict();
export type BenchmarkCorpus = z.infer<typeof BenchmarkCorpusSchema>;

const ArtifactReceiptSchema = z.object({
  path: RelativePathSchema,
  bytes: z.number().int().nonnegative(),
  sha256: Sha256Schema,
}).strict();

const RunRecordCoreSchema = z.object({
  schemaVersion: z.literal('1.0.0'),
  runId: z.string().regex(/^run-[a-f0-9]{20}$/),
  nonce: z.string().regex(/^[a-f0-9]{32}$/),
  caseId: z.string().regex(/^case-[a-z0-9]{8,64}$/),
  repetition: z.number().int().positive(),
  arm: OffsecEvaluationArmSchema,
  split: z.enum(['validation', 'holdout']),
  capability: OffsecCapabilitySchema,
  corpusSha256: Sha256Schema,
  sourceManifestSha256: Sha256Schema,
  promptSha256: Sha256Schema,
  contractSha256: Sha256Schema,
  resourceManifestSha256: Sha256Schema,
  entrypoint: z.enum(['claude-plugin', 'nunchi-assess', 'nunchi-assess-v2']),
  commandSha256: Sha256Schema,
  provider: z.string().min(1),
  model: z.string().min(1),
  reviewModel: z.string().min(1).optional(),
  effort: z.string().min(1),
  maxTurns: z.number().int().positive().nullable(),
  randomizationSeed: z.number().int().nonnegative(),
  executionOrder: z.number().int().nonnegative(),
  startedAt: z.string().datetime(),
  finishedAt: z.string().datetime(),
  elapsedMs: z.number().nonnegative(),
  exitCode: z.number().int(),
  artifacts: z.array(ArtifactReceiptSchema).min(1),
}).strict();

export const BenchmarkRunRecordSchema = RunRecordCoreSchema.extend({
  runSha256: Sha256Schema,
}).strict();
export type BenchmarkRunRecord = z.infer<typeof BenchmarkRunRecordSchema>;

const BenchmarkNormalizationRecordCoreSchema = z.object({
  schemaVersion: z.literal('1.0.0'),
  runSha256: Sha256Schema,
  sourceManifestSha256: Sha256Schema,
  adapter: z.enum(['ch015-markdown-v1', 'current-standard-finding-v1', 'current-standard-finding-v2']),
  normalizedSha256: Sha256Schema,
  normalizedFileSha256: Sha256Schema,
}).strict();

export const BenchmarkNormalizationRecordSchema = BenchmarkNormalizationRecordCoreSchema.extend({
  recordSha256: Sha256Schema,
}).strict();
export type BenchmarkNormalizationRecord = z.infer<typeof BenchmarkNormalizationRecordSchema>;

export const NormalizedBenchmarkFindingSchema = z.object({
  schemaVersion: z.literal('1.0.0'),
  runId: z.string().regex(/^run-[a-f0-9]{20}$/),
  runSha256: Sha256Schema,
  caseId: z.string().regex(/^case-[a-z0-9]{8,64}$/),
  arm: OffsecEvaluationArmSchema,
  findingId: z.string().min(1).max(128),
  title: z.string().min(1).max(512),
  verdict: z.enum(['supported', 'unsupported', 'abstain', 'escalate']),
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']),
  cwes: z.array(z.string().regex(/^CWE-\d+$/)),
  rootCauseId: z.string().regex(/^RC-[A-Z0-9][A-Z0-9._-]{0,63}$/).optional(),
  evidence: z.array(FindingEvidenceSchema),
  runtimeProof: z.object({
    scenarioId: z.string().min(1).max(128),
    receiptIds: z.array(z.string().min(1).max(128)).min(1),
  }).strict().optional(),
}).strict();
export type NormalizedBenchmarkFinding = z.infer<typeof NormalizedBenchmarkFindingSchema>;

export const BlindReviewPacketSchema = NormalizedBenchmarkFindingSchema.omit({
  runId: true,
  runSha256: true,
  arm: true,
  evidence: true,
}).extend({
  packetId: z.string().regex(/^packet-[a-f0-9]{24}$/),
  evidence: z.array(BlindFindingEvidenceSchema),
}).strict();
export type BlindReviewPacket = z.infer<typeof BlindReviewPacketSchema>;

export const BenchmarkJudgmentSchema = z.object({
  packetId: z.string().regex(/^packet-[a-f0-9]{24}$/),
  reviewerBlindId: z.string().regex(/^reviewer-[a-f0-9]{12}$/),
  authority: z.enum(['reviewer', 'adjudicator']),
  decision: z.enum(['true-positive', 'false-positive', 'novel-valid', 'duplicate', 'inconclusive']),
  labelId: z.string().regex(/^GT-[A-Z0-9][A-Z0-9._-]{0,63}$/).nullable(),
  sourceEvidenceValid: z.boolean(),
  runtimeProofValid: z.boolean().nullable(),
  rationale: z.string().min(20).max(4096),
}).strict().superRefine((value, context) => {
  if (value.decision === 'true-positive' && !value.labelId) {
    context.addIssue({ code: 'custom', message: 'true-positive judgment에는 labelId가 필요하다' });
  }
  if (value.decision !== 'true-positive' && value.labelId) {
    context.addIssue({ code: 'custom', message: 'true-positive 외 judgment에는 labelId를 허용하지 않는다' });
  }
});
export type BenchmarkJudgment = z.infer<typeof BenchmarkJudgmentSchema>;

export function createBenchmarkSourceManifest(input: {
  target: string;
  revision: string;
  files: readonly string[];
}): BenchmarkSourceManifest {
  const targetRoot = realpathSync(input.target);
  const files = [...new Set(input.files)].sort().map((path) => {
    const normalized = RelativePathSchema.parse(path);
    const absolute = canonicalFile(targetRoot, normalized);
    const content = readFileSync(absolute);
    return { path: normalized, bytes: content.byteLength, sha256: sha256(content) };
  });
  const core = SourceManifestCoreSchema.parse({ schemaVersion: '1.0.0', revision: input.revision, files });
  return BenchmarkSourceManifestSchema.parse({ ...core, manifestSha256: sha256(stableJson(core)) });
}

export function assertBenchmarkSourceManifestIntact(
  value: unknown,
  target: string,
): BenchmarkSourceManifest {
  const manifest = BenchmarkSourceManifestSchema.parse(value);
  const { manifestSha256, ...core } = manifest;
  if (sha256(stableJson(core)) !== manifestSha256) throw new Error('benchmark source manifest hash가 다르다');
  const paths = manifest.files.map((file) => file.path);
  if (new Set(paths).size !== paths.length || paths.join('\n') !== [...paths].sort().join('\n')) {
    throw new Error('benchmark source manifest path가 중복되거나 정렬되지 않았다');
  }
  const targetRoot = realpathSync(target);
  for (const file of manifest.files) {
    const content = readFileSync(canonicalFile(targetRoot, file.path));
    if (content.byteLength !== file.bytes || sha256(content) !== file.sha256) {
      throw new Error(`benchmark source file이 봉인 후 달라졌다: ${file.path}`);
    }
  }
  return manifest;
}

export function assertBenchmarkCorpusIntact(value: unknown): BenchmarkCorpus {
  const corpus = BenchmarkCorpusSchema.parse(value);
  const { corpusSha256, ...core } = corpus;
  if (sha256(stableJson(core)) !== corpusSha256) throw new Error('benchmark corpus hash가 다르다');
  const caseIds = corpus.cases.map((entry) => entry.caseId);
  if (new Set(caseIds).size !== caseIds.length) throw new Error('benchmark corpus caseId가 중복됐다');
  if (corpus.claimAuthority === 'final-holdout' && corpus.split !== 'holdout') {
    throw new Error('final-holdout authority는 holdout split에만 허용된다');
  }
  for (const entry of corpus.cases) {
    const labels = entry.labels.map((label) => label.labelId);
    if (new Set(labels).size !== labels.length) throw new Error(`benchmark labelId가 중복됐다: ${entry.caseId}`);
  }
  return corpus;
}

export function assertBenchmarkRunArtifactsIntact(
  value: unknown,
  runDir: string,
): BenchmarkRunRecord {
  const record = BenchmarkRunRecordSchema.parse(value);
  const { runSha256, ...core } = record;
  if (sha256(stableJson(core)) !== runSha256) throw new Error('benchmark run record hash가 다르다');
  if (record.exitCode !== 0) throw new Error('benchmark arm 실행이 성공하지 않았다');
  const runRoot = realpathSync(runDir);
  const paths = record.artifacts.map((artifact) => artifact.path);
  if (new Set(paths).size !== paths.length) throw new Error('benchmark run artifact가 중복됐다');
  for (const artifact of record.artifacts) {
    const content = readFileSync(canonicalFile(runRoot, artifact.path));
    if (content.byteLength !== artifact.bytes || sha256(content) !== artifact.sha256) {
      throw new Error(`benchmark artifact가 실행 후 달라졌다: ${artifact.path}`);
    }
  }
  return record;
}

export function validateNormalizedBenchmarkFindings(input: {
  findings: readonly unknown[];
  run: BenchmarkRunRecord;
  sourceManifest: BenchmarkSourceManifest;
  target: string;
}): NormalizedBenchmarkFinding[] {
  if (input.run.sourceManifestSha256 !== input.sourceManifest.manifestSha256) {
    throw new Error('benchmark run과 source manifest binding이 다르다');
  }
  const targetRoot = realpathSync(input.target);
  const allowed = new Set(input.sourceManifest.files.map((file) => file.path));
  const findings = input.findings.map((value) => NormalizedBenchmarkFindingSchema.parse(value));
  const identities = new Set<string>();
  for (const finding of findings) {
    if (finding.runId !== input.run.runId || finding.runSha256 !== input.run.runSha256 ||
        finding.caseId !== input.run.caseId || finding.arm !== input.run.arm) {
      throw new Error('normalized Finding의 run identity가 다르다');
    }
    const identity = `${finding.findingId}\0${finding.title}`;
    if (identities.has(identity)) throw new Error('normalized Finding이 중복됐다');
    identities.add(identity);
    for (const evidence of finding.evidence) {
      if (!allowed.has(evidence.path)) throw new Error(`Finding evidence가 sealed source 밖이다: ${evidence.path}`);
      assertSourceAnchor(targetRoot, evidence);
    }
    if (finding.verdict === 'supported' && finding.evidence.length === 0) {
      throw new Error('supported benchmark Finding에는 source evidence가 필요하다');
    }
    if (input.run.capability === 'pentest' && finding.verdict === 'supported' && !finding.runtimeProof) {
      throw new Error('supported pentest benchmark Finding에는 runtime proof가 필요하다');
    }
  }
  return findings;
}

export function assertBenchmarkNormalizationIntact(input: {
  record: unknown;
  findings: readonly unknown[];
  normalizedFile: Buffer;
  run: BenchmarkRunRecord;
  sourceManifest: BenchmarkSourceManifest;
}): BenchmarkNormalizationRecord {
  const record = BenchmarkNormalizationRecordSchema.parse(input.record);
  const { recordSha256, ...core } = record;
  if (sha256(stableJson(core)) !== recordSha256) throw new Error('benchmark normalization record hash가 다르다');
  if (record.runSha256 !== input.run.runSha256 ||
      record.sourceManifestSha256 !== input.sourceManifest.manifestSha256) {
    throw new Error('benchmark normalization provenance가 run/source와 다르다');
  }
  const findings = NormalizedBenchmarkFindingSchema.array().parse(input.findings);
  if (record.normalizedSha256 !== sha256(stableJson(findings)) ||
      record.normalizedFileSha256 !== sha256(input.normalizedFile)) {
    throw new Error('benchmark normalized Finding seal이 다르다');
  }
  return record;
}

export function assertNoBenchmarkLeak(task: string, corpus: BenchmarkCorpus): void {
  const normalized = task.toLowerCase();
  const forbidden = corpus.cases.flatMap((entry) => [
    entry.caseId,
    entry.repositoryPseudonym,
    entry.vulnerableRevision,
    entry.fixedRevision,
    ...entry.labels.flatMap((label) => [label.labelId, label.rootCauseId, label.dynamicOracleId]),
  ]).filter((value): value is string => Boolean(value));
  const leaked = forbidden.find((value) => normalized.includes(value.toLowerCase()));
  if (leaked) throw new Error(`benchmark task에 sealed ground-truth 식별자가 노출됐다: ${leaked}`);
}

export function createBlindReviewPackets(input: {
  findings: readonly NormalizedBenchmarkFinding[];
  salt?: string;
}): { packets: BlindReviewPacket[]; privateMapping: Map<string, NormalizedBenchmarkFinding> } {
  const salt = input.salt ?? randomBytes(32).toString('hex');
  if (!/^[a-f0-9]{64}$/.test(salt)) throw new Error('blind review salt가 잘못됐다');
  const privateMapping = new Map<string, NormalizedBenchmarkFinding>();
  const packets = input.findings.map((finding) => {
    const packetId = `packet-${sha256(`${salt}:${finding.runSha256}:${finding.findingId}:${finding.title}`).slice(0, 24)}`;
    const { runId: _runId, runSha256: _runSha256, arm: _arm, evidence, ...publicFinding } = finding;
    const blindEvidence = evidence.map(({ origin: _origin, ...anchor }) => anchor);
    const packet = BlindReviewPacketSchema.parse({ ...publicFinding, evidence: blindEvidence, packetId });
    privateMapping.set(packetId, finding);
    return packet;
  });
  return { packets, privateMapping };
}

export function resolveBenchmarkJudgments(
  packetIds: readonly string[],
  values: readonly unknown[],
): Map<string, BenchmarkJudgment> {
  const requested = new Set(packetIds);
  const judgments = values.map((value) => BenchmarkJudgmentSchema.parse(value));
  const resolved = new Map<string, BenchmarkJudgment>();
  for (const packetId of requested) {
    const entries = judgments.filter((value) => value.packetId === packetId);
    if (new Set(entries.map((value) => value.reviewerBlindId)).size !== entries.length) {
      throw new Error(`동일 reviewer가 judgment를 중복 제출했다: ${packetId}`);
    }
    const reviewers = entries.filter((value) => value.authority === 'reviewer');
    if (reviewers.length !== 2) throw new Error(`benchmark packet에는 독립 reviewer가 정확히 2명 필요하다: ${packetId}`);
    const signature = (value: BenchmarkJudgment): string => [
      value.decision, value.labelId ?? '', String(value.sourceEvidenceValid), String(value.runtimeProofValid),
    ].join('\0');
    if (signature(reviewers[0]!) === signature(reviewers[1]!)) {
      resolved.set(packetId, reviewers[0]!);
      continue;
    }
    const adjudicators = entries.filter((value) => value.authority === 'adjudicator');
    if (adjudicators.length !== 1) throw new Error(`불일치 packet에는 adjudicator 1명이 필요하다: ${packetId}`);
    resolved.set(packetId, adjudicators[0]!);
  }
  if (judgments.some((value) => !requested.has(value.packetId))) {
    throw new Error('알 수 없는 benchmark packet judgment가 있다');
  }
  return resolved;
}

function assertSourceAnchor(targetRoot: string, anchor: z.infer<typeof SourceAnchorSchema>): void {
  const lines = readFileSync(canonicalFile(targetRoot, anchor.path), 'utf8').split(/\r?\n/);
  if (anchor.lineEnd > lines.length) throw new Error(`Finding evidence line이 파일을 벗어났다: ${anchor.path}`);
  const observed = lines.slice(anchor.lineStart - 1, anchor.lineEnd).join('\n');
  if (observed.trim() !== anchor.quote.trim()) throw new Error(`Finding evidence quote가 원본과 다르다: ${anchor.path}`);
}

function canonicalFile(root: string, path: string): string {
  const absolute = resolve(root, RelativePathSchema.parse(path));
  if (!existsSync(absolute) || !lstatSync(absolute).isFile()) throw new Error(`benchmark file이 없다: ${path}`);
  const canonical = realpathSync(absolute);
  if (canonical !== root && !canonical.startsWith(`${root}${sep}`)) {
    throw new Error(`benchmark path가 target 밖이다: ${path}`);
  }
  return canonical;
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function benchmarkSha256(value: string | Buffer): string {
  return sha256(value);
}

export function benchmarkStableJson(value: unknown): string {
  return stableJson(value);
}

function sha256(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}
