import { createHash } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  compareOffsecArms,
  OffsecEvaluationObservationSchema,
  OffsecEvaluationPolicySchema,
  type OffsecCapability,
  type OffsecEvaluationArm,
} from '../src/runtime/offsec-evaluation.js';
import {
  evaluateLiveDastObservations,
  LIVE_DAST_ARMS,
  LIVE_DAST_METRICS,
} from '../src/runtime/live-dast-evaluation.js';
import { assertBenchmarkCorpusIntact, benchmarkStableJson } from '../src/runtime/offsec-benchmark.js';

type EvaluationMode = 'deterministic' | 'live';
type EvaluationSplit = 'validation' | 'holdout';
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const HOLDOUT_STATE_DIR = join(REPO_ROOT, 'evals', 'offsec', 'state');

export function evaluateObservationSet(input: {
  observations: readonly unknown[];
  policy: unknown;
  split: EvaluationSplit;
}) {
  const policy = OffsecEvaluationPolicySchema.parse(input.policy);
  const observations = input.observations.map((value) => OffsecEvaluationObservationSchema.parse(value));
  if (observations.some((value) => value.split !== input.split)) {
    throw new Error(`OffSec evaluation observation split이 요청 split과 다르다: ${input.split}`);
  }
  const comparisons = policy.declaredClaims.flatMap((capability) => [
    compare(capability, 'ch015', 'current-parallel'),
    compare(capability, 'current-sequential', 'current-parallel'),
  ]);
  return {
    schemaVersion: '1.0.0',
    claimAuthority: 'diagnostic-only' as const,
    status: observations.length > 0 ? 'evaluated' as const : 'not_run' as const,
    split: input.split,
    observationCount: observations.length,
    comparisons,
    liveDastEvaluation: evaluateLiveDastObservations({ observations, policy, split: input.split }),
  };

  function compare(capability: OffsecCapability, baseline: OffsecEvaluationArm, candidate: OffsecEvaluationArm) {
    return compareOffsecArms({ observations, capability, baseline, candidate, policy, split: input.split });
  }
}

export function claimHoldoutOpening(input: {
  observations: readonly unknown[];
  policySha256: string;
  corpus: unknown;
  stateDir?: string;
}) {
  const observations = input.observations.map((value) => OffsecEvaluationObservationSchema.parse(value));
  if (observations.length === 0 || observations.some((value) => value.split !== 'holdout')) {
    throw new Error('holdout opening에는 검증된 holdout observation이 필요하다');
  }
  if (!/^[a-f0-9]{64}$/.test(input.policySha256)) throw new Error('holdout policy hash가 잘못됐다');
  const corpus = assertBenchmarkCorpusIntact(input.corpus);
  if (corpus.split !== 'holdout' || corpus.claimAuthority !== 'final-holdout') {
    throw new Error('holdout opening에는 final-holdout corpus artifact가 필요하다');
  }
  if (observations.some((value) => value.provenance.corpusSha256 !== corpus.corpusSha256)) {
    throw new Error('holdout observation과 corpus artifact hash가 다르다');
  }
  const corpusCases = new Map(corpus.cases.map((entry) => [entry.caseId, entry]));
  if (observations.some((value) => corpusCases.get(value.caseId)?.capability !== value.metric.capability)) {
    throw new Error('holdout observation case가 corpus artifact와 다르다');
  }
  const observedCaseIds = [...new Set(observations.map((value) => value.caseId))].sort();
  const corpusCaseIds = [...corpusCases.keys()].sort();
  if (benchmarkStableJson(observedCaseIds) !== benchmarkStableJson(corpusCaseIds)) {
    throw new Error('holdout opening에는 corpus 전체 case observation이 필요하다');
  }
  if (observations.some((value) =>
    corpusCases.get(value.caseId)?.sourceManifestSha256 !== value.provenance.targetSha256)) {
    throw new Error('holdout observation target이 corpus source manifest와 다르다');
  }
  const corpusSha256 = [...new Set(observations.map((value) => value.provenance.corpusSha256))].sort();
  const observationBinding = [...observations]
    .sort((left, right) => benchmarkStableJson(left).localeCompare(benchmarkStableJson(right)));
  const bindingSha256 = createHash('sha256').update(benchmarkStableJson({
    corpusSha256,
    policySha256: input.policySha256,
    observationBinding,
  })).digest('hex');
  const openingKeySha256 = createHash('sha256').update(benchmarkStableJson({
    corpusSha256: corpus.corpusSha256,
    policySha256: input.policySha256,
  })).digest('hex');
  const stateDir = resolve(input.stateDir ?? HOLDOUT_STATE_DIR);
  const markerPath = join(stateDir, `holdout-${openingKeySha256}.opened.json`);
  const auditPath = join(stateDir, 'holdout-audit.jsonl');
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const openedAt = new Date().toISOString();
  try {
    writeFileSync(markerPath, `${JSON.stringify({ openingKeySha256, bindingSha256, corpusSha256, policySha256: input.policySha256, openedAt })}\n`, {
      flag: 'wx',
      mode: 0o600,
    });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
      throw new Error(`holdout corpus/policy binding은 이미 개봉됐다: ${openingKeySha256}`);
    }
    throw error;
  }
  appendHoldoutAudit(auditPath, { event: 'opened', bindingSha256, at: openedAt });
  return { bindingSha256, auditPath };
}

function appendHoldoutAudit(
  auditPath: string,
  record: { event: 'opened' | 'succeeded' | 'failed'; bindingSha256: string; at: string; error?: string },
): void {
  appendFileSync(auditPath, `${JSON.stringify(record)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'a' });
}

function parseArgs(argv: string[]): Map<string, string> {
  const allowed = new Set([
    'mode', 'split', 'policy', 'observations', 'output', 'final-holdout', 'corpus', 'arms', 'repetitions',
  ]);
  const values = new Map<string, string>();
  for (const arg of argv) {
    if (arg === '--') continue;
    const match = /^--([a-z-]+)=(.*)$/.exec(arg);
    if (!match?.[1]) throw new Error(`알 수 없는 eval 인수다: ${arg}`);
    if (!allowed.has(match[1])) throw new Error(`지원하지 않는 eval 인수다: --${match[1]}`);
    values.set(match[1], match[2] ?? '');
  }
  return values;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const mode = (args.get('mode') ?? 'deterministic') as EvaluationMode;
  const split = (args.get('split') ?? 'validation') as EvaluationSplit;
  if (!['deterministic', 'live'].includes(mode)) throw new Error(`eval mode가 잘못됐다: ${mode}`);
  if (!['validation', 'holdout'].includes(split)) throw new Error(`eval split이 잘못됐다: ${split}`);
  const policyPath = args.has('policy')
    ? resolve(args.get('policy')!)
    : join(REPO_ROOT, 'evals', 'offsec', 'policy.json');
  const observationsPath = args.has('observations')
    ? resolve(args.get('observations')!)
    : join(REPO_ROOT, 'evals', 'offsec', `observations.${mode}.${split}.jsonl`);
  const outputPath = args.has('output')
    ? resolve(args.get('output')!)
    : join(REPO_ROOT, 'evals', 'offsec', 'results', `${mode}-${split}.json`);
  mkdirSync(dirname(outputPath), { recursive: true, mode: 0o700 });
  if (args.has('repetitions') && (
    !/^\d+$/.test(args.get('repetitions')!) || Number(args.get('repetitions')) < 1
  )) {
    throw new Error('eval repetitions는 양의 정수여야 한다');
  }

  if (!existsSync(observationsPath)) {
    writeFileSync(outputPath, `${JSON.stringify({
      schemaVersion: '1.1.0',
      status: 'not_run',
      claimAuthority: 'diagnostic-only',
      mode,
      split,
      claim: 'inconclusive',
      reason: 'verified Live DAST observation file is absent; superiority is not evaluated',
      plannedArms: LIVE_DAST_ARMS,
      plannedMetrics: LIVE_DAST_METRICS,
      ...(args.has('arms') ? { requestedArms: args.get('arms')!.split(',').filter(Boolean) } : {}),
      ...(args.has('repetitions') ? { requestedRepetitions: Number(args.get('repetitions')) } : {}),
    }, null, 2)}\n`, { mode: 0o600 });
    console.log(`OffSec evaluation: not_run (${observationsPath})`);
    return;
  }
  const source = readFileSync(observationsPath, 'utf8');
  if (args.has('arms') || args.has('repetitions')) {
    throw new Error('이 evaluator는 arm을 실행하지 않는다; 수집된 observations를 명시해서 평가해야 한다');
  }
  const observations = source.split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
  const policySource = readFileSync(policyPath);
  const policy = JSON.parse(policySource.toString('utf8')) as unknown;
  OffsecEvaluationPolicySchema.parse(policy);
  const parsedObservations = observations.map((value) => OffsecEvaluationObservationSchema.parse(value));
  if (parsedObservations.some((value) => value.split !== split)) {
    throw new Error(`OffSec evaluation observation split이 요청 split과 다르다: ${split}`);
  }
  const policySha256 = createHash('sha256').update(policySource).digest('hex');
  let holdoutRequested = false;
  if (split === 'holdout' && parsedObservations.length > 0) {
    if (args.get('final-holdout') !== 'true') {
      throw new Error('holdout은 설정 고정 뒤 --final-holdout=true로 한 번만 개봉할 수 있다');
    }
    holdoutRequested = true;
  }
  const result = evaluateObservationSet({ observations: parsedObservations, policy, split });
  const holdoutClaim = holdoutRequested
    ? claimHoldoutOpening({
        observations: parsedObservations,
        policySha256,
        corpus: JSON.parse(readFileSync(resolve(requiredArg(args, 'corpus')), 'utf8')),
      })
    : undefined;
  try {
    const record = {
      ...result,
      claimAuthority: holdoutClaim ? 'final-holdout' as const : result.claimAuthority,
      mode,
      observationsSha256: createHash('sha256').update(source).digest('hex'),
      policySha256,
      ...(holdoutClaim ? { holdoutBindingSha256: holdoutClaim.bindingSha256 } : {}),
      evaluatedAt: new Date().toISOString(),
    };
    writeFileSync(outputPath, `${JSON.stringify(record, null, 2)}\n`, { mode: 0o600 });
    if (holdoutClaim) {
      appendHoldoutAudit(holdoutClaim.auditPath, {
        event: 'succeeded', bindingSha256: holdoutClaim.bindingSha256, at: new Date().toISOString(),
      });
    }
    console.log(`OffSec evaluation: ${record.status}, ${record.observationCount} observations`);
  } catch (error) {
    if (holdoutClaim) {
      appendHoldoutAudit(holdoutClaim.auditPath, {
        event: 'failed',
        bindingSha256: holdoutClaim.bindingSha256,
        at: new Date().toISOString(),
        error: error instanceof Error ? error.message : String(error),
      });
    }
    throw error;
  }
}

function requiredArg(args: Map<string, string>, name: string): string {
  const value = args.get(name);
  if (!value) throw new Error(`--${name}가 필요하다`);
  return value;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  });
}
