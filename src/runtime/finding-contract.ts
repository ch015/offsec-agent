import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  readdirSync,
  writeFileSync,
} from 'node:fs';
import { createHash } from 'node:crypto';
import { relative, resolve, sep } from 'node:path';

import { z } from 'zod';

import { loadOffsecContract, type OffsecContract } from './offsec-contract.js';

type StandardEvidence = {
  path: string;
  lineStart: number;
  lineEnd: number;
  quote: string;
};

export type StandardFinding = {
  id: string;
  contractVersion: string;
  phase: string;
  role: string;
  round: string | null;
  title: string;
  verdict: 'supported' | 'unsupported' | 'abstain' | 'escalate';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  evidenceClass: 'data-flow' | 'configuration' | 'access-control' | 'runtime' | 'documentation';
  reachability: 'confirmed' | 'plausible' | 'unconfirmed' | 'not-applicable';
  preconditions: string[];
  severityRationale: string;
  confidence: number;
  impact: string;
  remediation: string;
  standards: string[];
  unresolved: string[];
  evidence: StandardEvidence[];
  runtimeEvidence?: {
    scenarioId: string;
    receiptId: string;
    relatedReceiptIds?: string[];
    oracle?: string;
    reproducibility?: 'single-observation' | 'repeated' | 'differential' | 'state-transition';
    observedImpact: string;
    inferredImpact: string;
  };
};

type SubmitFinding = Pick<
  StandardFinding,
  | 'title'
  | 'verdict'
  | 'severity'
  | 'evidenceClass'
  | 'reachability'
  | 'preconditions'
  | 'severityRationale'
  | 'confidence'
  | 'impact'
  | 'remediation'
  | 'standards'
  | 'unresolved'
  | 'evidence'
  | 'runtimeEvidence'
>;

type JsonSchemaInput = Parameters<typeof z.fromJSONSchema>[0];

export type FindingContract = {
  StandardFindingSchema: z.ZodType<StandardFinding>;
  SubmitFindingShape: Record<string, z.ZodTypeAny>;
  contractVersion: string;
};

/**
 * 계약별 finding schema/submit shape를 조립하는 팩토리.
 * 스키마가 실제로 정의한 필드만 build한다. Historical evidence remains readable.
 */
export function buildFindingContract(contract: OffsecContract): FindingContract {
  const contractFindingSchema = contract.findingSchema;
  const properties = contractFindingSchema.properties as Record<string, JsonSchemaInput> | undefined;

  const StandardFindingSchemaLocal = z.fromJSONSchema(
    contractFindingSchema as JsonSchemaInput,
  ) as z.ZodType<StandardFinding>;

  const findingField = <T>(name: keyof SubmitFinding): z.ZodType<T> => {
    const schema = properties?.[name];
    if (!schema) throw new Error(`OffSec findingSchema에 submit field가 없다: ${String(name)}`);
    return z.fromJSONSchema(schema) as z.ZodType<T>;
  };

  const SubmitFindingShapeLocal: Record<string, z.ZodTypeAny> = {
    title: findingField<string>('title'),
    verdict: findingField<SubmitFinding['verdict']>('verdict'),
    severity: findingField<SubmitFinding['severity']>('severity'),
    evidenceClass: findingField<SubmitFinding['evidenceClass']>('evidenceClass'),
    reachability: findingField<SubmitFinding['reachability']>('reachability'),
    preconditions: findingField<string[]>('preconditions'),
    severityRationale: findingField<string>('severityRationale'),
    confidence: findingField<number>('confidence'),
    impact: findingField<string>('impact'),
    remediation: findingField<string>('remediation'),
    standards: findingField<string[]>('standards'),
    unresolved: findingField<string[]>('unresolved'),
    evidence: findingField<StandardEvidence[]>('evidence'),
  };
  // runtimeEvidence는 스키마가 정의한 경우에만 build한다 (v2는 생략).
  if (properties?.runtimeEvidence) {
    SubmitFindingShapeLocal.runtimeEvidence = findingField<NonNullable<SubmitFinding['runtimeEvidence']>>(
      'runtimeEvidence',
    ).optional();
  }

  return {
    StandardFindingSchema: StandardFindingSchemaLocal,
    SubmitFindingShape: SubmitFindingShapeLocal,
    contractVersion: contract.version,
  };
}

// 기본 단일 계약으로 build한 module-global binding.
const defaultFindingContract = buildFindingContract(loadOffsecContract());
export const StandardFindingSchema = defaultFindingContract.StandardFindingSchema;
export const SubmitFindingShape = defaultFindingContract.SubmitFindingShape;

const FINDINGS_LEDGER = 'standard-findings.jsonl';
const FINDINGS_RECORDS = 'standard-findings';

export type StandardFindingRecordReceipt = Readonly<{
  recordName: string;
  findingId: string;
  bytes: number;
  sha256: string;
}>;

function canonicalExistingPath(filePath: string, cwd: string): string {
  const absolute = resolve(cwd, filePath);
  if (!existsSync(absolute)) throw new Error(`evidence file이 없다: ${absolute}`);
  return realpathSync(absolute);
}

function isWithin(filePath: string, root: string): boolean {
  return filePath === root || filePath.startsWith(`${root}${sep}`);
}

function stableFindingId(path: string, lineStart: number, title: string): string {
  const digest = createHash('sha256').update(`${path}:${lineStart}:${title}`).digest('hex');
  const numeric = BigInt(`0x${digest.slice(0, 15)}`) % 1_000_000_000_000n;
  return `F-${numeric.toString().padStart(12, '0')}`;
}

export function validateEvidence(input: {
  evidence: StandardEvidence[];
  target: string;
  allowedFiles?: readonly string[];
}): StandardEvidence[] {
  const targetRoot = realpathSync(input.target);
  const allowedFiles = input.allowedFiles
    ? new Set(input.allowedFiles.map((path) => canonicalExistingPath(path, targetRoot)))
    : undefined;
  return input.evidence.map((evidence) => {
    if (evidence.lineEnd < evidence.lineStart) {
      throw new Error(`evidence line 범위가 역전됐다: ${evidence.lineStart}-${evidence.lineEnd}`);
    }
    const absolute = canonicalExistingPath(evidence.path, targetRoot);
    if (!isWithin(absolute, targetRoot)) throw new Error(`evidence가 target 밖을 가리킨다: ${evidence.path}`);
    if (allowedFiles && !allowedFiles.has(absolute)) {
      throw new Error(`evidence가 work unit owned source 밖을 가리킨다: ${evidence.path}`);
    }
    const lines = readFileSync(absolute, 'utf8').split(/\r?\n/);
    if (evidence.lineEnd > lines.length) {
      throw new Error(`evidence lineEnd가 파일 길이를 넘는다: ${evidence.lineEnd}/${lines.length}`);
    }
    const observed = lines.slice(evidence.lineStart - 1, evidence.lineEnd).join('\n');
    if (observed.trim() !== evidence.quote.trim()) {
      throw new Error(`evidence quote가 지정 line 범위와 일치하지 않는다: ${evidence.path}`);
    }
    return { ...evidence, path: relative(targetRoot, absolute) };
  });
}

export function submitStandardFinding(input: {
  target: string;
  engagementDir: string;
  phase: string;
  role: string;
  round?: string;
  evidenceAllowedFiles?: readonly string[];
  finding: SubmitFinding;
  contract?: OffsecContract;
}): StandardFinding {
  const contract = input.contract ?? loadOffsecContract();
  const findingContract = input.contract
    ? buildFindingContract(input.contract)
    : defaultFindingContract;
  const findingSchema = findingContract.StandardFindingSchema;
  const evidence = validateEvidence({
    evidence: input.finding.evidence,
    target: input.target,
    allowedFiles: input.evidenceAllowedFiles,
  });
  if (
    (input.finding.verdict === 'supported' || input.finding.verdict === 'unsupported') &&
    evidence.length === 0
  ) {
    throw new Error(`${input.finding.verdict} finding에는 검증된 evidence가 최소 1개 필요하다`);
  }
  if (
    (input.finding.verdict === 'abstain' || input.finding.verdict === 'escalate') &&
    input.finding.unresolved.length === 0
  ) {
    throw new Error(`${input.finding.verdict} finding에는 unresolved 사유가 필요하다`);
  }
  if (input.finding.severity === 'CRITICAL' || input.finding.severity === 'HIGH') {
    if (
      input.finding.evidenceClass === 'documentation' ||
      !['confirmed', 'plausible'].includes(input.finding.reachability)
    ) {
      throw new Error(`${input.finding.severity} severity에는 도달 가능한 비문서 증거가 필요하다`);
    }
    if (input.finding.preconditions.length === 0 || input.finding.severityRationale.trim().length < 20) {
      throw new Error(`${input.finding.severity} severity에는 precondition과 구체적 rationale이 필요하다`);
    }
  }
  if (input.finding.confidence > 0.9 && input.finding.reachability !== 'confirmed') {
    throw new Error('0.9 초과 confidence에는 confirmed reachability가 필요하다');
  }
  const first = evidence[0];
  const finding = findingSchema.parse({
    id: stableFindingId(first?.path ?? 'unresolved', first?.lineStart ?? 0, input.finding.title),
    contractVersion: contract.version,
    phase: input.phase,
    role: input.role,
    round: input.round ?? null,
    ...input.finding,
    evidence,
  });
  if (new Set(finding.standards).size !== finding.standards.length) {
    throw new Error('standards 항목이 중복됐다');
  }
  mkdirSync(input.engagementDir, { recursive: true, mode: 0o700 });
  const recordsDir = resolve(input.engagementDir, FINDINGS_RECORDS);
  mkdirSync(recordsDir, { recursive: true, mode: 0o700 });
  const identity = `${finding.id}\0${finding.phase}\0${finding.role}\0${finding.round ?? ''}`;
  const recordName = `${createHash('sha256').update(identity).digest('hex')}.json`;
  // #10: upsert — 동일 identity의 finding 재제출 시 최신 버전으로 덮어쓰기 (보강된 evidence/severity 반영)
  writeFileSync(resolve(recordsDir, recordName), `${JSON.stringify(finding)}\n`, {
    encoding: 'utf8',
    mode: 0o600,
  });
  return finding;
}

function joinLedger(engagementDir: string): string {
  return resolve(engagementDir, FINDINGS_LEDGER);
}

export function readStandardFindings(engagementDir: string): StandardFinding[] {
  const findings: StandardFinding[] = [];
  const recordsDir = resolve(engagementDir, FINDINGS_RECORDS);
  if (existsSync(recordsDir)) {
    for (const name of readdirSync(recordsDir).filter((entry) => entry.endsWith('.json')).sort()) {
      findings.push(StandardFindingSchema.parse(JSON.parse(readFileSync(resolve(recordsDir, name), 'utf8'))));
    }
  }
  const legacyPath = joinLedger(engagementDir);
  if (existsSync(legacyPath)) {
    for (const line of readFileSync(legacyPath, 'utf8').split(/\r?\n/).filter(Boolean)) {
      findings.push(StandardFindingSchema.parse(JSON.parse(line)));
    }
  }
  const unique = new Map<string, StandardFinding>();
  for (const finding of findings) {
    const key = `${finding.id}\0${finding.phase}\0${finding.role}\0${finding.round ?? ''}`;
    unique.set(key, finding);
  }
  return [...unique.values()];
}

export function readStandardFindingRecordReceipts(
  engagementDir: string,
): StandardFindingRecordReceipt[] {
  const recordsDir = resolve(engagementDir, FINDINGS_RECORDS);
  if (!existsSync(recordsDir)) return [];
  const names = readdirSync(recordsDir).sort();
  if (names.some((name) => !/^[a-f0-9]{64}\.json$/.test(name))) {
    throw new Error('standard Finding record directory에 비계약 파일이 있다');
  }
  return names
    .map((recordName) => {
      const recordPath = resolve(recordsDir, recordName);
      if (!lstatSync(recordPath).isFile()) throw new Error('standard Finding record가 일반 파일이 아니다');
      const content = readFileSync(recordPath);
      const finding = StandardFindingSchema.parse(JSON.parse(content.toString('utf8')));
      return {
        recordName,
        findingId: finding.id,
        bytes: content.byteLength,
        sha256: createHash('sha256').update(content).digest('hex'),
      };
    });
}

export function promoteStandardFindingRecords(input: {
  fromEngagementDir: string;
  toEngagementDir: string;
  expected: readonly StandardFindingRecordReceipt[];
}): StandardFindingRecordReceipt[] {
  const observed = readStandardFindingRecordReceipts(input.fromEngagementDir);
  if (JSON.stringify(observed) !== JSON.stringify(input.expected)) {
    throw new Error('work unit typed Finding receipt가 집계 전에 변경됐다');
  }
  const sourceDir = resolve(input.fromEngagementDir, FINDINGS_RECORDS);
  const destinationDir = resolve(input.toEngagementDir, FINDINGS_RECORDS);
  mkdirSync(destinationDir, { recursive: true, mode: 0o700 });
  for (const receipt of observed) {
    const content = readFileSync(resolve(sourceDir, receipt.recordName));
    const destination = resolve(destinationDir, receipt.recordName);
    try {
      writeFileSync(destination, content, { mode: 0o600, flag: 'wx' });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      if (!readFileSync(destination).equals(content)) {
        throw new Error(`work unit typed Finding이 root record와 충돌한다: ${receipt.findingId}`);
      }
    }
  }
  return observed;
}

export function assertStandardFindingsRepresented(
  engagementDir: string,
  reportPath: string,
  appendix = '',
): number {
  const content = readFileSync(resolve(reportPath), 'utf8') + appendix;
  const findings = readStandardFindings(engagementDir);
  for (const finding of findings) {
    if (!content.includes(finding.id)) {
      throw new Error(`최종 보고서가 표준 Finding을 소비하지 않았다: ${finding.id}`);
    }

  }
  return findings.length;
}

export function countStandardFindings(
  engagementDir: string,
  phase: string,
  role: string,
  round?: string,
): number {
  return readStandardFindings(engagementDir).filter(
    (finding) =>
      finding.phase === phase &&
      finding.role === role &&
      finding.round === (round ?? null),
  ).length;
}
