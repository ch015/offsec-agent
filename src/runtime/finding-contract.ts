import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  readdirSync,
} from 'node:fs';
import { createHash } from 'node:crypto';
import { relative, resolve, sep } from 'node:path';

import { z } from 'zod';

import { loadOffsecContract, type OffsecContract } from './offsec-contract.js';
import { atomicPrivateCreate, atomicPrivateWrite, readManagedFile } from './workflow/storage-files.js';

type StandardEvidence = {
  path: string;
  lineStart: number;
  lineEnd: number;
  quote: string;
};

/** Host-computed content anchor (scheme fp1). It proposes matches across runs and duplicate
 * warnings only; it never merges or overwrites findings on its own. */
export type FindingFingerprint = {
  scheme: 'fp1';
  path: string;
  anchor: string;
  ordinal: number;
  span: string;
  evidence: string[];
  weakness: string | null;
  digest: string;
};

/** Host allowlist for `revises`: each continuable ID with the primary locations it was filed at. */
export type RevisableFindings = ReadonlyMap<string, ReadonlyArray<Pick<FindingFingerprint, 'path' | 'anchor'>>>;

export type AnchoredRevision = { id: string; path: string; anchor: string };

/** JSON-safe allowlist entries (session specs cross a serialization boundary). */
export function anchoredRevisions(findings: readonly Pick<StandardFinding, 'id' | 'fingerprint'>[]): AnchoredRevision[] {
  return findings.flatMap(finding => finding.fingerprint
    ? [{ id: finding.id, path: finding.fingerprint.path, anchor: finding.fingerprint.anchor }] : []);
}

export function revisableFindings(entries: readonly AnchoredRevision[]): RevisableFindings {
  const map = new Map<string, Array<Pick<FindingFingerprint, 'path' | 'anchor'>>>();
  for (const { id, path, anchor } of entries) map.set(id, [...map.get(id) ?? [], { path, anchor }]);
  return map;
}

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
  /** Host-allowed earlier ID this submission continues (same claim, possibly retitled). */
  revises?: string;
  fingerprint?: FindingFingerprint;
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
  | 'revises'
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

  if (properties?.revises) SubmitFindingShapeLocal.revises = findingField<string>('revises').optional();

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

const sha256 = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');

function displayId(digest: string): string {
  const numeric = BigInt(`0x${digest.slice(0, 15)}`) % 1_000_000_000_000n;
  return `F-${numeric.toString().padStart(12, '0')}`;
}

// Whitespace-only differences never change identity. Case and comments are kept: code is case
// sensitive and comment syntax is language specific.
const normLine = (line: string) => line.normalize('NFC').replace(/\r$/, '').replace(/\s+/g, ' ').trim();
const normBlock = (quote: string) => quote.split('\n').map(normLine).filter(Boolean).join('\n');
const normTitle = (title: string) => title.normalize('NFKC').toLowerCase().replace(/\s+/g, ' ').trim().replace(/[.!?;:,。]+$/u, '');

function fingerprintBody(evidence: readonly StandardEvidence[], standards: readonly string[], ordinal: number) {
  const first = evidence[0];
  const key = first ? normBlock(first.quote).split('\n')[0] ?? '' : '';
  const cwe = standards.map(value => /CWE-(\d+)/i.exec(value)?.[1]).find(Boolean);
  return {
    scheme: 'fp1' as const,
    path: first ? first.path.normalize('NFC') : 'unresolved',
    anchor: key ? sha256(key) : '',
    ordinal: key ? ordinal : 0,
    span: first ? sha256(normBlock(first.quote)) : '',
    evidence: [...new Set(evidence.map(item => `${item.path.normalize('NFC')}:${sha256(normBlock(item.quote))}`))].sort(),
    weakness: cwe ? `CWE-${cwe}` : null,
  };
}

/** Evidence must already be validated: paths are target-relative and quotes match the source. */
export function computeFindingFingerprint(target: string, evidence: readonly StandardEvidence[],
  standards: readonly string[]): FindingFingerprint {
  const first = evidence[0];
  let ordinal = 0;
  if (first) {
    // Which occurrence of the key line this is, so repeated statements in one file stay distinct.
    const key = normBlock(first.quote).split('\n')[0] ?? '';
    const lines = readFileSync(resolve(realpathSync(target), first.path), 'utf8').split('\n').map(normLine);
    const at = lines.findIndex((line, index) => index >= first.lineStart - 1 && line === key);
    ordinal = at < 0 ? 0 : lines.slice(0, at + 1).filter(line => line === key).length;
  }
  const body = fingerprintBody(evidence, standards, ordinal);
  return { ...body, digest: sha256(JSON.stringify(body)) };
}

/** Line moves, range-end changes and title spelling differences keep the ID; a rewritten title
 * gets a new ID unless the submission names the earlier one through `revises`. */
export function deriveFindingId(fingerprint: Pick<FindingFingerprint, 'path' | 'anchor' | 'ordinal'>, title: string): string {
  return displayId(sha256(`fid2\0${fingerprint.path}\0${fingerprint.anchor}\0${fingerprint.ordinal}\0${normTitle(title)}`));
}

export function standardFindingRecordName(finding: Pick<StandardFinding, 'id' | 'phase' | 'role' | 'round'>): string {
  return `${sha256(`${finding.id}\0${finding.phase}\0${finding.role}\0${finding.round ?? ''}`)}.json`;
}

const versionAtLeast = (version: string, minimum: string) => {
  const [a, b] = [version, minimum].map(value => value.split('.').map(Number));
  for (let index = 0; index < 3; index++) if ((a![index] ?? 0) !== (b![index] ?? 0)) return (a![index] ?? 0) > (b![index] ?? 0);
  return true;
};

/** Records written by 2.2.0+ must carry a consistent fp1 identity. Earlier records keep their
 * legacy ID (path:lineStart:title) and are read unchanged; there is no migration. */
export function assertFindingIdentity(finding: StandardFinding): void {
  const fingerprint = finding.fingerprint;
  if (!fingerprint) {
    if (versionAtLeast(finding.contractVersion, '2.2.0')) throw new Error(`Finding identity fingerprint가 없다: ${finding.id}`);
    return;
  }
  const expected = fingerprintBody(finding.evidence, finding.standards, fingerprint.ordinal);
  // Compare in the canonical field order, independent of how the record's keys were serialized.
  const stored = Object.fromEntries(Object.keys(expected).map(key => [key, fingerprint[key as keyof typeof expected]]));
  if (Object.keys(fingerprint).length !== Object.keys(expected).length + 1
    || JSON.stringify(stored) !== JSON.stringify(expected) || fingerprint.digest !== sha256(JSON.stringify(expected))) {
    throw new Error(`Finding fingerprint가 기록 내용과 일치하지 않는다: ${finding.id}`);
  }
  if (finding.id !== (finding.revises ?? deriveFindingId(fingerprint, finding.title))) {
    throw new Error(`Finding ID가 identity 규칙과 일치하지 않는다: ${finding.id}`);
  }
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
  /** IDs this session may continue with `revises` (earlier attempts of the task, review targets). */
  revisableIds?: RevisableFindings;
}): StandardFinding {
  return submitStandardFindingWithNotices(input).finding;
}

export type FindingSubmissionNotices = {
  /** Same primary anchor, different ID: maybe the same claim retitled without `revises`. */
  possibleDuplicates: Array<{ id: string; title: string }>;
  /** Earlier bytes of this record that the submission replaced; they are kept in finding-history. */
  replaced?: { title: string; sha256: string };
};

export function submitStandardFindingWithNotices(input: Parameters<typeof submitStandardFinding>[0]): {
  finding: StandardFinding; notices: FindingSubmissionNotices;
} {
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
  const { revises, ...claim } = input.finding;
  const fingerprint = computeFindingFingerprint(input.target, evidence, claim.standards);
  if (revises !== undefined) {
    const anchors = input.revisableIds?.get(revises);
    if (!anchors) throw new Error(`revises 대상은 이 세션에서 이어 쓸 수 있는 Finding ID가 아니다: ${revises}`);
    // A revision keeps the claim's primary location; a claim elsewhere is a different claim with its own ID.
    if (!anchors.some(anchor => anchor.path === fingerprint.path && anchor.anchor === fingerprint.anchor)) {
      throw new Error(`revises는 같은 주 근거 문장(evidence[0])의 claim에만 쓸 수 있다: ${revises}`);
    }
  }
  // Host-owned fields come last so a caller can never supply its own ID, role or fingerprint.
  const finding = findingSchema.parse({
    ...claim,
    id: revises ?? deriveFindingId(fingerprint, claim.title),
    contractVersion: contract.version,
    phase: input.phase,
    role: input.role,
    round: input.round ?? null,
    evidence,
    ...(revises !== undefined ? { revises } : {}),
    fingerprint,
  });
  if (new Set(finding.standards).size !== finding.standards.length) {
    throw new Error('standards 항목이 중복됐다');
  }
  mkdirSync(input.engagementDir, { recursive: true, mode: 0o700 });
  const recordsDir = resolve(input.engagementDir, FINDINGS_RECORDS);
  mkdirSync(recordsDir, { recursive: true, mode: 0o700 });
  const recordName = standardFindingRecordName(finding);
  const recordPath = resolve(recordsDir, recordName);
  const bytes = `${JSON.stringify(finding)}\n`;
  const notices: FindingSubmissionNotices = { possibleDuplicates: [] };
  for (const name of readdirSync(recordsDir).filter(entry => /^[a-f0-9]{64}\.json$/.test(entry) && entry !== recordName)) {
    // Advisory only: an unreadable sibling never blocks the submission.
    let other: StandardFinding | undefined;
    try { other = JSON.parse(readManagedFile(input.engagementDir, resolve(recordsDir, name)).toString('utf8')) as StandardFinding; } catch { continue; }
    if (other?.fingerprint && other.id !== finding.id && other.fingerprint.path === fingerprint.path
      && other.fingerprint.anchor === fingerprint.anchor && other.fingerprint.ordinal === fingerprint.ordinal) {
      notices.possibleDuplicates.push({ id: other.id, title: other.title });
    }
  }
  // Upsert: resubmitting the same identity replaces the record (richer evidence or severity).
  // The replaced bytes are archived first so a revision never silently drops a claim.
  if (existsSync(recordPath)) {
    const previous = readManagedFile(input.engagementDir, recordPath);
    if (previous.toString('utf8') !== bytes) {
      const digest = sha256(previous);
      const archived = resolve(input.engagementDir, '.recovery', 'finding-history', recordName, `${digest}.json`);
      if (!existsSync(archived)) atomicPrivateWrite(archived, previous);
      notices.replaced = { title: (JSON.parse(previous.toString('utf8')) as StandardFinding).title, sha256: digest };
    }
  }
  // 원자적 교체: 중단돼도 이전 버전이나 새 버전 중 하나만 남고, 쓰다 만 JSON은 남지 않는다.
  atomicPrivateWrite(recordPath, bytes);
  return { finding, notices };
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
    unique.set(standardFindingRecordName(finding), finding);
  }
  return [...unique.values()];
}

export function readStandardFindingRecordReceipts(
  engagementDir: string,
): StandardFindingRecordReceipt[] {
  const recordsDir = resolve(engagementDir, FINDINGS_RECORDS);
  if (!existsSync(recordsDir)) return [];
  // Atomic record writes stage `<record>.json.<uuid>.tmp` beside the record; an interrupted write can
  // leave one behind. Only that exact staging name is skipped; any other foreign file still fails.
  const names = readdirSync(recordsDir).filter((name) => !/^[a-f0-9]{64}\.json\.[0-9a-f-]{36}\.tmp$/.test(name)).sort();
  if (names.some((name) => !/^[a-f0-9]{64}\.json$/.test(name))) {
    throw new Error('standard Finding record directory에 비계약 파일이 있다');
  }
  return names
    .map((recordName) => {
      const recordPath = resolve(recordsDir, recordName);
      if (!lstatSync(recordPath).isFile()) throw new Error('standard Finding record가 일반 파일이 아니다');
      const content = readFileSync(recordPath);
      const finding = StandardFindingSchema.parse(JSON.parse(content.toString('utf8')));
      assertFindingIdentity(finding);
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
  /** Retention may select the latest version of each record across several attempts. */
  selectedRecordNames?: ReadonlySet<string>;
  /** Host-authorized previous attempts; only exact matching root bytes may be replaced. */
  superseded?: readonly StandardFindingRecordReceipt[];
}): StandardFindingRecordReceipt[] {
  const observed = readStandardFindingRecordReceipts(input.fromEngagementDir);
  if (JSON.stringify(observed) !== JSON.stringify(input.expected)) {
    throw new Error('work unit typed Finding receipt가 집계 전에 변경됐다');
  }
  const sourceDir = resolve(input.fromEngagementDir, FINDINGS_RECORDS);
  const destinationDir = resolve(input.toEngagementDir, FINDINGS_RECORDS);
  mkdirSync(destinationDir, { recursive: true, mode: 0o700 });
  const selected = observed.filter(receipt => !input.selectedRecordNames || input.selectedRecordNames.has(receipt.recordName));
  for (const receipt of selected) {
    const content = readFileSync(resolve(sourceDir, receipt.recordName));
    const destination = resolve(destinationDir, receipt.recordName);
    try {
      atomicPrivateCreate(destination, content);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      const previous = readManagedFile(input.toEngagementDir, destination);
      if (!previous.equals(content)) {
        const sha256 = createHash('sha256').update(previous).digest('hex');
        const identity = (bytes: Buffer) => {
          const finding = StandardFindingSchema.parse(JSON.parse(bytes.toString('utf8')));
          // fp1 IDs already bind the anchor and title (or an allowed `revises`), so a retitled
          // revision of the same ID is the same claim. Legacy records keep the stricter tuple.
          return JSON.stringify(finding.fingerprint
            ? [finding.id, finding.contractVersion, finding.phase, finding.role, finding.round]
            : [finding.id, finding.contractVersion, finding.phase, finding.role, finding.round,
              finding.title, finding.evidence[0]?.path, finding.evidence[0]?.lineStart]);
        };
        if (identity(previous) !== identity(content) || !input.superseded?.some(old => old.recordName === receipt.recordName && old.findingId === receipt.findingId
          && old.bytes === previous.byteLength && old.sha256 === sha256)) {
          throw new Error(`work unit typed Finding이 root record와 충돌한다: ${receipt.findingId}`);
        }
        const archived = resolve(input.toEngagementDir, '.recovery', 'finding-history', receipt.recordName, `${sha256}.json`);
        if (existsSync(archived)) {
          if (!readManagedFile(input.toEngagementDir, archived).equals(previous)) throw new Error('Superseded Finding history integrity mismatch');
        } else atomicPrivateWrite(archived, previous);
        atomicPrivateWrite(destination, content);
      }
    }
  }
  return selected;
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
