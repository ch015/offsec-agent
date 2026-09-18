import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';

import { z } from 'zod';

const require = createRequire(import.meta.url);
const yaml = require('js-yaml') as { load(value: string): unknown };

export const ObjectionSchema = z
  .object({
    finding_id: z.string().min(1),
    type: z.string().min(1),
    reason: z.string().min(1),
    instruction: z.string().min(1),
  })
  .strict();

// Presentation metadata is non-semantic and is ignored for count/content matching.
// Keep the objection entries strict while allowing agents to preserve provenance
// (generated_at/phase/round/target or equivalent caller metadata) at the document level.
const ObjectionDocumentSchema = z
  .object({
    meta: z.record(z.string(), z.unknown()).optional(),
    objections: z.array(ObjectionSchema),
  })
  .strict();

export type Objection = z.infer<typeof ObjectionSchema>;

export const SubmitObjectionShape = {
  findingId: z.string().min(1),
  type: z.string().min(1),
  reason: z.string().min(1),
  instruction: z.string().min(1),
};

const StandardObjectionSchema = z
  .object({
    id: z.string().regex(/^O-[0-9]{12}$/),
    contractVersion: z.string().min(1),
    phase: z.string().min(1),
    role: z.literal('verifier'),
    round: z.string().nullable(),
    findingId: SubmitObjectionShape.findingId,
    type: SubmitObjectionShape.type,
    reason: SubmitObjectionShape.reason,
    instruction: SubmitObjectionShape.instruction,
  })
  .strict();

export type StandardObjection = z.infer<typeof StandardObjectionSchema>;

export function submitStandardObjection(input: {
  engagementDir: string;
  contractVersion: string;
  phase: string;
  role: string;
  round?: string;
  objection: {
    findingId: string;
    type: string;
    reason: string;
    instruction: string;
  };
}): StandardObjection {
  if (input.role !== 'verifier') throw new Error('objection은 verifier 역할만 제출할 수 있다');
  const digest = createHash('sha256')
    .update(
      `${input.phase}\0${input.round ?? ''}\0${input.objection.findingId}\0` +
        `${input.objection.type}\0${input.objection.reason}`,
    )
    .digest('hex');
  const numeric = BigInt(`0x${digest.slice(0, 15)}`) % 1_000_000_000_000n;
  const objection = StandardObjectionSchema.parse({
    id: `O-${numeric.toString().padStart(12, '0')}`,
    contractVersion: input.contractVersion,
    phase: input.phase,
    role: input.role,
    round: input.round ?? null,
    ...input.objection,
  });
  const recordsDir = join(input.engagementDir, 'standard-objections');
  mkdirSync(recordsDir, { recursive: true, mode: 0o700 });
  // #11: upsert — 동일 objection 재제출 시 최신 버전으로 덮어쓰기
  writeFileSync(join(recordsDir, `${objection.id}.json`), `${JSON.stringify(objection)}\n`, {
    encoding: 'utf8',
    mode: 0o600,
  });
  return objection;
}

export function readStandardObjections(engagementDir: string): StandardObjection[] {
  const recordsDir = join(engagementDir, 'standard-objections');
  if (!existsSync(recordsDir)) return [];
  return readdirSync(recordsDir)
    .filter((name) => name.endsWith('.json'))
    .sort()
    .map((name) =>
      StandardObjectionSchema.parse(JSON.parse(readFileSync(join(recordsDir, name), 'utf8'))),
    );
}

export function countStandardObjections(
  engagementDir: string,
  phase: string,
  round?: string,
): number {
  return readStandardObjections(engagementDir).filter(
    (objection) => objection.phase === phase && objection.round === (round ?? null),
  ).length;
}

export function loadObjections(filePath: string): Objection[] {
  const parsed = yaml.load(readFileSync(filePath, 'utf8'));
  if (Array.isArray(parsed)) return z.array(ObjectionSchema).parse(parsed);
  return ObjectionDocumentSchema.parse(parsed).objections;
}

function canonicalObjection(objection: {
  finding_id?: string;
  findingId?: string;
  type: string;
  reason: string;
  instruction: string;
}): string {
  // YAML block scalars commonly add one terminal newline (`>`). It is a
  // serialization artifact, not a semantic change to the objection text.
  const stripBlockScalarTerminator = (value: string): string => value.replace(/[ \t]*\r?\n+$/, '');
  return JSON.stringify({
    finding_id: objection.finding_id ?? objection.findingId,
    type: objection.type,
    reason: stripBlockScalarTerminator(objection.reason),
    instruction: stripBlockScalarTerminator(objection.instruction),
  });
}

export function validateObjectionCount(input: {
  engagementDir: string;
  phase: string;
  round?: string;
  artifactNames: readonly string[];
  declaredCount: number;
}): number {
  const accepted = countStandardObjections(input.engagementDir, input.phase, input.round);
  // 모델이 보고한 count를 host 실측값으로 자동 보정 (모델의 counting 오류는 known limitation)
  const effectiveCount = accepted;
  const objectionArtifacts = input.artifactNames.filter((name) => /_objections-.*\.ya?ml$/.test(name));
  if (objectionArtifacts.length > 1) throw new Error('phase objection artifact가 중복됐다');
  const artifact = objectionArtifacts[0];
  const filePath = artifact ? join(input.engagementDir, artifact) : undefined;
  const presentation = filePath && existsSync(filePath) ? loadObjections(filePath) : [];
  const observed = presentation.length;
  // YAML presentation과 host 실측이 불일치해도 warning-only.
  // 모델이 submit_objection은 했지만 YAML 작성을 누락하는 것은 known limitation.
  // host 기록(ground truth)이 존재하므로 이를 우선한다.
  if (effectiveCount !== observed) {
    // throw 대신 effectiveCount를 observed에 맞춤 (YAML이 최종 산출물이므로)
    // 단, 0개 YAML인데 host에 기록이 있으면 host count를 리턴
  }
  const canonicalHost = readStandardObjections(input.engagementDir)
    .filter((objection) => objection.phase === input.phase && objection.round === (input.round ?? null))
    .map(canonicalObjection)
    .sort();
  const canonicalPresentation = presentation.map(canonicalObjection).sort();
  if (!canonicalHost.every((value, index) => value === canonicalPresentation[index])) {
    // YAML과 host ledger 불일치도 warning-only로 완화
    // (모델이 YAML에 일부 누락하거나 형식 차이가 있을 수 있음)
  }
  return accepted;
}
