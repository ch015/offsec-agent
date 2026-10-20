import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { z } from 'zod';

import { AdaptiveLiveTestReceiptSchema } from './adaptive-live-test-broker.js';
import { LiveTestMethodSchema } from './live-test-contract.js';
export {
  AdaptiveLiveTestReceiptSchema,
  createAdaptiveLiveTestBroker,
  type AdaptiveLiveTestReceipt,
} from './adaptive-live-test-broker.js';

const RECEIPT_DIR = 'http-probe-receipts';
const ReceiptIdSchema = z.string().regex(/^HTTP-[a-f0-9]{20}$/);

const LiveTestReceiptCoreSchema = z.object({
  schemaVersion: z.literal('1.0.0'),
  receiptId: ReceiptIdSchema,
  scenarioId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/),
  planSha256: z.string().regex(/^[a-f0-9]{64}$/),
  request: z.object({
    method: z.enum(['GET', 'HEAD']),
    url: z.string().url(),
    accept: z.string().max(256).optional(),
    requestSha256: z.string().regex(/^[a-f0-9]{64}$/),
  }).strict(),
  response: z.object({
    status: z.number().int().min(100).max(599),
    headers: z.record(z.string(), z.string()),
    bodySha256: z.string().regex(/^[a-f0-9]{64}$/),
    capturedBytes: z.number().int().nonnegative(),
    truncated: z.boolean(),
    safeExcerpt: z.string().max(4096),
    elapsedMs: z.number().nonnegative(),
  }).strict(),
  observedAt: z.string().datetime(),
}).strict();

export const LegacyLiveTestReceiptSchema = LiveTestReceiptCoreSchema.extend({
  receiptSha256: z.string().regex(/^[a-f0-9]{64}$/),
}).strict();

export const LiveTestReceiptSchema = z.union([
  LegacyLiveTestReceiptSchema,
  AdaptiveLiveTestReceiptSchema,
]);
export type LiveTestReceipt = z.infer<typeof LiveTestReceiptSchema>;

export function createLiveTestBroker(input: {
  engagementDir: string;
  allowedBaseUrl: string;
  maxRequests?: number;
  maxResponseBytes?: number;
  timeoutMs?: number;
  planPath: string;
  planSha256: string;
  fetchImpl?: typeof fetch;
}) {
  const base = safeBaseUrl(input.allowedBaseUrl);
  const maxRequests = input.maxRequests ?? 20;
  const maxResponseBytes = input.maxResponseBytes ?? 1_048_576;
  const timeoutMs = input.timeoutMs ?? 10_000;
  if (!Number.isInteger(maxRequests) || maxRequests < 1 || maxRequests > 100) {
    throw new Error('HTTP probe request 상한이 잘못됐다');
  }
  if (!Number.isInteger(maxResponseBytes) || maxResponseBytes < 1 || maxResponseBytes > 5_242_880) {
    throw new Error('HTTP probe response byte 상한이 잘못됐다');
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60_000) {
    throw new Error('HTTP probe timeout이 잘못됐다');
  }
  const initialPlan = readLiveTestPlan(input.planPath);
  if (initialPlan.sha256 !== input.planSha256) throw new Error('HTTP probe plan hash가 host binding과 다르다');
  const receiptsDir = join(resolve(input.engagementDir), RECEIPT_DIR);
  mkdirSync(receiptsDir, { recursive: true, mode: 0o700 });
  const fetchImpl = input.fetchImpl ?? fetch;
  let requestCount = 0;

  return {
    async probe(request: {
      scenarioId: string;
      accept?: string;
    }): Promise<LiveTestReceipt> {
      const parsed = z.object({
        scenarioId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/),
        accept: z.string().max(256).optional(),
      }).strict().parse(request);
      requestCount += 1;
      if (requestCount > maxRequests) throw new Error(`HTTP probe request 상한을 초과했다: ${maxRequests}`);
      const currentPlan = readLiveTestPlan(input.planPath);
      if (currentPlan.sha256 !== input.planSha256) throw new Error('HTTP probe plan이 봉인 후 변경됐다');
      const scenario = currentPlan.plan.scenarios.find((candidate) => candidate.scenarioId === parsed.scenarioId);
      if (!scenario || scenario.safety !== 'ready') {
        throw new Error(`HTTP probe scenario가 plan에서 실행 가능하지 않다: ${parsed.scenarioId}`);
      }
      const url = scopedUrl(base, scenario.path);
      const requestCore = {
        method: scenario.method,
        url: url.toString(),
        ...(parsed.accept ? { accept: parsed.accept } : {}),
      };
      const requestSha256 = hash(JSON.stringify(requestCore));
      const receiptId = `HTTP-${hash(`${requestSha256}:${requestCount}:${randomBytes(16).toString('hex')}`).slice(0, 20)}`;
      const started = performance.now();
      const response = await fetchImpl(url, {
        method: scenario.method,
        redirect: 'manual',
        headers: parsed.accept ? { accept: parsed.accept } : undefined,
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location');
        if (location) scopedUrl(base, new URL(location, url).toString());
        throw new Error('HTTP probe redirect는 자동 추적하지 않는다');
      }
      const captured = await readBoundedBody(response, maxResponseBytes);
      const contentType = response.headers.get('content-type') ?? '';
      const safeExcerpt = /(?:text|json|xml|javascript|urlencoded)/i.test(contentType)
        ? redact(captured.bytes.toString('utf8').slice(0, 4096))
        : '';
      const core = LiveTestReceiptCoreSchema.parse({
        schemaVersion: '1.0.0',
        receiptId,
        scenarioId: parsed.scenarioId,
        planSha256: input.planSha256,
        request: { ...requestCore, requestSha256 },
        response: {
          status: response.status,
          headers: selectedHeaders(response.headers),
          bodySha256: hash(captured.bytes),
          capturedBytes: captured.bytes.byteLength,
          truncated: captured.truncated,
          safeExcerpt,
          elapsedMs: Math.max(0, performance.now() - started),
        },
        observedAt: new Date().toISOString(),
      });
      const receipt = LegacyLiveTestReceiptSchema.parse({
        ...core,
        receiptSha256: hash(stableJson(core)),
      });
      writeFileSync(join(receiptsDir, `${receiptId}.json`), `${JSON.stringify(receipt)}\n`, {
        encoding: 'utf8',
        mode: 0o600,
        flag: 'wx',
      });
      return receipt;
    },
  };
}

export function readLiveTestPlan(path: string): { plan: LiveTestPlan; sha256: string } {
  const content = readFileSync(resolve(path));
  return {
    plan: LiveTestPlanSchema.parse(JSON.parse(content.toString('utf8'))),
    sha256: hash(content),
  };
}

export function verifyLiveTestReceipt(input: {
  engagementDir: string;
  receiptId: string;
  scenarioId?: string;
  planSha256?: string;
}): LiveTestReceipt {
  const receiptId = ReceiptIdSchema.parse(input.receiptId);
  const path = join(resolve(input.engagementDir), RECEIPT_DIR, `${receiptId}.json`);
  if (!existsSync(path)) throw new Error(`HTTP probe receipt가 없다: ${receiptId}`);
  const receipt = LiveTestReceiptSchema.parse(JSON.parse(readFileSync(path, 'utf8')));
  const { receiptSha256, ...core } = receipt;
  if (
    receipt.receiptId !== receiptId ||
    (input.scenarioId !== undefined && receipt.scenarioId !== input.scenarioId)
  ) {
    throw new Error('HTTP probe receipt identity가 finding과 다르다');
  }
  if (input.planSha256 !== undefined && receipt.planSha256 !== input.planSha256) {
    throw new Error('HTTP probe receipt plan binding이 다르다');
  }
  if (hash(stableJson(core)) !== receiptSha256) throw new Error('HTTP probe receipt hash가 다르다');
  return receipt;
}

function safeBaseUrl(value: string): URL {
  const base = new URL(value);
  if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password || base.hash) {
    throw new Error('HTTP probe base URL이 안전 계약과 다르다');
  }
  return base;
}

function scopedUrl(base: URL, candidate: string): URL {
  const url = new URL(candidate, base);
  if (
    url.protocol !== base.protocol ||
    url.hostname !== base.hostname ||
    url.port !== base.port ||
    url.username ||
    url.password ||
    url.hash ||
    !withinPathPrefix(url.pathname, base.pathname)
  ) {
    throw new Error(`HTTP probe target이 승인 범위 밖이다: ${url.toString()}`);
  }
  return url;
}

function withinPathPrefix(candidate: string, prefix: string): boolean {
  const normalized = prefix.endsWith('/') ? prefix : `${prefix}/`;
  return candidate === prefix || candidate.startsWith(normalized);
}

async function readBoundedBody(response: Response, maximum: number): Promise<{ bytes: Buffer; truncated: boolean }> {
  if (!response.body) return { bytes: Buffer.alloc(0), truncated: false };
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  let truncated = false;
  while (true) {
    const next = await reader.read();
    if (next.done) break;
    const chunk = Buffer.from(next.value);
    const remaining = maximum - total;
    if (chunk.byteLength > remaining) {
      if (remaining > 0) chunks.push(chunk.subarray(0, remaining));
      truncated = true;
      await reader.cancel();
      break;
    }
    chunks.push(chunk);
    total += chunk.byteLength;
  }
  return { bytes: Buffer.concat(chunks), truncated };
}

function selectedHeaders(headers: Headers): Record<string, string> {
  const selected: Record<string, string> = {};
  for (const name of ['content-type', 'content-length', 'cache-control']) {
    const value = headers.get(name);
    if (value) selected[name] = value.slice(0, 512);
  }
  return selected;
}

const FORMAT_CHARS = /[​‌‍⁠﻿]/g;
const INJECTION_PATTERNS = [
  /\[SYSTEM\]/gi,
  /<\|im_start\|>/gi,
  /<\|im_end\|>/gi,
  /<\/?instructions?>/gi,
  /<\/?system(?:-[a-z]+)?>/gi,
  /<\/?anthropic>/gi,
  /Human:\s*\n/gi,
  /Assistant:\s*\n/gi,
  /<\|begin_of_turn\|>/gi,
  /<\|end_of_turn\|>/gi,
  /<<\/?SYS>>/gi,
];

function sanitizeExcerpt(value: string): string {
  let out = value.replace(FORMAT_CHARS, '');
  for (const p of INJECTION_PATTERNS) out = out.replace(p, '[FILTERED]');
  return out;
}

function redact(value: string): string {
  return sanitizeExcerpt(value)
    .replace(/\b(?:bearer\s+)?[A-Za-z0-9_-]{24,}\b/gi, '[REDACTED]')
    .replace(/("(?:password|token|secret|api[_-]?key)"\s*:\s*")[^"]*(")/gi, '$1[REDACTED]$2');
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function hash(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}
const LegacyPlanSourceEvidenceSchema = z.object({
  file: z.string().min(1).max(2048),
  line: z.number().int().positive().optional(),
  lines: z.array(z.number().int().positive()).min(1).max(128).optional(),
  sink: z.string().min(1).max(8192).optional(),
}).strict().refine(
  (value) => value.line !== undefined || value.lines !== undefined,
  'sourceEvidence에는 line 또는 lines가 필요하다',
);

// The source-first model card historically called the safe state "safe".  Keep
// that spelling as an input-only migration alias, but expose only the canonical
// host value to the rest of the runtime.
const LegacyPlanSafetySchema = z.preprocess(
  (value) => value === 'safe' ? 'ready' : value,
  z.enum(['ready', 'not_executable']),
);

export const LiveTestPlanSchema = z.object({
  schemaVersion: z.literal('1.0.0'),
  scenarios: z.array(z.object({
    scenarioId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/),
    path: z.string().min(1).max(2048),
    method: LiveTestMethodSchema,
    safety: LegacyPlanSafetySchema,
    preconditions: z.array(z.string().min(1)),
    successCriteria: z.string().min(1),
    failureCriteria: z.string().min(1),
    sourceEvidence: LegacyPlanSourceEvidenceSchema.optional(),
  }).strict()).max(100),
}).strict();
export type LiveTestPlan = z.infer<typeof LiveTestPlanSchema>;
