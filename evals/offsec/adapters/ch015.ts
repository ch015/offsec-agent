import { readFileSync, realpathSync } from 'node:fs';
import { relative, resolve, sep } from 'node:path';

import {
  NormalizedBenchmarkFindingSchema,
  type BenchmarkRunRecord,
  type BenchmarkSourceManifest,
  type NormalizedBenchmarkFinding,
} from '../../../src/runtime/offsec-benchmark.js';

const FINDING_HEADING = /^###\s+([A-Z][A-Z0-9-]*-\d+)\s*(?:\[([A-Z]+)\]|:)\s*(?:[-—:]\s*)?(.+)$/gm;
const FILE_LINE = /`?([A-Za-z0-9_.@/+()-]+\.[A-Za-z0-9]+):(\d+)(?:-(\d+))?`?/g;
const CWE = /\bCWE-(\d+)\b/g;

export function normalizeCh015MarkdownFindings(input: {
  reportPath: string;
  target: string;
  sourceManifest: BenchmarkSourceManifest;
  run: BenchmarkRunRecord;
}): NormalizedBenchmarkFinding[] {
  const markdown = readFileSync(resolve(input.reportPath), 'utf8');
  const matches = [...markdown.matchAll(FINDING_HEADING)];
  const allowed = new Set(input.sourceManifest.files.map((file) => file.path));
  const targetRoot = realpathSync(input.target);
  return matches.map((match, index) => {
    const block = markdown.slice(match.index!, matches[index + 1]?.index ?? markdown.length);
    const cwes = [...new Set([...block.matchAll(CWE)].map((value) => `CWE-${value[1]}`))];
    const evidence = [...block.matchAll(FILE_LINE)].flatMap((value) => {
      const path = normalizeTargetPath(targetRoot, value[1]!);
      if (!path || !allowed.has(path)) return [];
      const lineStart = Number(value[2]);
      const lineEnd = Number(value[3] ?? value[2]);
      const lines = readFileSync(resolve(targetRoot, path), 'utf8').split(/\r?\n/);
      if (lineStart < 1 || lineEnd < lineStart || lineEnd > lines.length) return [];
      return [{
        path,
        lineStart,
        lineEnd,
        quote: lines.slice(lineStart - 1, lineEnd).join('\n'),
        origin: 'adapter-resolved' as const,
      }];
    });
    const uniqueEvidence = [...new Map(evidence.map((value) => [
      `${value.path}:${value.lineStart}:${value.lineEnd}`,
      value,
    ])).values()];
    const excluded = hasExcludedStatus(block);
    return NormalizedBenchmarkFindingSchema.parse({
      schemaVersion: '1.0.0',
      runId: input.run.runId,
      runSha256: input.run.runSha256,
      caseId: input.run.caseId,
      arm: input.run.arm,
      findingId: match[1],
      title: match[3]!.trim(),
      verdict: uniqueEvidence.length > 0 && !excluded ? 'supported' : 'abstain',
      severity: normalizeSeverity(match[2] ?? severityFromBlock(block)),
      cwes,
      evidence: uniqueEvidence,
    });
  });
}

function hasExcludedStatus(block: string): boolean {
  const token = '(?:FALSE[_ -]?POSITIVE|EXCLUDED|DISPUTED|REJECTED|UNSUPPORTED)';
  const labeled = new RegExp(
    `(?:^|\\n)\\s*(?:[-*]\\s*)?\\*{0,2}(?:Status|상태|Classification|분류|Verdict|판정)\\*{0,2}` +
      `\\s*:\\s*\\*{0,2}${token}\\b`,
    'i',
  );
  const table = new RegExp(
    `(?:^|\\n)\\s*\\|\\s*(?:Status|상태|Classification|분류|Verdict|판정)\\s*\\|\\s*${token}\\s*\\|`,
    'i',
  );
  return labeled.test(block) || table.test(block);
}

function normalizeTargetPath(targetRoot: string, raw: string): string | undefined {
  const absolute = resolve(targetRoot, raw);
  if (absolute !== targetRoot && !absolute.startsWith(`${targetRoot}${sep}`)) return undefined;
  const normalized = relative(targetRoot, absolute).split(sep).join('/');
  return normalized && !normalized.startsWith('../') ? normalized : undefined;
}

function severityFromBlock(block: string): string {
  return block.match(/(?:Severity|심각도)\s*\|?\s*\*{0,2}(CRITICAL|HIGH|MEDIUM|LOW|INFO)/i)?.[1] ?? 'INFO';
}

function normalizeSeverity(value: string): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' {
  const normalized = value.toUpperCase();
  return ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(normalized)
    ? normalized as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
    : 'INFO';
}
