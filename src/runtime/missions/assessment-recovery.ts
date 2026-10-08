import { TerminationUnknownError, AdmissionDeferredError } from '../workflow/task-scheduler.js';
import { MissionBudgetExhaustedError } from '../providers/budgeted-runtime.js';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, realpathSync, readdirSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { PhaseResultFailure, ProviderRuntimeFailure } from '../providers/provider-runtime.js';
import { atomicPrivateWrite, readManagedFile } from '../workflow/storage-files.js';
import { reportDirectory } from '../workflow/run-location.js';
import { SourceReadCoverageSchema } from '../workflow/scope-assurance.js';

export class AnalysisInterruption extends Error {}
export function recoverableFailure(error: unknown): boolean {
  if (error instanceof TerminationUnknownError || error instanceof AdmissionDeferredError || error instanceof PhaseResultFailure || error instanceof ProviderRuntimeFailure || error instanceof AnalysisInterruption || error instanceof MissionBudgetExhaustedError) return true;
  const code = (error as NodeJS.ErrnoException | null)?.code ?? '';
  return /^(EIO|ENOSPC|EDQUOT|EBUSY|EMFILE|ENFILE|ECONNRESET|ECONNREFUSED|ETIMEDOUT|EHOSTUNREACH|08\w{3}|57P0[123]|53300|55P03)$/.test(code);
}
export async function retryProvider<T>(operation: () => Promise<T>): Promise<T> {
  try { return await operation(); }
  catch (error) { if (!(error instanceof ProviderRuntimeFailure)) throw error; return operation(); }
}
export function checkpointInput<T>(engagementDir: string): { runId: string; input: T; storageBackend?: 'file' | 'postgres' } {
  const value = JSON.parse(readFileSync(join(engagementDir, 'assess-v2-checkpoint-input.json'), 'utf8'));
  const { checkpointSha256, ...core } = value;
  const stable = (value: unknown): string => {
    if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
    if (value && typeof value === 'object') {
      const record = value as Record<string, unknown>;
      return `{${Object.keys(record).sort().map(key => `${JSON.stringify(key)}:${stable(record[key])}`).join(',')}}`;
    }
    return JSON.stringify(value);
  };
  if (core.schemaVersion !== '1.0.0' || createHash('sha256').update(stable(core)).digest('hex') !== checkpointSha256 || realpathSync(core.input.engagementDir) !== realpathSync(engagementDir)) throw new Error('v2 checkpoint hash or location mismatch');
  return core;
}
function recoveredJson(engagementDir: string, name: string): Record<string, any> | undefined {
  try {
    const value: unknown = JSON.parse(readManagedFile(engagementDir, join(engagementDir, name)).toString());
    return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, any> : undefined;
  } catch { return undefined; }
}

export function preservePartialReport(engagementDir: string, error: unknown): string {
  const path = join(reportDirectory(engagementDir), 'analysis.partial.md');
  const findings: string[] = [];
  // Keep each available observation visible even if another record is damaged.
  try {
    for (const name of readdirSync(join(engagementDir, 'standard-findings')).filter(name => name.endsWith('.json')).sort()) {
      const finding = recoveredJson(engagementDir, `standard-findings/${name}`);
      if (finding) findings.push(JSON.stringify(finding, null, 2));
    }
  } catch { /* No root records yet; source/unit artifacts remain in the archive. */ }
  const content = `# 분석 범위 미완료\n\nThis is a recovery report, not a completed security assessment.\n\n${String(error)}\n\nResume from the same engagement: ${engagementDir}\n\nCoverage checkpoint:\n\n\`\`\`json\n${JSON.stringify(partialCoverage(engagementDir), null, 2)}\n\`\`\`\n\nRetained finding observations (not a new verification verdict):\n\n` +
    findings.map(body => `\`\`\`json\n${body}\n\`\`\`\n`).join('\n');
  atomicPrivateWrite(join(engagementDir, 'analysis.partial.md'), content);
  if (path !== join(engagementDir, 'analysis.partial.md')) atomicPrivateWrite(path, content);
  return path;
}

export function partialCoverage(engagementDir: string) {
  const existing = recoveredJson(engagementDir, '00_analysis_coverage.json');
  const plan = recoveredJson(engagementDir, '00_work_plan.json');
  const manifest = recoveredJson(engagementDir, 'source_manifest.json');
  const strings = (value: unknown): string[] => Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
  const units: Array<{ ownedFiles?: Array<{ path?: string }> }> = Array.isArray(plan?.units) ? plan.units : [];
  const files = strings(manifest?.source_files).length ? strings(manifest?.source_files) : units.flatMap(unit => strings(unit?.ownedFiles?.map(file => file?.path)));
  const count = (value: unknown, fallback = 0) => Number.isSafeInteger(value) && Number(value) >= 0 ? Number(value) : fallback;
  const sourceReadCoverage = SourceReadCoverageSchema.safeParse(existing?.sourceReadCoverage);
  return { complete: false, completedUnits: count(existing?.completedUnits), totalUnits: count(existing?.totalUnits, units.length),
    ...(sourceReadCoverage.success ? { sourceReadCoverage: sourceReadCoverage.data } : {}),
    uncoveredFiles: existing && Array.isArray(existing.uncoveredFiles) ? strings(existing.uncoveredFiles) : files,
    semanticCoverage: 'not-proven' as const, ownedFilesRead: count(existing?.ownedFilesRead), ownedFileCount: count(existing?.ownedFileCount, files.length),
    preanalysisAvailable: existing?.preanalysisAvailable === true, followupQuestions: count(existing?.followupQuestions),
    deferredFollowupQuestions: count(existing?.deferredFollowupQuestions), requiredPreanalysisComplete: false };
}

export function assertResumeSources(target: string, engagementDir: string): void {
  const manifest = JSON.parse(readFileSync(join(engagementDir, 'source_manifest.json'), 'utf8')) as {
    source_receipts?: Array<{ path: string; bytes: number; sha256: string }>;
    dependency_receipts?: Array<{ path: string; bytes: number; sha256: string }>;
  };
  const root = realpathSync(target);
  for (const receipt of [...(manifest.source_receipts ?? []), ...(manifest.dependency_receipts ?? [])]) {
    const path = realpathSync(resolve(root, receipt.path)), rel = relative(root, path);
    if (rel === '..' || rel.startsWith(`..${sep}`) || rel.startsWith(sep)) throw new Error('resume source escapes target');
    const content = readFileSync(path);
    if (content.byteLength !== receipt.bytes || createHash('sha256').update(content).digest('hex') !== receipt.sha256) {
      throw new Error(`resume source changed; retain this run and analyze the new revision separately: ${receipt.path}`);
    }
  }
}
