import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { createArtifactRef, verifyRunArtifactRef } from '../contracts/result-contract.js';
import type { MissionRuntime } from '../workflow/mission-runtime.js';
import type { RunSnapshot } from '../workflow/state-store.js';
import { atomicPrivateWrite, managedPath, readManagedFile } from '../workflow/storage-files.js';
import { AnalysisInterruption } from './assessment-recovery.js';
import type { SourceReadCoverage } from '../workflow/scope-assurance.js';
import { SHARED_KNOWLEDGE_SNAPSHOT } from '../shared-knowledge.js';

export const COVERAGE_FILE = '00_analysis_coverage.json';
export const COMPLETION_COVERAGE_FILE = '00_completion_coverage.json';
const checkpointFiles = ['00_work_unit_results.json', '00_scope_assurance.json', '00_followup_plan.json', COVERAGE_FILE];
const objectUri = (sha256: string) => `artifact://checkpoints/objects/${sha256}`;

/** Seal after local immutable copies exist. A projection is never the recovery authority. */
export async function sealAnalysisCheckpoint(runtime: MissionRuntime, engagementDir: string, stage: 'units' | 'review'): Promise<void> {
  if (!runtime.artifactStore) throw new AnalysisInterruption('Analysis checkpoint storage is unavailable');
  const snapshot = await runtime.read();
  if (snapshot.analysisCheckpoint?.stage === stage) return;
  const artifacts = [];
  for (const name of [...checkpointFiles, ...(existsSync(join(engagementDir, SHARED_KNOWLEDGE_SNAPSHOT)) ? [SHARED_KNOWLEDGE_SNAPSHOT] : [])]) {
    const artifact = createArtifactRef({ engagementDir, name, phase: 'checkpoint', role: 'host', attempt: stage });
    await runtime.artifactStore.put({ uri: objectUri(artifact.sha256), content: readManagedFile(engagementDir, artifact.path),
      mediaType: artifact.mediaType, producer: 'checkpoint/host/1' });
    artifacts.push(artifact);
  }
  await runtime.append({ type: 'analysis.checkpoint', eventId: `${snapshot.runId}:analysis-checkpoint:${snapshot.analysisRevision ?? 0}:${stage}`, stage, artifacts });
}

export async function restoreAnalysisCheckpoint(runtime: MissionRuntime, engagementDir: string, snapshot: Readonly<RunSnapshot>): Promise<void> {
  for (const artifact of [...snapshot.analysisCheckpoint?.artifacts ?? [], ...(snapshot.completionCoverage ? [snapshot.completionCoverage] : [])]) {
    const path = managedPath(engagementDir, join(engagementDir, artifact.name));
    if (path !== artifact.path || ![...checkpointFiles, COMPLETION_COVERAGE_FILE, SHARED_KNOWLEDGE_SNAPSHOT].includes(artifact.name)) throw new Error('unsafe analysis checkpoint reference');
    try { verifyRunArtifactRef(artifact, engagementDir); continue; } catch { /* Recover only verified original bytes below. */ }
    try {
      if (!runtime.artifactStore) throw new Error('checkpoint store unavailable');
      const content = await runtime.artifactStore.get(objectUri(artifact.sha256));
      if (content.byteLength !== artifact.bytes || createHash('sha256').update(content).digest('hex') !== artifact.sha256) throw new Error('checkpoint object hash mismatch');
      if (existsSync(path)) {
        const previous = readManagedFile(engagementDir, path), digest = createHash('sha256').update(previous).digest('hex');
        atomicPrivateWrite(join(engagementDir, '.recovery', 'damaged-projections', `${artifact.name}.${digest}`), previous);
      }
      atomicPrivateWrite(path, content);
      verifyRunArtifactRef(artifact, engagementDir);
    } catch (error) { throw new AnalysisInterruption(`Cannot restore analysis checkpoint ${artifact.name}: ${String(error)}`); }
  }
}

/** Final coverage is immutable within a revision, including publication retries. */
export async function finalizeCoverage<T>(runtime: MissionRuntime, engagementDir: string, coverage: T): Promise<T> {
  const snapshot = await runtime.read();
  if (snapshot.completionCoverage) {
    verifyRunArtifactRef(snapshot.completionCoverage, engagementDir);
    return JSON.parse(readManagedFile(engagementDir, snapshot.completionCoverage.path).toString()) as T;
  }
  atomicPrivateWrite(join(engagementDir, COMPLETION_COVERAGE_FILE), JSON.stringify(coverage, null, 2) + '\n');
  const artifact = createArtifactRef({ engagementDir, name: COMPLETION_COVERAGE_FILE, phase: 'coverage', role: 'host', attempt: String(snapshot.analysisRevision ?? 0) });
  if (!runtime.artifactStore) throw new AnalysisInterruption('Completion coverage storage is unavailable');
  await runtime.artifactStore.put({ uri: objectUri(artifact.sha256), content: readManagedFile(engagementDir, artifact.path), mediaType: artifact.mediaType, producer: 'coverage/host/1' });
  await runtime.append({ type: 'coverage.finalized', eventId: `${snapshot.runId}:coverage:${snapshot.analysisRevision ?? 0}`, artifact });
  return coverage;
}

/** Keep host disclosures out of the model's immutable draft. */
export function coverageAppendix(coverage: { complete: boolean; uncoveredFiles: string[]; requiredPreanalysisComplete?: boolean; sourceReadCoverage?: SourceReadCoverage; preanalysisLimitations?: string[] }): string {
  const reads = coverage.sourceReadCoverage;
  const readNotice = reads ? '\n\n---\n\n## 소스 읽기 관측 범위\n\n' +
    `담당 분석 세션에서 허용된 Read 요청: ${reads.filesWithReadRequest.length}개 파일. ` +
    `Read 요청 미관측: ${reads.filesWithoutReadRequest.length}개 파일.\n\n` +
    `검증된 내용 전달: ${reads.filesDelivered?.length ?? 0}개 파일. 검증된 기존 분석 재사용: ${reads.filesValidatedReuse?.length ?? 0}개 파일.\n\n` +
    '읽기 요청, 실제 내용 전달, 검증된 분석 재사용을 구분합니다. 과거 읽기를 새 세션의 읽기로 집계하지 않습니다. 이 기록은 의미적 이해나 취약점 부재를 증명하지 않습니다. ' +
    `작업 실행 완료와 소스 전체 검토는 별개입니다. 파일별 목록: ${COVERAGE_FILE}.\n` : '';
  const toolNotice = coverage.preanalysisLimitations?.length ? '\n\n## 정적 도구 처리 한계\n\n' + coverage.preanalysisLimitations.map(item => `- ${item}`).join('\n') + '\n' : '';
  if (coverage.complete) return readNotice + toolNotice;
  return '\n\n---\n\n## 분석 범위 미완료\n\n' +
    'This host-generated notice describes incomplete execution, not a clean security assessment.\n' +
    (coverage.requiredPreanalysisComplete === false ? '\nRequired preanalysis did not complete.\n' : '') +
    `\nUnreviewed files: ${coverage.uncoveredFiles.length}. Full coverage: ${COVERAGE_FILE}.\n` +
    coverage.uncoveredFiles.map(file => `- ${JSON.stringify(file)}`).join('\n') + '\n' + readNotice + toolNotice;
}

/** Older completed runs did not seal coverage. Derive only facts established by
 * the event ledger and the sealed input; never use their mutable coverage JSON. */
export function legacyCompletedCoverage(input: {
  snapshot: Readonly<RunSnapshot>;
  units: Array<{ unitKey: string; ownedFiles: Array<{ path: string }> }>;
  sourceErrors: Array<{ path: string; code: string }>;
  requiredPreanalysisComplete: boolean;
  preanalysisAvailable: boolean;
}) {
  const attempts = Object.values(input.snapshot.attempts);
  const complete = new Set(attempts.filter(attempt => attempt.phase === 'analyze' && attempt.status === 'completed').map(attempt => attempt.round));
  const uncoveredFiles = [...new Set([...input.sourceErrors.map(issue => issue.path),
    ...input.units.filter(unit => !complete.has(unit.unitKey)).flatMap(unit => unit.ownedFiles.map(file => file.path))])];
  const followup = attempts.filter(attempt => attempt.round === 'cross-unit-followup');
  const followupPending = followup.length > 0 && !followup.some(attempt => attempt.status === 'completed');
  return {
    complete: uncoveredFiles.length === 0 && !followupPending && input.requiredPreanalysisComplete,
    requiredPreanalysisComplete: input.requiredPreanalysisComplete,
    completedUnits: input.units.filter(unit => complete.has(unit.unitKey)).length, totalUnits: input.units.length,
    uncoveredFiles, semanticCoverage: 'not-proven' as const, ownedFilesRead: 0,
    ownedFileCount: input.units.reduce((count, unit) => count + unit.ownedFiles.length, 0),
    preanalysisAvailable: input.preanalysisAvailable, followupQuestions: 0, deferredFollowupQuestions: followupPending ? 1 : 0,
    legacyCoverageReconstructed: true, unavailableLegacyCounts: ['ownedFilesRead', 'followupQuestions'],
  };
}
