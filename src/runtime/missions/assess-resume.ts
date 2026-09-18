import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';

import { createArtifactRef, verifyArtifactRef, verifyRunArtifactRef } from '../contracts/result-contract.js';
import {
  nextOwnerAuthRequest,
  prepareLiveDast,
  publicOwnerRequestArtifact,
  readResumeRecord,
} from '../live-dast-lifecycle.js';
import {
  readAuthInteractionSelection,
  readOwnerAuthRequest,
  sealOpaqueAuthSession,
} from '../live-auth-session.js';
import {
  awaitOwnerCompletion,
  createLocalHeadedBrowserAdapter,
  type AuthInteractionAdapter,
} from '../auth-interaction.js';
import { loadOffsecContract } from '../offsec-contract.js';
import {
  assess,
  AssessAwaitingInputError,
  readAssessCheckpoint,
  recordOffsecPublication,
  validateOffsecPublicationCandidate,
  type AssessDependencies,
} from './assess.js';
import { openMissionRuntime, type MissionRuntimeOptions } from '../workflow/mission-runtime.js';
import { readStandardFindingRecordReceipts } from '../finding-contract.js';
import {
  AutoRenewingRunLease,
  type RunLeaseBackend,
} from '../workflow/run-lease.js';

export type ResumeAssessOwnerAuthInput = Readonly<{
  engagementDir: string;
  runId?: string;
  expectedVersion: number;
  requestId: string;
  requestSha256: string;
  adapter: AuthInteractionAdapter;
  waitForOwner?: (challenge: Awaited<ReturnType<AuthInteractionAdapter['begin']>>) => Promise<void>;
}>;

export async function recoverAssessPublication(input: {
  engagementDir: string;
  runId: string;
}, runtimeOptions: MissionRuntimeOptions = {}): Promise<string> {
  const engagementDir = resolve(input.engagementDir);
  const contract = loadOffsecContract();
  const runtime = await openMissionRuntime({ engagementDir, runId: input.runId }, runtimeOptions);
  try {
    const snapshot = await runtime.read();
    if (snapshot.status === 'completed' && snapshot.publication) {
      verifyRunArtifactRef(snapshot.publication.artifact, engagementDir);
      return snapshot.publication.artifact.path;
    }
    if (snapshot.status !== 'running') throw new Error(`publication 복구 가능한 run 상태가 아니다: ${snapshot.status}`);
    if (Object.values(snapshot.attempts).some((attempt) =>
      attempt.status === 'started' || attempt.status === 'received')) {
      throw new Error('미종료 phase attempt가 있어 publication을 복구할 수 없다');
    }
    if (!snapshot.completedPhases.includes(contract.publication.phase)) {
      throw new Error(`publication 선행 phase가 완료되지 않았다: ${contract.publication.phase}`);
    }
    const manifest = JSON.parse(readFileSync(join(engagementDir, 'source_manifest.json'), 'utf8')) as { hash?: unknown };
    if (typeof manifest.hash !== 'string' || !/^[a-f0-9]{64}$/.test(manifest.hash)) {
      throw new Error('source manifest hash가 없거나 잘못됐다');
    }
    const fanoutDecision = JSON.parse(readFileSync(join(engagementDir, 'fanout_decision.json'), 'utf8')) as {
      manifest_hash?: unknown;
    };
    if (fanoutDecision.manifest_hash !== manifest.hash) {
      throw new Error('source manifest hash가 sealed fanout decision과 다르다');
    }
    const checkpoint = existsSync(join(engagementDir, 'assess-checkpoint-input.json'))
      ? (verifyAssessCheckpointReceipt(engagementDir, snapshot), readAssessCheckpoint(engagementDir))
      : undefined;
    const verificationMode = checkpoint?.input.verificationMode ?? 'VA_ONLY';
    const preparedLiveDast = verificationMode.includes('PENTEST')
      ? prepareLiveDast({
          engagementDir,
          runId: input.runId,
          profilePath: checkpoint?.input.liveTestProfilePath,
          mode: checkpoint?.input.authInteractionMode,
        })
      : undefined;
    validateOffsecPublicationCandidate({
      engagementDir,
      candidate: join(engagementDir, contract.publication.finalArtifact),
      requirePocBinding: verificationMode.includes('PENTEST'),
      allowEmptyCandidates: readStandardFindingRecordReceipts(engagementDir).length === 0,
      preparedLiveDast,
    });
    return await recordOffsecPublication({
      runtime,
      engagementDir,
      runId: input.runId,
      contractId: contract.id,
      finalArtifact: contract.publication.finalArtifact,
      sourceManifestSha256: manifest.hash,
    });
  } finally {
    await runtime.close();
  }
}

export async function resumeAssessFromCheckpoint(input: {
  engagementDir: string;
  runId: string;
}, dependencies: Omit<AssessDependencies, 'existingRuntime' | 'existingLeaseGuard' | 'resumeCompletedPhases'> & {
  runtime?: MissionRuntimeOptions;
  leaseBackend?: RunLeaseBackend;
  workerId?: string;
} = {}) {
  const engagementDir = resolve(input.engagementDir);
  const checkpoint = readAssessCheckpoint(engagementDir);
  if (checkpoint.runId !== input.runId) throw new Error('assess checkpoint runId가 요청과 다르다');
  if (
    existsSync(join(engagementDir, '00_work_plan.json')) &&
    !existsSync(join(engagementDir, '00_work_unit_results.json'))
  ) {
    throw new Error('미완료 work-unit wave는 먼저 완료 또는 정리해야 한다');
  }
  const runtime = await openMissionRuntime({ engagementDir, runId: input.runId }, {
    ...dependencies.runtime,
    ...(dependencies.workerId ? { workerId: dependencies.workerId } : {}),
  });
  if (runtime.state.backend === 'file' && !dependencies.leaseBackend) {
    await runtime.close();
    throw new Error('file OffSec resume에는 leaseBackend가 필요하다');
  }
  const externalLease = runtime.state.backend === 'file' && dependencies.leaseBackend
    ? await AutoRenewingRunLease.acquire(dependencies.leaseBackend, {
        runId: input.runId,
        ownerId: dependencies.workerId ?? `assess-checkpoint-resume-${process.pid}`,
        ttlMs: 1_800_000,
      })
    : undefined;
  const lease = runtime.leaseGuard ?? externalLease;
  try {
    await lease?.assertActive();
    const snapshot = await runtime.read();
    verifyAssessCheckpointReceipt(engagementDir, snapshot);
    if (snapshot.status !== 'running') throw new Error(`OffSec checkpoint resume 가능한 상태가 아니다: ${snapshot.status}`);
    if (Object.values(snapshot.attempts).some((attempt) =>
      attempt.status === 'started' || attempt.status === 'received')) {
      throw new Error('미종료 phase attempt를 먼저 reconcile해야 한다');
    }
    return await assess(checkpoint.input, {
      ...dependencies,
      existingRuntime: runtime,
      ...(lease ? { existingLeaseGuard: lease } : {}),
      resumeCompletedPhases: true,
    });
  } finally {
    await externalLease?.release();
    await runtime.close();
  }
}

export async function resumeAssessOwnerAuth(
  input: ResumeAssessOwnerAuthInput,
  dependencies: Omit<AssessDependencies, 'existingRuntime' | 'existingLeaseGuard'> & {
    runtime?: MissionRuntimeOptions;
    leaseBackend?: RunLeaseBackend;
    workerId?: string;
  } = {},
) {
  const engagementDir = resolve(input.engagementDir);
  const saved = readResumeRecord(engagementDir);
  const runId = input.runId ?? saved.runId;
  if (runId !== saved.runId) throw new Error('assess resume runId가 봉인된 input과 다르다');
  const runtime = await openMissionRuntime({ engagementDir, runId }, {
    ...dependencies.runtime,
    ...(dependencies.workerId ? { workerId: dependencies.workerId } : {}),
  });
  if (runtime.state.backend === 'file' && !dependencies.leaseBackend) {
    await runtime.close();
    throw new Error('file OffSec resume에는 leaseBackend가 필요하다');
  }
  const externalLease = runtime.state.backend === 'file' && dependencies.leaseBackend
    ? await AutoRenewingRunLease.acquire(dependencies.leaseBackend, {
        runId,
        ownerId: dependencies.workerId ?? `assess-resume-${process.pid}`,
        ttlMs: 1_800_000,
      })
    : undefined;
  const lease = runtime.leaseGuard ?? externalLease;
  try {
    await lease?.assertActive();
    let snapshot = await runtime.read();
    verifyAssessCheckpointReceipt(engagementDir, snapshot);
    const selection = readAuthInteractionSelection(engagementDir);
    const request = readOwnerAuthRequest(
      engagementDir,
      input.requestId,
      new Date(),
      { allowExpired: snapshot.status === 'running' || snapshot.status === 'completed' },
    );
    if (
      request.runId !== runId ||
      request.requestSha256 !== input.requestSha256 ||
      request.selectionSha256 !== selection.selectionSha256
    ) {
      throw new Error('owner auth resume identity가 봉인된 request와 다르다');
    }
    if (snapshot.status === 'completed') {
      if (!snapshot.publication) throw new Error('완료된 assess run의 publication artifact가 없다');
      verifyRunArtifactRef(snapshot.publication.artifact, engagementDir);
      const finalReport = resolve(engagementDir, loadOffsecContract().publication.finalArtifact);
      if (resolve(snapshot.publication.artifact.path) !== finalReport) {
        throw new Error('완료된 assess run의 publication artifact 경로가 다르다');
      }
      return { outcome: { texts: [], ledger: [] }, engagementDir, phases: [], finalReport };
    }
    const preparedBefore = prepareLiveDast({
      engagementDir,
      runId,
      profilePath: saved.liveTestProfilePath,
      mode: saved.authInteractionMode,
    });
    const existing = preparedBefore.authSessions.get(request.actorId);
    if (snapshot.status === 'awaiting-input') {
      if (snapshot.lastSeq !== input.expectedVersion) {
        throw new Error(`OffSec resume version 충돌: ${input.expectedVersion} != ${snapshot.lastSeq}`);
      }
      if (!snapshot.awaitingInput || !snapshot.inputManifest) {
        throw new Error('OffSec owner auth awaiting/input artifact가 없다');
      }
      verifyArtifactRef(snapshot.awaitingInput.artifact, engagementDir);
      if (input.adapter.mode !== request.interactionMode) {
        throw new Error('resume adapter가 봉인된 auth interaction mode와 다르다');
      }
      const session = existing ?? await (async () => {
        const challenge = await input.adapter.begin(request);
        await awaitOwnerCompletion(input.waitForOwner ?? noOwnerWait, challenge);
        const capture = await input.adapter.capture(request);
        return sealOpaqueAuthSession({ engagementDir, selection, request, capture });
      })();
      await lease?.assertActive();
      const revision = snapshot.inputManifest.inputRevision + 1;
      const manifestName = `assess-resume-input.r${String(revision).padStart(4, '0')}.json`;
      const manifestPath = join(engagementDir, manifestName);
      if (!existsSync(manifestPath)) {
        writeFileSync(manifestPath, readFileSync(join(engagementDir, 'assess-resume-input.json')), {
          flag: 'wx',
          mode: 0o600,
        });
      }
      const manifest = createArtifactRef({
        engagementDir,
        name: manifestName,
        phase: 'input',
        role: 'host',
        attempt: String(revision),
      });
      const profileContent = readFileSync(saved.liveTestProfilePath);
      const checkpointPath = join(engagementDir, 'assess-checkpoint-input.json');
      const checkpointContent = readFileSync(checkpointPath);
      snapshot = await runtime.appendBatch([{
        type: 'input.revised',
        eventId: `${runId}:input:${revision}`,
        input: {
          inputRevision: revision,
          contextEpoch: sha256(`${snapshot.inputManifest.contextEpoch}:${request.requestSha256}:${session.sessionSha256}`),
          manifest,
          allowedReadFiles: [checkpointPath, saved.liveTestProfilePath],
          fileHashes: [{
              path: checkpointPath,
              sha256: sha256(checkpointContent),
              bytes: checkpointContent.byteLength,
            }, {
              path: saved.liveTestProfilePath,
              sha256: sha256(profileContent),
              bytes: profileContent.byteLength,
            }],
          parent: {
            manifestSha256: snapshot.inputManifest.manifest.sha256,
            triggerArtifactSha256: snapshot.awaitingInput.artifact.sha256,
          },
        },
      }, {
        type: 'run.resumed',
        eventId: `${runId}:owner-auth:${request.requestId}:resumed`,
      }]);
    } else if (snapshot.status !== 'running' || !existing) {
      throw new Error(`OffSec run이 owner auth resume 가능한 상태가 아니다: ${snapshot.status}`);
    }

    const prepared = prepareLiveDast({
      engagementDir,
      runId,
      profilePath: saved.liveTestProfilePath,
      mode: saved.authInteractionMode,
    });
    const nextRequest = nextOwnerAuthRequest({ engagementDir, prepared });
    if (nextRequest) {
      const name = publicOwnerRequestArtifact(engagementDir, nextRequest);
      const artifact = createArtifactRef({
        engagementDir,
        name,
        phase: 'owner-auth',
        role: 'host',
        attempt: String(snapshot.lastSeq + 1),
      });
      const waiting = await runtime.append({
        type: 'run.awaiting-input',
        eventId: `${runId}:owner-auth:${nextRequest.requestId}`,
        reason: `테스트 actor ${nextRequest.actorId}의 owner authentication이 필요하다`,
        artifact,
      });
      throw new AssessAwaitingInputError(
        engagementDir,
        nextRequest.requestId,
        nextRequest.requestSha256,
        waiting.lastSeq,
      );
    }
    await lease?.assertActive();
    const checkpointInput = existsSync(join(engagementDir, 'assess-checkpoint-input.json'))
      ? readAssessCheckpoint(engagementDir).input
      : {
          target: saved.target,
          scope: saved.scope,
          engagementId: saved.runId,
          engagementDir,
          model: saved.model,
          reviewModel: saved.reviewModel,
          effort: saved.effort,
          maxTurns: saved.maxTurns,
          maxBudgetUsd: saved.maxBudgetUsd,
          verificationMode: saved.verificationMode,
          semgrepMode: saved.semgrepMode,
          workUnitMode: saved.workUnitMode,
          maxConcurrency: saved.maxConcurrency,
          liveTestProfilePath: saved.liveTestProfilePath,
          authInteractionMode: saved.authInteractionMode,
        };
    return await assess(checkpointInput, {
      ...dependencies,
      existingRuntime: runtime,
      ...(lease ? { existingLeaseGuard: lease } : {}),
    });
  } finally {
    await input.adapter.close();
    await externalLease?.release();
    await runtime.close();
  }
}

async function noOwnerWait(): Promise<void> {
  throw new Error('owner authentication 완료 신호 callback이 필요하다');
}

function sha256(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}

function verifyAssessCheckpointReceipt(
  engagementDir: string,
  snapshot: { inputManifest?: { fileHashes: Array<{ path: string; sha256: string; bytes: number }> } },
): void {
  const path = join(engagementDir, 'assess-checkpoint-input.json');
  const receipt = snapshot.inputManifest?.fileHashes.find((value) => resolve(value.path) === resolve(path));
  if (!receipt) throw new Error('OffSec assess checkpoint runtime receipt가 없다');
  const content = readFileSync(path);
  if (receipt.sha256 !== sha256(content) || receipt.bytes !== content.byteLength) {
    throw new Error('OffSec assess checkpoint runtime receipt가 다르다');
  }
}

async function main(): Promise<void> {
  const flags = new Map(process.argv.slice(2).map((arg) => {
    const match = /^--([a-z-]+)=(.*)$/.exec(arg);
    if (!match?.[1]) throw new Error(`잘못된 인자다: ${arg}`);
    return [match[1], match[2] ?? ''];
  }));
  const engagementDir = flags.get('engagement-dir');
  const requestId = flags.get('request-id');
  const requestSha256 = flags.get('request-sha256');
  const expectedVersion = Number(flags.get('expected-version'));
  if (!engagementDir || !requestId || !requestSha256 || !Number.isInteger(expectedVersion)) {
    throw new Error('--engagement-dir, --request-id, --request-sha256, --expected-version이 필요하다');
  }
  const adapter = createLocalHeadedBrowserAdapter({
    engagementDir,
    executablePath: flags.get('browser-executable'),
  });
  await resumeAssessOwnerAuth({
    engagementDir,
    requestId,
    requestSha256,
    expectedVersion,
    adapter,
    waitForOwner: async (challenge) => {
      console.log(JSON.stringify(challenge, null, 2));
      const prompt = createInterface({ input: stdin, output: stdout });
      try {
        await prompt.question('로그인을 완료한 뒤 Enter를 누르세요. ');
      } finally {
        prompt.close();
      }
    },
  }, { runtime: { backend: 'postgres' } });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error: unknown) => {
    console.error('assess resume failed:', error);
    process.exit(1);
  });
}
