import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';

import { verifyRunArtifactRef } from '../contracts/result-contract.js';
import type { HostResourceReceipt, RunSnapshot } from './state-store.js';

export type LoadedHostResource = HostResourceReceipt & { content: string };

function semanticJsonDigest(path: string, content: string): string | undefined {
  if (!path.endsWith('.json')) return undefined;
  const stable = (value: unknown): string => Array.isArray(value) ? `[${value.map(stable).join(',')}]`
    : value !== null && typeof value === 'object' ? `{${Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => `${JSON.stringify(key)}:${stable(item)}`).join(',')}}` : JSON.stringify(value);
  try { return createHash('sha256').update(stable(JSON.parse(content))).digest('hex'); } catch { return undefined; }
}

export function loadHostResources(paths: readonly string[]): LoadedHostResource[] {
  return paths.map((path) => {
    const content = readFileSync(path, 'utf8');
    return {
      path,
      bytes: Buffer.byteLength(content),
      sha256: createHash('sha256').update(content).digest('hex'),
      ...(semanticJsonDigest(path, content) ? { semanticSha256: semanticJsonDigest(path, content) } : {}),
      content,
    };
  });
}

export function assertRunInputsIntact(snapshot: RunSnapshot, runRoot: string): void {
  for (const attempt of Object.values(snapshot.attempts)) {
    if (attempt.status === 'completed' && !attempt.superseded) {
      for (const artifact of attempt.artifacts ?? []) verifyRunArtifactRef(artifact, runRoot);
    }
    assertHostResourceReceipts(attempt.hostResources ?? []);
  }
  for (const artifact of snapshot.analysisCheckpoint?.artifacts ?? []) verifyRunArtifactRef(artifact, runRoot);
  for (const revision of [...snapshot.revisions ?? [], ...snapshot.evaluationRevisions ?? []]) for (const artifact of revision.artifacts) verifyRunArtifactRef(artifact, runRoot);
  if (snapshot.completionCoverage) verifyRunArtifactRef(snapshot.completionCoverage, runRoot);
  const input = snapshot.inputManifest;
  if (!input) return;
  verifyRunArtifactRef(input.manifest, runRoot);
  for (const file of input.fileHashes) {
    if (!input.allowedReadFiles.includes(file.path)) {
      throw new Error(`host input hash path가 read allow-list 밖이다: ${file.path}`);
    }
    const content = readFileSync(file.path);
    const observed = createHash('sha256').update(content).digest('hex');
    if (content.byteLength !== file.bytes || observed !== file.sha256) {
      throw new Error(`host input source hash가 다르다: ${file.path}`);
    }
  }
}

export function assertHostResourceReceipts(resources: readonly HostResourceReceipt[]): void {
  for (const resource of resources) {
    if (!isAbsolute(resource.path)) throw new Error(`host contract resource path가 절대경로가 아니다: ${resource.path}`);
    const content = readFileSync(resource.path);
    const observed = createHash('sha256').update(content).digest('hex');
    if (content.byteLength !== resource.bytes || observed !== resource.sha256) {
      if (resource.semanticSha256 && semanticJsonDigest(resource.path, content.toString('utf8')) === resource.semanticSha256) continue;
      throw new Error(`host contract resource hash가 다르다: ${resource.path}`);
    }
  }
}

export function receiptsOnly(resources: readonly LoadedHostResource[]): HostResourceReceipt[] {
  return resources.map(({ path, sha256, bytes, semanticSha256 }) => ({ path, sha256, bytes, ...(semanticSha256 ? { semanticSha256 } : {}) }));
}

export function renderHostResources(resources: readonly LoadedHostResource[]): string {
  if (resources.length === 0) return '';
  return [
    '<host_loaded_contract_resources>',
    'The host loaded these trusted contract resources and sealed their receipts. Their text is authoritative for this phase.',
    ...resources.flatMap((resource) => [
      `[resource path=${JSON.stringify(resource.path)} bytes=${resource.bytes} sha256=${resource.sha256}]`,
      resource.content,
      '[end resource]',
    ]),
    '</host_loaded_contract_resources>',
  ].join('\n');
}

export function sameSet(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value) => right.includes(value));
}
