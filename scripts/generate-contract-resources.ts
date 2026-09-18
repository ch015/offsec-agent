import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

import {
  normalizeResourcePath,
  contractResourceSha256,
  type ContractResource,
} from '../src/runtime/contracts/resource-manifest.js';

const ROOT = resolve(import.meta.dirname, '..');
const check = process.argv.includes('--check');

function readJson(path: string): Record<string, any> {
  return JSON.parse(readFileSync(path, 'utf8')) as Record<string, any>;
}

function writeJson(path: string, value: unknown): void {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function resourcePaths(paths: readonly string[]): string[] {
  return [...new Set(paths.map(normalizeResourcePath))];
}

function resourcesFor(root: string, paths: readonly string[]): ContractResource[] {
  return resourcePaths(paths).map((path) => {
    const fullPath = join(root, path);
    if (!existsSync(fullPath)) throw new Error(`contract resource가 없다: ${fullPath}`);
    return { path, sha256: contractResourceSha256(readFileSync(fullPath)) };
  });
}

function updateContract(path: string, root: string, paths: readonly string[]): void {
  const current = readJson(path);
  const next = { ...current, resources: resourcesFor(root, paths) };
  if (check) {
    if (JSON.stringify(current) !== JSON.stringify(next)) {
      throw new Error(`contract resource manifest가 최신이 아니다: ${relative(ROOT, path)}`);
    }
    return;
  }
  writeJson(path, next);
}

const offsecRoot = join(ROOT, 'domains', 'offsec');
const offsecContractPath = join(offsecRoot, 'contracts', 'offsec-contract.v1.json');
const offsec = readJson(offsecContractPath);
const offsecSchemaPaths = [
  offsec.schemaResources.phaseResultSchema,
  offsec.schemaResources.findingSchema,
  offsec.schemaResources.liveTestProfileSchema,
] as string[];
if (!check) {
  writeJson(join(offsecRoot, offsecSchemaPaths[0]), offsec.phaseResultSchema);
  writeJson(join(offsecRoot, offsecSchemaPaths[1]), offsec.findingSchema);
}
updateContract(
  offsecContractPath,
  offsecRoot,
  [
    ...Object.values(offsec.roles).flatMap((role: any) => [
      role.agentFile,
      ...role.skills.map((skill: string) => `skills/${skill.split(':').pop()}/SKILL.md`),
    ]),
    ...offsec.phases.flatMap((phase: any) => phase.requiredMethodFiles),
    ...Object.values(offsec.methodologyResources ?? {}).flatMap((paths: any) => paths),
    offsec.analysisResources.semgrepManifest,
    ...offsec.analysisResources.semgrepRules,
    ...offsecSchemaPaths,
  ],
);

console.log(check ? 'contract resource manifests: in sync' : 'contract resource manifests: generated');

// ── v2 계약 resource manifest ────────────────────────────────────
const offsecV2Path = join(offsecRoot, 'contracts', 'offsec-contract.v2.json');
if (existsSync(offsecV2Path)) {
  const v2 = readJson(offsecV2Path);
  const v2SchemaPaths = [
    v2.schemaResources.phaseResultSchema,
    v2.schemaResources.findingSchema,
    ...(v2.schemaResources.liveTestProfileSchema ? [v2.schemaResources.liveTestProfileSchema] : []),
  ] as string[];
  if (!check) {
    writeJson(join(offsecRoot, v2SchemaPaths[0]), v2.phaseResultSchema);
    writeJson(join(offsecRoot, v2SchemaPaths[1]), v2.findingSchema);
  }
  updateContract(
    offsecV2Path,
    offsecRoot,
    [
      ...Object.values(v2.roles).flatMap((role: any) => [
        role.agentFile,
        ...role.skills.map((skill: string) => `skills/${skill.split(':').pop()}/SKILL.md`),
      ]),
      ...v2.phases.flatMap((phase: any) => phase.requiredMethodFiles ?? []),
      ...Object.values(v2.methodologyResources ?? {}).flatMap((paths: any) => paths),
      v2.analysisResources.semgrepManifest,
      ...v2.analysisResources.semgrepRules,
      ...v2SchemaPaths,
    ],
  );
  console.log(check ? 'v2 contract resource manifests: in sync' : 'v2 contract resource manifests: generated');
}
