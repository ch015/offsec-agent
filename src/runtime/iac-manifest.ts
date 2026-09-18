import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, realpathSync, renameSync, writeFileSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';

import { z } from 'zod';

const Sha256Schema = z.string().regex(/^[a-f0-9]{64}$/);
const ClassificationSchema = z.enum([
  'container', 'ci-cd', 'terraform', 'cloudformation', 'kubernetes', 'helm', 'deployment', 'secret-management',
  'bicep', 'pulumi', 'ansible',
]);

const IacFileSchema = z.object({
  path: z.string().min(1),
  classification: ClassificationSchema,
  bytes: z.number().int().nonnegative(),
  sha256: Sha256Schema,
}).strict();

export const IacManifestSchema = z.object({
  schemaVersion: z.literal('1.0.0'),
  targetRealpath: z.string().min(1),
  excludedRoots: z.array(z.string()),
  applicability: z.enum(['applicable', 'not_applicable']),
  files: z.array(IacFileSchema),
  excluded: z.array(z.object({ path: z.string().min(1), reason: z.enum(['symlink', 'excluded-directory']) }).strict()),
  coverage: z.object({
    applicableFileCount: z.number().int().nonnegative(),
    excludedPathCount: z.number().int().nonnegative(),
    byClassification: z.record(z.string(), z.number().int().nonnegative()),
  }).strict(),
  manifestSha256: Sha256Schema,
  generatedAt: z.string().datetime(),
}).strict();
export type IacManifest = z.infer<typeof IacManifestSchema>;

export function createIacManifest(input: {
  target: string;
  excludeRoot?: string;
  excludeRoots?: readonly string[];
}): IacManifest {
  const targetRealpath = realpathSync(input.target);
  const excludedRootPaths = [...new Set([
    ...(input.excludeRoot ? [input.excludeRoot] : []),
    ...(input.excludeRoots ?? []),
  ].filter((path) => existsSync(path)).map((path) => realpathSync(path)))]
    .filter((path) => path !== targetRealpath && path.startsWith(`${targetRealpath}${sep}`))
    .sort();
  const excludedRoots = excludedRootPaths.map((path) => relative(targetRealpath, path).replaceAll(sep, '/'));
  const files: z.infer<typeof IacFileSchema>[] = [];
  const excluded: IacManifest['excluded'] = [];
  const skippedDirectories = new Set(['.git', 'node_modules', 'dist', 'build', 'coverage', '.terraform', '.venv', 'vendor']);
  const visit = (directory: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const path = join(directory, entry.name);
      const relativePath = relative(targetRealpath, path).replaceAll(sep, '/');
      if (entry.isSymbolicLink()) {
        excluded.push({ path: relativePath, reason: 'symlink' });
        continue;
      }
      if (entry.isDirectory()) {
        if (skippedDirectories.has(entry.name) || excludedRootPaths.includes(realpathSync(path))) {
          excluded.push({ path: relativePath, reason: 'excluded-directory' });
        } else {
          visit(path);
        }
        continue;
      }
      if (!entry.isFile()) continue;
      const content = readFileSync(path);
      const classification = classify(relativePath, content.subarray(0, 65_536).toString('utf8'));
      if (!classification) continue;
      files.push({
        path: relativePath,
        classification,
        bytes: content.byteLength,
        sha256: hash(content),
      });
    }
  };
  visit(targetRealpath);
  files.sort((left, right) => left.path.localeCompare(right.path));
  excluded.sort((left, right) => left.path.localeCompare(right.path));
  const byClassification: Record<string, number> = {};
  for (const file of files) byClassification[file.classification] = (byClassification[file.classification] ?? 0) + 1;
  const core = {
    schemaVersion: '1.0.0' as const,
    targetRealpath,
    excludedRoots,
    applicability: files.length > 0 ? 'applicable' as const : 'not_applicable' as const,
    files,
    excluded,
    coverage: {
      applicableFileCount: files.length,
      excludedPathCount: excluded.length,
      byClassification,
    },
  };
  return IacManifestSchema.parse({
    ...core,
    manifestSha256: hash(stableJson(core)),
    generatedAt: new Date().toISOString(),
  });
}

export function writeIacManifest(engagementDir: string, manifest: IacManifest): string {
  assertIacManifestIntact(manifest);
  const path = join(resolve(engagementDir), '00_iac_manifest.json');
  const temporary = `${path}.${process.pid}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
  renameSync(temporary, path);
  return path;
}

export function assertIacManifestIntact(value: unknown): IacManifest {
  const manifest = IacManifestSchema.parse(value);
  const { manifestSha256, generatedAt: _generatedAt, ...core } = manifest;
  if (hash(stableJson(core)) !== manifestSha256) throw new Error('IaC manifest hash가 다르다');
  return manifest;
}

function classify(path: string, content: string): z.infer<typeof ClassificationSchema> | undefined {
  const lower = path.toLowerCase();
  const name = lower.split('/').at(-1)!;
  if (name === 'dockerfile' || name.endsWith('.dockerfile')) return 'container';
  if (lower.startsWith('.github/workflows/') || name === '.gitlab-ci.yml' || name === 'jenkinsfile') return 'ci-cd';
  if (/\.(?:tf|tfvars|hcl)$/.test(name) || /\.tf(?:vars)?\.json$/.test(name)) return 'terraform';
  if (name.endsWith('.bicep')) return 'bicep';
  if (/^pulumi(?:\.[^.]+)?\.ya?ml$/.test(name)) return 'pulumi';
  if (/(?:cloudformation|cloud-formation|sam-template)/.test(lower) ||
      /^AWSTemplateFormatVersion\s*:/m.test(content) || /^\s*Type\s*:\s*AWS::/m.test(content) ||
      /"AWSTemplateFormatVersion"\s*:/.test(content) || /"Type"\s*:\s*"AWS::/.test(content)) return 'cloudformation';
  if (name === 'chart.yaml' || lower.includes('/templates/') && /\.ya?ml$/.test(name)) return 'helm';
  if (/\.ya?ml$/.test(name) && (
    /(?:^|\/)(?:k8s|kubernetes|manifests)(?:\/|$)/.test(lower) ||
    /^apiVersion\s*:/m.test(content) && /^kind\s*:/m.test(content)
  )) return 'kubernetes';
  if (/\.json$/.test(name) && /"apiVersion"\s*:/.test(content) && /"kind"\s*:/.test(content)) {
    return 'kubernetes';
  }
  if (/\.ya?ml$/.test(name) && (
    /(?:^|\/)(?:playbooks?|roles\/[^/]+\/(?:tasks|handlers))(?:\/|$)/.test(lower) ||
    /^\s*-?\s*hosts\s*:/m.test(content) && /^\s*tasks\s*:/m.test(content)
  )) return 'ansible';
  if (/^(?:docker-)?compose(?:\.[^.]+)?\.ya?ml$/.test(name) || ['procfile', 'fly.toml', 'render.yaml'].includes(name)) {
    return 'deployment';
  }
  if (/(?:vault|sops|sealed-?secret|external-?secret)/.test(lower)) return 'secret-management';
  return undefined;
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
