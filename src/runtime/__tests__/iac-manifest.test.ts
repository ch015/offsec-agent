import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { assertIacManifestIntact, createIacManifest } from '../iac-manifest.js';

describe('IaC manifest', () => {
  it('classifies deterministic infrastructure files and validates the sealed manifest', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-iac-'));
    mkdirSync(join(target, '.github', 'workflows'), { recursive: true });
    mkdirSync(join(target, 'infra'), { recursive: true });
    writeFileSync(join(target, 'Dockerfile'), 'FROM node:22\n');
    writeFileSync(join(target, '.github', 'workflows', 'ci.yml'), 'name: ci\n');
    writeFileSync(join(target, 'infra', 'main.tf'), 'resource "x" "y" {}\n');
    writeFileSync(join(target, 'infra', 'main.tf.json'), '{"resource":{"test":{"example":{}}}}\n');
    writeFileSync(join(target, 'infra', 'environment.tfvars.json'), '{"region":"test"}\n');
    writeFileSync(join(target, 'deployment.yaml'), 'apiVersion: apps/v1\nkind: Deployment\n');
    writeFileSync(join(target, 'deployment.json'), '{"apiVersion":"apps/v1","kind":"Deployment"}\n');
    writeFileSync(join(target, 'template.yaml'), 'Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n');
    writeFileSync(join(target, 'template.json'), '{"Resources":{"Bucket":{"Type":"AWS::S3::Bucket"}}}\n');
    writeFileSync(join(target, 'main.bicep'), 'resource account "Microsoft.Storage/storageAccounts@2023-01-01" = {}\n');
    writeFileSync(join(target, 'Pulumi.yaml'), 'name: example\nruntime: nodejs\n');
    writeFileSync(join(target, 'playbook.yml'), '- hosts: all\n  tasks:\n    - debug: msg=test\n');
    symlinkSync(join(target, 'infra', 'main.tf'), join(target, 'infra', 'linked.tf'));
    const first = createIacManifest({ target });
    const second = createIacManifest({ target });
    expect(first.applicability).toBe('applicable');
    expect(Object.fromEntries(first.files.map((file) => [file.path, file.classification]))).toMatchObject({
      '.github/workflows/ci.yml': 'ci-cd',
      Dockerfile: 'container',
      'infra/main.tf': 'terraform',
      'infra/main.tf.json': 'terraform',
      'infra/environment.tfvars.json': 'terraform',
      'deployment.yaml': 'kubernetes',
      'deployment.json': 'kubernetes',
      'template.yaml': 'cloudformation',
      'template.json': 'cloudformation',
      'main.bicep': 'bicep',
      'Pulumi.yaml': 'pulumi',
      'playbook.yml': 'ansible',
    });
    expect(first.manifestSha256).toBe(second.manifestSha256);
    expect(first.excluded).toContainEqual({ path: 'infra/linked.tf', reason: 'symlink' });
    writeFileSync(join(target, 'infra', 'added.tf'), 'resource "new" "value" {}\n');
    writeFileSync(join(target, 'infra', 'main.tf'), '# changed\n');
    expect(() => assertIacManifestIntact(first)).not.toThrow();
    expect(() => assertIacManifestIntact({ ...first, applicability: 'not_applicable' })).toThrow(/hash/);
  });

  it('emits typed not_applicable for targets without IaC', () => {
    const target = mkdtempSync(join(tmpdir(), 'nunchi-no-iac-'));
    writeFileSync(join(target, 'app.ts'), 'export const ok = true;\n');
    const manifest = createIacManifest({ target });
    expect(manifest.applicability).toBe('not_applicable');
    expect(manifest.coverage.applicableFileCount).toBe(0);
  });
});
