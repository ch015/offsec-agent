import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const root = fileURLToPath(new URL('../', import.meta.url));
const [packed] = JSON.parse(execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], { cwd: root, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 }));
const paths = new Set(packed.files.map(file => file.path));
const forbidden = [...paths].filter(path => /(^|\/)(?:__tests__|test|\.ch015|\.nunchi|\.recon-cache|engagements)(\/|$)|\/harness\/eval\/reports\/|\.(?:log|jsonl)$|\/missions\/assess-resume\.|\/live-dast-lifecycle\.|offsec-contract\.v1\.json$|offsec-(?:finding|phase-result)-schema\.v1\.json$/.test(path)
  || path.split('/').some(part => /^\.env(?:\.|$)/.test(part) && part !== '.env.example'));
if (forbidden.length) throw new Error(`Package contains private/runtime/retired material: ${forbidden.join(', ')}`);
const contract = JSON.parse(readFileSync(join(root, 'domains/offsec/contracts/offsec-contract.v2.json'), 'utf8'));
const required = ['dist/src/index.js', 'dist/src/index.d.ts', 'src/index.ts',
  'dist/domains/offsec/ch015.config.json', 'dist/domains/offsec/contracts/offsec-contract.v2.json',
  ...contract.resources.map(resource => `dist/domains/offsec/${resource.path}`)];
const missing = required.filter(path => !paths.has(path));
if (missing.length) throw new Error(`Package is missing runtime resources: ${missing.join(', ')}`);
console.log(JSON.stringify({ files: paths.size, requiredResources: required.length, excludedRuntimeMaterial: true, retiredExecutionAbsent: true }));
