import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { regressionFiles, validateImplementationMap } from './lib/implementation-map.js';

const root = resolve(import.meta.dirname, '..');
const args = process.argv.slice(2);
try {
  const runTests = args.length === 1 && args[0] === '--test';
  const featureId = args.length === 2 && args[0] === '--feature' ? args[1] : undefined;
  if (args.length && !runTests && !featureId) throw new Error('Usage: check-implementation-map.ts [--test | --feature <id>]');
  const { map, errors } = validateImplementationMap(root, JSON.parse(readFileSync(resolve(root, 'docs/implementation-map.json'), 'utf8')));
  if (errors.length || !map) throw new Error(errors.join('\n'));
  if (featureId) {
    const feature = map.features.find(item => item.id === featureId) ?? map.plannedCapabilities.find(item => item.id === featureId);
    if (!feature) throw new Error(`Unknown feature: ${featureId}`);
    console.log(JSON.stringify(feature, null, 2));
  } else {
    const files = regressionFiles(map);
    console.log(`Implementation map: ${map.features.length} current features, ${map.plannedCapabilities.length} proposals, ${files.length} regression files. References valid; behavior requires tests/review.`);
    if (runTests) {
      const require = createRequire(import.meta.url);
      const vitest = resolve(require.resolve('vitest/package.json'), '..', 'vitest.mjs');
      // Core recovery cases fsync entire runs; avoid competing file workers
      // turning the existing short publication deadline into an intermittent failure.
      const result = spawnSync(process.execPath, [vitest, 'run', '--allowOnly=false', '--maxWorkers=1', ...files], { cwd: root, stdio: 'inherit' });
      if (result.error) throw result.error;
      process.exitCode = result.status ?? 1;
    }
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
