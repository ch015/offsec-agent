/** Verify role selection uses the single active contract without launching a model. */
import { mkdtempSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { getOffsecPhase, loadOffsecContract } from '../src/runtime/offsec-contract.js';
import { buildOptions } from '../src/runtime/session.js';
const target = realpathSync(process.argv[2] ?? process.cwd());
const contract = loadOffsecContract(), phase = getOffsecPhase('recon', contract);
const engagementDir = mkdtempSync(join(tmpdir(), 'offsec-entry-probe-'));
for (const entryAgent of ['scanner', 'nunchi-offsec:scanner', 'offsec-lead']) {
  try {
    buildOptions({ domain: 'offsec', target, engagementDir, engagementId: 'entry-probe', phase: phase.id,
      agentRole: phase.role, entryAgent, prompt: 'Contract assembly probe; no model invocation.' });
    if (entryAgent !== 'scanner') throw new Error('Unexpected legacy or plugin alias accepted');
    console.log(`${entryAgent}: active contract role`);
  } catch (error) {
    if (entryAgent === 'scanner') throw error;
    console.log(`${entryAgent}: rejected (${String(error)})`);
  }
}
