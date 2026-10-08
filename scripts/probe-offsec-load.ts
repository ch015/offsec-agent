/** Assemble every active role and validate its tool/delegation policy without a model call. */
import { mkdtempSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadOffsecContract } from '../src/runtime/offsec-contract.js';
import { buildOptions } from '../src/runtime/session.js';
const target = realpathSync(process.argv[2] ?? process.cwd());
const contract = loadOffsecContract();
for (const phase of contract.phases.filter(phase => phase.role !== 'host')) {
  const options = buildOptions({ domain: 'offsec', target, engagementDir: mkdtempSync(join(tmpdir(), 'offsec-role-probe-')),
    engagementId: 'role-probe', phase: phase.id, agentRole: phase.role, prompt: 'Contract assembly probe; no model invocation.' });
  const tools = Array.isArray(options.tools) ? options.tools : [];
  if (tools.includes('Agent') || tools.includes('Bash')) throw new Error(`Unexpected delegation/shell tool for ${phase.role}`);
  if (['scanner', 'analyzer', 'reviewer'].includes(phase.role) && !tools.includes('mcp__nunchi__read_source')) throw new Error(`Missing source reader: ${phase.role}`);
  console.log(JSON.stringify({ phase: phase.id, role: phase.role, tools, contract: contract.version }));
}
