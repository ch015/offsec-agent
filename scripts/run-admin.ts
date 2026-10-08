import { readFile } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';

import { HostInputRecordSchema } from '../src/runtime/workflow/state-store.js';
import { openMissionRuntime, type MissionRuntime, type MissionRuntimeOptions } from '../src/runtime/workflow/mission-runtime.js';
import { acquireRunLock } from '../src/runtime/workflow/run-lock.js';
import {
  inspectRun,
  reconcileIncompleteAttempt,
  resumeRunWithInput,
  type ReconcileReasonCode,
} from '../src/runtime/workflow/reconciliation.js';
import { FileTelemetrySink, recordRunTelemetry } from '../src/runtime/workflow/telemetry.js';
import { resumeAssessV2 } from '../src/runtime/missions/assess-v2.js';

type Parsed = { command: string; flags: Map<string, string> };

function parseArgs(argv: readonly string[]): Parsed {
  const [command = '', ...rest] = argv;
  const flags = new Map<string, string>();
  for (const value of rest) {
    if (!value.startsWith('--') || !value.includes('=')) throw new Error(`잘못된 인수다: ${value}`);
    const [key, ...parts] = value.slice(2).split('=');
    flags.set(key!, parts.join('='));
  }
  return { command, flags };
}

function required(flags: Map<string, string>, key: string): string {
  const value = flags.get(key);
  if (!value) throw new Error(`--${key}가 필요하다`);
  return value;
}

function integer(flags: Map<string, string>, key: string): number {
  const value = Number(required(flags, key));
  if (!Number.isInteger(value) || value < 0) throw new Error(`--${key}가 음이 아닌 정수가 아니다`);
  return value;
}

async function main(): Promise<void> {
  const { command, flags } = parseArgs(process.argv.slice(2));
  if (!['inspect', 'reconcile', 'resume', 'resume-assess', 'recover-publication'].includes(command)) {
    throw new Error('사용: pnpm run:admin <inspect|reconcile|resume|resume-assess|recover-publication> --engagement=<dir> --run-id=<id> [options]');
  }
  const engagementDir = realpathSync(resolve(required(flags, 'engagement')));
  const runId = required(flags, 'run-id');
  const backend = flags.get('backend') as MissionRuntimeOptions['backend'] | undefined;
  const telemetry = new FileTelemetrySink(resolve(flags.get('telemetry') ?? join(engagementDir, 'run-telemetry.jsonl')));
  if (command === 'recover-publication' || command === 'resume-assess') {
    const checkpoint = JSON.parse(await readFile(join(engagementDir, 'assess-v2-checkpoint-input.json'), 'utf8'));
    if (checkpoint.runId !== runId) throw new Error('--run-id does not match the stored run');
    const result = await resumeAssessV2(engagementDir, { runtime: { ...(backend ? { backend } : {}) } });
    process.stdout.write(`${JSON.stringify({ finalReport: result.finalReport, coverage: result.coverage }, null, 2)}\n`);
    if (!result.coverage.complete) process.exitCode = 2;
    return;
  }
  const release = command === 'inspect' ? () => {} : acquireRunLock(join(dirname(engagementDir), `.${basename(engagementDir)}.agent.lock`));
  let runtime: MissionRuntime | undefined;
  try {
    runtime = await openMissionRuntime({ engagementDir, runId }, { ...(backend ? { backend } : {}), telemetry });
    if ((await runtime.read()).runId !== runId) throw new Error('--run-id does not match the stored run');
    if (command === 'inspect') {
      const inspection = await inspectRun(runtime.state);
      await recordRunTelemetry(telemetry, await runtime.read(), { kind: 'run.snapshot' });
      process.stdout.write(`${JSON.stringify(inspection, null, 2)}\n`);
      return;
    }
    const expectedVersion = integer(flags, 'expected-version');
    const fencingToken = runtime.leaseGuard?.fencingToken();
    if (command === 'reconcile') {
      const reasonCode = required(flags, 'reason') as ReconcileReasonCode;
      if (!['provider-error', 'accounting-incomplete', 'lease-lost', 'unknown'].includes(reasonCode)) {
        throw new Error(`--reason이 잘못됐다: ${reasonCode}`);
      }
      await reconcileIncompleteAttempt({
        state: runtime.state,
        expectedVersion,
        phase: required(flags, 'phase'),
        ...(flags.has('round') ? { round: flags.get('round')! } : {}),
        attempt: integer(flags, 'attempt'),
        reasonCode,
        ...(fencingToken === undefined ? {} : { fencingToken }),
        telemetry,
      });
      process.stdout.write(`${JSON.stringify(await inspectRun(runtime.state), null, 2)}\n`);
      return;
    }
    const revisedInput = HostInputRecordSchema.parse(JSON.parse(
      await readFile(resolve(required(flags, 'input-json')), 'utf8'),
    ) as unknown);
    await resumeRunWithInput({
      state: runtime.state,
      expectedVersion,
      revisedInput,
      ...(fencingToken === undefined ? {} : { fencingToken }),
      telemetry,
    });
    process.stdout.write(`${JSON.stringify(await inspectRun(runtime.state), null, 2)}\n`);
  } finally {
    try { await runtime?.close(); } finally { release(); }
  }
}

void main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
