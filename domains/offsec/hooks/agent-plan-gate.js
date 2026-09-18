#!/usr/bin/env node
'use strict';

const path = require('path');
const {
  commitReservation,
  initFanoutPlan,
  reconcileFanout,
  reserveAgents,
} = require('../lib/ch015/agent-plan');

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const opts = { command };
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i];
    if (!arg.startsWith('--')) continue;
    const key = arg.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    const next = rest[i + 1];
    if (next == null || next.startsWith('--')) {
      opts[key] = true;
    } else {
      opts[key] = next;
      i++;
    }
  }
  return opts;
}

function splitList(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value;
  return String(value).split(',').map((v) => v.trim()).filter(Boolean);
}

function engagementDirFrom(opts) {
  const dir = opts.engagementDir || process.env.AGENT_ENGAGEMENT_DIR;
  if (!dir) throw new Error('engagement-dir required');
  return path.resolve(dir);
}

function printJson(value) {
  process.stdout.write(JSON.stringify(value, null, 2) + '\n');
}

function run(opts) {
  switch (opts.command) {
    case 'init': {
      const engagementDir = engagementDirFrom(opts);
      const target = opts.target || process.env.PROJECT_DIR || process.cwd();
      const result = initFanoutPlan({
        engagementDir,
        target,
        analysisMode: opts.analysisMode,
        verificationMode: opts.verificationMode,
        flow: opts.flow,
        vaMode: opts.vaMode,
        dimensionParallelismMode: opts.dimensionParallelismMode,
        forceParallel: opts.forceParallel === true || opts.forceParallel === 'true',
      });
      printJson({
        ok: true,
        engagement_dir: engagementDir,
        source_file_count: result.manifest.source_file_count,
        loc_estimate: result.manifest.loc_estimate,
        subproject_count: result.manifest.subproject_count,
        decision: result.decision,
      });
      return 0;
    }
    case 'reserve': {
      const engagementDir = engagementDirFrom(opts);
      const reservation = reserveAgents(engagementDir, {
        phase: opts.phase,
        role: opts.role,
        count: opts.count,
        expectedArtifacts: splitList(opts.expectedArtifacts || opts.artifacts),
      });
      printJson({ ok: true, reservation_id: reservation.id, reservation });
      return 0;
    }
    case 'commit': {
      const engagementDir = engagementDirFrom(opts);
      const reservation = commitReservation(engagementDir, {
        reservationId: opts.reservation || opts.reservationId,
        artifacts: splitList(opts.artifacts),
      });
      printJson({ ok: true, reservation });
      return 0;
    }
    case 'reconcile':
    case 'status': {
      const engagementDir = engagementDirFrom(opts);
      const result = reconcileFanout(engagementDir, {
        checkCurrentSource: opts.checkCurrentSource !== 'false',
      });
      printJson(result);
      return result.ok ? 0 : 2;
    }
    default:
      process.stderr.write([
        'Usage:',
        '  node hooks/agent-plan-gate.js init --engagement-dir <dir> --target <repo> [--analysis-mode ast]',
        '  node hooks/agent-plan-gate.js reserve --engagement-dir <dir> --phase va --role va-auditor --count 1',
        '  node hooks/agent-plan-gate.js commit --engagement-dir <dir> --reservation <id> --artifacts 01_va_result-1st.md',
        '  node hooks/agent-plan-gate.js reconcile --engagement-dir <dir>',
      ].join('\n') + '\n');
      return 1;
  }
}

if (require.main === module) {
  try {
    process.exitCode = run(parseArgs(process.argv.slice(2)));
  } catch (e) {
    process.stderr.write(`[CH015][agent-plan-gate] ${e.message}\n`);
    process.exitCode = e.code && String(e.code).startsWith('AGENT_') ? 2 : 1;
  }
}

module.exports = { parseArgs, run };
