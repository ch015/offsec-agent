'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { loadConfig } = require('../core/config');
const {
  createSourceManifest,
  loadSourceManifest,
  sourceManifestContentHash,
  stableJson,
  writeSourceManifest,
} = require('./source-manifest');

const DECISION_FILE = 'fanout_decision.json';
const STATE_FILE = 'agent_fanout_state.json';
const INVOCATION_LEDGER = 'agent_invocations.jsonl';

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function nowIso() {
  return new Date().toISOString();
}

function normalizeRole(role) {
  const value = String(role || '').toLowerCase();
  if (value.includes('va-auditor') || value === 'va') return 'va-auditor';
  if (value.includes('verifier') || value === 'verify') return 'verifier';
  if (value.includes('pentester') || value === 'pentest') return 'pentester';
  if (value.includes('redteam') || value === 'red-team') return 'redteam';
  if (value.includes('scanner')) return 'scanner';
  return value || 'unknown';
}

function normalizePhase(phase) {
  const value = String(phase || '').toLowerCase().replace(/_/g, '-');
  if (['va', 'initial-va', 'phase-1-va'].includes(value)) return 'va';
  if (['verify', 'initial-verify', 'phase-2-verify'].includes(value)) return 'verify';
  if (['feedback-va', 'va-feedback', 'feedback'].includes(value)) return 'va-feedback';
  if (['feedback-verify', 'verify-feedback'].includes(value)) return 'verify-feedback';
  if (value === 'pentest') return 'pentest';
  if (value === 'redteam' || value === 'red-team') return 'redteam';
  if (value === 'tier0-scan' || value === 'scan') return 'tier0-scan';
  if (value === 'tier1-va') return 'tier1-va';
  if (value === 'tier1-verify') return 'tier1-verify';
  return value || 'unknown';
}

function phaseRoleKey(phase, role) {
  return `${normalizePhase(phase)}:${normalizeRole(role)}`;
}

function readJson(filePath) {
  if (!fs.existsSync(filePath)) return null;
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

function writeJsonAtomic(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const tmp = `${filePath}.tmp.${process.pid}`;
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2), { encoding: 'utf8', mode: 0o600 });
  fs.renameSync(tmp, filePath);
}

function sleepMs(ms) {
  const sab = new SharedArrayBuffer(4);
  const arr = new Int32Array(sab);
  Atomics.wait(arr, 0, 0, ms);
}

function withStateLock(engagementDir, fn, opts = {}) {
  fs.mkdirSync(engagementDir, { recursive: true, mode: 0o700 });
  const lockDir = path.join(engagementDir, '.agent-plan.lock');
  const timeoutMs = opts.timeoutMs || 5000;
  const staleMs = opts.staleMs || 30000;
  const start = Date.now();

  while (true) {
    try {
      fs.mkdirSync(lockDir);
      break;
    } catch (e) {
      if (e.code !== 'EEXIST') throw e;
      try {
        const stat = fs.statSync(lockDir);
        if (Date.now() - stat.mtimeMs > staleMs) fs.rmSync(lockDir, { recursive: true, force: true });
      } catch {}
      if (Date.now() - start > timeoutMs) {
        const err = new Error('AGENT_PLAN_LOCK_TIMEOUT');
        err.code = 'AGENT_PLAN_LOCK_TIMEOUT';
        throw err;
      }
      sleepMs(25);
    }
  }

  try {
    return fn();
  } finally {
    fs.rmSync(lockDir, { recursive: true, force: true });
  }
}

function isLargeScale(manifest, opts = {}) {
  if (opts.flow === 'standard') return false;
  if (opts.flow === 'large-scale' || opts.flow === 'large_scale' || opts.largeScale === true) return true;
  return (
    Number(manifest.subproject_count || 0) >= 5 ||
    Number(manifest.source_file_count || 0) >= 500 ||
    Number(manifest.loc_estimate || 0) >= 100000
  );
}

function selectVaMode(manifest, config, opts = {}) {
  const dimensionConfig = config?.ch015?.dimensionParallelism || {};
  const minSourceFiles = Number(dimensionConfig.min_source_files || 50);
  const configuredMode = String(opts.vaMode || opts.dimensionParallelismMode || dimensionConfig.mode || 'grouped').toLowerCase();
  const sourceCount = Number(manifest.source_file_count || 0);

  if (sourceCount < minSourceFiles && !opts.forceParallel) {
    return {
      mode: 'sequential',
      initial_agents: 1,
      reason: `source_file_count ${sourceCount} < ${minSourceFiles}; sequential forced`,
    };
  }

  if (configuredMode === 'full') {
    return {
      mode: 'full',
      initial_agents: 8,
      reason: 'full dimension parallelism explicitly configured',
    };
  }

  if (configuredMode === 'sequential' || dimensionConfig.enabled === false) {
    return {
      mode: 'sequential',
      initial_agents: 1,
      reason: 'sequential configured',
    };
  }

  return {
    mode: 'grouped',
    initial_agents: 4,
    reason: `source_file_count ${sourceCount} >= ${minSourceFiles}; grouped mode`,
  };
}

function createFanoutDecision(input) {
  const config = input.config || loadConfig();
  const manifest = input.manifest;
  if (!manifest || typeof manifest !== 'object') throw new Error('source manifest required');

  const large = isLargeScale(manifest, input);
  const vaPolicy = large
    ? { mode: 'large-scale', initial_agents: 0, reason: 'large-scale flow uses scan_plan batch fanout' }
    : selectVaMode(manifest, config, input);
  const maxFeedbackIterations = Number(
    input.maxFeedbackIterations ??
    config?.feedbackLoop?.max_iterations ??
    2
  );
  const verificationMode = input.verificationMode || 'VA_ONLY';
  const analysisMode = input.analysisMode || config?.ch015?.analysisMode?.default || 'llm';

  const limits = {};
  if (large) {
    limits['tier0-scan:scanner'] = 1;
    limits['tier1-va:va-auditor'] = Number(input.maxTier1VaAgents || 999);
    // F3: large-scale verify fanout 상한 16. 호출자가 더 큰 값을 넘겨도 16으로 절상(clamp)한다.
    // standard 모드(=1)와 달리 배치 검증이 필요하므로 1보다 크되, 무제한(999)은 예산 폭증 위험.
    limits['tier1-verify:verifier'] = Math.min(Number(input.maxTier1VerifyAgents || 16), 16);
  } else {
    limits['va:va-auditor'] = vaPolicy.initial_agents;
    // Verify는 VA 에이전트 수에 맞춰 그룹으로 생성한다(sequential→1, grouped→4, full→8).
    // 각 verifier는 자기 그룹 차원을 Autonomous-first로 검증하고, 그룹 간 중복·취약점 그룹핑은
    // offsec-lead 수렴(cluster 시더 + report-gate)이 전담한다.
    limits['verify:verifier'] = vaPolicy.initial_agents;
    limits['va-feedback:va-auditor'] = maxFeedbackIterations;
    // feedback verify는 이의-스코프 재분석이라 라운드당 1개(그룹 fan-out 아님).
    limits['verify-feedback:verifier'] = maxFeedbackIterations;
  }
  if (String(verificationMode).includes('PENTEST')) limits['pentest:pentester'] = 1;
  if (String(verificationMode).includes('REDTEAM')) limits['redteam:redteam'] = 1;

  const core = {
    schema_version: 1,
    created_at: nowIso(),
    target_realpath: manifest.target_realpath,
    manifest_hash: manifest.hash,
    manifest_content_hash: manifest.content_hash || sourceManifestContentHash(manifest),
    source_file_count: manifest.source_file_count,
    loc_estimate: manifest.loc_estimate,
    subproject_count: manifest.subproject_count,
    git_head: manifest.git_head || null,
    flow: large ? 'large-scale' : 'standard',
    analysis_mode: analysisMode,
    ast_policy: {
      run_once_before_fanout: analysisMode === 'ast',
      shared_artifact: analysisMode === 'ast' ? '.ch015/ast-context.yaml' : null,
    },
    verification_mode: verificationMode,
    va: {
      mode: vaPolicy.mode,
      initial_agents: vaPolicy.initial_agents,
      allowed_groups: vaPolicy.mode === 'grouped'
        ? ['auth', 'data', 'config', 'availability']
        : [],
      reason: vaPolicy.reason,
    },
    verify: {
      initial_agents: large ? 0 : vaPolicy.initial_agents,
      // VA와 동일 그룹 스킴으로 fan-out. grouped/full이면 verifier마다 고유 그룹 식별자가 있어야
      // 02a 산출물이 충돌하지 않는다(grouped: 4 그룹 / full: 8 차원).
      mode: large ? 'large-scale-batched' : (vaPolicy.mode === 'sequential' ? 'lite_r0_5' : 'grouped_r0_5'),
      allowed_groups: large
        ? []
        : vaPolicy.mode === 'grouped'
          ? ['auth', 'data', 'config', 'availability']
          : vaPolicy.mode === 'full'
            ? ['a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8']
            : [],
    },
    feedback: {
      max_iterations: maxFeedbackIterations,
      va_agents_per_iteration: 1,
      verify_agents_per_iteration: 1,
    },
    limits,
  };

  return {
    ...core,
    decision_hash: sha256(stableJson(core)),
  };
}

function decisionPath(engagementDir) {
  return path.join(engagementDir, DECISION_FILE);
}

function statePath(engagementDir) {
  return path.join(engagementDir, STATE_FILE);
}

function loadDecision(engagementDir) {
  return readJson(decisionPath(engagementDir));
}

function saveDecision(engagementDir, decision) {
  writeJsonAtomic(decisionPath(engagementDir), decision);
}

function loadState(engagementDir) {
  return readJson(statePath(engagementDir)) || {
    schema_version: 1,
    reservations: [],
    updated_at: nowIso(),
  };
}

function saveState(engagementDir, state) {
  state.updated_at = nowIso();
  writeJsonAtomic(statePath(engagementDir), state);
}

function initFanoutPlan(opts) {
  if (!opts.engagementDir) throw new Error('engagementDir required');
  if (!opts.target && !opts.manifest) throw new Error('target or manifest required');
  const manifest = opts.manifest || createSourceManifest(opts.target, opts);
  const decision = createFanoutDecision({ ...opts, manifest });
  writeSourceManifest(opts.engagementDir, manifest);
  saveDecision(opts.engagementDir, decision);
  saveState(opts.engagementDir, {
    schema_version: 1,
    decision_hash: decision.decision_hash,
    reservations: [],
    updated_at: nowIso(),
  });
  return { manifest, decision };
}

function activeCountFor(state, phase, role) {
  const key = phaseRoleKey(phase, role);
  return (state.reservations || [])
    .filter((r) => phaseRoleKey(r.phase, r.role) === key && r.status !== 'cancelled')
    .reduce((sum, r) => sum + Number(r.count || 1), 0);
}

function reserveAgents(engagementDir, opts) {
  return withStateLock(engagementDir, () => {
    const decision = loadDecision(engagementDir);
    if (!decision) throw new Error('fanout_decision.json missing');
    const state = loadState(engagementDir);
    const phase = normalizePhase(opts.phase);
    const role = normalizeRole(opts.role);
    const count = Math.max(1, Number(opts.count || 1));
    const key = phaseRoleKey(phase, role);
    const limit = decision.limits ? Number(decision.limits[key]) : NaN;

    if (!Number.isFinite(limit)) {
      const err = new Error(`AGENT_FANOUT_PHASE_NOT_ALLOWED: ${key}`);
      err.code = 'AGENT_FANOUT_PHASE_NOT_ALLOWED';
      throw err;
    }

    const nextCount = activeCountFor(state, phase, role) + count;
    if (nextCount > limit) {
      const err = new Error(`AGENT_FANOUT_LIMIT_EXCEEDED: ${key} ${nextCount}/${limit}`);
      err.code = 'AGENT_FANOUT_LIMIT_EXCEEDED';
      err.detail = { key, requested: count, nextCount, limit };
      throw err;
    }

    const reservation = {
      id: `rsv_${Date.now()}_${process.pid}_${crypto.randomBytes(4).toString('hex')}`,
      phase,
      role,
      count,
      status: 'reserved',
      created_at: nowIso(),
      expected_artifacts: opts.expectedArtifacts || [],
      metadata: opts.metadata || {},
    };
    state.decision_hash = decision.decision_hash;
    state.reservations.push(reservation);
    saveState(engagementDir, state);
    return reservation;
  });
}

function appendInvocationLedger(engagementDir, reservation, artifacts) {
  const filePath = path.join(engagementDir, INVOCATION_LEDGER);
  const line = JSON.stringify({
    timestamp: nowIso(),
    phase: reservation.phase,
    agent_role: reservation.role,
    subagent_type: reservation.role,
    status: 'completed',
    reservation_id: reservation.id,
    agent_count: reservation.count,
    artifacts,
    fanout_gate: true,
  }) + '\n';
  fs.appendFileSync(filePath, line, { encoding: 'utf8', mode: 0o600 });
}

function commitReservation(engagementDir, opts) {
  return withStateLock(engagementDir, () => {
    const state = loadState(engagementDir);
    const reservation = (state.reservations || []).find((r) => r.id === opts.reservationId);
    if (!reservation) {
      const err = new Error(`AGENT_FANOUT_RESERVATION_MISSING: ${opts.reservationId}`);
      err.code = 'AGENT_FANOUT_RESERVATION_MISSING';
      throw err;
    }
    if (reservation.status === 'cancelled') {
      const err = new Error(`AGENT_FANOUT_RESERVATION_CANCELLED: ${opts.reservationId}`);
      err.code = 'AGENT_FANOUT_RESERVATION_CANCELLED';
      throw err;
    }
    if (reservation.status === 'committed') return reservation;

    reservation.status = 'committed';
    reservation.committed_at = nowIso();
    reservation.artifacts = Array.isArray(opts.artifacts) ? opts.artifacts : [];
    saveState(engagementDir, state);
    appendInvocationLedger(engagementDir, reservation, reservation.artifacts);
    return reservation;
  });
}

function listFiles(engagementDir) {
  try {
    return fs.readdirSync(engagementDir).filter((name) => {
      try {
        return fs.statSync(path.join(engagementDir, name)).isFile();
      } catch {
        return false;
      }
    }).sort();
  } catch {
    return [];
  }
}

function countCanonicalArtifacts(engagementDir) {
  const files = listFiles(engagementDir);
  const fanoutVa = files.filter((name) => (
    /^01_va_result-1st-[A-Za-z0-9_-]+\.md$/.test(name) &&
    name !== '01_va_result-1st-integrated.md'
  ));
  const sequentialVa = files.includes('01_va_result-1st.md') ? 1 : 0;
  const feedbackVa = files.filter((name) => /^03_va_result-[A-Za-z0-9_-]+\.md$/.test(name)).length;

  // Verify는 VA와 대칭이어야 한다. grouped/full verify는 02_verify_result-1st-<gid>.md
  // 접미사 파일을 커밋하므로, 정확일치만 세면 committed>actual → 발행이 차단됐다.
  const fanoutVerify = files.filter((name) => (
    /^02_verify_result-1st-[A-Za-z0-9_-]+\.md$/.test(name) &&
    name !== '02_verify_result-1st-integrated.md'
  ));
  const sequentialVerify = files.includes('02_verify_result-1st.md') ? 1 : 0;

  return {
    'va:va-auditor': sequentialVa + fanoutVa.length,
    'verify:verifier': sequentialVerify + fanoutVerify.length,
    'va-feedback:va-auditor': feedbackVa,
    'verify-feedback:verifier': files.filter((name) => /^04_verify_result-[A-Za-z0-9_-]+\.md$/.test(name)).length,
    'pentest:pentester': files.filter((name) => /^06_pentest_result.*\.md$/.test(name)).length,
    'redteam:redteam': files.filter((name) => /^06b_redteam_result.*\.md$/.test(name)).length,
  };
}

function summarizeReservations(state) {
  const summary = {};
  for (const r of state.reservations || []) {
    const key = phaseRoleKey(r.phase, r.role);
    if (!summary[key]) summary[key] = { reserved: 0, committed: 0, pending: 0, cancelled: 0 };
    const count = Number(r.count || 1);
    if (r.status === 'committed') summary[key].committed += count;
    else if (r.status === 'cancelled') summary[key].cancelled += count;
    else summary[key].pending += count;
    if (r.status !== 'cancelled') summary[key].reserved += count;
  }
  return summary;
}

function pendingArtifactCapacity(state, engagementDir, key) {
  return (state.reservations || [])
    .filter((reservation) => (
      phaseRoleKey(reservation.phase, reservation.role) === key &&
      reservation.status !== 'cancelled' &&
      reservation.status !== 'committed'
    ))
    .reduce((sum, reservation) => {
      const expected = Array.isArray(reservation.expected_artifacts)
        ? reservation.expected_artifacts
        : [];
      const hasExpectedArtifact = expected.some((artifact) => (
        typeof artifact === 'string' &&
        fs.existsSync(path.join(engagementDir, artifact))
      ));
      return sum + (hasExpectedArtifact ? Number(reservation.count || 1) : 0);
    }, 0);
}

function validateManifestFreshness(engagementDir, decision, opts = {}) {
  const errors = [];
  const stored = loadSourceManifest(engagementDir);
  if (!stored) {
    errors.push({ code: 'SOURCE_MANIFEST_MISSING', file: 'source_manifest.json' });
    return errors;
  }
  const storedContentHash = sourceManifestContentHash(stored);
  const expectedContentHash = decision.manifest_content_hash || storedContentHash;
  if (stored.hash !== decision.manifest_hash || storedContentHash !== expectedContentHash) {
    errors.push({
      code: 'SOURCE_MANIFEST_HASH_MISMATCH',
      expected: decision.manifest_hash,
      observed: stored.hash,
    });
  }

  if (opts.checkCurrentSource !== false && decision.target_realpath && fs.existsSync(decision.target_realpath)) {
    const current = createSourceManifest(decision.target_realpath, { policy: stored.policy });
    if (current.content_hash !== storedContentHash) {
      errors.push({
        code: 'SOURCE_MANIFEST_STALE',
        expected: decision.manifest_hash,
        observed: current.content_hash,
        target: decision.target_realpath,
      });
    }
  }
  return errors;
}

function reconcileFanout(engagementDir, opts = {}) {
  const decision = loadDecision(engagementDir);
  const state = loadState(engagementDir);
  const errors = [];
  const warnings = [];

  if (!decision) {
    return {
      ok: false,
      errors: [{ code: 'FANOUT_DECISION_MISSING', file: DECISION_FILE }],
      warnings,
      actual: {},
      reservations: summarizeReservations(state),
    };
  }

  if (state.decision_hash && state.decision_hash !== decision.decision_hash) {
    errors.push({
      code: 'FANOUT_DECISION_HASH_MISMATCH',
      expected: decision.decision_hash,
      observed: state.decision_hash,
    });
  }
  errors.push(...validateManifestFreshness(engagementDir, decision, opts));

  const actual = countCanonicalArtifacts(engagementDir);
  const reservations = summarizeReservations(state);
  const keys = new Set([
    ...Object.keys(decision.limits || {}),
    ...Object.keys(actual),
    ...Object.keys(reservations),
  ]);

  for (const key of keys) {
    const limit = Number((decision.limits || {})[key] || 0);
    const actualCount = Number(actual[key] || 0);
    const reserved = Number(reservations[key]?.reserved || 0);
    const committed = Number(reservations[key]?.committed || 0);
    const pending = Number(reservations[key]?.pending || 0);
    const pendingArtifactAllowance = opts.allowPendingArtifacts
      ? pendingArtifactCapacity(state, engagementDir, key)
      : 0;

    if (actualCount > limit) {
      errors.push({ code: 'AGENT_ARTIFACT_LIMIT_EXCEEDED', key, actual: actualCount, limit });
    }
    if (reserved > limit) {
      errors.push({ code: 'AGENT_RESERVATION_LIMIT_EXCEEDED', key, reserved, limit });
    }
    if (actualCount > committed + pendingArtifactAllowance) {
      errors.push({ code: 'AGENT_ARTIFACT_WITHOUT_COMMIT', key, actual: actualCount, committed });
    } else if (actualCount > committed && pendingArtifactAllowance > 0) {
      warnings.push({
        code: 'AGENT_ARTIFACT_PENDING_COMMIT',
        key,
        actual: actualCount,
        committed,
        pending: pendingArtifactAllowance,
      });
    }
    if (committed > actualCount) {
      errors.push({ code: 'AGENT_COMMIT_WITHOUT_ARTIFACT', key, committed, actual: actualCount });
    }
    if (pending > 0) {
      warnings.push({ code: 'AGENT_RESERVATION_PENDING', key, pending });
    }
  }

  return {
    ok: errors.length === 0,
    errors,
    warnings,
    decision_hash: decision.decision_hash,
    actual,
    reservations,
    limits: decision.limits || {},
  };
}

module.exports = {
  commitReservation,
  countCanonicalArtifacts,
  createFanoutDecision,
  initFanoutPlan,
  loadDecision,
  loadState,
  normalizePhase,
  normalizeRole,
  phaseRoleKey,
  reconcileFanout,
  reserveAgents,
  saveDecision,
  summarizeReservations,
  validateManifestFreshness,
};
