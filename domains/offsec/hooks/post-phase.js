'use strict';

/**
 * post-phase hook — 각 Phase 종료 시 로그 기록 + 예산 추적 + 상태 기록 + 권한 정리 (P3-4).
 *
 * 보안 강화:
 *  - 로그 파일은 0600으로 생성 (file permission hardening)
 *  - 로그 디렉토리는 0700 (owner-only)
 *  - 기록은 tmp + rename 원자적 (append는 race가 있지만 jsonl은 line-오리엔티드)
 *  - 예산 한도 초과 시 process.exit(2) 로 세션 중단 시그널
 *
 * Context rot 완화 (ECC 연구 기반):
 *  - Phase 경계마다 phase_state.json을 engagement_dir에 자동 기록
 *  - Lead 세션일 때 lead_state 섹션 포함
 *  - Phase 순서 검증 — 비순차 전환 시 stderr 경고
 */

const fs = require('fs');
const path = require('path');
const { withFileLock } = require('../lib/core/io.js');

const PHASE_LOG_DIR = path.join(__dirname, '..', 'harness', 'eval', 'reports');

function ensureSecureDir(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  } else {
    try { fs.chmodSync(dir, 0o700); } catch {}
  }
}

function atomicAppendLine(file, line) {
  withFileLock(file, () => fs.appendFileSync(file, line, { mode: 0o600, encoding: 'utf8' }));
}

function tryTrackBudget(update) {
  const { track } = require('./budget-tracker.js');
  return track(update);
}

function main() {
  // Save original umask and set to 0077 for owner-only file creation
  const prevUmask = process.umask(0o077);

  try {
    const phase = process.env.AGENT_PHASE || 'unknown';
    const engagementId = process.env.AGENT_ENGAGEMENT_ID || 'unknown';
    const findingCount = parseInt(process.env.AGENT_FINDING_COUNT || '0', 10);
    const evidenceCount = parseInt(process.env.AGENT_EVIDENCE_COUNT || '0', 10);
    const hallucinationCount = parseInt(process.env.AGENT_HALLUCINATION_COUNT || '0', 10);
    const tokensDelta = parseInt(process.env.AGENT_PHASE_TOKENS || '0', 10);
    const costDelta = parseFloat(process.env.AGENT_PHASE_COST_USD || '0');

    const logEntry = {
      timestamp: new Date().toISOString(),
      engagement_id: engagementId,
      phase,
      finding_count: findingCount,
      evidence_count: evidenceCount,
      hallucination_count: hallucinationCount,
      hallucination_rate: evidenceCount > 0
        ? (hallucinationCount / evidenceCount).toFixed(4)
        : '0.0000',
      tokens_delta: tokensDelta,
      cost_delta_usd: costDelta,
    };

    ensureSecureDir(PHASE_LOG_DIR);
    const logFile = path.join(PHASE_LOG_DIR, `${engagementId}_phase_log.jsonl`);
    atomicAppendLine(logFile, JSON.stringify(logEntry) + '\n');

    const baseline = 0.0;
    if (evidenceCount > 0 && hallucinationCount / evidenceCount > baseline) {
      console.error(`[CH015 WARNING] Hallucination rate ${logEntry.hallucination_rate} exceeds baseline ${baseline}`);
    }

    // Budget tracking — abort on hard limits
    if (process.env.AGENT_ENGAGEMENT_DIR) {
      const res = tryTrackBudget({ tokens: tokensDelta, cost_usd: costDelta });
      if (res && res.alerts) {
        const aborts = res.alerts.filter((a) => a.level === 'ABORT');
        const warns = res.alerts.filter((a) => a.level === 'WARN');
        for (const w of warns) {
          console.error(`[CH015 BUDGET WARN] ${w.name}: ${w.current}/${w.max}`);
        }
        if (aborts.length) {
          for (const a of aborts) {
            console.error(`[CH015 BUDGET ABORT] ${a.name}: ${a.current}/${a.max}`);
          }
          process.exit(2);
        }
      }

      // Phase state persistence — context rot 완화
      savePhaseState(process.env.AGENT_ENGAGEMENT_DIR, {
        phase, engagementId, findingCount, evidenceCount,
        hallucinationCount, tokensDelta, costDelta,
        role: process.env.AGENT_ROLE || '',
      });
    }
  } finally {
    process.umask(prevUmask);
  }
}

const PHASE_ORDER = [
  'recon', 'va', 'verify', 'pentest', 'redteam', 'convergence',
];

function savePhaseState(engagementDir, ctx) {
  const stateFile = path.join(engagementDir, 'phase_state.json');
  return withFileLock(stateFile, () => savePhaseStateUnlocked(stateFile, ctx));
}

function savePhaseStateUnlocked(stateFile, ctx) {
  let prev = null;
  if (fs.existsSync(stateFile)) {
    try { prev = JSON.parse(fs.readFileSync(stateFile, 'utf8')); } catch {}
  }

  const completedPhases = (prev && prev.completed_phases) || [];
  if (ctx.phase && ctx.phase !== 'unknown' && !completedPhases.includes(ctx.phase)) {
    // Phase 순서 검증 — 의도적으로 warn-only (exit 2 차단 아님).
    // 비순차 전환은 정상 플로우에서도 발생할 수 있어(피드백 루프 재진입,
    // 2라운드 verify→va 재실행 등) 차단하면 과차단이 된다. 순서 강제는
    // verifier 불변식(I1/I2) 등 결정론 게이트가 별도로 담당한다.
    const curIdx = PHASE_ORDER.indexOf(ctx.phase);
    if (completedPhases.length > 0 && curIdx >= 0) {
      const lastCompleted = completedPhases[completedPhases.length - 1];
      const lastIdx = PHASE_ORDER.indexOf(lastCompleted);
      if (lastIdx >= 0 && curIdx < lastIdx) {
        console.error(
          `[CH015 PHASE ORDER] non-sequential: ${lastCompleted}(${lastIdx}) → ${ctx.phase}(${curIdx})`
        );
      }
    }
    completedPhases.push(ctx.phase);
  }

  const cumulativeFindings = (prev && prev.cumulative_findings) || 0;
  const cumulativeEvidence = (prev && prev.cumulative_evidence) || 0;
  const cumulativeTokens = (prev && prev.cumulative_tokens) || 0;
  const cumulativeCost = (prev && prev.cumulative_cost_usd) || 0;

  const state = {
    updated_at: new Date().toISOString(),
    engagement_id: ctx.engagementId,
    current_phase: ctx.phase,
    completed_phases: completedPhases,
    cumulative_findings: cumulativeFindings + ctx.findingCount,
    cumulative_evidence: cumulativeEvidence + ctx.evidenceCount,
    cumulative_tokens: cumulativeTokens + ctx.tokensDelta,
    cumulative_cost_usd: +(cumulativeCost + ctx.costDelta).toFixed(6),
  };

  // Lead 세션 상태 확장
  if (ctx.role === 'offsec-lead') {
    const agentCalls = (prev && prev.lead_state && prev.lead_state.agent_calls) || [];
    agentCalls.push({ phase: ctx.phase, ts: state.updated_at });
    state.lead_state = {
      agent_calls: agentCalls,
      last_gate_phase: ctx.phase,
    };
  }

  const tmp = `${stateFile}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(state, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, stateFile);
}

main();
