'use strict';

const fs = require('fs');
const path = require('path');
const { readStdin, parseHookInput, outputContext, logToStderr } = require('../lib/core/io');
const { PLUGIN_NAME, getPluginPath } = require('../lib/core/platform');
const { reconcileFanout } = require('../lib/ch015/agent-plan');

function tryReadJson(filePath) {
  if (!fs.existsSync(filePath)) return null;
  try { return JSON.parse(fs.readFileSync(filePath, 'utf8')); } catch { return null; }
}

function buildSessionDebrief(engagementDir) {
  const lines = [];
  const phaseState = tryReadJson(path.join(engagementDir, 'phase_state.json'));
  const budget = tryReadJson(path.join(engagementDir, 'budget.json'));
  const fanoutDecision = tryReadJson(path.join(engagementDir, 'fanout_decision.json'));

  if (phaseState) {
    const completed = phaseState.completed_phases || [];
    lines.push(`  완료 Phase: ${completed.join(' → ') || '없음'}`);
    lines.push(`  현재 Phase: ${phaseState.current_phase || 'unknown'}`);
    lines.push(`  누적 Finding: ${phaseState.cumulative_findings || 0}건 (증거 ${phaseState.cumulative_evidence || 0}건)`);
    if (phaseState.lead_state) {
      lines.push(`  Lead Agent 호출: ${phaseState.lead_state.agent_calls.length}회`);
    }
  }

  if (budget) {
    const tokK = Math.round((budget.tokens || 0) / 1000);
    lines.push(`  토큰 소비: ${tokK}K / 비용: $${(budget.cost_usd || 0).toFixed(2)}`);
  }

  if (fanoutDecision) {
    const checkCurrentSource = process.env.CH015_STOP_CHECK_CURRENT_SOURCE === '1';
    const fanout = reconcileFanout(engagementDir, {
      checkCurrentSource,
      // Provider 종료 훅은 호스트의 phase 결과 commit보다 먼저 실행될 수 있다.
      // 대기 중 reservation이 실제 산출물을 설명하면 호스트 commit 후 재검증한다.
      allowPendingArtifacts: true,
    });
    const fanoutStatus = fanout.ok
      ? (fanout.warnings.length > 0 ? 'PENDING_HOST_COMMIT' : 'OK')
      : 'INTEGRITY_VIOLATION';
    lines.push(`  Agent Fanout: ${fanoutStatus}`);
    if (!fanout.ok) {
      lines.push(`  Fanout 위반: ${fanout.errors.map((e) => e.code).join(', ')}`);
      writeIntegrityMarker(engagementDir, fanout);
    }
  }

  return lines;
}

function writeIntegrityMarker(engagementDir, fanout) {
  const markerPath = path.join(engagementDir, 'INTEGRITY_VIOLATION.json');
  const payload = {
    type: 'AGENT_FANOUT_INTEGRITY_VIOLATION',
    detected_at: new Date().toISOString(),
    fanout,
  };
  const tmp = `${markerPath}.tmp.${process.pid}`;
  fs.writeFileSync(tmp, JSON.stringify(payload, null, 2), { mode: 0o600, encoding: 'utf8' });
  fs.renameSync(tmp, markerPath);
}

function discoverEngagementDir(input = {}) {
  const explicit =
    process.env.AGENT_ENGAGEMENT_DIR ||
    input.engagement_dir ||
    input.engagementDir;
  if (explicit && fs.existsSync(explicit)) return explicit;

  const root = getPluginPath('knowledge-base', 'engagements');
  if (!fs.existsSync(root)) return '';
  const candidates = fs.readdirSync(root)
    .map((name) => path.join(root, name))
    .filter((p) => {
      try {
        return fs.statSync(p).isDirectory();
      } catch {
        return false;
      }
    })
    .sort((a, b) => {
      try {
        return fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs;
      } catch {
        return 0;
      }
    });
  return candidates.find((p) => fs.existsSync(path.join(p, 'fanout_decision.json'))) || candidates[0] || '';
}

async function main() {
  try {
    const raw = await readStdin();
    const input = parseHookInput(raw);
    const engagementDir = discoverEngagementDir(input);

    const sections = [`[${PLUGIN_NAME.toUpperCase()}] 세션 종료`];

    if (engagementDir && fs.existsSync(engagementDir)) {
      const debrief = buildSessionDebrief(engagementDir);
      if (debrief.length > 0) {
        sections.push('');
        sections.push('진단 현황:');
        sections.push(...debrief);
      }
    }

    sections.push('');
    sections.push('다음 세션 시작 시:');
    sections.push('  /ch015:status  — 이전 진단 현황 확인');
    sections.push('  /ch015:report  — 보고서 생성');

    outputContext(sections.join('\n'));
  } catch (e) {
    logToStderr(`[${PLUGIN_NAME}] on-stop error: ${e.message}`);
    outputContext(`[${PLUGIN_NAME.toUpperCase()}] 세션 종료`);
  }
}

main();
