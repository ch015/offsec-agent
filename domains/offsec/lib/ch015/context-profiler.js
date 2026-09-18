'use strict';

const fs = require('fs');
const path = require('path');

const CHARS_PER_TOKEN_ESTIMATE = 3.5;

/**
 * Estimate token count for a text string
 * Uses a character-based approximation (~3.5 chars per token for mixed EN/KO/code)
 */
function estimateTokens(text) {
  return Math.ceil(text.length / CHARS_PER_TOKEN_ESTIMATE);
}

/**
 * Measure a single skill file
 * @param {string} filepath
 * @returns {Object} { path, lines, chars, estimated_tokens }
 */
function measureFile(filepath) {
  const content = fs.readFileSync(filepath, 'utf8');
  const lines = content.split('\n').length;
  const chars = content.length;
  const tokens = estimateTokens(content);

  return {
    path: filepath,
    filename: path.basename(filepath),
    lines,
    chars,
    estimated_tokens: tokens
  };
}

/**
 * Profile all skill files and group by loading phase
 * Based on context-loading.md staged loading protocol
 */
function profileSkillDirectory(skillsRoot) {
  const results = {
    totalFiles: 0,
    totalLines: 0,
    totalTokens: 0,
    phases: {},
    files: [],
    recommendations: []
  };

  const phaseMapping = buildPhaseMapping(skillsRoot);

  const allMdFiles = findMdFiles(skillsRoot);

  for (const filepath of allMdFiles) {
    const measurement = measureFile(filepath);
    const relPath = path.relative(skillsRoot, filepath).split(path.sep).join('/');
    measurement.relPath = relPath;
    measurement.phase = phaseMapping[relPath] || 'unknown';

    results.files.push(measurement);
    results.totalFiles++;
    results.totalLines += measurement.lines;
    results.totalTokens += measurement.estimated_tokens;

    if (!results.phases[measurement.phase]) {
      results.phases[measurement.phase] = { files: [], totalTokens: 0, totalLines: 0 };
    }
    results.phases[measurement.phase].files.push(measurement);
    results.phases[measurement.phase].totalTokens += measurement.estimated_tokens;
    results.phases[measurement.phase].totalLines += measurement.lines;
  }

  generateRecommendations(results);

  return results;
}

/**
 * skills/ch015 실제 트리 기준 phase 매핑.
 * depth/, principles/ 디렉터리는 디스크에서 동적으로 열거해 파일 추가 시 자동 반영한다.
 */
function buildPhaseMapping(skillsRoot) {
  const mapping = {};

  // Phase 0 — 항상 로드
  mapping['SKILL.md'] = 'phase_0_always';
  mapping['offsec/va/SKILL.md'] = 'phase_0_always';
  mapping['common/context-loading.md'] = 'phase_0_always';

  mapping['common/recon.md'] = 'phase_0_recon';

  // Phase 1 — 아키텍처 분석 보조 원칙 모듈 (principles/)
  for (const rel of listMdFilesIn(skillsRoot, 'offsec/va/principles')) {
    mapping[rel] = 'phase_1_architecture';
  }

  // Phase 2 — 심층 분석 (deep-analysis 본문 + 온디맨드 depth 모듈 + 전문 분석 가이드)
  mapping['offsec/va/deep-analysis.md'] = 'phase_2_deep_analysis';
  mapping['offsec/va/concurrency.md'] = 'phase_2_deep_analysis';
  mapping['offsec/va/supply-chain.md'] = 'phase_2_deep_analysis';
  mapping['common/taint-analysis.md'] = 'phase_2_deep_analysis';
  for (const rel of listMdFilesIn(skillsRoot, 'offsec/va/depth')) {
    mapping[rel] = 'phase_2_deep_analysis';
  }

  mapping['offsec/va/compliance.md'] = 'phase_3_compliance';

  mapping['common/compensating-control.md'] = 'phase_3_5_self_verify';

  mapping['common/evidence-verification.md'] = 'phase_4_5_evidence_verify';

  mapping['offsec/va/regulatory.md'] = 'phase_5r_regulatory';

  mapping['offsec/verifier/SKILL.md'] = 'verify';
  mapping['offsec/pentest/SKILL.md'] = 'pentest';
  mapping['offsec/redteam/SKILL.md'] = 'redteam';
  mapping['review/feedback/SKILL.md'] = 'review';
  mapping['common/parallel-analysis.md'] = 'orchestration';
  mapping['common/project-scanner.md'] = 'orchestration';
  mapping['common/large-scale-flow.md'] = 'orchestration';

  return mapping;
}

/**
 * skillsRoot 하위 특정 디렉터리의 .md 파일을 relPath('/' 구분자)로 열거
 */
function listMdFilesIn(skillsRoot, relDir) {
  const dir = path.join(skillsRoot, ...relDir.split('/'));
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  return entries
    .filter(e => e.isFile() && e.name.endsWith('.md'))
    .map(e => `${relDir}/${e.name}`);
}

const MAX_MD_SCAN_DEPTH = 6;

function findMdFiles(dir, depth = 0) {
  if (depth > MAX_MD_SCAN_DEPTH) return [];
  const results = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...findMdFiles(fullPath, depth + 1));
    } else if (entry.name.endsWith('.md')) {
      results.push(fullPath);
    }
  }
  return results;
}

function generateRecommendations(results) {
  const MODEL_WINDOW = 200000;
  const SYSTEM_OVERHEAD = 15000;
  const INSTRUCTION_BUDGET = 0.25;
  const maxInstructionTokens = (MODEL_WINDOW - SYSTEM_OVERHEAD) * INSTRUCTION_BUDGET;

  if (results.totalTokens > maxInstructionTokens) {
    results.recommendations.push({
      type: 'TOKEN_BUDGET_EXCEEDED',
      message: `Total instruction tokens (${results.totalTokens}) exceed ${INSTRUCTION_BUDGET * 100}% budget (${Math.floor(maxInstructionTokens)}). Consider splitting dimensions into core/patterns.`,
      severity: 'HIGH'
    });
  }

  for (const [phase, data] of Object.entries(results.phases)) {
    if (phase === 'phase_1_architecture' && data.totalTokens > 20000) {
      results.recommendations.push({
        type: 'DIMENSION_FILES_LARGE',
        message: `Phase 1 Architecture dimensions total ${data.totalTokens} tokens. Consider extracting Anti-Pattern/Healthy Pattern sections into separate on-demand files.`,
        severity: 'MEDIUM'
      });
    }
  }

  const largeFiles = results.files.filter(f => f.estimated_tokens > 5000);
  for (const f of largeFiles) {
    results.recommendations.push({
      type: 'LARGE_FILE',
      message: `${f.relPath} is ${f.estimated_tokens} tokens (${f.lines} lines). Consider splitting.`,
      severity: 'LOW'
    });
  }
}

/**
 * Print profile report to console
 */
function printProfile(results) {
  console.log('═══════════════════════════════════════════════');
  console.log('  Context Profile Report');
  console.log('═══════════════════════════════════════════════');
  console.log(`  Total files: ${results.totalFiles}`);
  console.log(`  Total lines: ${results.totalLines}`);
  console.log(`  Total estimated tokens: ${results.totalTokens}`);
  console.log(`  Model window: 200K  |  Budget (25%): ${Math.floor(200000 * 0.25)}`);
  console.log('');

  const phaseOrder = [
    'phase_0_always', 'phase_0_recon', 'phase_1_architecture',
    'phase_2_deep_analysis', 'phase_3_compliance', 'phase_3_5_self_verify',
    'phase_4_5_evidence_verify', 'phase_5r_regulatory',
    'verify', 'pentest', 'redteam', 'review', 'orchestration', 'unknown'
  ];

  for (const phase of phaseOrder) {
    const data = results.phases[phase];
    if (!data) continue;

    console.log(`  [${phase}] ${data.totalTokens} tokens / ${data.totalLines} lines`);
    for (const f of data.files.sort((a, b) => b.estimated_tokens - a.estimated_tokens)) {
      console.log(`    ${f.relPath.padEnd(50)} ${String(f.estimated_tokens).padStart(6)} tok  ${String(f.lines).padStart(5)} ln`);
    }
    console.log('');
  }

  if (results.recommendations.length > 0) {
    console.log('  Recommendations');
    for (const rec of results.recommendations) {
      console.log(`    [${rec.severity}] ${rec.message}`);
    }
    console.log('');
  }

  console.log('═══════════════════════════════════════════════');
}

if (require.main === module) {
  const skillsRoot = path.join(__dirname, '..', '..', 'skills', 'ch015');
  const results = profileSkillDirectory(skillsRoot);
  printProfile(results);
}

module.exports = { estimateTokens, measureFile, profileSkillDirectory, printProfile, buildPhaseMapping, findMdFiles };
