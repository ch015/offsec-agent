'use strict';

// Finding-scoped 런타임 환경변수 사용 (프리픽스 없음).
// 참조: docs/agent-runtime-env.md

const fs = require('fs');
const path = require('path');

// A1-A8 핵심 차원 + M9/M10 보조 축 + 레거시 별칭
const DIMENSION_PATTERN = /^(A[1-8]|M9|M10|AUTH|DATA|INPUT|CONFIG|CRYPTO|STATE|APISEC|LEAK)$/i;

function isSupportedDimension(dimension) {
  return typeof dimension === 'string' && DIMENSION_PATTERN.test(dimension);
}

/**
 * known_findings.yaml 내용에서 dimension이 토큰 경계로 등장하는
 * pattern 블록만 골라낸다. 단순 substring 매칭은 `DATA`가 `metadata`에,
 * `A1`이 `A10`에 매칭되는 오탐을 내므로 영숫자/언더스코어 경계를 강제한다.
 */
function matchDimensionBlocks(content, dimension) {
  if (typeof content !== 'string' || !isSupportedDimension(dimension)) return [];
  // dimension은 DIMENSION_PATTERN 화이트리스트 통과값만 오므로 영숫자뿐 — escape 불필요
  const dimRx = new RegExp(
    `(?:^|[^A-Za-z0-9_])${dimension}(?:$|[^A-Za-z0-9_])`,
    'i'
  );
  return content.split('pattern_id:').filter((block) => dimRx.test(block));
}

function main() {
  const findingId = process.env.AGENT_FINDING_ID || 'unknown';
  const severity = process.env.AGENT_SEVERITY || 'INFO';
  const dimension = process.env.AGENT_DIMENSION || '';

  if (!isSupportedDimension(dimension)) {
    return;
  }

  const patternsDir = path.join(__dirname, '..', 'knowledge-base', 'patterns');
  const knownFindingsPath = path.join(patternsDir, 'known_findings.yaml');

  if (fs.existsSync(knownFindingsPath)) {
    const content = fs.readFileSync(knownFindingsPath, 'utf8');
    const dimensionPatterns = matchDimensionBlocks(content, dimension);

    if (dimensionPatterns.length > 0) {
      console.log(`[CH015] Finding ${findingId} (${severity}/${dimension}): ${dimensionPatterns.length} known pattern(s) in this dimension`);
    }
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  isSupportedDimension,
  matchDimensionBlocks,
};
