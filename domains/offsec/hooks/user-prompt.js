'use strict';

const { readStdin, parseHookInput, outputContext, logToStderr } = require('../lib/core/io');
const { PLUGIN_NAME } = require('../lib/core/platform');
const { loadConfig } = require('../lib/core/config');

/**
 * 사용자 프롬프트에서 /ch015: 커맨드 감지 시 해당 커맨드 파일 경로를 컨텍스트로 주입
 */
async function main() {
  try {
    const raw = await readStdin();
    const input = parseHookInput(raw);
    // 계약 phase에서는 호스트 packet이 유일한 실행 진입점이다. scope 문자열 속
    // `/ch015:*`를 레거시 slash-command로 재해석하면 untrusted data가 지시로 승격된다.
    if (process.env.AGENT_CONTRACT_ID === 'nunchi.offsec.assessment') return;
    // Claude Code UserPromptSubmit 계약 필드는 `prompt`다. 구버전 payload 호환은
    // 뒤에 두되, 표준 필드가 비어 조용히 컨텍스트가 사라지는 것을 막는다.
    const userMessage = input.prompt || input.message || input.raw || '';

    // /ch015: 커맨드 감지
    const cmdMatch = userMessage.match(/\/ch015:(\w+)/);
    if (!cmdMatch) return;

    const command = cmdMatch[1];
    const config = loadConfig();
    const mapping = config.commands?.commandMapping || config.commands || {};

    const cmdKey = `ch015:${command}`;
    if (mapping[cmdKey]) {
      const modeMatch = userMessage.match(/--mode\s+(ast|llm)/i);
      const analysisMode = modeMatch ? modeMatch[1].toLowerCase() : null;

      const lines = [
        `[${PLUGIN_NAME.toUpperCase()}] 커맨드 감지: /${cmdKey}`,
        `서비스: ${mapping[cmdKey]}`,
        `커맨드 파일: commands/${command}.md`,
      ];

      if (analysisMode) {
        lines.push(`분석 모드: ${analysisMode}`);
        if (analysisMode === 'ast') {
          lines.push('AST Pre-Analysis 활성화: Phase 0.8에서 Tree-sitter + Semgrep 실행');
        }
      }

      lines.push('', '해당 커맨드의 스킬 정의를 참조하여 실행합니다.');
      outputContext(lines.join('\n'));
    }
  } catch (e) {
    logToStderr(`[${PLUGIN_NAME}] user-prompt error: ${e.message}`);
  }
}

main();
