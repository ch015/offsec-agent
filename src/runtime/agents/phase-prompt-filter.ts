/**
 * Phase-specific prompt section filtering.
 * Extracts relevant sections from agent .md files based on the current phase.
 * Falls back to full prompt if no phase-specific config exists.
 */

export interface PhaseSections {
  /** Section headings to include (## level). If empty/undefined, include all. */
  include?: string[];
  /** Section headings to exclude. Applied after include. */
  exclude?: string[];
}

/**
 * Phase-section mappings for offsec agents.
 * Only agents with 100+ line prompts that serve multiple phases are listed.
 * Missing agent or phase → full prompt (conservative fallback).
 */
const PHASE_MAP: Record<string, Record<string, PhaseSections>> = {
  pentester: {
    'pentest-plan': {
      include: ['페르소나', '실행 모드', '실현 가능성 (Feasibility)', 'OffSec Lead와의 인터페이스'],
    },
    'pentest-discovery': {
      include: ['페르소나', '실행 모드', '실행 최적화', 'OffSec Lead와의 인터페이스'],
    },
    // pentest: ALL (main execution) — no entry means full prompt
    'pentest-feedback': {
      include: ['페르소나', '실행 모드', 'OffSec Lead와의 인터페이스'],
    },
  },
  verifier: {
    // verify / pentest-verify: ALL (main execution) — no entry
    'verify-feedback': {
      include: ['페르소나', '자기 한계', '이의 유형 분류', 'OffSec Lead와의 인터페이스'],
    },
    'pentest-verify-feedback': {
      include: ['페르소나', '자기 한계', '이의 유형 분류', 'OffSec Lead와의 인터페이스'],
    },
  },
  'va-auditor': {
    // va: ALL (main execution) — no entry
    'va-feedback': {
      include: ['페르소나', '실행 모드', 'OffSec Lead와의 인터페이스'],
    },
  },
  // offsec-lead: 76 lines, not worth splitting — omitted entirely
};

/**
 * Parse markdown into sections by ## headings.
 * Returns array of { heading, content } where heading is the ## title text
 * and content is the full text of that section (heading line included).
 * Content before the first ## heading is treated as the "preamble" with heading ''.
 */
function parseSections(markdown: string): { heading: string; content: string }[] {
  const lines = markdown.split('\n');
  const sections: { heading: string; startLine: number }[] = [];
  for (let i = 0; i < lines.length; i++) {
    const match = /^## (.+)$/.exec(lines[i]);
    if (match) {
      sections.push({ heading: match[1].trim(), startLine: i });
    }
  }
  const result: { heading: string; content: string }[] = [];
  // Preamble (everything before first ##)
  if (sections.length === 0) {
    return [{ heading: '', content: markdown }];
  }
  if (sections[0].startLine > 0) {
    result.push({
      heading: '',
      content: lines.slice(0, sections[0].startLine).join('\n'),
    });
  }
  for (let i = 0; i < sections.length; i++) {
    const start = sections[i].startLine;
    const end = i + 1 < sections.length ? sections[i + 1].startLine : lines.length;
    result.push({
      heading: sections[i].heading,
      content: lines.slice(start, end).join('\n'),
    });
  }
  return result;
}

/**
 * Extract sections from markdown by ## headings.
 * Always includes the preamble (content before first ##).
 * Heading matching is substring-based to tolerate suffixes like "(Feasibility)".
 */
export function extractSections(markdown: string, headings: string[]): string {
  const sections = parseSections(markdown);
  const parts: string[] = [];
  // Always include preamble (identity/core)
  const preamble = sections.find((s) => s.heading === '');
  if (preamble) parts.push(preamble.content);

  for (const section of sections) {
    if (section.heading === '') continue;
    const matched = headings.some(
      (h) => section.heading === h || section.heading.startsWith(h),
    );
    if (matched) parts.push(section.content);
  }

  const result = parts.join('\n').trim();
  // Safety: never return empty
  return result || markdown;
}

/**
 * Get full prompt or filtered prompt based on phase.
 * Returns full prompt when: agent not in map, phase not in map, or result would be empty.
 */
export function buildFilteredPrompt(fullPrompt: string, agent: string, phase: string): string {
  const agentMap = PHASE_MAP[agent];
  if (!agentMap) return fullPrompt;
  const phaseConfig = agentMap[phase];
  if (!phaseConfig) return fullPrompt;

  let result = fullPrompt;

  if (phaseConfig.include && phaseConfig.include.length > 0) {
    result = extractSections(fullPrompt, phaseConfig.include);
  }

  if (phaseConfig.exclude && phaseConfig.exclude.length > 0) {
    const sections = parseSections(result);
    const filtered = sections.filter(
      (s) => s.heading === '' || !phaseConfig.exclude!.some(
        (h) => s.heading === h || s.heading.startsWith(h),
      ),
    );
    result = filtered.map((s) => s.content).join('\n').trim();
  }

  // Never return empty — fallback to full prompt
  return result || fullPrompt;
}
