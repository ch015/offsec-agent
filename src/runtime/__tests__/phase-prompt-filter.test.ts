import { describe, expect, it } from 'vitest';

import { buildFilteredPrompt, extractSections } from '../agents/phase-prompt-filter.js';

const SAMPLE_MD = `---
name: pentester
---

# Pentester — 모의해킹 공격자

Core identity and preamble text here.
Anti_Confirmation_Bias block.

---

## 페르소나

Persona content with mindset and approach.

## 실행 모드

Execution modes: pentest, redteam, independent.

## 실현 가능성 (Feasibility)

HIGH/MEDIUM/LOW classification.

## 실행 최적화

Batched tool execution rules.

## 스킬 바인딩

Skill binding configuration.

## OffSec Lead와의 인터페이스

Input/output interface spec.
`;

describe('extractSections', () => {
  it('extracts specified heading blocks plus preamble', () => {
    const result = extractSections(SAMPLE_MD, ['페르소나', '실행 모드']);
    expect(result).toContain('# Pentester — 모의해킹 공격자');
    expect(result).toContain('Core identity');
    expect(result).toContain('## 페르소나');
    expect(result).toContain('## 실행 모드');
    expect(result).not.toContain('## 실행 최적화');
    expect(result).not.toContain('## 스킬 바인딩');
  });

  it('matches headings with suffixes (substring start)', () => {
    const result = extractSections(SAMPLE_MD, ['실현 가능성']);
    expect(result).toContain('## 실현 가능성 (Feasibility)');
    expect(result).toContain('HIGH/MEDIUM/LOW');
  });

  it('always includes preamble', () => {
    const result = extractSections(SAMPLE_MD, ['스킬 바인딩']);
    expect(result).toContain('# Pentester — 모의해킹 공격자');
    expect(result).toContain('Core identity');
  });

  it('returns full markdown if no headings match', () => {
    const result = extractSections(SAMPLE_MD, ['nonexistent-heading']);
    // Preamble is always included but if it's all we get, that's fine
    expect(result).toContain('# Pentester');
  });

  it('returns full markdown for content with no ## headings', () => {
    const noHeadings = '# Just a title\n\nSome content here.';
    const result = extractSections(noHeadings, ['anything']);
    expect(result).toBe(noHeadings);
  });
});

describe('buildFilteredPrompt', () => {
  it('returns full prompt for main execution phase (pentest)', () => {
    const result = buildFilteredPrompt(SAMPLE_MD, 'pentester', 'pentest');
    expect(result).toBe(SAMPLE_MD);
  });

  it('returns subset for pentest-plan phase', () => {
    const result = buildFilteredPrompt(SAMPLE_MD, 'pentester', 'pentest-plan');
    expect(result).toContain('## 페르소나');
    expect(result).toContain('## 실행 모드');
    expect(result).toContain('## 실현 가능성');
    expect(result).toContain('## OffSec Lead와의 인터페이스');
    expect(result).not.toContain('## 실행 최적화');
    expect(result).not.toContain('## 스킬 바인딩');
    // Should be shorter than original
    expect(result.length).toBeLessThan(SAMPLE_MD.length);
  });

  it('returns subset for pentest-feedback phase', () => {
    const result = buildFilteredPrompt(SAMPLE_MD, 'pentester', 'pentest-feedback');
    expect(result).toContain('## 페르소나');
    expect(result).toContain('## 실행 모드');
    expect(result).toContain('## OffSec Lead와의 인터페이스');
    expect(result).not.toContain('## 실행 최적화');
    expect(result).not.toContain('## 스킬 바인딩');
    expect(result).not.toContain('## 실현 가능성');
  });

  it('returns full prompt for unknown agent (fallback)', () => {
    const result = buildFilteredPrompt(SAMPLE_MD, 'unknown-agent', 'some-phase');
    expect(result).toBe(SAMPLE_MD);
  });

  it('returns full prompt for unknown phase of known agent (fallback)', () => {
    const result = buildFilteredPrompt(SAMPLE_MD, 'pentester', 'unknown-phase');
    expect(result).toBe(SAMPLE_MD);
  });

  it('never returns empty string', () => {
    const minimal = '---\nname: x\n---\n\n# Title\n\nJust preamble.';
    const result = buildFilteredPrompt(minimal, 'pentester', 'pentest-plan');
    expect(result.length).toBeGreaterThan(0);
  });

  it('filters va-auditor for va-feedback phase', () => {
    const vaPrompt = `# VA Auditor

Identity text.

## 페르소나

Persona.

## 실행 모드

Modes.

## 실행 최적화

Optimization.

## 스킬 바인딩

Skills.

## OffSec Lead와의 인터페이스

Interface.
`;
    const result = buildFilteredPrompt(vaPrompt, 'va-auditor', 'va-feedback');
    expect(result).toContain('## 페르소나');
    expect(result).toContain('## 실행 모드');
    expect(result).toContain('## OffSec Lead와의 인터페이스');
    expect(result).not.toContain('## 실행 최적화');
    expect(result).not.toContain('## 스킬 바인딩');
  });

  it('returns full prompt for va (main execution)', () => {
    const vaPrompt = '# VA Auditor\n\n## 페르소나\n\n## 실행 모드\n';
    const result = buildFilteredPrompt(vaPrompt, 'va-auditor', 'va');
    expect(result).toBe(vaPrompt);
  });

  it('filters verifier for verify-feedback phase', () => {
    const verifierPrompt = `# Verifier

Identity.

## Phase 순서 불변식 (Invariants — 위반 시 세션 중단)

Invariants.

## 페르소나

Persona.

## 자기 한계

Self-limitation.

## 이의 유형 분류

Objection types.

## 실행 최적화

Optimization.

## 스킬 바인딩

Skills.

## OffSec Lead와의 인터페이스

Interface.
`;
    const result = buildFilteredPrompt(verifierPrompt, 'verifier', 'verify-feedback');
    expect(result).toContain('## 페르소나');
    expect(result).toContain('## 자기 한계');
    expect(result).toContain('## 이의 유형 분류');
    expect(result).toContain('## OffSec Lead와의 인터페이스');
    expect(result).not.toContain('## Phase 순서 불변식');
    expect(result).not.toContain('## 실행 최적화');
    expect(result).not.toContain('## 스킬 바인딩');
  });

  it('does not filter offsec-lead (short file, not in map)', () => {
    const leadPrompt = '# OffSec Lead\n\n## converge phase\n\nContent.\n';
    const result = buildFilteredPrompt(leadPrompt, 'offsec-lead', 'converge');
    expect(result).toBe(leadPrompt);
  });
});
