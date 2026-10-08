import { describe, expect, it } from 'vitest';
import { resolveAssessmentBudget } from '../missions/assessment-support.js';
import { parseAssessV2Args } from '../missions/analysis-selection.js';

describe('monetary accounting policy', () => {
  it('records only even when old caller or contract limits are present', () => {
    expect(resolveAssessmentBudget({ maxBudgetUsd: 25 }, 50)).toBeUndefined();
    expect(resolveAssessmentBudget({ costPolicy: 'record-only', maxBudgetUsd: 25 }, 50)).toBeUndefined();
    expect(resolveAssessmentBudget({}, 50)).toBeUndefined();
  });
  it('requires explicit enforcement and preserves the no-cost-guard override', () => {
    expect(resolveAssessmentBudget({ costPolicy: 'enforce', maxBudgetUsd: 25 }, 50)).toBe(25);
    expect(resolveAssessmentBudget({ costPolicy: 'enforce', maxBudgetUsd: 25, noCostGuard: true }, 50)).toBeUndefined();
    expect(() => resolveAssessmentBudget({ costPolicy: 'enforce' }, null)).toThrow(/requires/);
    expect(() => resolveAssessmentBudget({ costPolicy: 'enforce', maxBudgetUsd: -1 }, null)).toThrow(/양수/);
    expect(() => resolveAssessmentBudget({ costPolicy: 'invalid' as 'enforce' }, null)).toThrow(/costPolicy/);
  });
  it('accepts explicit CLI policy in both supported flag forms', () => {
    expect(parseAssessV2Args(['/tmp/app', '--cost-policy', 'record-only']).flags.get('cost-policy')).toBe('record-only');
    expect(parseAssessV2Args(['/tmp/app', '--cost-policy=enforce', '--max-usd=25']).flags.get('cost-policy')).toBe('enforce');
  });
});
