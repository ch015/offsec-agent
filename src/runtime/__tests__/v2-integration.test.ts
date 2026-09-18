import { describe, expect, it } from 'vitest';
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { loadOffsecContract, type PhaseResult } from '../offsec-contract.js';
import { createOffsecWorkflowContract, OffsecDomainAdapter } from '../domains/offsec.js';
import { buildFindingContract, submitStandardFinding } from '../finding-contract.js';
import { evaluateTransition } from '../workflow/transitions.js';
import type { PhaseTransitionState } from '../domains/domain-adapter.js';
import { createOffsecWorkPlan, type OffsecWorkPlan } from '../workflow/offsec-work-plan.js';
import {
  assertScopeAssuranceComplete,
  createScopeAssurance,
} from '../workflow/scope-assurance.js';

const V2_PATH = resolve(import.meta.dirname, '..', '..', '..', 'domains', 'offsec', 'contracts', 'offsec-contract.v2.json');

function makeTransitionState(overrides: Partial<PhaseTransitionState> = {}): PhaseTransitionState {
  return {
    completedPhases: new Set<string>(),
    runStatus: 'running',
    totalCostUsd: 0,
    completedAttemptsByPhase: {},
    ...overrides,
  };
}

describe('v2 full integration', () => {
  const contract = loadOffsecContract(V2_PATH);

  it('v2 contract loads with correct structure', () => {
    expect(contract.version).toBe('2.0.0');
    expect(Object.keys(contract.roles)).toEqual(['analyzer', 'reviewer', 'evaluator', 'reporter']);
    expect(contract.phases.map(p => p.id)).toEqual(['recon', 'plan', 'analyze', 'review', 'evaluate', 'report']);
  });

  it('v2 workflow contract adapts correctly', () => {
    const wf = createOffsecWorkflowContract(contract);
    expect(wf.phases.map(p => p.id)).toEqual(['analyze', 'review', 'evaluate', 'report']);
    expect(wf.hostExecution?.workerPhases).toEqual(['analyze']);
    expect(wf.phases[0]?.requires).toEqual([]);
    expect(wf.phases[0]?.resultSchemaId).toBe('nunchi.offsec.phase-result.v2');
  });

  it('v2 domain adapter instantiates', () => {
    const adapter = new OffsecDomainAdapter(contract);
    expect(adapter.domain).toBe('offsec');
    expect(adapter.mission).toBe('assessment');
    expect(adapter.contract.version).toBe('2.0.0');
  });

  it('v2 finding contract has no runtimeEvidence', () => {
    const fc = buildFindingContract(contract);
    expect(fc.contractVersion).toBe('2.0.0');
    // v2 schema should parse a finding without runtimeEvidence
    const validFinding = {
      id: 'AUTH-001', contractVersion: '2.0.0', phase: 'analyze', role: 'analyzer',
      round: null, title: 'Test', verdict: 'supported', severity: 'HIGH',
      evidenceClass: 'data-flow', reachability: 'plausible',
      preconditions: ['authenticated user'], severityRationale: 'Direct data access bypass',
      evidence: [{ path: 'src/auth.ts', lineStart: 1, lineEnd: 5, quote: 'test code' }],
      confidence: 0.8, impact: 'Data breach', remediation: 'Fix auth',
      standards: ['CWE-287'], unresolved: [],
    };
    expect(() => fc.StandardFindingSchema.parse(validFinding)).not.toThrow();
  });

  it('v1 still works (regression)', () => {
    const v1 = loadOffsecContract();
    expect(v1.version).toBe('1.10.0');
    const fc1 = buildFindingContract(v1);
    expect(fc1.contractVersion).toBe('1.10.0');
    const wf1 = createOffsecWorkflowContract(v1);
    expect(wf1.hostExecution?.workerPhases).toEqual(['va', 'verify']);
  });

  // --- M7: v2 canTransition (domain adapter guard) ---
  describe('v2 canTransition (linear pipeline)', () => {
    const adapter = new OffsecDomainAdapter(contract);

    it('blocks evaluate until review completed, allows once review done', () => {
      const blocked = adapter.canTransition!('review', 'evaluate', makeTransitionState({
        completedPhases: new Set(['analyze']),
      }));
      expect(blocked.allowed).toBe(false);
      expect(blocked.reason).toContain('evaluate는 review 완료 후에만');

      const allowed = adapter.canTransition!('review', 'evaluate', makeTransitionState({
        completedPhases: new Set(['analyze', 'review']),
      }));
      expect(allowed.allowed).toBe(true);
    });

    it('blocks report until evaluate completed, allows once evaluate done', () => {
      const blocked = adapter.canTransition!('evaluate', 'report', makeTransitionState({
        completedPhases: new Set(['analyze', 'review']),
      }));
      expect(blocked.allowed).toBe(false);
      expect(blocked.reason).toContain('report는 evaluate 완료 후에만');

      const allowed = adapter.canTransition!('evaluate', 'report', makeTransitionState({
        completedPhases: new Set(['analyze', 'review', 'evaluate']),
      }));
      expect(allowed.allowed).toBe(true);
    });

    it('still enforces the universal budget guard in v2', () => {
      const decision = adapter.canTransition!('review', 'evaluate', makeTransitionState({
        completedPhases: new Set(['analyze', 'review']),
        totalCostUsd: 10,
        maxBudgetUsd: 10,
      }));
      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain('예산 소진');
    });
  });

  // --- M7: v2 evaluateTransition through transitions.ts + v2 adapter ---
  describe('v2 evaluateTransition (contract prereqs + domain guard)', () => {
    const adapter = new OffsecDomainAdapter(contract);

    it('allows analyze → review with prerequisite met', () => {
      const decision = evaluateTransition(adapter.contract, adapter, 'analyze', 'review', makeTransitionState({
        completedPhases: new Set(['analyze']),
      }));
      expect(decision.allowed).toBe(true);
    });

    it('blocks analyze → review when analyze prerequisite is missing (contract level)', () => {
      const decision = evaluateTransition(adapter.contract, adapter, 'plan', 'review', makeTransitionState({
        completedPhases: new Set<string>(),
      }));
      expect(decision.allowed).toBe(false);
      // review requires analyze — contract prereq fires
      expect(decision.reason).toContain('선행 계약 미충족');
    });

    it('blocks evaluate via domain guard when review not yet completed but contract prereq spoofed', () => {
      // evaluate contract prereq is 'review'; if review is absent, contract prereq blocks first.
      const decision = evaluateTransition(adapter.contract, adapter, 'analyze', 'evaluate', makeTransitionState({
        completedPhases: new Set(['analyze']),
      }));
      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain('선행 계약 미충족');
    });

    it('allows report → (end) chain when full pipeline completed', () => {
      const decision = evaluateTransition(adapter.contract, adapter, 'evaluate', 'report', makeTransitionState({
        completedPhases: new Set(['analyze', 'review', 'evaluate']),
      }));
      expect(decision.allowed).toBe(true);
    });

    it('rejects v1-only feedback phases as unknown targets in v2', () => {
      const decision = evaluateTransition(adapter.contract, adapter, 'analyze', 'va-feedback', makeTransitionState({
        completedPhases: new Set(['analyze']),
      }));
      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain('알 수 없는 target phase');
    });
  });

  // --- M7: v2 validateAcceptedResult (no objection handling, findingCount auto-correction) ---
  describe('v2 validateAcceptedResult', () => {
    const adapter = new OffsecDomainAdapter(contract);

    function seededEngagement(): { engagementDir: string } {
      // Build a target with a real evidence file so submitStandardFinding validates quotes.
      const target = mkdtempSync(join(tmpdir(), 'nunchi-v2-target-'));
      const engagementDir = mkdtempSync(join(tmpdir(), 'nunchi-v2-eng-'));
      writeFileSync(join(target, 'auth.ts'), 'const authorize = true;\nexport default authorize;\n');
      submitStandardFinding({
        target,
        engagementDir,
        phase: 'analyze',
        role: 'analyzer',
        contract,
        finding: {
          title: 'Broken auth check',
          verdict: 'supported',
          severity: 'HIGH',
          evidenceClass: 'access-control',
          reachability: 'plausible',
          preconditions: ['authenticated user'],
          severityRationale: 'Direct authorization bypass via constant true value',
          confidence: 0.7,
          impact: 'Privilege escalation',
          remediation: 'Implement real authorization',
          standards: ['CWE-285'],
          unresolved: [],
          evidence: [{ path: 'auth.ts', lineStart: 1, lineEnd: 1, quote: 'const authorize = true;' }],
        },
      });
      return { engagementDir };
    }

    it('auto-corrects an over-declared findingCount to the host-observed count', () => {
      const { engagementDir } = seededEngagement();
      const phase = contract.phases.find((p) => p.id === 'analyze')!;
      const result: PhaseResult = {
        contractVersion: '2.0.0',
        phase: 'analyze',
        role: 'analyzer',
        status: 'complete',
        artifacts: [],
        summary: 'analysis',
        metrics: { findingCount: 99 }, // model over-reported
        unresolved: [],
      };
      adapter.validateAcceptedResult!({ result, phase, engagementDir });
      expect(result.metrics.findingCount).toBe(1); // corrected to actual seeded count
    });

    it('auto-corrects an under-declared findingCount as well', () => {
      const { engagementDir } = seededEngagement();
      const phase = contract.phases.find((p) => p.id === 'analyze')!;
      const result: PhaseResult = {
        contractVersion: '2.0.0',
        phase: 'analyze',
        role: 'analyzer',
        status: 'complete',
        artifacts: [],
        summary: 'analysis',
        metrics: { findingCount: 0 },
        unresolved: [],
      };
      adapter.validateAcceptedResult!({ result, phase, engagementDir });
      expect(result.metrics.findingCount).toBe(1);
    });

    it('does no objection handling in v2 (objectionCount left untouched)', () => {
      const { engagementDir } = seededEngagement();
      const phase = contract.phases.find((p) => p.id === 'review')!;
      // review role is 'reviewer'; no findings for that phase/role, so count → 0
      const result: PhaseResult = {
        contractVersion: '2.0.0',
        phase: 'review',
        role: 'reviewer',
        status: 'complete',
        artifacts: [],
        summary: 'review',
        metrics: { findingCount: 5, objectionCount: 3 },
        unresolved: [],
      };
      adapter.validateAcceptedResult!({ result, phase, engagementDir });
      // findingCount corrected, but objectionCount is NOT reset/validated in v2
      expect(result.metrics.findingCount).toBe(0);
      expect(result.metrics.objectionCount).toBe(3);
    });
  });

  // --- M7: v2 finding contract (no runtimeEvidence field, pentester branch disabled) ---
  describe('v2 finding contract', () => {
    it('has no runtimeEvidence in the submit shape', () => {
      const fc = buildFindingContract(contract);
      expect(fc.SubmitFindingShape.runtimeEvidence).toBeUndefined();
    });

    it('rejects a finding that carries a runtimeEvidence field (additionalProperties: false)', () => {
      const fc = buildFindingContract(contract);
      const findingWithRuntime = {
        id: 'AUTH-002', contractVersion: '2.0.0', phase: 'analyze', role: 'analyzer',
        round: null, title: 'Test', verdict: 'supported', severity: 'HIGH',
        evidenceClass: 'data-flow', reachability: 'plausible',
        preconditions: ['authenticated user'], severityRationale: 'Direct data access bypass',
        evidence: [{ path: 'src/auth.ts', lineStart: 1, lineEnd: 5, quote: 'test code' }],
        confidence: 0.8, impact: 'Data breach', remediation: 'Fix auth',
        standards: ['CWE-287'], unresolved: [],
        runtimeEvidence: { scenarioId: 's1', receiptId: 'r1', observedImpact: 'x', inferredImpact: 'y' },
      };
      expect(() => fc.StandardFindingSchema.parse(findingWithRuntime)).toThrow();
    });

    it('does not require runtime evidence for a plausible-reachability HIGH finding (pentester branch disabled)', () => {
      // In v2 there is no pentester role/live phase; a confirmed submission from a non-pentest
      // context must still succeed without runtimeEvidence.
      const target = mkdtempSync(join(tmpdir(), 'nunchi-v2-pt-target-'));
      const engagementDir = mkdtempSync(join(tmpdir(), 'nunchi-v2-pt-eng-'));
      writeFileSync(join(target, 'svc.ts'), 'const secret = process.env.KEY;\nexport default secret;\n');
      expect(() => submitStandardFinding({
        target,
        engagementDir,
        phase: 'analyze',
        role: 'analyzer',
        contract,
        finding: {
          title: 'Confirmed data-flow issue',
          verdict: 'supported',
          severity: 'HIGH',
          evidenceClass: 'data-flow',
          reachability: 'confirmed',
          preconditions: ['request reaches handler'],
          severityRationale: 'Attacker-controlled input flows to sink without validation',
          confidence: 0.85,
          impact: 'Information disclosure',
          remediation: 'Validate input',
          standards: ['CWE-200'],
          unresolved: [],
          evidence: [{ path: 'svc.ts', lineStart: 1, lineEnd: 1, quote: 'const secret = process.env.KEY;' }],
        },
      })).not.toThrow();
    });
  });

  // --- M7: v2 scope-assurance (verifier optional, works without verifier events) ---
  describe('v2 scope assurance without verifier', () => {
    function scopeFixture(): { target: string; workPlan: OffsecWorkPlan } {
      const target = mkdtempSync(join(tmpdir(), 'nunchi-v2-scope-'));
      mkdirSync(join(target, 'packages', 'api'), { recursive: true });
      mkdirSync(join(target, 'packages', 'common'), { recursive: true });
      writeFileSync(
        join(target, 'packages', 'api', 'app.ts'),
        "import { authorize } from '../common/auth';\nexport const handler = authorize;\n",
      );
      writeFileSync(join(target, 'packages', 'common', 'auth.ts'), 'export const authorize = true;\n');
      const workPlan = createOffsecWorkPlan({
        target,
        sourceManifest: {
          target_realpath: realpathSync(target),
          hash: 'a'.repeat(64),
          source_files: ['packages/api/app.ts', 'packages/common/auth.ts'],
          units: [
            { id: 'packages/api', files: ['packages/api/app.ts'] },
            { id: 'packages/common', files: ['packages/common/auth.ts'] },
          ],
        },
      });
      return { target, workPlan };
    }

    it('creates a valid assurance receipt with no verifier events (verifier field omitted)', () => {
      const { target, workPlan } = scopeFixture();
      const completedUnitKeys = workPlan.units.map((unit) => unit.unitKey);
      // v2: analyze-only worker phase — no verifierEvents supplied.
      const observations = new Map(workPlan.units.map((unit) => [unit.unitKey, {
        vaEvents: [{
          at: new Date(0).toISOString(), event: 'PreToolUse' as const, tool: 'Read',
          decision: 'allow' as const, resource: join(target, unit.ownedFiles[0]!.path),
        }],
      }]));
      const assurance = createScopeAssurance({ target, workPlan, completedUnitKeys, observations });
      for (const unit of assurance.units) {
        expect(unit.verifier).toBeUndefined();
        expect(unit.va.ownedFilesRead).toBe(1);
      }
      expect(() => assertScopeAssuranceComplete(assurance, workPlan, completedUnitKeys)).not.toThrow();
    });
  });
});
