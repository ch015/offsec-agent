import { submitStandardFinding } from '../../finding-contract.js';

const [target, engagementDir, source] = process.argv.slice(2);
if (!target || !engagementDir || !source) process.exit(64);

try {
  submitStandardFinding({
    target,
    engagementDir,
    phase: 'va',
    role: 'va-auditor',
    finding: {
      title: 'Concurrent finding',
      verdict: 'supported',
      severity: 'MEDIUM',
      evidenceClass: 'data-flow',
      reachability: 'confirmed',
      preconditions: ['attacker input'],
      severityRationale: 'The fixture records a deterministic concurrent data-flow finding.',
      confidence: 0.8,
      impact: `Concurrent fixture impact.${'x'.repeat(128_000)}`,
      remediation: 'Fix the fixture.',
      standards: ['CWE-20'],
      unresolved: [],
      evidence: [{ path: source, lineStart: 1, lineEnd: 1, quote: 'export const value = 1;' }],
    },
  });
  process.stdout.write('accepted');
} catch (error) {
  if (error instanceof Error && error.message.includes('이미 제출')) {
    process.stdout.write('duplicate');
  } else {
    throw error;
  }
}
