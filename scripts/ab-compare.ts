/**
 * A/B 판정 — engagement 산출물에서 기계적으로만 읽는다.
 *
 * 지표를 실행 **전에** 고정한다. 사후에 유리한 해석을 붙이지 않기 위해서다.
 * 실행: pnpm tsx scripts/ab-compare.ts <A engagement dir> <B engagement dir>
 */
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { basename, join } from 'node:path';

type Metrics = {
  label: string;
  /** M1 반앵커링: verifier 가 VA 보고서 전에 자율 산출물을 썼는가 */
  anchoringViolation: boolean | null;
  /** M2 팬아웃 원장 행 수 (= 게이트를 통과한 위임 수) */
  invocationRows: number;
  /** M3 호스트 원장이 관측한 SubagentStart 수 */
  subagentStarts: number;
  /** M4 도달한 단계 — 정본 명명 산출물 존재로 판정 */
  phases: Record<string, boolean>;
  /** M5 벤더 게이트 차단 기록 */
  auditViolations: Record<string, number>;
  /** M6 리드가 기록한 누적 토큰 */
  budgetTokens: number | null;
  artifactCount: number;
};

const PHASE_MARKERS: Record<string, RegExp> = {
  recon: /^00_recon_result\.yaml$/,
  va: /^01_va_result-.*\.md$/,
  verify_autonomous: /^02a_verify_autonomous-.*\.md$/,
  verify_objections: /^02_verify_objections-.*\.yaml$/,
  verify_result: /^02_verify_result-.*\.md$/,
  convergence: /^06c_.*\.yaml$/,
  final_report: /^(07|08)_.*\.md$|final.*report/i,
};

function readMetrics(dir: string): Metrics {
  const files = existsSync(dir) ? readdirSync(dir) : [];

  const objections = files.find((f) => /^02_verify_objections-.*\.yaml$/.test(f));
  let anchoringViolation: boolean | null = null;
  if (objections !== undefined) {
    const text = readFileSync(join(dir, objections), 'utf8');
    const m = /anchoring_violation:\s*(true|false)/.exec(text);
    if (m?.[1] !== undefined) anchoringViolation = m[1] === 'true';
  }

  const countLines = (name: string): number =>
    files.includes(name)
      ? readFileSync(join(dir, name), 'utf8').split('\n').filter(Boolean).length
      : 0;

  const hostLedger = files.includes('host-ledger.jsonl')
    ? readFileSync(join(dir, 'host-ledger.jsonl'), 'utf8')
        .split('\n')
        .filter(Boolean)
        .map((l) => JSON.parse(l) as { event?: string })
    : [];

  const auditViolations: Record<string, number> = {};
  if (files.includes('audit.log')) {
    for (const line of readFileSync(join(dir, 'audit.log'), 'utf8').split('\n')) {
      const kind = line.split('\t')[1];
      if (kind) auditViolations[kind] = (auditViolations[kind] ?? 0) + 1;
    }
  }

  let budgetTokens: number | null = null;
  if (files.includes('budget.json')) {
    const b = JSON.parse(readFileSync(join(dir, 'budget.json'), 'utf8')) as { tokens?: number };
    budgetTokens = b.tokens ?? null;
  }

  const phases: Record<string, boolean> = {};
  for (const [phase, re] of Object.entries(PHASE_MARKERS)) {
    phases[phase] = files.some((f) => re.test(f));
  }

  return {
    label: basename(dir),
    anchoringViolation,
    invocationRows: countLines('agent_invocations.jsonl'),
    subagentStarts: hostLedger.filter((r) => r.event === 'SubagentStart').length,
    phases,
    auditViolations,
    budgetTokens,
    artifactCount: files.length,
  };
}

const [aDir, bDir] = process.argv.slice(2);
if (!aDir || !bDir) {
  console.error('사용: pnpm tsx scripts/ab-compare.ts <A dir> <B dir>');
  process.exit(2);
}

const a = readMetrics(aDir);
const b = readMetrics(bDir);

const row = (name: string, av: unknown, bv: unknown): string =>
  `${name.padEnd(26)} ${String(av).padEnd(22)} ${String(bv)}`;

console.log(`\n${'지표'.padEnd(24)} ${'A'.padEnd(22)} B`);
console.log('-'.repeat(70));
console.log(row('M1 anchoring_violation', a.anchoringViolation, b.anchoringViolation));
console.log(row('M2 invocation 원장 행', a.invocationRows, b.invocationRows));
console.log(row('M3 SubagentStart 관측', a.subagentStarts, b.subagentStarts));
for (const phase of Object.keys(PHASE_MARKERS)) {
  console.log(row(`M4 ${phase}`, a.phases[phase], b.phases[phase]));
}
console.log(row('M5 게이트 차단 종류', JSON.stringify(a.auditViolations), JSON.stringify(b.auditViolations)));
console.log(row('M6 budget tokens', a.budgetTokens, b.budgetTokens));
console.log(row('산출물 수', a.artifactCount, b.artifactCount));
console.log(
  '\nM2 vs M3 불일치는 위임이 팬아웃 게이트를 거치지 않았다는 뜻이다 (M3 는 호스트 관측이라 누락되지 않음).',
);
