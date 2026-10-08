import type { SemgrepMode } from './assessment-types.js';

export type AnalysisMode = 'ast';
export type AnalysisTool = 'semgrep';
export type AnalysisSelectionInput = {
  mode?: AnalysisMode;
  tools?: AnalysisTool[];
  semgrepMode?: SemgrepMode;
};

/** Explicit selection must never silently enable, disable or skip a requested tool. */
export function resolveAnalysisSelection(input: AnalysisSelectionInput): {
  mode: AnalysisMode; tools?: AnalysisTool[]; semgrepMode: SemgrepMode;
} {
  for (const field of ['verificationMode', 'vaMode', 'liveTestTarget', 'liveTestProfile', 'liveTestPlan', 'flow', 'maxFeedbackIterations', 'ownerAuth']) {
    if (field in input) throw new Error(`Unsupported retired assessment option: ${field}`);
  }
  if (input.mode !== undefined && input.mode !== 'ast') throw new Error(`Unsupported analysis mode: ${input.mode}; expected ast`);
  if (input.semgrepMode !== undefined && !['required', 'best-effort', 'off'].includes(input.semgrepMode)) {
    throw new Error(`semgrepMode must be required, best-effort or off: ${input.semgrepMode}`);
  }
  if (input.tools !== undefined && (!Array.isArray(input.tools) || input.tools.some(tool => tool !== 'semgrep') || new Set(input.tools).size !== input.tools.length)) {
    throw new Error('tools must be [] or ["semgrep"] (CLI: --tools none or --tools semgrep)');
  }
  if (input.tools !== undefined) {
    const enabled = input.tools.includes('semgrep');
    if (input.semgrepMode !== undefined && enabled === (input.semgrepMode === 'off')) {
      throw new Error('tools selection conflicts with semgrepMode');
    }
    return { mode: 'ast', tools: [...input.tools], semgrepMode: input.semgrepMode ?? (enabled ? 'required' : 'off') };
  }
  // Preserve old callers; the new explicit mode without tools selects AST alone.
  return { mode: 'ast', semgrepMode: input.semgrepMode ?? (input.mode === 'ast' ? 'off' : 'best-effort') };
}

const VALUE_FLAGS = new Set(['reuse-from', 'mode', 'tools', 'model', 'review-model', 'effort', 'max-turns', 'max-usd', 'cost-policy',
  'semgrep', 'work-units', 'max-concurrency', 'max-files-per-agent', 'max-source-tokens-per-agent',
  'max-followup-hypotheses', 'engagement-dir']);
const BOOLEAN_FLAGS = new Set(['resume', 'no-cost-guard', 'help']);

export function parseAssessV2Args(argv: readonly string[]): { flags: Map<string, string>; positional: string[] } {
  const flags = new Map<string, string>(), positional: string[] = [];
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index]!;
    if (arg === '--') { positional.push(...argv.slice(index + 1)); break; }
    if (!arg.startsWith('--')) { positional.push(arg); continue; }
    const match = /^--([a-z-]+)(?:=(.*))?$/.exec(arg);
    const name = match?.[1];
    if (!name || (!VALUE_FLAGS.has(name) && !BOOLEAN_FLAGS.has(name))) throw new Error(`Unknown option: ${arg}`);
    if (flags.has(name)) throw new Error(`Duplicate option: --${name}`);
    let value = match![2];
    if (BOOLEAN_FLAGS.has(name)) {
      value ??= 'true';
      if (!['true', 'false'].includes(value)) throw new Error(`--${name} expects true or false`);
    } else {
      if (value === undefined) {
        const next = argv[index + 1];
        if (next === undefined || next.startsWith('--')) throw new Error(`--${name} requires a value`);
        value = next; index++;
      }
      if (!value.trim()) throw new Error(`--${name} requires a nonempty value`);
    }
    flags.set(name, value);
  }
  return { flags, positional };
}

export function parseAnalysisTools(value: string): AnalysisTool[] {
  if (value === 'none') return [];
  const tools = value.split(',').map(tool => tool.trim());
  if (tools.some(tool => tool !== 'semgrep') || new Set(tools).size !== tools.length) {
    throw new Error(`Unsupported tools: ${value}; expected semgrep or none`);
  }
  return tools as AnalysisTool[];
}
