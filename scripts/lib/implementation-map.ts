import { readFileSync, realpathSync, statSync } from 'node:fs';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import ts from 'typescript';
import { z } from 'zod';

const Text = z.string().trim().min(1);
const Id = z.string().regex(/^[a-z][a-z0-9-]*$/);
const Reference = z.object({ path: Text, symbol: Text.optional() }).strict();
const TestReference = z.object({ path: Text, title: Text }).strict();
export const ImplementationMapSchema = z.object({
  schemaVersion: z.literal(1),
  reviewedAt: z.iso.date(),
  scope: Text,
  features: z.array(z.object({
    id: Id, name: Text, status: z.enum(['implemented', 'partial']),
    behavior: Text,
    entrypoints: z.array(Reference.extend({ symbol: Text })).min(1),
    callers: z.array(Reference).min(1),
    contracts: z.array(Text).min(1),
    tests: z.array(TestReference).min(1),
    invariants: z.array(Text).min(1),
    limitations: z.array(Text).min(1),
  }).strict()).min(1),
  plannedCapabilities: z.array(z.object({
    id: Id, name: Text, relatedFeatureIds: z.array(Id).min(1),
    acceptanceCriteria: z.array(Text).min(1),
  }).strict()),
}).strict();
export type ImplementationMap = z.infer<typeof ImplementationMapSchema>;

/** Check actual declarations/test calls, not comments or incidental text matches.
 * This is a navigation guard, not a proof of the documented behavior or call graph. */
function inspectSource(path: string, content: string) {
  const source = ts.createSourceFile(path, content, ts.ScriptTarget.Latest, true);
  const symbols = new Set<string>(), tests = new Set<string>();
  // Recognize it.each(...)(title, fn) as well as it(title, fn). Fail closed for
  // conditional/disabled suites; they cannot serve as unconditional regressions.
  function callParts(node: ts.Node): string[] {
    if (ts.isIdentifier(node)) return [node.text];
    if (ts.isPropertyAccessExpression(node)) return [...callParts(node.expression), node.name.text];
    if (ts.isElementAccessExpression(node) && ts.isStringLiteral(node.argumentExpression)) return [...callParts(node.expression), node.argumentExpression.text];
    if (ts.isCallExpression(node) || ts.isTaggedTemplateExpression(node)) return callParts(ts.isCallExpression(node) ? node.expression : node.tag);
    return [];
  }
  function visit(node: ts.Node, disabled = false) {
    if ((ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node) || ts.isInterfaceDeclaration(node)
      || ts.isTypeAliasDeclaration(node) || ts.isEnumDeclaration(node) || ts.isVariableDeclaration(node))
      && node.name && ts.isIdentifier(node.name)) symbols.add(node.name.text);
    let disabledChildren = disabled;
    if (ts.isCallExpression(node)) {
      const parts = callParts(node.expression);
      if (['it', 'test', 'describe'].includes(parts[0] ?? '')) {
        disabledChildren ||= parts.some(part => ['skip', 'todo', 'only', 'skipIf', 'runIf', 'fails'].includes(part));
        const [title, body] = node.arguments;
        if (!disabledChildren && ['it', 'test'].includes(parts[0]!) && title
          && (ts.isStringLiteral(title) || ts.isNoSubstitutionTemplateLiteral(title))
          && body && (ts.isArrowFunction(body) || ts.isFunctionExpression(body))) tests.add(title.text);
      }
    }
    ts.forEachChild(node, child => visit(child, disabledChildren));
  }
  visit(source);
  return { symbols, tests };
}

export function validateImplementationMap(root: string, value: unknown): { map?: ImplementationMap; errors: string[] } {
  const parsed = ImplementationMapSchema.safeParse(value);
  if (!parsed.success) return { errors: parsed.error.issues.map(issue => `${issue.path.join('.')}: ${issue.message}`) };
  const map = parsed.data, errors: string[] = [], base = realpathSync(root);
  const cache = new Map<string, ReturnType<typeof inspectSource>>();
  const ids = new Set<string>();
  for (const item of [...map.features, ...map.plannedCapabilities]) {
    if (ids.has(item.id)) errors.push(`Duplicate feature ID: ${item.id}`);
    ids.add(item.id);
  }
  function checkFile(path: string, label: string): string | undefined {
    if (isAbsolute(path) || path.includes('\\') || path.split('/').some(part => !part || part === '..' || part === '.')) {
      errors.push(`${label}: expected a normalized repository-relative path: ${path}`); return;
    }
    try {
      const full = realpathSync(resolve(base, path)), rel = relative(base, full);
      if (isAbsolute(rel) || rel === '..' || rel.startsWith(`..${sep}`) || !statSync(full).isFile()) {
        errors.push(`${label}: reference must be a file inside the repository: ${path}`); return;
      }
      return full;
    } catch { errors.push(`${label}: missing/unreadable file: ${path}`); }
  }
  function source(path: string, label: string) {
    const full = checkFile(path, label);
    if (!full) return;
    if (!/\.[cm]?[jt]sx?$/.test(path)) { errors.push(`${label}: expected a source file: ${path}`); return; }
    if (!cache.has(full)) cache.set(full, inspectSource(path, readFileSync(full, 'utf8')));
    return cache.get(full)!;
  }
  for (const feature of map.features) {
    for (const ref of [...feature.entrypoints, ...feature.callers]) {
      const found = source(ref.path, feature.id);
      if (found && ref.symbol && !found.symbols.has(ref.symbol)) errors.push(`${feature.id}: missing declaration ${ref.symbol} in ${ref.path}`);
    }
    for (const path of feature.contracts) checkFile(path, feature.id);
    for (const ref of feature.tests) {
      if (!/^(src|evals)\/.+\.test\.ts$/.test(ref.path)) {
        errors.push(`${feature.id}: test must be a Vitest-discovered .test.ts file under src/ or evals/: ${ref.path}`); continue;
      }
      const found = source(ref.path, feature.id);
      if (found && !found.tests.has(ref.title)) errors.push(`${feature.id}: missing active test ${JSON.stringify(ref.title)} in ${ref.path}`);
    }
  }
  const featureIds = new Set(map.features.map(feature => feature.id));
  for (const planned of map.plannedCapabilities) for (const id of planned.relatedFeatureIds) {
    if (!featureIds.has(id)) errors.push(`${planned.id}: unknown related feature: ${id}`);
  }
  return { map, errors };
}

export function regressionFiles(map: ImplementationMap): string[] {
  return [...new Set(map.features.flatMap(feature => feature.tests.map(test => test.path)))].sort();
}
