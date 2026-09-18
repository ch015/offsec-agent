import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

const REPO_ROOT = resolve(import.meta.dirname, '..', '..', '..');

export interface KnowledgeEntry {
  path: string;          // absolute path
  phases: string[];      // from frontmatter
  keywords: string[];    // from frontmatter (optional)
}

const cache = new Map<string, KnowledgeEntry[]>();

function parseFrontmatter(content: string): { phases?: string[]; keywords?: string[] } {
  if (!content.startsWith('---\n')) return {};
  const end = content.indexOf('\n---\n', 4);
  if (end === -1) return {};
  const block = content.slice(4, end);
  const result: { phases?: string[]; keywords?: string[] } = {};
  for (const line of block.split('\n')) {
    const phasesMatch = line.match(/^phases:\s*\[([^\]]*)\]/);
    if (phasesMatch) {
      result.phases = phasesMatch[1].split(',').map((s) => s.trim()).filter(Boolean);
    }
    const keywordsMatch = line.match(/^keywords:\s*\[([^\]]*)\]/);
    if (keywordsMatch) {
      result.keywords = keywordsMatch[1].split(',').map((s) => s.trim()).filter(Boolean);
    }
  }
  return result;
}

function walkMd(dir: string): string[] {
  const results: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...walkMd(full));
    } else if (entry.name.endsWith('.md')) {
      results.push(full);
    }
  }
  return results;
}

/** Scan KB directory and parse frontmatter metadata */
export function scanKnowledgeBase(domain: string): KnowledgeEntry[] {
  const cached = cache.get(domain);
  if (cached) return cached;

  const kbRoot = join(REPO_ROOT, 'domains', domain, 'knowledge-base');
  if (!statSync(kbRoot, { throwIfNoEntry: false })?.isDirectory()) return [];

  const files = walkMd(kbRoot);
  const entries: KnowledgeEntry[] = files.map((filePath) => {
    const content = readFileSync(filePath, 'utf8');
    const meta = parseFrontmatter(content);
    return {
      path: filePath,
      phases: meta.phases ?? [],
      keywords: meta.keywords ?? [],
    };
  });

  cache.set(domain, entries);
  return entries;
}

/** Filter KB entries for a specific phase */
export function resolveKnowledgeFiles(domain: string, phase: string): string[] {
  const entries = scanKnowledgeBase(domain);
  return entries
    .filter((entry) => entry.phases.length === 0 || entry.phases.includes(phase))
    .map((entry) => entry.path);
}

/** Reset cache — for testing only */
export function _resetKnowledgeCache(): void {
  cache.clear();
}
