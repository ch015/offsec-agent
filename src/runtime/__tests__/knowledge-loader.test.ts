import { join, resolve } from 'node:path';
import { describe, it, expect, beforeEach } from 'vitest';

import { scanKnowledgeBase, resolveKnowledgeFiles, _resetKnowledgeCache } from '../knowledge/loader.js';

const REPO_ROOT = resolve(import.meta.dirname, '..', '..', '..');
const KB_ROOT = join(REPO_ROOT, 'domains', 'offsec', 'knowledge-base');

describe('knowledge/loader', () => {
  beforeEach(() => {
    _resetKnowledgeCache();
  });

  describe('scanKnowledgeBase', () => {
    it('returns entries with correct paths, phases, and keywords', () => {
      const entries = scanKnowledgeBase('offsec');
      expect(entries.length).toBeGreaterThanOrEqual(20);

      const a1 = entries.find((e) => e.path.includes('a1-auth.md'));
      expect(a1).toBeDefined();
      expect(a1!.phases).toEqual(['va', 'verify', 'pentest', 'converge', 'report']);
      expect(a1!.keywords).toEqual([]);

      const aiAgent = entries.find((e) => e.path.includes('ai-agent.md'));
      expect(aiAgent).toBeDefined();
      expect(aiAgent!.phases).toEqual(['va', 'pentest', 'verify']);
      expect(aiAgent!.keywords).toEqual(['llm', 'prompt-injection', 'ai', 'agent', 'ml']);
    });

    it('parses keywords correctly for tier2 overlays', () => {
      const entries = scanKnowledgeBase('offsec');
      const cloudAws = entries.find((e) => e.path.includes('cloud-aws.md'));
      expect(cloudAws!.keywords).toEqual(['aws', 's3', 'lambda', 'iam', 'ec2']);

      const web3 = entries.find((e) => e.path.includes('tier2-overlays/web3.md'));
      expect(web3!.keywords).toEqual(['web3', 'defi', 'smart-contract', 'blockchain']);
    });

    it('files without frontmatter have empty phases (include in all)', () => {
      const entries = scanKnowledgeBase('offsec');
      const readme = entries.find((e) => e.path.endsWith('knowledge-base/README.md'));
      expect(readme).toBeDefined();
      expect(readme!.phases).toEqual([]);
    });

    it('caches the scan result', () => {
      const first = scanKnowledgeBase('offsec');
      const second = scanKnowledgeBase('offsec');
      expect(first).toBe(second);
    });
  });

  describe('resolveKnowledgeFiles', () => {
    it('va phase includes tier1, tier2, conventions, and README', () => {
      const files = resolveKnowledgeFiles('offsec', 'va');
      // tier1 — all 8 files
      expect(files.filter((f) => f.includes('tier1-dimensions/'))).toHaveLength(8);
      // tier2 — all 10 overlays
      expect(files.filter((f) => f.includes('tier2-overlays/'))).toHaveLength(10);
      // conventions
      expect(files).toContain(join(KB_ROOT, 'conventions', 'finding-id-naming.md'));
      // README (no phases = all phases)
      expect(files).toContain(join(KB_ROOT, 'README.md'));
    });

    it('report phase includes tier1 but NOT tier2 overlays', () => {
      const files = resolveKnowledgeFiles('offsec', 'report');
      // tier1 — all 8 files
      expect(files.filter((f) => f.includes('tier1-dimensions/'))).toHaveLength(8);
      // tier2 — excluded (phases: [va, pentest, verify])
      expect(files.filter((f) => f.includes('tier2-overlays/'))).toHaveLength(0);
      // README included (no restriction)
      expect(files).toContain(join(KB_ROOT, 'README.md'));
    });

    it('converge phase includes tier1 and conventions but NOT tier2', () => {
      const files = resolveKnowledgeFiles('offsec', 'converge');
      expect(files.filter((f) => f.includes('tier1-dimensions/'))).toHaveLength(8);
      expect(files.filter((f) => f.includes('tier2-overlays/'))).toHaveLength(0);
      expect(files).toContain(join(KB_ROOT, 'conventions', 'finding-id-naming.md'));
    });

    it('verify phase includes tier1 and tier2', () => {
      const files = resolveKnowledgeFiles('offsec', 'verify');
      expect(files.filter((f) => f.includes('tier1-dimensions/'))).toHaveLength(8);
      expect(files.filter((f) => f.includes('tier2-overlays/'))).toHaveLength(10);
    });

    it('returns empty array for unknown domain', () => {
      const files = resolveKnowledgeFiles('nonexistent', 'va');
      expect(files).toEqual([]);
    });
  });
});
