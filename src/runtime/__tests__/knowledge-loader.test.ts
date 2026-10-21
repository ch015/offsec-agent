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
      expect(entries.length).toBeGreaterThanOrEqual(19);

      const a1 = entries.find((e) => e.path.includes('a1-auth.md'));
      expect(a1).toBeDefined();
      expect(a1!.phases).toEqual(['analyze', 'review']);
      expect(a1!.keywords).toEqual([]);

      const aiAgent = entries.find((e) => e.path.includes('ai-agent.md'));
      expect(aiAgent).toBeDefined();
      expect(aiAgent!.phases).toEqual(['analyze', 'review']);
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
    it('analyze and review phases include tier1, tier2, and README', () => {
      for (const phase of ['analyze', 'review']) {
        const files = resolveKnowledgeFiles('offsec', phase);
        expect(files.filter((f) => f.includes('tier1-dimensions/'))).toHaveLength(8);
        expect(files.filter((f) => f.includes('tier2-overlays/'))).toHaveLength(10);
        expect(files).toContain(join(KB_ROOT, 'README.md'));
      }
    });

    it('report and evaluate phases get no tier1 or tier2 methodology', () => {
      for (const phase of ['report', 'evaluate', 'recon']) {
        const files = resolveKnowledgeFiles('offsec', phase);
        expect(files.filter((f) => f.includes('tier1-dimensions/') || f.includes('tier2-overlays/'))).toEqual([]);
      }
    });

    it('returns empty array for unknown domain', () => {
      const files = resolveKnowledgeFiles('nonexistent', 'analyze');
      expect(files).toEqual([]);
    });
  });
});
