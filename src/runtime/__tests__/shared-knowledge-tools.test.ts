import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, mkdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

vi.mock('@anthropic-ai/claude-agent-sdk', () => ({
  createSdkMcpServer: (config: unknown) => config,
  tool: (name: string, _description: string, schema: unknown, handler: unknown) => ({ name, schema, handler }),
}));
import { createFindingMcpServer } from '../finding-mcp-server.js';
import { loadOffsecContract } from '../offsec-contract.js';
import { readSharedKnowledge, snapshotSharedKnowledge, type SharedKnowledgeContext } from '../shared-knowledge.js';
import { authorizeToolCall, createToolPolicy } from '../workflow/policy.js';
import { z } from 'zod';
import { observeSourceDelivery, sourceRangeDelivered } from '../source-delivery.js';

type TestTool = { name: string; handler: (value: unknown) => Promise<{ content: Array<{ text: string }>; isError?: boolean }> };
const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

describe('shared knowledge MCP transport', () => {
  it('caps oversized reads and delivers every UTF-8 byte through continuation offsets', async () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'source-reader-large-'))); roots.push(root);
    const file = join(root, 'large.json'), source = JSON.stringify({ value: 'x'.repeat(23985) + '🙂가'.repeat(5000) });
    writeFileSync(file, source);
    const server = createFindingMcpServer({ target: root, engagementDir: root, phase: 'analyze', role: 'analyzer', sourceReadFiles: [file] }) as unknown as { tools: (TestTool & { schema: z.ZodRawShape })[] };
    const reader = server.tools.find(tool => tool.name === 'read_source')!;
    const deliveries = [];
    let offset: number | null = 0, combined = '';
    while (offset !== null) {
      const args = z.object(reader.schema).parse({ file_path: file, offset, limit: 1_000_000 });
      const result = await reader.handler(args);
      expect(result.isError).not.toBe(true);
      const chunk = JSON.parse(result.content[0]!.text);
      expect(chunk.byteEnd - chunk.byteStart).toBeLessThanOrEqual(24003);
      expect(chunk.byteStart).toBe(offset);
      expect(chunk.byteEnd).toBeGreaterThan(offset);
      combined += chunk.content;
      deliveries.push(observeSourceDelivery({ target: root, file, allowedFiles: [file], toolCallId: `read-${offset}`, content: result.content[0]!.text })!.delivery);
      offset = chunk.nextOffset;
    }
    expect(deliveries.length).toBeGreaterThan(1);
    expect(combined).toBe(source);
    expect(sourceRangeDelivered(file, deliveries)).toBe(true);
    for (const limit of [0, -1, 0.5, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
      expect(z.object(reader.schema).safeParse({ file_path: file, limit }).success).toBe(false);
    }
  });
  it('grants bounded reads consistently to all source and reporting roles while preserving exact scope', async () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'source-reader-tools-'))); roots.push(root);
    const file = join(root, 'app.ts'); writeFileSync(file, 'export const app = 1;\n');
    const contract = loadOffsecContract();
    for (const phase of contract.phases.filter(phase => phase.role !== 'host')) {
      const role = phase.role;
      const policy = createToolPolicy({ contractId: contract.id, domain: 'offsec', phase: phase.id, role,
        targetDir: root, engagementDir: root, allowedTools: new Set(contract.roles[role]!.tools),
        allowedReadFiles: [file], allowedReadRoots: [], allowedMethodFiles: [], allowImplicitRootRead: false,
        allowedArtifacts: new Set(), allowedDelegates: new Set() });
      expect(authorizeToolCall(policy, { tool: 'mcp__nunchi__read_source', input: { file_path: file }, agentType: role }).decision).toBe('allow');
      const server = createFindingMcpServer({ target: root, engagementDir: root, phase: phase.id, role, sourceReadFiles: [file] }) as unknown as { tools: TestTool[] };
      expect(server.tools.every(tool => contract.roles[role]!.tools.includes(`mcp__nunchi__${tool.name}`))).toBe(true);
      expect(server.tools.some(tool => tool.name === 'submit_finding')).toBe(['analyzer', 'reviewer'].includes(role));
      const reader = server.tools.find(tool => tool.name === 'read_source')!;
      const result = await reader.handler({ file_path: file });
      expect(result.isError).not.toBe(true); expect(JSON.parse(result.content[0]!.text).content).toBe('export const app = 1;\n');
      const outside = join(root, 'outside.ts'); writeFileSync(outside, 'secret');
      expect((await reader.handler({ file_path: outside })).isError).toBe(true);
    }
  });
  it('automatically shares accepted findings with other live analyzers, without double-storing identical claims', async () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'shared-tools-'))); roots.push(root);
    const target = join(root, 'source'); mkdirSync(target);
    const source = join(target, 'app.ts'); writeFileSync(source, 'return sink(input);\n');
    const context: SharedKnowledgeContext = { engagementDir: join(root, 'run'), namespace: 'c'.repeat(64), sourceFiles: [source] };
    const contract = loadOffsecContract(resolve(import.meta.dirname, '../../../domains/offsec/contracts/offsec-contract.v2.json'));
    const tools = (round: string, sharedKnowledge = context) => (createFindingMcpServer({ target,
      engagementDir: join(context.engagementDir, round), phase: 'analyze', role: 'analyzer', round, contract,
      evidenceAllowedFiles: [source], sharedKnowledge,
    }) as unknown as { tools: TestTool[] }).tools;
    const finding = { title: 'Untrusted input reaches sink', verdict: 'supported', severity: 'HIGH',
      evidenceClass: 'data-flow', reachability: 'confirmed', preconditions: ['Attacker controls input'],
      severityRationale: 'An input-to-sink flow crosses a sensitive trust boundary.', confidence: 0.9,
      impact: 'Attacker input reaches a sensitive sink.', remediation: 'Validate input before the sink.',
      standards: ['CWE-20'], unresolved: [], evidence: [{ path: source, lineStart: 1, lineEnd: 1, quote: 'return sink(input);' }] };
    const first = tools('unit-a'), second = tools('unit-b');
    const submit = (list: TestTool[]) => list.find(tool => tool.name === 'submit_finding')!.handler(finding);
    expect((await submit(first)).isError).not.toBe(true);
    const lookup = await second.find(tool => tool.name === 'lookup_shared_knowledge')!.handler({ paths: ['app.ts'] });
    const page = JSON.parse(lookup.content[0]!.text);
    expect(page.total).toBe(1); expect(page.records[0].id).toMatch(/^K-/);
    expect((await submit(second)).isError).not.toBe(true);
    expect(readSharedKnowledge(context)).toHaveLength(1);
    const frozen = tools('review', { ...context, snapshotPath: snapshotSharedKnowledge(context) });
    expect(frozen.some(tool => tool.name === 'publish_shared_observation')).toBe(false);
    const result = await frozen.find(tool => tool.name === 'get_shared_knowledge')!.handler({ id: page.records[0].id });
    const shared = JSON.parse(result.content[0]!.text);
    expect(shared.finding.verdict).toBe('supported');
    expect(shared.contributors).toHaveLength(2);
    expect(shared.contributors.every((value: { findingId: string }) => /^F-/.test(value.findingId))).toBe(true);
    const unsupported = await first.find(tool => tool.name === 'publish_shared_observation')!.handler({
      summary: 'Fake observation', tags: [], evidence: [{ path: source, lineStart: 1, lineEnd: 1, quote: 'not in source' }],
    });
    expect(unsupported.isError).toBe(true); expect(readSharedKnowledge(context)).toHaveLength(1);
  });
});
