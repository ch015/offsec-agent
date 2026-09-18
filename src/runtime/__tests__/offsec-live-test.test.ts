import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { createLiveTestBroker, readLiveTestPlan, verifyLiveTestReceipt } from '../live-test-broker.js';

describe('OffSec live test broker', () => {
  it('accepts the source-plan method set and preserves source evidence', () => {
    const engagementDir = mkdtempSync(join(tmpdir(), 'nunchi-live-plan-'));
    const planPath = join(engagementDir, '05_pentest_plan.json');
    writeFileSync(planPath, `${JSON.stringify({
      schemaVersion: '1.0.0',
      scenarios: [{
        scenarioId: 'SC-POST', path: '/items', method: 'POST', safety: 'safe',
        preconditions: ['isolated test'], successCriteria: '201', failureCriteria: 'non-201',
        sourceEvidence: { file: 'routes/items.ts', lines: [10, 14], sink: 'createItem()' },
      }],
    })}\n`);

    const parsed = readLiveTestPlan(planPath).plan.scenarios[0]!;
    expect(parsed.method).toBe('POST');
    expect(parsed.safety).toBe('ready');
    expect(parsed.sourceEvidence).toEqual({ file: 'routes/items.ts', lines: [10, 14], sink: 'createItem()' });
  });

  it('records a bounded redacted receipt and verifies its binding', async () => {
    const engagementDir = mkdtempSync(join(tmpdir(), 'nunchi-live-test-'));
    const planPath = join(engagementDir, '05_pentest_plan.json');
    writeFileSync(planPath, `${JSON.stringify({
      schemaVersion: '1.0.0',
      scenarios: [{
        scenarioId: 'SC-1', path: 'health', method: 'GET', safety: 'ready',
        preconditions: ['isolated test'], successCriteria: '200', failureCriteria: 'non-200',
      }],
    })}\n`);
    const planSha256 = (await import('node:crypto')).createHash('sha256').update(readFileSync(planPath)).digest('hex');
    const broker = createLiveTestBroker({
      engagementDir,
      allowedBaseUrl: 'https://test.example/app/',
      planPath,
      planSha256,
      fetchImpl: async () => new Response(
        '{"token":"abcdefghijklmnopqrstuvwxyz123456","ok":true}',
        { status: 200, headers: { 'content-type': 'application/json', 'set-cookie': 'secret=yes' } },
      ),
    });
    const receipt = await broker.probe({ scenarioId: 'SC-1' });

    expect(receipt.request.url).toBe('https://test.example/app/health');
    expect(receipt.response.safeExcerpt).toContain('[REDACTED]');
    expect(receipt.response.headers['set-cookie']).toBeUndefined();
    expect(verifyLiveTestReceipt({ engagementDir, receiptId: receipt.receiptId, scenarioId: 'SC-1' }))
      .toEqual(receipt);
  });

  it('rejects cross-origin, prefix escape, redirects, and tampered receipts', async () => {
    const engagementDir = mkdtempSync(join(tmpdir(), 'nunchi-live-scope-'));
    const planPath = join(engagementDir, '05_pentest_plan.json');
    writeFileSync(planPath, `${JSON.stringify({
      schemaVersion: '1.0.0',
      scenarios: [
        { scenarioId: 'SC-1', path: 'https://evil.example/', method: 'GET', safety: 'ready', preconditions: [], successCriteria: 'x', failureCriteria: 'y' },
        { scenarioId: 'SC-2', path: '/admin', method: 'GET', safety: 'ready', preconditions: [], successCriteria: 'x', failureCriteria: 'y' },
        { scenarioId: 'SC-3', path: 'redirect', method: 'GET', safety: 'ready', preconditions: [], successCriteria: 'x', failureCriteria: 'y' },
        { scenarioId: 'SC-4', path: 'ok', method: 'HEAD', safety: 'ready', preconditions: [], successCriteria: 'x', failureCriteria: 'y' },
      ],
    })}\n`);
    const planSha256 = (await import('node:crypto')).createHash('sha256').update(readFileSync(planPath)).digest('hex');
    const broker = createLiveTestBroker({
      engagementDir,
      allowedBaseUrl: 'https://test.example/app/',
      planPath,
      planSha256,
      fetchImpl: async () => new Response('', { status: 302, headers: { location: 'https://evil.example/' } }),
    });
    await expect(broker.probe({ scenarioId: 'SC-1' }))
      .rejects.toThrow(/범위 밖/);
    await expect(broker.probe({ scenarioId: 'SC-2' }))
      .rejects.toThrow(/범위 밖/);
    await expect(broker.probe({ scenarioId: 'SC-3' }))
      .rejects.toThrow(/범위 밖|자동 추적/);

    const successful = createLiveTestBroker({
      engagementDir,
      allowedBaseUrl: 'https://test.example/app/',
      planPath,
      planSha256,
      fetchImpl: async () => new Response('ok', { status: 200, headers: { 'content-type': 'text/plain' } }),
    });
    const receipt = await successful.probe({ scenarioId: 'SC-4' });
    const path = join(engagementDir, 'http-probe-receipts', `${receipt.receiptId}.json`);
    const value = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
    writeFileSync(path, `${JSON.stringify({ ...value, scenarioId: 'SC-X' })}\n`);
    expect(() => verifyLiveTestReceipt({ engagementDir, receiptId: receipt.receiptId, scenarioId: 'SC-4' }))
      .toThrow(/identity|hash/);
  });
});
