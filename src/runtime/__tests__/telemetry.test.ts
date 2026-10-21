import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { FileRunStateStore } from '../workflow/state-store.js';
import { FileTelemetrySink, InMemoryTelemetrySink, recordRunTelemetry } from '../workflow/telemetry.js';

describe('recordRunTelemetry', () => {
  it('reports an incomplete run status', async () => {
    const root = await mkdtemp(join(tmpdir(), 'nunchi-telemetry-incomplete-'));
    try {
      const store = FileRunStateStore.create({
        engagementDir: root, runId: 'run-incomplete', contractId: 'nunchi.test', contractVersion: '1.0.0', domain: 'soc', mission: 'report',
      });
      const snapshot = store.append({ type: 'run.incomplete', eventId: 'run-incomplete:incomplete', reason: 'coverage remains incomplete' });
      const sink = new InMemoryTelemetrySink();
      expect((await recordRunTelemetry(sink, snapshot, { kind: 'resume' })).status).toBe('incomplete');
      expect(sink.list()).toHaveLength(1);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe('FileTelemetrySink', () => {
  it('persists validated JSONL telemetry for operator inspection', async () => {
    const root = await mkdtemp(join(tmpdir(), 'nunchi-telemetry-'));
    const sink = new FileTelemetrySink(join(root, 'run-telemetry.jsonl'));
    try {
      await sink.append({
        eventId: 'run-1:telemetry:inspect:1',
        at: '2026-08-05T00:00:00.000Z',
        kind: 'run.snapshot',
        runId: 'run-1',
        contractId: 'nunchi.test',
        contractVersion: '1.0.0',
        domain: 'feedback',
        mission: 'design-review',
        status: 'running',
        lastSeq: 1,
        totalCostUsd: 0,
        completedPhaseCount: 0,
        attemptCount: 0,
        artifactCount: 0,
      });
      expect(await sink.list()).toHaveLength(1);
      await expect(sink.append({ runId: 'invalid' } as never)).rejects.toThrow();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
