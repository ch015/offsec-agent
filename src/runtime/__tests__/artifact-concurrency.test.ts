import { mkdtemp, open, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { FileSystemArtifactStore, InMemoryArtifactStore } from '../workflow/artifact-store.js';
import { ResilientArtifactStore } from '../workflow/resilient-artifacts.js';

vi.mock('node:fs/promises', async importOriginal => {
  const actual = await importOriginal<typeof import('node:fs/promises')>();
  return { ...actual, open: vi.fn(actual.open) };
});

describe('concurrent immutable artifact writes', () => {
  it.each(['put', 'flush'])('acknowledges concurrent duplicate replication %s calls without marking storage unavailable', async operation => {
    const root = await mkdtemp(join(tmpdir(), 'replication-concurrency-'));
    const remote = new InMemoryArtifactStore(), both = Promise.withResolvers<void>();
    let calls = 0;
    const store = new ResilientArtifactStore(root, { get: remote.get.bind(remote), put: async input => {
      if (++calls === 2) both.resolve();
      await both.promise;
      return remote.put(input);
    } });
    const input = { uri: 'artifact://run-1/shared', content: Buffer.from('complete artifact'), mediaType: 'text/plain', producer: 'host/run-1' };
    try {
      if (operation === 'flush') {
        const offline = new ResilientArtifactStore(root, { get: remote.get.bind(remote), put: async () => { throw new Error('offline fixture'); } });
        await offline.put(input);
        await Promise.all([store.flush(), store.flush()]);
      } else await Promise.all([store.put(input), store.put(input)]);
      expect(store.health()).toEqual({ pendingReplication: 0, errors: [] });
      await store.put({ ...input, uri: 'artifact://run-1/next' });
      expect(calls).toBe(3);
      expect(Buffer.from(await remote.get('artifact://run-1/next'))).toEqual(input.content);
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it.each(['same', 'content', 'producer'])('publishes complete bytes atomically while preserving %s collision semantics', async variant => {
    const root = await mkdtemp(join(tmpdir(), 'artifact-concurrency-'));
    const actual = await vi.importActual<typeof import('node:fs/promises')>('node:fs/promises');
    const started = Promise.withResolvers<void>(), resume = Promise.withResolvers<void>();
    const input = { uri: 'artifact://run-1/shared', content: Buffer.from('complete artifact'), mediaType: 'text/plain', producer: 'host/run-1' };
    const secondInput = { ...input, ...(variant === 'content' ? { content: Buffer.from('different artifact') } : {}),
      ...(variant === 'producer' ? { producer: 'other-producer' } : {}) };
    vi.mocked(open).mockImplementationOnce(async (...args) => {
      const handle = await actual.open(...args);
      const write = handle.writeFile.bind(handle);
      vi.spyOn(handle, 'writeFile').mockImplementationOnce(async () => {
        await write(input.content.subarray(0, 4));
        started.resolve();
        await resume.promise;
        await write(input.content.subarray(4));
      });
      return handle;
    });
    const first = new FileSystemArtifactStore(root).put(input);
    // Attach a handler immediately so failures are always consumed.
    const firstResult = Promise.allSettled([first]);
    try {
      await started.promise;
      const secondResult = await Promise.allSettled([new FileSystemArtifactStore(root).put(secondInput)]);
      resume.resolve();
      const outcomes = [...await firstResult, ...secondResult];
      expect(outcomes.map(result => result.status)).toEqual([variant === 'same' ? 'fulfilled' : 'rejected', 'fulfilled']);
      if (outcomes[0]?.status === 'rejected') expect(String(outcomes[0].reason)).toContain('collision');
      expect(Buffer.from(await new FileSystemArtifactStore(root).get(input.uri))).toEqual(secondInput.content);
    } finally {
      resume.resolve();
      await firstResult;
      vi.restoreAllMocks();
      await rm(root, { recursive: true, force: true });
    }
  });
});
