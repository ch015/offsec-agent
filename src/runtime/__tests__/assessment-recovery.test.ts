import { describe, expect, it } from 'vitest';
import { KnowledgeIntegrityError, KnowledgeStorageError } from '../knowledge/postgres-knowledge.js';
import { recoverableFailure } from '../missions/assessment-recovery.js';
import { ProviderRuntimeFailure } from '../providers/provider-runtime.js';

describe('recoverableFailure', () => {
  it('retries knowledge connection failures on resume but not pin or digest mismatches', () => {
    expect(recoverableFailure(new KnowledgeStorageError('PostgreSQL knowledge operation failed (08006)'))).toBe(true);
    expect(recoverableFailure(new KnowledgeIntegrityError('Pinned run instructions changed; restore their original revision or start a new run.'))).toBe(false);
    expect(recoverableFailure(new KnowledgeIntegrityError('Knowledge catalog does not match the pinned run'))).toBe(false);
    expect(new KnowledgeIntegrityError('x')).toBeInstanceOf(KnowledgeStorageError);
    const wrapped = new ProviderRuntimeFailure('Anthropic session failed', undefined, { cause: new KnowledgeIntegrityError('Instruction revision integrity mismatch') });
    expect(recoverableFailure(wrapped)).toBe(false);
    expect(recoverableFailure(new ProviderRuntimeFailure('provider overloaded'))).toBe(true);
  });
});
