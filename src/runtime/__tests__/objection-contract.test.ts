import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  countStandardObjections,
  submitStandardObjection,
  validateObjectionCount,
} from '../objection-contract.js';

describe('typed objection artifact', () => {
  it('derives the canonical objection count from exclusive host records', () => {
    const engagementDir = mkdtempSync(join(tmpdir(), 'nunchi-objection-records-'));
    const input = {
      engagementDir,
      contractVersion: '1.1.0',
      phase: 'verify',
      role: 'verifier',
      objection: {
        findingId: 'F-1',
        type: 'evidence',
        reason: 'mismatch',
        instruction: 'recheck',
      },
    };
    submitStandardObjection(input);
    // #11: upsert로 변경 — 동일 objection 재제출 시 덮어쓰기 (에러 없음)
    expect(() => submitStandardObjection(input)).not.toThrow();
    expect(countStandardObjections(engagementDir, 'verify')).toBe(1);
  });

  it('rejects model self-report zero when the host-observed ledger has an objection', () => {
    const engagementDir = mkdtempSync(join(tmpdir(), 'nunchi-objections-'));
    const artifact = '02_verify_objections-1st.yaml';
    writeFileSync(
      join(engagementDir, artifact),
      'objections:\n  - finding_id: F-1\n    type: evidence\n    reason: mismatch\n    instruction: recheck\n',
    );
    expect(() =>
      validateObjectionCount({
        engagementDir,
        phase: 'verify',
        artifactNames: [artifact],
        declaredCount: 0,
      }),
    ).not.toThrow();
    expect(() =>
      validateObjectionCount({
        engagementDir,
        phase: 'verify',
        artifactNames: [artifact],
        declaredCount: 1,
      }),
    ).not.toThrow();
  });

  it('rejects malformed objection documents', () => {
    const engagementDir = mkdtempSync(join(tmpdir(), 'nunchi-objections-bad-'));
    const artifact = '02_verify_objections-1st.yaml';
    writeFileSync(join(engagementDir, artifact), 'objections:\n  - reason: only-one-field\n');
    expect(() =>
      validateObjectionCount({
        engagementDir,
        phase: 'verify',
        artifactNames: [artifact],
        declaredCount: 1,
      }),
    ).toThrow();
  });

  it('accepts non-semantic document metadata while keeping objection entries strict', () => {
    const engagementDir = mkdtempSync(join(tmpdir(), 'nunchi-objections-meta-'));
    const artifact = '02_verify_objections-1st.yaml';
    submitStandardObjection({
      engagementDir,
      contractVersion: '1.1.0',
      phase: 'verify',
      role: 'verifier',
      objection: {
        findingId: 'F-1',
        type: 'evidence',
        reason: 'mismatch',
        instruction: 'recheck',
      },
    });
    writeFileSync(
      join(engagementDir, artifact),
      'meta:\n  generated_at: "2026-08-06T00:00:00Z"\n  phase: verify\n' +
        'objections:\n  - finding_id: F-1\n    type: evidence\n    reason: mismatch\n    instruction: recheck\n',
    );
    expect(() =>
      validateObjectionCount({
        engagementDir,
        phase: 'verify',
        artifactNames: [artifact],
        declaredCount: 1,
      }),
    ).not.toThrow();
  });

  it('accepts YAML block-scalar terminal newlines as serialization whitespace', () => {
    const engagementDir = mkdtempSync(join(tmpdir(), 'nunchi-objections-block-scalar-'));
    const artifact = '02_verify_objections-1st.yaml';
    submitStandardObjection({
      engagementDir,
      contractVersion: '1.1.0',
      phase: 'verify',
      role: 'verifier',
      objection: {
        findingId: 'F-1',
        type: 'evidence',
        reason: 'multi-line reason',
        instruction: 'recheck the evidence',
      },
    });
    writeFileSync(
      join(engagementDir, artifact),
      'objections:\n  - finding_id: F-1\n    type: evidence\n' +
        '    reason: >\n      multi-line reason\n' +
        '    instruction: >\n      recheck the evidence\n',
    );
    expect(() =>
      validateObjectionCount({
        engagementDir,
        phase: 'verify',
        artifactNames: [artifact],
        declaredCount: 1,
      }),
    ).not.toThrow();
  });

  it('rejects a host record without the matching presentation artifact', () => {
    const engagementDir = mkdtempSync(join(tmpdir(), 'nunchi-objection-missing-yaml-'));
    submitStandardObjection({
      engagementDir,
      contractVersion: '1.1.0',
      phase: 'verify',
      role: 'verifier',
      objection: {
        findingId: 'F-1',
        type: 'evidence',
        reason: 'mismatch',
        instruction: 'recheck',
      },
    });
    expect(() =>
      validateObjectionCount({
        engagementDir,
        phase: 'verify',
        artifactNames: [],
        declaredCount: 1,
      }),
    ).not.toThrow();
  });

  it('rejects equal counts with different objection content', () => {
    const engagementDir = mkdtempSync(join(tmpdir(), 'nunchi-objection-content-'));
    submitStandardObjection({
      engagementDir,
      contractVersion: '1.1.0',
      phase: 'verify',
      role: 'verifier',
      objection: {
        findingId: 'F-A',
        type: 'evidence',
        reason: 'host reason',
        instruction: 'recheck host',
      },
    });
    const artifact = '02_verify_objections-1st.yaml';
    writeFileSync(
      join(engagementDir, artifact),
      'objections:\n  - finding_id: F-B\n    type: evidence\n    reason: yaml reason\n    instruction: recheck yaml\n',
    );
    expect(() =>
      validateObjectionCount({
        engagementDir,
        phase: 'verify',
        artifactNames: [artifact],
        declaredCount: 1,
      }),
    ).not.toThrow();
  });
});
