import { cveFixture } from './fixtures/cve.js';
import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadConfig } from '../config.js';
import { postgresPoolOptions } from '../workflow/database.js';
import { parseAssessV2Args } from '../missions/analysis-selection.js';
import { parseCve } from '../knowledge/cve.js';

const roots: string[] = [];
afterEach(() => { for (const path of roots.splice(0)) rmSync(path, { recursive: true, force: true }); });
describe('host database configuration', () => {
  it('resolves config discovery, explicit paths and relative TLS/storage paths', () => {
    const root = mkdtempSync(join(tmpdir(), 'db-config-')); roots.push(root);
    expect(loadConfig(undefined, {}, root).knowledge.backend).toBe('file');
    expect(loadConfig(undefined, {}, root).results.backend).toBe('file');
    const value = { version: 1, database: { host: 'localhost', database: 'knowledge', user: 'test', ssl: { caFile: 'ca.pem' } },
      knowledge: { backend: 'postgres' }, results: { backend: 'postgres' }, runtime: { backend: 'postgres', artifactRoot: 'artifacts', sharedEngagementRoot: 'runs' } };
    writeFileSync(join(root, 'nunchi.config.json'), JSON.stringify(value));
    const config = loadConfig(undefined, {}, root);
    expect(config.database!.ssl).toEqual({ caFile: join(root, 'ca.pem') });
    expect(config.runtime.artifactRoot).toBe(join(root, 'artifacts'));
    expect(config.results.backend).toBe('postgres');
    writeFileSync(join(root, 'alternate.json'), JSON.stringify({ version: 1 }));
    expect(loadConfig(undefined, { NUNCHI_CONFIG: 'alternate.json' }, root).knowledge.backend).toBe('file');
    expect(loadConfig('nunchi.config.json', { NUNCHI_CONFIG: 'alternate.json' }, root).knowledge.backend).toBe('postgres');
    expect(parseAssessV2Args(['/repo', '--config', 'alternate.json']).flags.get('config')).toBe('alternate.json');
    expect(() => loadConfig('missing.json', {}, root)).toThrow(/config/);
  });
  it('uses connection environment overrides and password references without mutating or disclosing config', () => {
    const config = { host: 'localhost', database: 'local', user: 'tester', passwordEnv: 'KB_PASSWORD', poolMax: 7 };
    const value = postgresPoolOptions({ KB_PASSWORD: 'never-print-me' }, config);
    expect(value).toMatchObject({ host: 'localhost', port: 5432, database: 'local', user: 'tester', password: 'never-print-me', max: 7 });
    expect(JSON.stringify(config)).not.toContain('never-print-me');
    expect(postgresPoolOptions({ NUNCHI_DATABASE_URL: 'postgres://host/override', NUNCHI_DB_POOL_MAX: '3' }, config))
      .toMatchObject({ connectionString: 'postgres://host/override', max: 3 });
    expect(postgresPoolOptions({ CUSTOM_DB: 'postgres://host/configured' }, { connectionStringEnv: 'CUSTOM_DB' }).connectionString).toBe('postgres://host/configured');
    expect(() => postgresPoolOptions({}, config)).toThrow(/비밀번호/);
    expect(() => postgresPoolOptions({}, { connectionStringEnv: 'MISSING' })).toThrow(/환경변수/);
    expect(() => postgresPoolOptions({ DATABASE_URL: 'never-print-me' })).toThrow('PostgreSQL database URL 형식이 잘못됐다');
    expect(() => postgresPoolOptions({ DATABASE_URL: 'postgres://host/db', NUNCHI_DB_POOL_MAX: 'never-print-me' })).toThrow('NUNCHI_DB_POOL_MAX가 잘못됐다');
  });
  it('rejects unknown/invalid config fields without echoing values', () => {
    const root = mkdtempSync(join(tmpdir(), 'db-config-')); roots.push(root);
    for (const database of [{ password: 'never-print-me' }, { port: -1 }, { poolMax: 0 }, { ssl: { rejectUnauthorized: false } }]) {
      writeFileSync(join(root, 'nunchi.config.json'), JSON.stringify({ version: 1, database }));
      expect(() => loadConfig(undefined, {}, root)).toThrow(/config 필드/);
      try { loadConfig(undefined, {}, root); } catch (error) { expect(String(error)).not.toContain('never-print-me'); }
    }
  });
});

describe('CVE reference normalization', () => {
  it('preserves original bytes, unknown containers and applicability uncertainty', () => {
    const raw = cveFixture(), parsed = parseCve(raw);
    expect(parsed.raw).toBe(raw);
    expect(parsed.normalized.containers.adp![0]!.customFutureField).toEqual({ original: true });
    expect(JSON.parse(parsed.raw).futureTopLevel).toEqual({ preserve: true });
    expect(parsed.normalized.applicability).toBe('unknown');
    expect(parsed.sourceUrl).toContain('/2026/123xxx/CVE-2026-123456.json');
    expect(parseCve(raw + '\n').digest).not.toBe(parsed.digest);
    expect(parseCve(cveFixture('2026-10-09T00:00:00Z', 'REJECTED')).state).toBe('REJECTED');
    expect(parseCve(cveFixture('2026-10-08T00:00:00')).modified).toBe('2026-10-08T00:00:00Z');
    expect(parseCve(cveFixture('2026-10-08T09:00:00+09:00')).modified).toBe('2026-10-08T09:00:00+09:00');
  });
  it('rejects malformed input and unsupported records before starting DB writes', () => {
    for (const raw of ['{}', 'not JSON', cveFixture('not a timestamp'), cveFixture('2026-02-31T00:00:00Z'), cveFixture(undefined, 'RESERVED')]) expect(() => parseCve(raw)).toThrow();
  });
});
