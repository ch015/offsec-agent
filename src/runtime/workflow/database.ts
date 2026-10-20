import type { Pool } from 'pg';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { DatabaseConfigSchema, type DatabaseConfig } from '../config.js';

import type { SqlPool } from './run-lease.js';

export type DatabaseEnvironment = Record<string, string | undefined>;

export function databaseUrlFromEnv(env: DatabaseEnvironment = process.env): string {
  const value = env.NUNCHI_DATABASE_URL ?? env.DATABASE_URL;
  if (!value) {
    throw new Error('NUNCHI_DATABASE_URL 또는 DATABASE_URL이 필요하다');
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('PostgreSQL database URL 형식이 잘못됐다');
  }
  if (url.protocol !== 'postgres:' && url.protocol !== 'postgresql:') {
    throw new Error('PostgreSQL database URL이 아니다');
  }
  return value;
}

export function postgresPoolOptions(env: DatabaseEnvironment = process.env, config: DatabaseConfig = {}): import('pg').PoolConfig {
  const parsed = DatabaseConfigSchema.safeParse(config);
  if (!parsed.success) throw new Error('PostgreSQL config 필드가 잘못됐다');
  const settings = parsed.data;
  const configuredMax = env.NUNCHI_DB_POOL_MAX === undefined ? settings.poolMax : Number(env.NUNCHI_DB_POOL_MAX);
  if (!Number.isInteger(configuredMax) || configuredMax < 1 || configuredMax > 100) {
    throw new Error('NUNCHI_DB_POOL_MAX가 잘못됐다');
  }
  const url = env.NUNCHI_DATABASE_URL ?? env.DATABASE_URL ?? (settings.connectionStringEnv ? env[settings.connectionStringEnv] : undefined);
  if (!url && settings.connectionStringEnv) throw new Error('설정한 PostgreSQL 연결 환경변수가 없다');
  if (!url && (!settings.host || !settings.database || !settings.user)) throw new Error('PostgreSQL 연결 URL 또는 config의 host/database/user가 필요하다');
  if (!url && settings.passwordEnv && env[settings.passwordEnv] === undefined) throw new Error('설정한 PostgreSQL 비밀번호 환경변수가 없다');
  let ssl: import('pg').PoolConfig['ssl'] = false;
  if (settings.ssl) {
    try { ssl = { rejectUnauthorized: true, ...(settings.ssl.caFile ? { ca: readFileSync(settings.ssl.caFile, 'utf8') } : {}) }; }
    catch { throw new Error('PostgreSQL TLS CA 파일을 읽을 수 없다'); }
  }
  return {
    ...(url ? { connectionString: databaseUrlFromEnv({ NUNCHI_DATABASE_URL: url }) } : {
      host: settings.host, port: settings.port, database: settings.database, user: settings.user,
      password: settings.passwordEnv ? env[settings.passwordEnv] : undefined,
    }),
    max: configuredMax,
    application_name: env.NUNCHI_DB_APPLICATION_NAME ?? 'secops-offsec-agent',
    connectionTimeoutMillis: settings.connectionTimeoutMs, statement_timeout: settings.statementTimeoutMs,
    ssl,
  };
}

export function createPostgresPool(env: DatabaseEnvironment = process.env, config?: DatabaseConfig): Pool & SqlPool {
  const { Pool: PostgresPool } = createRequire(import.meta.url)('pg') as typeof import('pg');
  return new PostgresPool(postgresPoolOptions(env, config));
}
