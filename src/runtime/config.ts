import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { z } from 'zod';

const EnvName = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/);
export const DatabaseConfigSchema = z.object({
  connectionStringEnv: EnvName.optional(),
  host: z.string().min(1).optional(), port: z.number().int().min(1).max(65535).default(5432),
  database: z.string().min(1).optional(), user: z.string().min(1).optional(), passwordEnv: EnvName.optional(),
  poolMax: z.number().int().min(1).max(100).default(10),
  connectionTimeoutMs: z.number().int().min(100).max(120000).default(10000),
  statementTimeoutMs: z.number().int().min(100).max(300000).default(30000),
  ssl: z.union([z.literal(false), z.object({ caFile: z.string().min(1).optional() }).strict()]).default(false),
}).strict();
const ConfigSchema = z.object({
  version: z.literal(1), database: DatabaseConfigSchema.optional(),
  knowledge: z.object({ backend: z.enum(['file', 'postgres']).default('file') }).strict().default({ backend: 'file' }),
  results: z.object({ backend: z.enum(['file', 'postgres']).default('file') }).strict().default({ backend: 'file' }),
  runtime: z.object({ backend: z.enum(['file', 'postgres']).default('file'),
    sharedEngagementRoot: z.string().min(1).optional(), artifactRoot: z.string().min(1).optional(),
  }).strict().default({ backend: 'file' }),
}).strict();
export type DatabaseConfig = z.input<typeof DatabaseConfigSchema>;
export type AppConfig = z.infer<typeof ConfigSchema>;

/** Host configuration only. Never include this object in a checkpoint or model prompt.
 * Only an explicit path or NUNCHI_CONFIG selects a file: a nunchi.config.json in the working
 * directory is not read implicitly, so a stray local file cannot redirect storage or migrations. */
export function loadConfig(path?: string, env: NodeJS.ProcessEnv = process.env, cwd = process.cwd()): AppConfig {
  const requested = path ?? env.NUNCHI_CONFIG;
  if (!requested) return ConfigSchema.parse({ version: 1 });
  const file = resolve(cwd, requested);
  let raw: unknown;
  try { raw = JSON.parse(readFileSync(file, 'utf8')); }
  catch { throw new Error('Nunchi config를 읽을 수 없다. 경로와 JSON 형식을 확인한다.'); }
  const parsed = ConfigSchema.safeParse(raw);
  if (!parsed.success) throw new Error(`Nunchi config 필드가 잘못됐다: ${parsed.error.issues.map(issue => issue.path.join('.')).join(', ')}`);
  const config = parsed.data;
  if (config.database?.ssl && config.database.ssl.caFile) config.database.ssl.caFile = resolve(dirname(file), config.database.ssl.caFile);
  if (config.runtime.sharedEngagementRoot) config.runtime.sharedEngagementRoot = resolve(dirname(file), config.runtime.sharedEngagementRoot);
  if (config.runtime.artifactRoot) config.runtime.artifactRoot = resolve(dirname(file), config.runtime.artifactRoot);
  return config;
}
