import { readFile, readdir, stat } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { pathToFileURL } from 'node:url';
import { loadConfig } from '../src/runtime/config.js';
import { createPostgresPool } from '../src/runtime/workflow/database.js';
import { PostgresKnowledgeStore } from '../src/runtime/knowledge/postgres-knowledge.js';

async function* cveFiles(path: string): AsyncGenerator<string> {
  const entry = await stat(path);
  if (entry.isFile()) { yield path; return; }
  for (const file of await readdir(path, { withFileTypes: true })) {
    if (file.isDirectory() && !file.name.startsWith('.')) yield* cveFiles(join(path, file.name));
    else if (file.isFile() && /^CVE-\d{4}-\d{4,}\.json$/.test(file.name)) yield join(path, file.name);
  }
}

async function main() {
  const { values, positionals } = parseArgs({ allowPositionals: true, options: {
    config: { type: 'string' }, id: { type: 'string' }, query: { type: 'string' },
    digest: { type: 'string' }, offset: { type: 'string' }, limit: { type: 'string' },
    'source-revision': { type: 'string' },
  } });
  const [command, input] = positionals;
  if (!['migrate', 'import', 'query', 'get'].includes(command ?? '') || (command === 'import' && !input) ||
      (command === 'get' && (!values.id || !values.digest))) {
    throw new Error('Usage: pnpm db:migrate [--config path] | pnpm knowledge:import <CVE JSON file/directory> [--config path] | pnpm knowledge:query [--id CVE-...] [--query text] [--offset 0] [--limit 5] [--config path] | pnpm knowledge:get --id CVE-... --digest sha256 [--config path]');
  }
  const config = loadConfig(values.config);
  const pool = createPostgresPool(process.env, config.database);
  pool.on('error', () => undefined);
  try {
    if (command === 'migrate') {
      try {
        for (const path of ['../src/runtime/workflow/postgres-run-state.sql', '../src/runtime/knowledge/schema.sql', '../src/runtime/review-notes.sql']) {
          await pool.query(await readFile(new URL(path, import.meta.url), 'utf8'));
        }
      } catch { throw new Error('PostgreSQL migration failed; check database config and schema privileges.'); }
      console.log('PostgreSQL mission, knowledge and result schemas ready');
      return;
    }
    const store = new PostgresKnowledgeStore(pool);
    if (command === 'import') {
      let inserted = 0, unchanged = 0;
      for await (const path of cveFiles(resolve(input!))) {
        if ((await stat(path)).size > 4 * 1024 * 1024) throw new Error('CVE record exceeds 4 MiB');
        const bytes = await readFile(path), raw = bytes.toString('utf8');
        if (!Buffer.from(raw, 'utf8').equals(bytes)) throw new Error('CVE input must be valid UTF-8; original bytes were not imported.');
        const receipt = await store.importCve(raw, { uri: pathToFileURL(path).href, revision: values['source-revision'] });
        if (receipt.inserted) inserted++; else unchanged++;
      }
      if (!inserted && !unchanged) throw new Error('No CVE JSON records found');
      console.log(JSON.stringify({ inserted, unchanged, snapshot: await store.currentPin() }));
    } else if (command === 'query') {
      console.log(JSON.stringify(await store.lookupAdvisories(await store.currentPin(), { id: values.id, query: values.query,
        offset: values.offset === undefined ? undefined : Number(values.offset), limit: values.limit === undefined ? undefined : Number(values.limit) }), null, 2));
    } else {
      // Exact raw bytes, including every original container and unknown field.
      process.stdout.write((await store.getAdvisory(await store.currentPin(), values.id!, values.digest!)).raw_text);
    }
  } finally { await pool.end(); }
}

main().catch(error => { console.error(error instanceof Error ? error.message : 'Knowledge command failed'); process.exitCode = 1; });
