-- Additive migration; no extensions or changes to existing mission tables.
BEGIN;
CREATE TABLE IF NOT EXISTS nunchi_knowledge_catalog (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  catalog_id uuid NOT NULL DEFAULT gen_random_uuid(), revision bigint NOT NULL DEFAULT 0
);
INSERT INTO nunchi_knowledge_catalog(singleton) VALUES(true) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS nunchi_knowledge_runs (
  scope_id text PRIMARY KEY, catalog_id uuid NOT NULL, reference_revision bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS nunchi_shared_records (
  scope_id text NOT NULL, view_id text NOT NULL, record_id text NOT NULL,
  body jsonb NOT NULL, search_text text NOT NULL, paths text[] NOT NULL,
  search_vector tsvector GENERATED ALWAYS AS (to_tsvector('simple', search_text)) STORED,
  PRIMARY KEY(scope_id, view_id, record_id)
);
CREATE INDEX IF NOT EXISTS nunchi_shared_search ON nunchi_shared_records USING gin(search_vector);
CREATE INDEX IF NOT EXISTS nunchi_shared_paths ON nunchi_shared_records USING gin(paths);
CREATE TABLE IF NOT EXISTS nunchi_shared_origins (
  scope_id text NOT NULL, view_id text NOT NULL, record_id text NOT NULL,
  digest text NOT NULL, body jsonb NOT NULL,
  PRIMARY KEY(scope_id, view_id, record_id, digest),
  FOREIGN KEY(scope_id, view_id, record_id) REFERENCES nunchi_shared_records
);
CREATE TABLE IF NOT EXISTS nunchi_knowledge_documents (
  scope_id text NOT NULL, kind text NOT NULL CHECK(kind IN ('finding', 'instruction')),
  record_key text NOT NULL, digest text NOT NULL, body text NOT NULL,
  finding_id text, role text, phase text, recorded_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(scope_id, kind, record_key, digest)
);
CREATE INDEX IF NOT EXISTS nunchi_finding_id ON nunchi_knowledge_documents(scope_id, finding_id);
CREATE TABLE IF NOT EXISTS nunchi_advisory_revisions (
  cve_id text NOT NULL, digest text NOT NULL, catalog_revision bigint NOT NULL,
  source_url text NOT NULL, source_modified_at timestamptz NOT NULL,
  state text NOT NULL CHECK(state IN ('PUBLISHED', 'REJECTED')),
  title text NOT NULL, search_text text NOT NULL, normalized jsonb NOT NULL, raw_text text NOT NULL,
  ingested_at timestamptz NOT NULL DEFAULT now(),
  search_vector tsvector GENERATED ALWAYS AS (to_tsvector('simple', search_text)) STORED,
  PRIMARY KEY(cve_id, digest)
);
ALTER TABLE nunchi_advisory_revisions ADD COLUMN IF NOT EXISTS import_origin jsonb NOT NULL DEFAULT '{"method":"local-import"}'::jsonb;
CREATE INDEX IF NOT EXISTS nunchi_advisory_history ON nunchi_advisory_revisions(cve_id, source_modified_at DESC, catalog_revision DESC);
CREATE INDEX IF NOT EXISTS nunchi_advisory_search ON nunchi_advisory_revisions USING gin(search_vector);
COMMIT;
