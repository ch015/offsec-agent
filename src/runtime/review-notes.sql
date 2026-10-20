BEGIN;

CREATE TABLE IF NOT EXISTS nunchi_review_catalog (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  catalog_id uuid NOT NULL DEFAULT gen_random_uuid()
);
INSERT INTO nunchi_review_catalog(singleton) VALUES(true) ON CONFLICT DO NOTHING;

-- Independent of nunchi_runs: annotations also support existing file-backed runs.
CREATE TABLE IF NOT EXISTS nunchi_review_histories (
  run_id text PRIMARY KEY,
  source_manifest_sha256 text NOT NULL CHECK (source_manifest_sha256 ~ '^[a-f0-9]{64}$'),
  head text NOT NULL DEFAULT 'empty',
  entry_count integer NOT NULL DEFAULT 0 CHECK (entry_count >= 0)
);
CREATE TABLE IF NOT EXISTS nunchi_review_entries (
  run_id text NOT NULL REFERENCES nunchi_review_histories(run_id),
  sequence integer NOT NULL CHECK (sequence > 0),
  note_id text NOT NULL,
  sha256 text NOT NULL CHECK (sha256 ~ '^[a-f0-9]{64}$'),
  body jsonb NOT NULL,
  PRIMARY KEY (run_id, sequence),
  UNIQUE (run_id, note_id)
);

COMMIT;
