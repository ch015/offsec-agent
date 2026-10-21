-- Additive schema boundary for the PostgreSQL RunStateStore.
-- The repository must execute event, lease, artifact, and outbox writes in one transaction.
-- Driver version, migration ownership, and artifact backend remain deployment decisions.

create table if not exists nunchi_runs (
  run_id text primary key,
  contract_id text not null,
  contract_version text not null,
  domain text not null,
  mission text not null,
  status text not null check (status in ('running', 'awaiting-input', 'completed', 'blocked', 'incomplete')),
  max_budget_usd numeric,
  total_cost_usd numeric not null default 0,
  last_seq bigint not null default 0,
  state jsonb not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- A partial publication ends the run as 'incomplete' (run.incomplete). Tables created before
-- that status existed keep an older status check. Replace only such checks, whatever their name,
-- so a migrated table is left untouched. The replacement holds an exclusive lock on nunchi_runs
-- until the migration transaction commits.
do $$
declare
  legacy record;
  replaced boolean := false;
begin
  for legacy in
    select conname from pg_constraint
    where conrelid = 'nunchi_runs'::regclass and contype = 'c'
      and pg_get_constraintdef(oid) like '%status%'
      and pg_get_constraintdef(oid) not like '%incomplete%'
  loop
    execute format('alter table nunchi_runs drop constraint if exists %I', legacy.conname);
    replaced := true;
  end loop;
  if replaced then
    alter table nunchi_runs add constraint nunchi_runs_status_check
      check (status in ('running', 'awaiting-input', 'completed', 'blocked', 'incomplete'));
  end if;
end $$;

create table if not exists nunchi_run_events (
  run_id text not null references nunchi_runs(run_id),
  seq bigint not null,
  event_id text not null,
  fencing_token bigint not null,
  event_type text not null,
  payload jsonb not null,
  created_at timestamptz not null default now(),
  primary key (run_id, seq),
  unique (run_id, event_id)
);

create table if not exists nunchi_run_leases (
  run_id text primary key references nunchi_runs(run_id),
  owner_id text not null,
  token uuid not null,
  fencing_token bigint not null,
  expires_at timestamptz not null,
  updated_at timestamptz not null default now()
);

create table if not exists nunchi_artifact_receipts (
  uri text primary key,
  sha256 char(64) not null,
  bytes bigint not null check (bytes >= 0),
  media_type text not null,
  producer text not null,
  created_at timestamptz not null default now()
);

create table if not exists nunchi_outbox (
  id text primary key,
  idempotency_key text not null unique,
  topic text not null,
  payload_sha256 char(64) not null,
  payload jsonb not null,
  status text not null check (status in ('queued', 'delivering', 'delivered', 'dead-letter')),
  attempts integer not null default 0 check (attempts >= 0),
  claim_token uuid,
  claim_expires_at timestamptz,
  last_error text,
  available_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table nunchi_outbox add column if not exists claim_token uuid;
alter table nunchi_outbox add column if not exists claim_expires_at timestamptz;
create index if not exists nunchi_outbox_claimable_idx
  on nunchi_outbox (status, available_at, claim_expires_at);
