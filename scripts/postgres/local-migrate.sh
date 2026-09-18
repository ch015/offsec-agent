#!/usr/bin/env bash
set -euo pipefail

db_host="${NUNCHI_DB_HOST:-127.0.0.1}"
db_port="${NUNCHI_DB_PORT:-55432}"
db_name="${NUNCHI_DB_NAME:-nunchi_local}"
db_user="${NUNCHI_DB_USER:-$(id -un)}"
database_url="${NUNCHI_DATABASE_URL:-postgresql://${db_user}@${db_host}:${db_port}/${db_name}}"

command -v psql >/dev/null 2>&1 || {
  echo "psql 명령을 찾을 수 없다" >&2
  exit 1
}

psql "$database_url" -v ON_ERROR_STOP=1 \
  -f src/runtime/workflow/postgres-run-state.sql >/dev/null
echo "PostgreSQL schema ready"
