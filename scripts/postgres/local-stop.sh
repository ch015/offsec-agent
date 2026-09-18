#!/usr/bin/env bash
set -euo pipefail

db_dir="${NUNCHI_DB_DATA_DIR:-/private/tmp/secops-nunchi-postgres}"
command -v pg_ctl >/dev/null 2>&1 || {
  echo "pg_ctl 명령을 찾을 수 없다" >&2
  exit 1
}

if [[ -f "$db_dir/PG_VERSION" ]] && pg_ctl -D "$db_dir" status >/dev/null 2>&1; then
  pg_ctl -D "$db_dir" -m fast stop >/dev/null
  echo "local PostgreSQL stopped"
else
  echo "local PostgreSQL is not running"
fi
