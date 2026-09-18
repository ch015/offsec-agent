#!/usr/bin/env bash
set -euo pipefail

db_dir="${NUNCHI_DB_DATA_DIR:-/private/tmp/secops-nunchi-postgres}"
db_host="${NUNCHI_DB_HOST:-127.0.0.1}"
db_port="${NUNCHI_DB_PORT:-55432}"
db_name="${NUNCHI_DB_NAME:-nunchi_local}"
db_user="${NUNCHI_DB_USER:-$(id -un)}"

for command_name in initdb pg_ctl pg_isready psql createdb; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "$command_name 명령을 찾을 수 없다" >&2
    exit 1
  }
done

mkdir -p "$db_dir"
if [[ ! -f "$db_dir/PG_VERSION" ]]; then
  initdb -D "$db_dir" --auth=trust --username="$db_user" --no-locale >/dev/null
fi

if ! pg_ctl -D "$db_dir" status >/dev/null 2>&1; then
  pg_ctl -D "$db_dir" \
    -o "-h $db_host -p $db_port" \
    -l "$db_dir/server.log" \
    start >/dev/null
fi

until pg_isready -h "$db_host" -p "$db_port" -U "$db_user" -d postgres >/dev/null 2>&1; do
  sleep 1
done

if ! psql "postgresql://${db_user}@${db_host}:${db_port}/postgres" -Atqc \
  "SELECT 1 FROM pg_database WHERE datname = '$db_name'" | grep -qx '1'; then
  createdb -h "$db_host" -p "$db_port" -U "$db_user" "$db_name"
fi

echo "local PostgreSQL ready: ${db_host}:${db_port}/${db_name}"
