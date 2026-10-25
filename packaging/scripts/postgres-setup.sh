#!/usr/bin/env bash
# Clavis PostgreSQL setup (executed by clavis-postgres-setup.service as the
# postgres user, or run manually as root):
#
#   1. waits for the local PostgreSQL server,
#   2. creates the clavis login role,
#   3. creates the clavis database (owner clavis),
#   4. applies the shared Clavis schema.
#
# Settings can be overridden in /etc/clavis/postgres.env.
set -euo pipefail

if [ -f /etc/clavis/postgres.env ]; then
  # shellcheck disable=SC1091
  . /etc/clavis/postgres.env
fi

DB_USER="${CLAVIS_DB_USER:-clavis}"
DB_PASS="${CLAVIS_DB_PASS:-clavis}"
DB_NAME="${CLAVIS_DB_NAME:-clavis}"
PG_HOST="${CLAVIS_PG_HOST:-/var/run/postgresql}"
SCHEMA="${CLAVIS_SCHEMA:-/usr/share/clavis/postgres/schema.sql}"

if [ ! -f "$SCHEMA" ]; then
  echo "clavis-postgres: schema file not found: $SCHEMA" >&2
  exit 1
fi

# Wait for the local server (the unit is ordered after postgresql.service,
# but the socket may take a moment).
for _ in $(seq 1 30); do
  if pg_isready -h "$PG_HOST" -U postgres >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

# 1. role
psql -v ON_ERROR_STOP=1 -h "$PG_HOST" -U postgres -d postgres <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${DB_USER}') THEN
    CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASS}';
  END IF;
END
\$\$;
SQL

# 2. database
EXISTS_DB=$(psql -h "$PG_HOST" -U postgres -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname = '${DB_NAME}'")
if [ "$EXISTS_DB" != "1" ]; then
  createdb -h "$PG_HOST" -U postgres -O "$DB_USER" "$DB_NAME"
fi

# 3. schema
PGPASSWORD="$DB_PASS" psql -v ON_ERROR_STOP=1 -h "$PG_HOST" -U "$DB_USER" -d "$DB_NAME" -f "$SCHEMA"

echo "clavis-postgres: schema applied to database '$DB_NAME' (user '$DB_USER')"
