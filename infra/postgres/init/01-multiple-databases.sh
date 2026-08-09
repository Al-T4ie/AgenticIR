#!/bin/bash
# Create the extra databases listed in POSTGRES_MULTIPLE_DATABASES (comma-separated)
# and enable pgvector everywhere. Runs once, on first initialisation of the volume.
set -euo pipefail

create_database() {
  local db="$1"
  echo "  creating database '$db'"
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
	SELECT 'CREATE DATABASE "$db"'
	WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$db')\gexec
	GRANT ALL PRIVILEGES ON DATABASE "$db" TO "$POSTGRES_USER";
EOSQL
}

enable_vector() {
  local db="$1"
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$db" \
    -c 'CREATE EXTENSION IF NOT EXISTS vector;' || true
}

enable_vector "$POSTGRES_DB"

if [ -n "${POSTGRES_MULTIPLE_DATABASES:-}" ]; then
  echo "Creating additional databases: $POSTGRES_MULTIPLE_DATABASES"
  for db in $(echo "$POSTGRES_MULTIPLE_DATABASES" | tr ',' ' '); do
    create_database "$db"
    enable_vector "$db"
  done
fi
