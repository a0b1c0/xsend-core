#!/usr/bin/env bash
set -euo pipefail

DB_NAME="${1:-xadmin-db-v2}"
TARGET="${2:-remote}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

WRANGLER_ARGS=()
if [[ "${TARGET}" == "remote" ]]; then
  WRANGLER_ARGS+=(--remote)
fi

echo "Applying xsend migrations to D1 database: ${DB_NAME} (${TARGET})"

echo " -> migrations/0001_xsend_relay_schema.sql"
npx wrangler d1 execute "${DB_NAME}" "${WRANGLER_ARGS[@]}" --file "./migrations/0001_xsend_relay_schema.sql"

echo " -> migrations/0002_clients_client_type_backfill.sql (optional)"
if ! npx wrangler d1 execute "${DB_NAME}" "${WRANGLER_ARGS[@]}" --file "./migrations/0002_clients_client_type_backfill.sql"; then
  echo "    skipped: clients.client_type already exists (or migration previously applied)."
fi

echo " -> migrations/0003_xsend_billing_schema.sql"
npx wrangler d1 execute "${DB_NAME}" "${WRANGLER_ARGS[@]}" --file "./migrations/0003_xsend_billing_schema.sql"

echo " -> migrations/0004_xsend_billing_enhanced.sql"
npx wrangler d1 execute "${DB_NAME}" "${WRANGLER_ARGS[@]}" --file "./migrations/0004_xsend_billing_enhanced.sql"

echo "Done."
