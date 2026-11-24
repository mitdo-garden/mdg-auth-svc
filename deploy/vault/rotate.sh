#!/usr/bin/env bash
# Rotate Transit JWT key for one environment. Auth-svc hot-reloads within reload_interval.
# Usage:
#   VAULT_ADDR=... VAULT_ROLE_ID=... VAULT_SECRET_ID=... ./rotate.sh
#   VAULT_ADDR=... VAULT_TOKEN=... ./rotate.sh
set -euo pipefail

: "${VAULT_ADDR:?VAULT_ADDR is required}"
TRANSIT_KEY="${VAULT_TRANSIT_KEY:-jwt-access}"

if [[ -n "${VAULT_TOKEN:-}" ]]; then
  export VAULT_TOKEN
elif [[ -n "${VAULT_ROLE_ID:-}" && -n "${VAULT_SECRET_ID:-}" ]]; then
  VAULT_TOKEN="$(vault write -field=token auth/approle/login \
    role_id="$VAULT_ROLE_ID" secret_id="$VAULT_SECRET_ID")"
  export VAULT_TOKEN
else
  echo "set VAULT_TOKEN or VAULT_ROLE_ID+VAULT_SECRET_ID" >&2
  exit 1
fi

echo "rotating transit key ${TRANSIT_KEY} at ${VAULT_ADDR}"
vault write -f "transit/keys/${TRANSIT_KEY}/rotate"
vault read -format=json "transit/keys/${TRANSIT_KEY}" | \
  python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; print("latest_version=", d.get("latest_version"))'
echo "done — auth-svc will pick up vN within vault.reload_interval_seconds"
