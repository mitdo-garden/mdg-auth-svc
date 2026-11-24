#!/usr/bin/env bash
# Idempotent local Transit + KV secrets + AppRole bootstrap (no Terraform required).
# Invoked by `make vault` / `make run-*`.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
CREDS_FILE="${ROOT}/.dev-creds"
SECRETS_FILE="${ROOT}/.app-secrets.env"
SECRETS_EXAMPLE="${ROOT}/.app-secrets.env.example"
VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-root}"
KEY="${VAULT_TRANSIT_KEY:-jwt-access}"
CONTAINER="${VAULT_CONTAINER:-mdg-vault}"
KV_MOUNT="${VAULT_KV_MOUNT:-secret}"

# -i so policy HCL on stdin reaches vault inside the container.
vault_cmd() {
  if command -v vault >/dev/null 2>&1; then
    VAULT_ADDR="$VAULT_ADDR" VAULT_TOKEN="$VAULT_TOKEN" vault "$@"
  else
    docker exec -i \
      -e VAULT_ADDR=http://127.0.0.1:8200 \
      -e VAULT_TOKEN="$VAULT_TOKEN" \
      "$CONTAINER" vault "$@"
  fi
}

write_policy() {
  local name="$1"
  local body="$2"
  printf '%s\n' "$body" | vault_cmd policy write "$name" -
}

echo "bootstrapping Vault at ${VAULT_ADDR} (transit=${KEY}, kv=${KV_MOUNT}/mdg-auth/*)"

if ! vault_cmd secrets list -format=json 2>/dev/null | grep -q '"transit/"'; then
  vault_cmd secrets enable transit >/dev/null
fi

if ! vault_cmd read "transit/keys/${KEY}" >/dev/null 2>&1; then
  vault_cmd write -f "transit/keys/${KEY}" type=ecdsa-p256 >/dev/null
else
  KEY_TYPE="$(vault_cmd read -field=type "transit/keys/${KEY}" 2>/dev/null || true)"
  if [[ -n "$KEY_TYPE" && "$KEY_TYPE" != "ecdsa-p256" ]]; then
    echo "transit key ${KEY} has type ${KEY_TYPE}; recreate as ecdsa-p256 for ES256" >&2
    echo "  vault delete transit/keys/${KEY} && re-run bootstrap" >&2
    exit 1
  fi
fi

if ! vault_cmd secrets list -format=json 2>/dev/null | grep -q "\"${KV_MOUNT}/\""; then
  vault_cmd secrets enable -path="${KV_MOUNT}" kv-v2 >/dev/null
fi

write_policy mdg-auth-jwt "path \"transit/sign/${KEY}\" {
  capabilities = [\"update\"]
}
path \"transit/sign/${KEY}/*\" {
  capabilities = [\"update\"]
}
path \"transit/keys/${KEY}\" {
  capabilities = [\"read\"]
}
path \"${KV_MOUNT}/data/mdg-auth/*\" {
  capabilities = [\"read\"]
}
path \"${KV_MOUNT}/metadata/mdg-auth/*\" {
  capabilities = [\"read\"]
}"

write_policy mdg-auth-jwt-rotator "path \"transit/keys/${KEY}/rotate\" {
  capabilities = [\"update\"]
}
path \"transit/keys/${KEY}\" {
  capabilities = [\"read\"]
}"

vault_cmd auth enable approle >/dev/null 2>&1 || true

vault_cmd write auth/approle/role/mdg-auth-svc \
  token_policies=mdg-auth-jwt \
  token_ttl=1h \
  token_max_ttl=4h >/dev/null

vault_cmd write auth/approle/role/mdg-auth-jwt-rotator \
  token_policies=mdg-auth-jwt-rotator \
  token_ttl=15m \
  token_max_ttl=30m >/dev/null

# Seed app secrets (OAuth + session). Prefer .app-secrets.env; fall back to env / test defaults.
if [[ ! -f "$SECRETS_FILE" && -f "$SECRETS_EXAMPLE" ]]; then
  echo "missing ${SECRETS_FILE} — copy from ${SECRETS_EXAMPLE} and fill real values" >&2
fi

load_secret() {
  local key="$1" default="${2:-}"
  local val=""
  if [[ -f "$SECRETS_FILE" ]]; then
    val="$(grep -E "^${key}=" "$SECRETS_FILE" 2>/dev/null | tail -n1 | cut -d= -f2- || true)"
  fi
  if [[ -z "$val" ]]; then
    val="${!key-}"
  fi
  if [[ -z "$val" ]]; then
    val="$default"
  fi
  printf '%s' "$val"
}

seed_kv() {
  local env_name="$1"
  shift
  vault_cmd kv put "${KV_MOUNT}/mdg-auth/${env_name}" "$@" >/dev/null
  echo "seeded ${KV_MOUNT}/mdg-auth/${env_name}"
}

GOOGLE_CLIENT_ID="$(load_secret GOOGLE_CLIENT_ID)"
GOOGLE_CLIENT_SECRET="$(load_secret GOOGLE_CLIENT_SECRET)"
GITHUB_CLIENT_ID="$(load_secret GITHUB_CLIENT_ID)"
GITHUB_CLIENT_SECRET="$(load_secret GITHUB_CLIENT_SECRET)"
SESSION_SECRET="$(load_secret SESSION_SECRET)"

if [[ -n "$GOOGLE_CLIENT_ID" && -n "$GOOGLE_CLIENT_SECRET" && -n "$SESSION_SECRET" ]]; then
  seed_kv dev \
    google_client_id="$GOOGLE_CLIENT_ID" \
    google_client_secret="$GOOGLE_CLIENT_SECRET" \
    github_client_id="$GITHUB_CLIENT_ID" \
    github_client_secret="$GITHUB_CLIENT_SECRET" \
    session_secret="$SESSION_SECRET"
else
  echo "skip dev KV seed (set deploy/vault/.app-secrets.env)" >&2
fi

# Test path always gets disposable placeholders (overridable via .app-secrets.env TEST_*).
seed_kv test \
  google_client_id="$(load_secret TEST_GOOGLE_CLIENT_ID 'test-google-client-id.apps.googleusercontent.com')" \
  google_client_secret="$(load_secret TEST_GOOGLE_CLIENT_SECRET 'test-google-client-secret')" \
  github_client_id="$(load_secret TEST_GITHUB_CLIENT_ID 'test-github-client-id')" \
  github_client_secret="$(load_secret TEST_GITHUB_CLIENT_SECRET 'test-github-client-secret')" \
  session_secret="$(load_secret TEST_SESSION_SECRET 'test-session-secret-32bytes-minimum!!')"

ROLE_ID="$(vault_cmd read -field=role_id auth/approle/role/mdg-auth-svc/role-id)"
SECRET_ID="$(vault_cmd write -f -field=secret_id auth/approle/role/mdg-auth-svc/secret-id)"

umask 077
cat >"$CREDS_FILE" <<EOF
VAULT_ROLE_ID=${ROLE_ID}
VAULT_SECRET_ID=${SECRET_ID}
EOF
echo "wrote ${CREDS_FILE}"
