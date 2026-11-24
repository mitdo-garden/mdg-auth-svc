#!/usr/bin/env bash
# Idempotent LocalStack KMS (ECC_NIST_P256 SIGN_VERIFY) + Secrets Manager bootstrap.
# Invoked by `make aws` / `make run-dev` (default JWT_SIGNER=kms).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
CREDS_FILE="${ROOT}/.dev-creds"
# Reuse the same OAuth seed file as Vault bootstrap when present.
SECRETS_FILE="${SECRETS_FILE:-$ROOT/../vault/.app-secrets.env}"
ENDPOINT="${AWS_ENDPOINT_URL:-http://127.0.0.1:4566}"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
ALIAS="${KMS_ALIAS:-alias/mdg-auth-jwt}"
KID="${KMS_KID:-kms-1}"
SECRET_NAME_DEV="${KMS_SECRETS_ID_DEV:-mdg-auth/dev}"
SECRET_NAME_TEST="${KMS_SECRETS_ID_TEST:-mdg-auth/test}"
KEY_SPEC="ECC_NIST_P256"

export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_DEFAULT_REGION="$REGION"
export AWS_ENDPOINT_URL="$ENDPOINT"

aws_cmd() {
  if command -v awslocal >/dev/null 2>&1; then
    awslocal "$@"
  elif command -v aws >/dev/null 2>&1; then
    aws --endpoint-url="$ENDPOINT" "$@"
  else
    docker exec -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_DEFAULT_REGION \
      mdg-localstack awslocal "$@"
  fi
}

create_p256_key() {
  aws_cmd kms create-key \
    --key-usage SIGN_VERIFY \
    --customer-master-key-spec "$KEY_SPEC" \
    --description "mdg-auth-svc JWT ES256" \
    --query 'KeyMetadata.KeyId' --output text
}

echo "bootstrapping LocalStack at ${ENDPOINT} (kms=${ALIAS}, secrets=${SECRET_NAME_DEV})"

i=0
until aws_cmd kms list-keys >/dev/null 2>&1; do
  i=$((i + 1))
  if [[ $i -ge 40 ]]; then
    echo "LocalStack KMS not ready at ${ENDPOINT}" >&2
    exit 1
  fi
  sleep 1
done

if ! aws_cmd kms describe-key --key-id "$ALIAS" >/dev/null 2>&1; then
  KEY_ID="$(create_p256_key)"
  aws_cmd kms create-alias --alias-name "$ALIAS" --target-key-id "$KEY_ID" >/dev/null
  echo "created ${ALIAS} -> ${KEY_ID}"
else
  KEY_ID="$(aws_cmd kms describe-key --key-id "$ALIAS" --query 'KeyMetadata.KeyId' --output text)"
  SPEC="$(aws_cmd kms describe-key --key-id "$ALIAS" --query 'KeyMetadata.CustomerMasterKeySpec' --output text 2>/dev/null || true)"
  if [[ -n "$SPEC" && "$SPEC" != "$KEY_SPEC" ]]; then
    echo "existing ${ALIAS} is ${SPEC}; creating ${KEY_SPEC} and retargeting alias" >&2
    KEY_ID="$(create_p256_key)"
    aws_cmd kms update-alias --alias-name "$ALIAS" --target-key-id "$KEY_ID" >/dev/null
    echo "updated ${ALIAS} -> ${KEY_ID}"
  else
    echo "using existing ${ALIAS} -> ${KEY_ID}"
  fi
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

put_secret_json() {
  local name="$1"
  shift
  local payload
  payload="$(
    GOOGLE_CLIENT_ID="$1" GOOGLE_CLIENT_SECRET="$2" \
    GITHUB_CLIENT_ID="$3" GITHUB_CLIENT_SECRET="$4" \
    SESSION_SECRET="$5" \
    python3 -c 'import json,os; print(json.dumps({
      "google_client_id": os.environ["GOOGLE_CLIENT_ID"],
      "google_client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
      "github_client_id": os.environ["GITHUB_CLIENT_ID"],
      "github_client_secret": os.environ["GITHUB_CLIENT_SECRET"],
      "session_secret": os.environ["SESSION_SECRET"],
    }))'
  )"
  if aws_cmd secretsmanager describe-secret --secret-id "$name" >/dev/null 2>&1; then
    aws_cmd secretsmanager put-secret-value --secret-id "$name" --secret-string "$payload" >/dev/null
  else
    aws_cmd secretsmanager create-secret --name "$name" --secret-string "$payload" >/dev/null
  fi
  echo "seeded secretsmanager://${name}"
}

G_ID="$(load_secret GOOGLE_CLIENT_ID)"
G_SEC="$(load_secret GOOGLE_CLIENT_SECRET)"
GH_ID="$(load_secret GITHUB_CLIENT_ID)"
GH_SEC="$(load_secret GITHUB_CLIENT_SECRET)"
SESS="$(load_secret SESSION_SECRET)"

if [[ -n "$G_ID" && -n "$G_SEC" && -n "$SESS" ]]; then
  put_secret_json "$SECRET_NAME_DEV" "$G_ID" "$G_SEC" "$GH_ID" "$GH_SEC" "$SESS"
else
  echo "skip ${SECRET_NAME_DEV} seed (set deploy/vault/.app-secrets.env)" >&2
fi

put_secret_json "$SECRET_NAME_TEST" \
  "$(load_secret TEST_GOOGLE_CLIENT_ID 'test-google-client-id.apps.googleusercontent.com')" \
  "$(load_secret TEST_GOOGLE_CLIENT_SECRET 'test-google-client-secret')" \
  "$(load_secret TEST_GITHUB_CLIENT_ID 'test-github-client-id')" \
  "$(load_secret TEST_GITHUB_CLIENT_SECRET 'test-github-client-secret')" \
  "$(load_secret TEST_SESSION_SECRET 'test-session-secret-32bytes-minimum!!')"

umask 077
cat >"$CREDS_FILE" <<EOF
JWT_SIGNER=kms
AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
AWS_REGION=${REGION}
AWS_DEFAULT_REGION=${REGION}
AWS_ENDPOINT_URL=${ENDPOINT}
KMS_ENDPOINT=${ENDPOINT}
KMS_KEY_ID=${ALIAS}
KMS_KID=${KID}
KMS_SECRETS_ID=${SECRET_NAME_DEV}
EOF
echo "wrote ${CREDS_FILE}"
