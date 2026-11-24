# AWS local (LocalStack KMS + Secrets Manager)

Dev stand-in for `jwt.signer=kms`. Mirrors Vault’s `make run-dev` flow.

Image is pinned to **`localstack/localstack:4.14.0`** (last community build that starts **without** an auth token). Newer tags (`stable` / 2026.x) require `LOCALSTACK_AUTH_TOKEN` from https://app.localstack.cloud/settings/auth-tokens (Hobby plan works).

```bash
# once: same OAuth seed as Vault
cp deploy/vault/.app-secrets.env.example deploy/vault/.app-secrets.env
# fill values…

make run-dev   # LocalStack + bootstrap + auth-svc (:8080); default JWT_SIGNER=kms
```

| Piece | Local value |
|-------|-------------|
| Endpoint | `http://127.0.0.1:4566` |
| KMS alias | `alias/mdg-auth-jwt` (ECC_NIST_P256 `SIGN_VERIFY`) |
| Secrets | `mdg-auth/dev`, `mdg-auth/test` |
| Creds file | `deploy/aws/.dev-creds` (gitignored) |

Inspect:

```bash
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test
export AWS_ENDPOINT_URL=http://127.0.0.1:4566 AWS_DEFAULT_REGION=us-east-1
aws --endpoint-url="$AWS_ENDPOINT_URL" kms describe-key --key-id alias/mdg-auth-jwt
aws --endpoint-url="$AWS_ENDPOINT_URL" secretsmanager get-secret-value --secret-id mdg-auth/dev
```

Real AWS (no LocalStack): set `JWT_SIGNER=kms`, omit `AWS_ENDPOINT_URL`, use IAM + real `KMS_KEY_ID` / `KMS_SECRETS_ID`. See [`docs/jwt-signing.md`](../../docs/jwt-signing.md).
