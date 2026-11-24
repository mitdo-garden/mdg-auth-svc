# Vault (local + Terraform)

Used when `jwt.signer=vault` (default). For AWS KMS mode and the full comparison, see [`docs/jwt-signing.md`](../../docs/jwt-signing.md).

```bash
cp .app-secrets.env.example .app-secrets.env   # fill google/github/session
make run-dev    # compose + Transit + KV seed + AppRole + auth-svc
./rotate.sh     # rotate Transit key (CI or emergency)
```

| Piece | Path |
|-------|------|
| Transit JWT key | `transit/keys/jwt-access` (ecdsa-p256, not exportable) |
| App secrets (KV v2) | `secret/mdg-auth/<env>` |

KV fields: `google_client_id`, `google_client_secret`, `github_client_id`, `github_client_secret`, `session_secret`.

Staging/prd: apply this Terraform module with a separate state/workspace per env. Do not copy key material between environments.
