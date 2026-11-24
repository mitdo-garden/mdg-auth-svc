# Test environment deploy

Self-contained stack: **MySQL** + **Vault (Transit + KV)** + **mdg-auth-svc** (`APP_ENV=test`).

## One command

From `mdg-auth-svc/`:

```bash
make deploy-test
```

Then:

```bash
curl http://127.0.0.1:5001/healthz
curl http://127.0.0.1:5001/.well-known/jwks.json
```

| Service | Host port |
|---------|-----------|
| auth-svc | `5001` |
| Vault   | `8201` |
| MySQL   | `3307` |

Stop:

```bash
make deploy-test-down
```

## OAuth (optional)

`vault-init` seeds `secret/mdg-auth/test`. Override via `deploy/test/.env`:

```bash
cp deploy/test/.env.example deploy/test/.env
# edit GOOGLE_* / GITHUB_* / SESSION_SECRET / FRONTEND_URL
make deploy-test
```

Callback URLs stay in YAML / env; client secrets come from Vault KV.

## Notes

- JWT: Vault Transit (`jwt-access`). Secrets: KV `secret/mdg-auth/test`. Test uses `VAULT_TOKEN=root`.
- For Vault vs AWS KMS (`jwt.signer`), see [`docs/jwt-signing.md`](../../docs/jwt-signing.md).
- Schema loads from `migrations/001_init.sql` on first MySQL start.
- Image build uses the root `Dockerfile`.
