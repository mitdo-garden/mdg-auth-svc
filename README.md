# mdg-auth-svc

OAuth (Google / GitHub) + ES256 access JWT (Vault Transit **or** AWS KMS) + opaque refresh tokens. Go (Fiber) + MySQL.

## Layout

```
configs/           YAML profiles: config.yaml + config.<APP_ENV>.yaml (+ APP_PROFILES)
deploy/gitops/     env manifests for mdg-infra-platform ship (dev.yaml, …)
deploy/vault/      local Vault compose, bootstrap, Terraform, rotate
deploy/aws/        local LocalStack (KMS + Secrets Manager)
deploy/test/       full test stack (MySQL + Vault + image)
cmd/server/
internal/{auth,vault,awskms,config,...}
pkg/jwks/          consumer library for other Mitdo services
docs/jwt-signing.md
```

Service and `mdg-infra-platform` are **separate git repos** (no sibling checkout).

[`.github/workflows/release.yml`](.github/workflows/release.yml):

```text
build → deploy-dev → deploy-sit → deploy-stg → deploy-prd
```

- **build** — Docker only (this repo)
- **deploy-*** — calls platform action  
  `mitdo-garden/mdg-infra-platform/.github/actions/ship-env@main`  
  (clones platform into runner temp; fetches this service’s manifest remotely)

Gate with GitHub Environment reviewers or **stop_after**. Needs `AWS_ROLE_ARN`,
`TF_STATE_BUCKET`; optional `PLATFORM_REPO_TOKEN`. See
[mdg-infra-platform/docs/client-usage.md](../mdg-infra-platform/docs/client-usage.md).

## Run locally

```bash
cp deploy/vault/.app-secrets.env.example deploy/vault/.app-secrets.env   # once; fill OAuth + session
make migrate
make run-dev                        # :8080 — LocalStack KMS (default)
JWT_SIGNER=vault make run-dev       # :8080 — Vault Transit + KV
make deploy-test                    # :5001 — compose test env (Vault)
make test
```

## JWT backend switch

One command: `make run-dev` (default **kms** / LocalStack).

| Mode | Command | Sign | App secrets |
|------|---------|------|-------------|
| AWS KMS (local, default) | `make run-dev` | KMS | Secrets Manager `mdg-auth/dev` |
| Vault | `JWT_SIGNER=vault make run-dev` | Transit | KV `secret/mdg-auth/dev` |
| AWS KMS (real) | IAM + no LocalStack endpoint | KMS | Secrets Manager / env |

```bash
# Real AWS (no LocalStack)
export JWT_SIGNER=kms AWS_REGION=ap-southeast-1
unset AWS_ENDPOINT_URL KMS_ENDPOINT
export KMS_KEY_ID=alias/mdg-auth-jwt KMS_SECRETS_ID=mdg-auth/prd
```

Full detail: [`docs/jwt-signing.md`](docs/jwt-signing.md) · [`deploy/aws/README.md`](deploy/aws/README.md) · [`deploy/test/README.md`](deploy/test/README.md).

### Env (summary)

| Env | Purpose |
|-----|---------|
| `APP_ENV` | `dev` / `test` / `prd` (primary overlay; deltas only) |
| `APP_PROFILES` | optional extra overlays, e.g. `aws` → `config.aws.yaml` |
| `JWT_SIGNER` | `kms` (default) or `vault` |
| `VAULT_*` | Vault URL / AppRole / token / KV path |
| `KMS_KEY_ID`, `KMS_REGION`, `KMS_KID`, `KMS_SECRETS_ID` | AWS KMS + Secrets Manager |
| `MYSQL_HOST` / `MYSQL_USER` / … | Compose/K8s DSN pieces |
| `FRONTEND_URL`, `GOOGLE_CALLBACK_URL`, `GITHUB_CALLBACK_URL` | Optional public URL overrides |
| `SESSION_SECRET`, `GOOGLE_CLIENT_*`, `GITHUB_CLIENT_*` | Optional secret overrides |

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/auth/:provider` | no | Start OAuth |
| `GET` | `/auth/:provider/callback` | no | Web cookies or `?format=json` |
| `POST` | `/auth/:provider/token` | no | `{ "code" }` → tokens |
| `POST` | `/auth/refresh` | refresh | Rotate refresh + new access |
| `GET` | `/me` | access | Current user |
| `GET` | `/.well-known/jwks.json` | no | JWKS |
| `POST` | `/auth/logout` | no | Revoke + clear cookies |
| `GET` | `/healthz` | no | Liveness |

Access: short-lived ES256 JWT (`kid` from Transit version or `kms.kid`). Refresh: opaque, SHA-256 in DB, reuse detection revokes the family.

Other services:

```go
cl, _ := jwks.NewClient("http://localhost:8080/.well-known/jwks.json")
v := jwks.NewVerifier(cl, "mdg-auth-svc")
```

## Mitdo UI

1. OAuth redirect URIs → `http://localhost:8080/v1/auth/{google\|github}/callback`
2. `make run-dev` here; UI `npm run dev`
3. UI calls `:8080/v1/*` with credentials (`VITE_API_BASE_URL`)
