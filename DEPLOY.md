# Production deployment guide

This repository deploys `mdg-auth-svc` from GitHub Actions to Amazon EC2 through Amazon ECR and AWS Systems Manager (SSM).

The workflow is `.github/workflows/deploy.yaml`, named **deploy production ECR**.

## Deployment flow

1. Push to `main` or run the workflow manually.
2. GitHub validates the production environment variables.
3. GitHub assumes an AWS IAM role using OIDC.
4. GitHub creates or updates the ECR repository and pushes:
   - `<ecr-registry>/mdg-auth-svc:<git-sha>`
   - `<ecr-registry>/mdg-auth-svc:latest`
5. GitHub sends `AWS-RunShellScript` to the EC2 instance through SSM.
6. EC2 pulls the SHA-tagged image, replaces `mdg-auth-svc`, and starts it on host port `8080`.
7. The workflow waits for `/healthz` to return successfully on `127.0.0.1:8080`.

## AWS resources to create

| Resource | Example | Purpose |
|---|---|---|
| AWS region | `ap-southeast-1` | Region for ECR, KMS, Secrets Manager, EC2, and SSM |
| ECR repository | `mdg-auth-svc` | Stores service images |
| EC2 instance | configured instance ID | Runs Docker and the auth container |
| IAM role for GitHub Actions | `mdg-auth-github-actions-prd` | OIDC assume-role, ECR push, and SSM deploy |
| EC2 IAM instance role | `mdg-auth-svc-ec2-prd` | ECR pull and SSM agent permissions |
| SSM | AWS Systems Manager | Executes deployment commands on EC2 |
| KMS asymmetric key | P-256 `SIGN_VERIFY` key | Signs ES256 JWT access tokens |
| KMS alias | `alias/mdg-auth-jwt-prd` | Stable reference for `KMS_KEY_ID` |
| Secrets Manager secret | `mdg-auth/prd` | OAuth credentials and session secret |
| MySQL database | `mdg_auth` | Users and refresh-token families |
| GitHub environment | `mitdo-cloud-auth-svc-prd` | Holds AWS deployment variables |

## 1. Create the KMS signing key

The key must use the P-256 elliptic curve and `SIGN_VERIFY` key usage.

```bash
export AWS_REGION=ap-southeast-1

KEY_ID=$(aws kms create-key \
  --region "$AWS_REGION" \
  --key-usage SIGN_VERIFY \
  --customer-master-key-spec ECC_NIST_P256 \
  --description "mdg-auth-svc JWT ES256 production key" \
  --query 'KeyMetadata.KeyId' \
  --output text)

aws kms create-alias \
  --region "$AWS_REGION" \
  --alias-name alias/mdg-auth-jwt-prd \
  --target-key-id "$KEY_ID"

aws kms describe-key \
  --region "$AWS_REGION" \
  --key-id alias/mdg-auth-jwt-prd
```

Use:

- `JWT_SIGNER=kms`
- `KMS_KEY_ID=alias/mdg-auth-jwt-prd`
- `KMS_KID=kms-prd-1`
- `KMS_REGION=$AWS_REGION` or rely on `AWS_REGION`

`KMS_KID` is included in the JWT header and JWKS response. Change it when rotating to a new key. The current implementation exposes one active key/public key at a time.

## 2. Create the production Secrets Manager secret

Create `mdg-auth/prd` with a JSON secret:

```json
{
  "google_client_id": "...",
  "google_client_secret": "...",
  "github_client_id": "...",
  "github_client_secret": "...",
  "session_secret": "at-least-32-random-bytes",
  "mysql_host": "mysql.example.internal",
  "mysql_port": "3306",
  "mysql_user": "mdg_auth_app",
  "mysql_password": "...",
  "mysql_database": "mdg_auth",
  "mysql_params": "parseTime=true&loc=UTC&tls=true"
}
```

Create or update it with AWS CLI:

```bash
aws secretsmanager create-secret \
  --region "$AWS_REGION" \
  --name mdg-auth/prd \
  --secret-string '{"google_client_id":"...","google_client_secret":"...","github_client_id":"...","github_client_secret":"...","session_secret":"replace-with-at-least-32-random-bytes","mysql_host":"mysql.example.internal","mysql_port":"3306","mysql_user":"mdg_auth_app","mysql_password":"...","mysql_database":"mdg_auth","mysql_params":"parseTime=true&loc=UTC&tls=true"}'
```

For an existing secret:

```bash
aws secretsmanager put-secret-value \
  --region "$AWS_REGION" \
  --secret-id mdg-auth/prd \
  --secret-string '{"google_client_id":"...","google_client_secret":"...","github_client_id":"...","github_client_secret":"...","session_secret":"replace-with-at-least-32-random-bytes","mysql_host":"mysql.example.internal","mysql_port":"3306","mysql_user":"mdg_auth_app","mysql_password":"...","mysql_database":"mdg_auth","mysql_params":"parseTime=true&loc=UTC&tls=true"}'
```

The secret is loaded by `internal/awskms/secrets.go`. Environment variables such as `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, and `SESSION_SECRET` override values from Secrets Manager.

## 3. Prepare MySQL

Create database `mdg_auth` and a restricted application account. Apply the schema:

```bash
mysql -h "$MYSQL_HOST" -P "$MYSQL_PORT" -u "$MYSQL_USER" -p "$MYSQL_DATABASE" \
  < migrations/001_init.sql
```

If a migration fails because a table already exists, verify the existing schema instead of repeatedly executing the file. The application opens the database and pings it during startup; it does not create these tables automatically.

## 4. Create the ECR repository

The workflow can create the repository automatically. To create it ahead of deployment:

```bash
aws ecr create-repository \
  --region "$AWS_REGION" \
  --repository-name mdg-auth-svc
```

Recommended repository settings:

- image tag mutability: mutable (needed by `latest`)
- private repository
- lifecycle policy for old images
- encryption: AWS-managed encryption or KMS
- registry scanning enabled

## 5. Configure GitHub OIDC and deployment IAM

Create or reuse a GitHub Actions IAM role and add an OIDC trust policy scoped to this repository and environment.

Example OIDC subject:

```text
repo:mitdo-garden/mdg-auth-svc:environment:mitdo-cloud-auth-svc-prd
```

The role needs:

- `sts:GetCallerIdentity`
- ECR authorization and repository push permissions
- SSM `SendCommand`, `GetCommandInvocation`, and `ListCommandInvocations`
- permission to wait/read EC2 SSM command status

Example policy fragments:

```json
{
  "Action": [
    "ecr:GetAuthorizationToken"
  ],
  "Resource": "*",
  "Effect": "Allow"
}
```

```json
{
  "Action": [
    "ecr:BatchCheckLayerAvailability",
    "ecr:CompleteLayerUpload",
    "ecr:CreateRepository",
    "ecr:DescribeRepositories",
    "ecr:GetDownloadUrlForLayer",
    "ecr:InitiateLayerUpload",
    "ecr:PutImage",
    "ecr:UploadLayerPart",
    "ecr:BatchGetImage"
  ],
  "Resource": "arn:aws:ecr:ap-southeast-1:<account-id>:repository/mdg-auth-svc",
  "Effect": "Allow"
}
```

```json
{
  "Action": [
    "ssm:SendCommand",
    "ssm:GetCommandInvocation",
    "ssm:ListCommandInvocations"
  ],
  "Resource": "*",
  "Effect": "Allow"
}
```

Restrict the final SSM and EC2 resources further when account boundaries permit it.

## 6. Configure the EC2 instance

The instance must have:

- Amazon Linux or a compatible Linux distribution
- Docker installed and running
- AWS CLI v2 installed
- SSM Agent installed, running, and online
- an IAM instance profile attached
- outbound access to ECR, AWS APIs, MySQL, and OAuth providers
- port `8080` reachable from the load balancer or proxy
- a suitable security group (normally allow HTTP/HTTPS from the load balancer, not public database access)

Attach `AmazonSSMManagedInstanceCore` to the EC2 instance role, plus ECR pull permissions:

```json
{
  "Action": [
    "ecr:GetAuthorizationToken"
  ],
  "Resource": "*",
  "Effect": "Allow"
}
```

```json
{
  "Action": [
    "ecr:BatchCheckLayerAvailability",
    "ecr:GetDownloadUrlForLayer",
    "ecr:BatchGetImage"
  ],
  "Resource": "arn:aws:ecr:ap-southeast-1:<account-id>:repository/mdg-auth-svc",
  "Effect": "Allow"
}
```

The EC2 role **does not** need the KMS or Secrets Manager permissions for the container if application credentials are supplied entirely through `/etc/mdg-auth-svc.env`. If the container must call KMS and Secrets Manager itself, also attach:

```json
{
  "Action": [
    "kms:Sign",
    "kms:GetPublicKey",
    "kms:DescribeKey"
  ],
  "Resource": "arn:aws:kms:ap-southeast-1:<account-id>:key/<key-id>",
  "Effect": "Allow"
}
```

```json
{
  "Action": "secretsmanager:GetSecretValue",
  "Resource": "arn:aws:secretsmanager:ap-southeast-1:<account-id>:secret:mdg-auth/prd-*",
  "Effect": "Allow"
}
```

This application currently uses the EC2/container AWS credential chain for KMS and Secrets Manager, so the EC2 instance role is the normal production credential source unless credentials are otherwise injected.

## 7. Create the EC2 environment file

Create `/etc/mdg-auth-svc.env` on EC2 with `600` permissions:

```bash
sudo install -m 600 /dev/null /etc/mdg-auth-svc.env
sudo tee /etc/mdg-auth-svc.env >/dev/null <<'EOF'
APP_ENV=prd
SERVER_PORT=8080

JWT_SIGNER=kms
KMS_REGION=ap-southeast-1
KMS_KEY_ID=alias/mdg-auth-jwt-prd
KMS_KID=kms-prd-1
KMS_SECRETS_ID=mdg-auth/prd

FRONTEND_URL=https://app.example
GOOGLE_CALLBACK_URL=https://api.example/v1/auth/google/callback
GITHUB_CALLBACK_URL=https://api.example/v1/auth/github/callback
EOF

sudo chmod 600 /etc/mdg-auth-svc.env
sudo chown root:root /etc/mdg-auth-svc.env
```

Do not commit this file. Keep the actual domain, callback URLs, database host, and secrets in AWS/GitHub secrets or the EC2 host configuration.

OAuth callback URLs must match the provider application configuration:

- Google: `https://api.example/v1/auth/google/callback`
- GitHub: `https://api.example/v1/auth/github/callback`

The container is started with:

```text
-p 8080:8080
--env-file /etc/mdg-auth-svc.env
-v /var/lib/mdg-auth-svc:/app/data
```

The `/app/data` volume is currently not required for application state, but it is reserved for persistent host data.

## 8. Configure GitHub environment variables

In GitHub:

**Settings → Environments → mitdo-cloud-auth-svc-prd**

Add these variables:

| Variable | Example |
|---|---|
| `AWS_REGION` | `ap-southeast-1` |
| `AWS_ROLE_ARN` | `arn:aws:iam::<account-id>:role/mdg-auth-github-actions-prd` |
| `ECR_REPOSITORY` | `mdg-auth-svc` |
| `EC2_INSTANCE_ID` | `i-0123456789abcdef0` |

Use environment protection rules or required reviewers if production approval is needed.

## 9. Deploy

Before the first deployment:

1. Apply `migrations/001_init.sql`.
2. Create KMS key and alias.
3. Create Secrets Manager secret.
4. Configure EC2 Docker, SSM, IAM, security groups, and `/etc/mdg-auth-svc.env`.
5. Configure GitHub OIDC trust and environment variables.
6. Verify the EC2 instance is **Online** in SSM.

Deploy from GitHub:

- Push code to `main`; or
- open **Actions → deploy production ECR → Run workflow**

The workflow fails if:

- a required GitHub environment variable is missing;
- GitHub cannot assume the AWS role;
- the ECR image cannot be built or pushed;
- `/etc/mdg-auth-svc.env` is missing or unreadable on EC2;
- SSM cannot execute the command;
- Docker cannot start or pull the image;
- `/healthz` does not respond within 30 attempts.

## 10. Verify production

Run on EC2:

```bash
docker ps --filter name=^/mdg-auth-svc$
docker logs --tail 100 mdg-auth-svc
curl -fsS http://127.0.0.1:8080/
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/.well-known/jwks.json
```

Confirm:

- container status is `Up`;
- `/healthz` returns the service status;
- JWKS contains the configured `kid` and ES256 key;
- Google and GitHub callback URLs return the expected OAuth behavior;
- database connectivity succeeds;
- KMS signing and Secrets Manager reads succeed.

## KMS rotation

The current signer loads one active public key and one active `kid`.

For a controlled rotation:

1. Create a new P-256 `SIGN_VERIFY` KMS key.
2. Create or retarget `alias/mdg-auth-jwt-prd` if using an alias.
3. Set a new `KMS_KID`, for example `kms-prd-2`.
4. Deploy the new configuration.
5. Keep the old JWKS/public key available until existing access JWTs expire (currently 15 minutes by default).
6. Revoke or disable the old key only after its tokens are no longer valid.

The application does not currently retain multiple public keys in one JWKS response. Rotating requires care if there is a period in which both old and new keys must verify existing tokens.

## Rollback

To roll back by image tag:

```bash
export AWS_REGION=ap-southeast-1
export EC2_INSTANCE_ID=i-0123456789abcdef0
export ECR_REGISTRY=<account-id>.dkr.ecr.ap-southeast-1.amazonaws.com
export ECR_REPOSITORY=mdg-auth-svc
export IMAGE_TAG=<previous-git-sha>

PARAMETERS=$(python3 - <<'PY'
import json, os
image = f"{os.environ['ECR_REGISTRY']}/{os.environ['ECR_REPOSITORY']}:{os.environ['IMAGE_TAG']}"
print(json.dumps({"commands": [
  "set -euo pipefail",
  f"docker pull '{image}'",
  "docker rm -f mdg-auth-svc 2>/dev/null || true",
  f"docker run -d --name mdg-auth-svc --restart unless-stopped -p 8080:8080 --env-file /etc/mdg-auth-svc.env -v /var/lib/mdg-auth-svc:/app/data '{image}'",
  "for i in $(seq 1 30); do curl -fsS http://127.0.0.1:8080/healthz && exit 0; sleep 2; done; docker logs --tail 100 mdg-auth-svc; exit 1"
]}))
PY
)

aws ssm send-command \
  --region "$AWS_REGION" \
  --instance-ids "$EC2_INSTANCE_ID" \
  --document-name AWS-RunShellScript \
  --parameters "$PARAMETERS"
```

Prefer rerunning GitHub Actions at the previous commit for an auditable rollback, if the repository and workflow continue to support it.
