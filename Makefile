.PHONY: run run-dev run-test build tidy migrate migrate-test vault aws test deploy-test deploy-test-down deploy-test-logs

# Backend: kms (default) | vault
#   make run-dev
#   JWT_SIGNER=vault make run-dev
JWT_SIGNER ?= kms

VAULT_ADDR ?= http://127.0.0.1:8200
VAULT_TOKEN ?= root
VAULT_TRANSIT_KEY ?= jwt-access

AWS_ENDPOINT_URL ?= http://127.0.0.1:4566

run: run-dev

define run-with-vault
	set -a; . deploy/vault/.dev-creds; set +a; \
	APP_ENV=$(1) \
	JWT_SIGNER=vault \
	VAULT_ADDR=$(VAULT_ADDR) \
	VAULT_TRANSIT_KEY=$(VAULT_TRANSIT_KEY) \
	go run ./cmd/server
endef

define run-with-kms
	set -a; . deploy/aws/.dev-creds; set +a; \
	APP_ENV=$(1) \
	JWT_SIGNER=kms \
	KMS_SECRETS_ID=mdg-auth/$(1) \
	go run ./cmd/server
endef

run-dev:
ifeq ($(JWT_SIGNER),vault)
	@$(MAKE) vault
	$(call run-with-vault,dev)
else
	@$(MAKE) aws
	$(call run-with-kms,dev)
endif

run-test:
ifeq ($(JWT_SIGNER),vault)
	@$(MAKE) vault
	$(call run-with-vault,test)
else
	@$(MAKE) aws
	$(call run-with-kms,test)
endif

build:
	go build -o bin/mdg-auth-svc ./cmd/server

test:
	go test ./...

tidy:
	go mod tidy

migrate:
	mysql -h 127.0.0.1 -P 3306 -uroot -proot -e "DROP DATABASE IF EXISTS mdg_auth; CREATE DATABASE mdg_auth CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
	mysql -h 127.0.0.1 -P 3306 -uroot -proot mdg_auth < migrations/001_init.sql

migrate-test:
	mysql -h 127.0.0.1 -P 3306 -uroot -proot -e "DROP DATABASE IF EXISTS mdg_auth_test; CREATE DATABASE mdg_auth_test CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
	mysql -h 127.0.0.1 -P 3306 -uroot -proot mdg_auth_test < migrations/001_init.sql

vault:
	docker compose -f deploy/vault/docker-compose.yml up -d
	@echo "waiting for Vault at $(VAULT_ADDR)..."
	@i=0; \
	until curl -sf "$(VAULT_ADDR)/v1/sys/health" >/dev/null 2>&1; do \
		i=$$((i+1)); \
		if [ $$i -ge 30 ]; then echo "Vault did not become ready" >&2; exit 1; fi; \
		sleep 1; \
	done
	VAULT_ADDR=$(VAULT_ADDR) VAULT_TOKEN=$(VAULT_TOKEN) VAULT_TRANSIT_KEY=$(VAULT_TRANSIT_KEY) \
		./deploy/vault/bootstrap-dev.sh

aws:
	docker compose -f deploy/aws/docker-compose.yml up -d
	@echo "waiting for LocalStack at $(AWS_ENDPOINT_URL)..."
	@i=0; \
	until curl -sf "$(AWS_ENDPOINT_URL)/_localstack/health" >/dev/null 2>&1; do \
		i=$$((i+1)); \
		if [ $$i -ge 60 ]; then echo "LocalStack did not become ready" >&2; exit 1; fi; \
		sleep 1; \
	done
	AWS_ENDPOINT_URL=$(AWS_ENDPOINT_URL) ./deploy/aws/bootstrap-dev.sh

deploy-test:
	@test -f deploy/test/.env || cp deploy/test/.env.example deploy/test/.env
	docker compose -f deploy/test/docker-compose.yml --env-file deploy/test/.env up -d --build
	@echo "waiting for auth healthz..."
	@i=0; \
	until curl -sf http://127.0.0.1:5001/healthz >/dev/null 2>&1; do \
		i=$$((i+1)); \
		if [ $$i -ge 60 ]; then echo "auth-svc did not become ready" >&2; \
			docker compose -f deploy/test/docker-compose.yml logs --tail=80 auth; exit 1; fi; \
		sleep 2; \
	done
	@echo "test env up: http://127.0.0.1:5001"

deploy-test-down:
	docker compose -f deploy/test/docker-compose.yml --env-file deploy/test/.env down

deploy-test-logs:
	docker compose -f deploy/test/docker-compose.yml logs -f auth
