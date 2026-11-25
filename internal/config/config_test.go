package config

import (
	"strings"
	"testing"
)

func withVaultEnv(t *testing.T) {
	t.Helper()
	t.Setenv("JWT_SIGNER", "vault")
	t.Setenv("VAULT_ADDR", "http://127.0.0.1:8200")
	t.Setenv("VAULT_TOKEN", "test-root-token")
	t.Setenv("VAULT_TRANSIT_KEY", "jwt-access")
}

func withOAuthEnv(t *testing.T) {
	t.Helper()
	t.Setenv("GOOGLE_CLIENT_ID", "test-google-client-id.apps.googleusercontent.com")
	t.Setenv("GOOGLE_CLIENT_SECRET", "test-google-client-secret")
	t.Setenv("GITHUB_CLIENT_ID", "test-github-client-id")
	t.Setenv("GITHUB_CLIENT_SECRET", "test-github-client-secret")
	t.Setenv("SESSION_SECRET", "test-session-secret-32bytes-minimum!!")
}

func TestLoadTestEnv(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	withVaultEnv(t)
	withOAuthEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AppEnv != EnvTest || cfg.Port != "5001" {
		t.Fatalf("env=%s port=%s", cfg.AppEnv, cfg.Port)
	}
	if err := cfg.ValidateSecrets(); err != nil {
		t.Fatal(err)
	}
	if cfg.Vault.TransitKey != "jwt-access" {
		t.Fatalf("vault=%+v", cfg.Vault)
	}
}

func TestLoadDev(t *testing.T) {
	t.Setenv("APP_ENV", "dev")
	withVaultEnv(t)
	withOAuthEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AppEnv != EnvDev || cfg.Port != "8080" {
		t.Fatalf("env=%s port=%s", cfg.AppEnv, cfg.Port)
	}
	if cfg.Google.CallbackURL == "" {
		t.Fatal("expected google callback")
	}
}

func TestNormalizeEnv(t *testing.T) {
	if NormalizeEnv("") != EnvDev {
		t.Fatal("default")
	}
	if NormalizeEnv("sit") != EnvSit {
		t.Fatal("sit")
	}
	if NormalizeEnv("staging") != EnvStg {
		t.Fatal("staging -> stg")
	}
	if NormalizeEnv("prd") != EnvPrd {
		t.Fatal("prd")
	}
}

func TestVaultEnvPlaceholder(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	t.Setenv("JWT_SIGNER", "vault")
	t.Setenv("VAULT_ADDR", "http://vault.example:8200")
	t.Setenv("VAULT_ROLE_ID", "role")
	t.Setenv("VAULT_SECRET_ID", "secret")
	t.Setenv("VAULT_TRANSIT_KEY", "jwt-access")
	t.Setenv("VAULT_SECRETS_PATH", "secret/data/mdg-auth/custom")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.JWTSigner != JWTSignerVault {
		t.Fatalf("signer=%s", cfg.JWTSigner)
	}
	if cfg.Vault.Address != "http://vault.example:8200" {
		t.Fatalf("vault=%+v", cfg.Vault)
	}
	if cfg.Vault.RoleID != "role" || cfg.Vault.SecretID != "secret" {
		t.Fatalf("approle=%+v", cfg.Vault)
	}
	if cfg.Vault.SecretsPath != "secret/data/mdg-auth/custom" {
		t.Fatalf("secrets_path=%s", cfg.Vault.SecretsPath)
	}
}

func TestKMSEnvPlaceholder(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	t.Setenv("JWT_SIGNER", "kms")
	t.Setenv("KMS_REGION", "ap-southeast-1")
	t.Setenv("KMS_KEY_ID", "alias/mdg-auth-jwt")
	t.Setenv("KMS_KID", "kms-prod")
	t.Setenv("KMS_SECRETS_ID", "mdg-auth/test")
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("VAULT_TOKEN", "")
	t.Setenv("VAULT_ROLE_ID", "")
	t.Setenv("VAULT_SECRET_ID", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.JWTSigner != JWTSignerKMS {
		t.Fatalf("signer=%s", cfg.JWTSigner)
	}
	if cfg.KMS.Region != "ap-southeast-1" || cfg.KMS.KeyID != "alias/mdg-auth-jwt" {
		t.Fatalf("kms=%+v", cfg.KMS)
	}
	if cfg.KMS.Kid != "kms-prod" || cfg.KMS.SecretsID != "mdg-auth/test" {
		t.Fatalf("kms=%+v", cfg.KMS)
	}
}

func TestNormalizeJWTSigner(t *testing.T) {
	if NormalizeJWTSigner("") != JWTSignerKMS {
		t.Fatal("default")
	}
	if NormalizeJWTSigner("vault") != JWTSignerVault {
		t.Fatal("vault")
	}
}

func TestMySQLHostEnvPlaceholder(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	withVaultEnv(t)
	t.Setenv("MYSQL_HOST", "mysql")
	t.Setenv("MYSQL_USER", "root")
	t.Setenv("MYSQL_PASSWORD", "root")
	t.Setenv("MYSQL_DATABASE", "mdg_auth_test")
	t.Setenv("MYSQL_PORT", "3306")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if want := "root:root@tcp(mysql:3306)/mdg_auth_test?parseTime=true&loc=UTC"; cfg.MySQLDSN != want {
		t.Fatalf("dsn=%s", cfg.MySQLDSN)
	}
}

func TestDatabaseNamePlaceholderStyle(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	withVaultEnv(t)
	t.Setenv("MYSQL_DATABASE", "custom_db")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !strings.Contains(cfg.MySQLDSN, "/custom_db?") {
		t.Fatalf("dsn=%s", cfg.MySQLDSN)
	}
}

func TestApplyAppSecretsMySQL(t *testing.T) {
	cfg := &Config{}
	cfg.ApplyAppSecrets(map[string]string{
		"mysql_host":     "mysql.internal",
		"mysql_port":     "3306",
		"mysql_user":     "auth_app",
		"mysql_password": "p@ssword",
		"mysql_database": "mdg_auth",
		"mysql_params":   "parseTime=true&loc=UTC&tls=true",
	})

	if !strings.Contains(cfg.MySQLDSN, "@tcp(mysql.internal:3306)/mdg_auth?") {
		t.Fatalf("dsn=%s", cfg.MySQLDSN)
	}
}
