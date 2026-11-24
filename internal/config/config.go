package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
)

const (
	EnvDev  = "dev"
	EnvTest = "test"
	EnvSit  = "sit"
	EnvStg  = "stg"
	EnvPrd  = "prd"

	JWTSignerVault = "vault"
	JWTSignerKMS   = "kms"
)

// OAuthClient holds one provider's OAuth app credentials.
type OAuthClient struct {
	ClientID     string
	ClientSecret string
	CallbackURL  string
}

func (o OAuthClient) Configured() bool {
	return strings.TrimSpace(o.ClientID) != "" &&
		strings.TrimSpace(o.ClientSecret) != "" &&
		strings.TrimSpace(o.CallbackURL) != ""
}

// VaultConfig is HashiCorp Vault Transit + KV (when jwt.signer=vault).
type VaultConfig struct {
	Address        string
	Token          string
	RoleID         string
	SecretID       string
	TransitKey     string
	ReloadInterval time.Duration
	Namespace      string
	SecretsPath    string
}

// KMSConfig is AWS KMS asymmetric JWT signing (when jwt.signer=kms).
type KMSConfig struct {
	Region         string
	KeyID          string
	Kid            string
	SecretsID      string
	Endpoint       string
	ReloadInterval time.Duration
}

// Config is loaded from configs/*.yaml with ${ENV:default} placeholders.
type Config struct {
	AppName           string
	AppEnv            string
	Port              string
	MySQLDSN          string
	Google            OAuthClient
	GitHub            OAuthClient
	SessionSecret     []byte
	JWTIssuer         string
	JWTSigner         string
	Vault             VaultConfig
	KMS               KMSConfig
	AccessTTL         time.Duration
	RefreshTTL        time.Duration
	FrontendURL       string
	CookieName        string
	RefreshCookieName string
	CookieDomain      string
	CookieSecure      bool
	ProjectRoot       string
}

func Load() (*Config, error) {
	env := NormalizeEnv(os.Getenv("APP_ENV"))
	root := findProjectRoot()

	v := viper.New()
	v.AddConfigPath(filepath.Join(root, "configs"))
	v.SetConfigType("yaml")

	v.SetConfigName("config")
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read configs/config.yaml: %w", err)
	}

	if err := mergeEnvAndProfiles(v, env); err != nil {
		return nil, err
	}

	// Spring-style ${NAME:default} from process env into all string leaves.
	expanded := expandSettings(v.AllSettings())
	mergeExpanded(v.Set, "", expanded)

	accessTTL := v.GetInt("jwt.access_ttl_seconds")
	if accessTTL <= 0 {
		accessTTL = 900
	}
	refreshTTL := v.GetInt("jwt.refresh_ttl_seconds")
	if refreshTTL <= 0 {
		refreshTTL = 1209600
	}
	reloadSec := v.GetInt("jwt.reload_interval_seconds")
	if reloadSec <= 0 {
		reloadSec = 30
	}
	reload := time.Duration(reloadSec) * time.Second

	cfg := &Config{
		AppName:  firstNonEmpty(v.GetString("app.name"), "mdg-auth-svc"),
		AppEnv:   env,
		Port:     firstNonEmpty(v.GetString("server.port"), "5000"),
		MySQLDSN: mysqlDSN(v),
		Google: OAuthClient{
			ClientID:     v.GetString("google.client_id"),
			ClientSecret: v.GetString("google.client_secret"),
			CallbackURL:  v.GetString("google.callback_url"),
		},
		GitHub: OAuthClient{
			ClientID:     v.GetString("github.client_id"),
			ClientSecret: v.GetString("github.client_secret"),
			CallbackURL:  v.GetString("github.callback_url"),
		},
		SessionSecret:     []byte(v.GetString("security.session_secret")),
		JWTIssuer:         firstNonEmpty(v.GetString("jwt.issuer"), "mdg-auth-svc"),
		JWTSigner:         NormalizeJWTSigner(v.GetString("jwt.signer")),
		AccessTTL:         time.Duration(accessTTL) * time.Second,
		RefreshTTL:        time.Duration(refreshTTL) * time.Second,
		FrontendURL:       strings.TrimRight(v.GetString("frontend.url"), "/"),
		CookieName:        firstNonEmpty(v.GetString("cookie.name"), "mitdo_session"),
		RefreshCookieName: firstNonEmpty(v.GetString("cookie.refresh_name"), "mitdo_refresh"),
		CookieDomain:      v.GetString("cookie.domain"),
		CookieSecure:      v.GetBool("cookie.secure"),
		ProjectRoot:       root,
		Vault: VaultConfig{
			Address:        v.GetString("vault.address"),
			Token:          v.GetString("vault.token"),
			RoleID:         v.GetString("vault.role_id"),
			SecretID:       v.GetString("vault.secret_id"),
			TransitKey:     firstNonEmpty(v.GetString("vault.transit_key"), "jwt-access"),
			ReloadInterval: reload,
			Namespace:      v.GetString("vault.namespace"),
			SecretsPath:    v.GetString("vault.secrets_path"),
		},
		KMS: KMSConfig{
			Region:         v.GetString("kms.region"),
			KeyID:          v.GetString("kms.key_id"),
			Kid:            firstNonEmpty(v.GetString("kms.kid"), "kms-1"),
			SecretsID:      v.GetString("kms.secrets_id"),
			Endpoint:       v.GetString("kms.endpoint"),
			ReloadInterval: reload,
		},
	}

	if err := cfg.validateBoot(); err != nil {
		return nil, fmt.Errorf("config (%s): %w", env, err)
	}
	return cfg, nil
}

// ValidateSecrets checks OAuth + session after Vault KV / Secrets Manager / env filled them.
func (c *Config) ValidateSecrets() error {
	if !c.Google.Configured() && !c.GitHub.Configured() {
		return fmt.Errorf("configure google and/or github oauth (secrets backend or env)")
	}
	if len(c.SessionSecret) < 32 {
		return fmt.Errorf("session_secret must be at least 32 bytes (secrets backend or env)")
	}
	return nil
}

func mysqlDSN(v *viper.Viper) string {
	if dsn := strings.TrimSpace(v.GetString("mysql.dsn")); dsn != "" {
		return dsn
	}
	host := v.GetString("mysql.host")
	port := firstNonEmpty(v.GetString("mysql.port"), "3306")
	user := v.GetString("mysql.user")
	pass := v.GetString("mysql.password")
	dbName := v.GetString("mysql.database")
	params := firstNonEmpty(v.GetString("mysql.params"), "parseTime=true&loc=UTC")
	if host == "" || user == "" || dbName == "" {
		return ""
	}
	return fmt.Sprintf("%s@tcp(%s:%s)/%s?%s",
		url.UserPassword(user, pass).String(), host, port, dbName, params)
}

func (c *Config) validateBoot() error {
	if strings.TrimSpace(c.MySQLDSN) == "" {
		return fmt.Errorf("mysql is required")
	}
	if strings.TrimSpace(c.FrontendURL) == "" {
		return fmt.Errorf("frontend.url is required")
	}
	if strings.TrimSpace(c.Google.CallbackURL) == "" && strings.TrimSpace(c.GitHub.CallbackURL) == "" {
		return fmt.Errorf("google.callback_url and/or github.callback_url required in yaml")
	}
	switch c.JWTSigner {
	case JWTSignerVault:
		if strings.TrimSpace(c.Vault.Address) == "" {
			return fmt.Errorf("vault.address is required when jwt.signer=vault")
		}
		if strings.TrimSpace(c.Vault.TransitKey) == "" {
			return fmt.Errorf("vault.transit_key is required when jwt.signer=vault")
		}
		hasToken := strings.TrimSpace(c.Vault.Token) != ""
		hasAppRole := strings.TrimSpace(c.Vault.RoleID) != "" && strings.TrimSpace(c.Vault.SecretID) != ""
		if !hasToken && !hasAppRole {
			return fmt.Errorf("vault requires VAULT_TOKEN or VAULT_ROLE_ID+VAULT_SECRET_ID")
		}
	case JWTSignerKMS:
		if strings.TrimSpace(c.KMS.KeyID) == "" {
			return fmt.Errorf("kms.key_id is required when jwt.signer=kms")
		}
		if strings.TrimSpace(c.KMS.Region) == "" {
			return fmt.Errorf("kms.region (or AWS_REGION) is required when jwt.signer=kms")
		}
	default:
		return fmt.Errorf("jwt.signer must be %q or %q", JWTSignerVault, JWTSignerKMS)
	}
	return nil
}

func (c *Config) IsDev() bool  { return c.AppEnv == EnvDev }
func (c *Config) IsTest() bool { return c.AppEnv == EnvTest }
func (c *Config) IsSit() bool  { return c.AppEnv == EnvSit }
func (c *Config) IsStg() bool  { return c.AppEnv == EnvStg }
func (c *Config) IsPrd() bool  { return c.AppEnv == EnvPrd }

func (c *Config) EffectiveCookieSecure() bool {
	return c.CookieSecure || c.IsPrd()
}

func NormalizeJWTSigner(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", JWTSignerKMS, "aws", "aws-kms", "awskms":
		return JWTSignerKMS
	case JWTSignerVault, "transit", "hashicorp":
		return JWTSignerVault
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

func NormalizeEnv(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "dev", "development", "local":
		return EnvDev
	case "test", "testing", "ci":
		return EnvTest
	case "sit", "system-integration", "system_integration":
		return EnvSit
	case "stg", "staging", "stage":
		return EnvStg
	case "prd", "prod", "production":
		return EnvPrd
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func findProjectRoot() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "configs", "config.yaml")); err == nil {
			return dir
		}
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return wd
		}
		dir = parent
	}
}
