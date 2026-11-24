package vault

import (
	"fmt"
	"log/slog"

	"github.com/hashicorp/vault/api"

	"github.com/mitdo-garden/mdg-auth-svc/internal/config"
)

// Client wraps the Vault HTTP API with AppRole or token auth.
type Client struct {
	api    *api.Client
	log    *slog.Logger
	cfg    config.VaultConfig
	signer *TransitSigner
}

// New authenticates to Vault (token or AppRole) and returns a client.
func New(cfg config.VaultConfig, log *slog.Logger) (*Client, error) {
	if log == nil {
		log = slog.Default()
	}
	apiCfg := api.DefaultConfig()
	apiCfg.Address = cfg.Address
	cli, err := api.NewClient(apiCfg)
	if err != nil {
		return nil, fmt.Errorf("vault client: %w", err)
	}
	if cfg.Namespace != "" {
		cli.SetNamespace(cfg.Namespace)
	}

	c := &Client{api: cli, log: log, cfg: cfg}
	if err := c.authenticate(); err != nil {
		return nil, err
	}
	c.signer = NewTransitSigner(c, cfg.TransitKey)
	return c, nil
}

func (c *Client) authenticate() error {
	if tok := c.cfg.Token; tok != "" {
		c.api.SetToken(tok)
		return nil
	}
	secret, err := c.api.Logical().Write("auth/approle/login", map[string]any{
		"role_id":   c.cfg.RoleID,
		"secret_id": c.cfg.SecretID,
	})
	if err != nil {
		return fmt.Errorf("vault approle login: %w", err)
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return fmt.Errorf("vault approle login: empty token")
	}
	c.api.SetToken(secret.Auth.ClientToken)
	return nil
}

// API exposes the underlying Vault client for tests.
func (c *Client) API() *api.Client { return c.api }

// Signer returns the Transit JWT signer (shared, hot-reloaded active kid).
func (c *Client) Signer() *TransitSigner { return c.signer }
