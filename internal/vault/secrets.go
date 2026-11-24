package vault

import (
	"fmt"

	"github.com/mitdo-garden/mdg-auth-svc/internal/config"
)

// LoadAppSecrets reads OAuth + session_secret from KV (v2) into cfg.
// Non-empty values already set (YAML / env) are left unchanged.
func (c *Client) LoadAppSecrets(cfg *config.Config) error {
	path := cfg.Vault.SecretsPath
	if path == "" {
		path = defaultSecretsPath(cfg.AppEnv)
	}
	secret, err := c.api.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("vault read %s: %w", path, err)
	}
	if secret == nil || secret.Data == nil {
		return fmt.Errorf("vault read %s: empty response", path)
	}
	data := kvData(secret.Data)
	if len(data) == 0 {
		return fmt.Errorf("vault read %s: no data", path)
	}

	strMap := make(map[string]string, len(data))
	for k, v := range data {
		if s, ok := v.(string); ok {
			strMap[k] = s
		}
	}
	cfg.ApplyAppSecrets(strMap)
	c.log.Info("vault app secrets loaded", "path", path)
	return nil
}

func defaultSecretsPath(appEnv string) string {
	return "secret/data/mdg-auth/" + appEnv
}

// kvData unwraps KV-v2 {"data": {...}} or returns flat KV-v1 data.
func kvData(raw map[string]any) map[string]any {
	if inner, ok := raw["data"].(map[string]any); ok {
		return inner
	}
	return raw
}
