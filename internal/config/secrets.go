package config

import "strings"

// ApplyAppSecrets fills empty OAuth + session fields from a string map
// (Vault KV or AWS Secrets Manager JSON). Existing non-empty values win.
func (c *Config) ApplyAppSecrets(data map[string]string) {
	if len(data) == 0 {
		return
	}
	fill := func(dst *string, key string) {
		if strings.TrimSpace(*dst) != "" {
			return
		}
		if v := strings.TrimSpace(data[key]); v != "" {
			*dst = v
		}
	}
	fill(&c.Google.ClientID, "google_client_id")
	fill(&c.Google.ClientSecret, "google_client_secret")
	fill(&c.GitHub.ClientID, "github_client_id")
	fill(&c.GitHub.ClientSecret, "github_client_secret")
	if len(c.SessionSecret) == 0 {
		if v := strings.TrimSpace(data["session_secret"]); v != "" {
			c.SessionSecret = []byte(v)
		}
	}
}
