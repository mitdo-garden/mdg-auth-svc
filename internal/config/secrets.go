package config

import (
	"fmt"
	"net/url"
	"strings"
)

// ApplyAppSecrets fills OAuth, session, and MySQL fields from a string map
// (Vault KV or AWS Secrets Manager JSON). Existing environment/YAML values win.
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

	if strings.TrimSpace(c.MySQLDSN) == "" {
		if dsn := strings.TrimSpace(data["mysql_dsn"]); dsn != "" {
			c.MySQLDSN = dsn
		} else {
			host := strings.TrimSpace(data["mysql_host"])
			port := strings.TrimSpace(data["mysql_port"])
			user := strings.TrimSpace(data["mysql_user"])
			password := strings.TrimSpace(data["mysql_password"])
			database := strings.TrimSpace(data["mysql_database"])
			params := strings.TrimSpace(data["mysql_params"])
			if port == "" {
				port = "3306"
			}
			if params == "" {
				params = "parseTime=true&loc=UTC"
			}
			if host != "" && user != "" && database != "" {
				c.MySQLDSN = fmt.Sprintf("%s@tcp(%s:%s)/%s?%s",
					url.UserPassword(user, password).String(), host, port, database, params)
			}
		}
	}
}
