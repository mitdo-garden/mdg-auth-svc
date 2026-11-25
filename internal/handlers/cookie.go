package handlers

import (
	"net"
	"strings"
)

// sessionCookieDomain keeps a configured Domain only when the request host
// matches it. Requests on mitdo.tech always use that domain. A Domain=localhost
// cookie is rejected by the browser for any other host, so those requests get
// a host-only cookie.
func sessionCookieDomain(configured, requestHost string) string {
	host := requestHost
	if h, _, err := net.SplitHostPort(requestHost); err == nil {
		host = h
	}
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "mitdo.cloud" || strings.HasSuffix(host, ".mitdo.cloud") {
		return "mitdo.cloud"
	}
	if host == "mitdo.tech" || strings.HasSuffix(host, ".mitdo.tech") {
		return "mitdo.tech"
	}
	configured = strings.TrimSpace(configured)
	if configured == "" {
		return ""
	}
	domain := strings.ToLower(configured)
	if host == domain || strings.HasSuffix(host, "."+domain) {
		return configured
	}
	return ""
}
