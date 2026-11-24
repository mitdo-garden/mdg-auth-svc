package handlers

import (
	"net"
	"strings"
)

const publicDomain = "mitdo.tech"

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
	if host == publicDomain || strings.HasSuffix(host, "."+publicDomain) {
		return publicDomain
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
