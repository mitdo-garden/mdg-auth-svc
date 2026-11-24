package origin

import (
	"net"
	"net/url"
	"strings"
)

const publicDomain = "mitdo.tech"

// Allowed accepts the configured frontend origin. In dev it also accepts
// mitdo.tech (any port) and the same scheme and port on localhost or any IP.
func Allowed(origin, frontendURL string, allowLAN bool) bool {
	origin = strings.TrimRight(strings.TrimSpace(origin), "/")
	frontendURL = strings.TrimRight(strings.TrimSpace(frontendURL), "/")
	if origin == "" || frontendURL == "" {
		return false
	}
	if origin == frontendURL {
		return true
	}
	if !allowLAN {
		return false
	}
	want, err := url.Parse(frontendURL)
	got, err2 := url.Parse(origin)
	if err != nil || err2 != nil || want.Scheme == "" || got.Hostname() == "" {
		return false
	}
	if onPublicDomain(got.Hostname()) {
		return true
	}
	if !strings.EqualFold(got.Scheme, want.Scheme) || got.Port() != want.Port() {
		return false
	}
	return lanHost(got.Hostname())
}

// ReturnOrigin keeps only an allowed http(s) origin. Paths and credentials are dropped.
func ReturnOrigin(raw, frontendURL string, allowLAN bool) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	origin := u.Scheme + "://" + u.Host
	if !Allowed(origin, frontendURL, allowLAN) {
		return ""
	}
	return origin
}

// RewriteCallback keeps the configured callback path and port, and uses the
// request host when that host is mitdo.tech or an IP. Localhost stays as configured.
func RewriteCallback(configured, requestHost string) string {
	u, err := url.Parse(strings.TrimSpace(configured))
	if err != nil || u.Host == "" {
		return configured
	}
	host := requestHost
	if h, _, err := net.SplitHostPort(requestHost); err == nil {
		host = h
	}
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "" || host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return configured
	}
	if !onPublicDomain(host) && net.ParseIP(host) == nil {
		return configured
	}
	if port := u.Port(); port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else {
		u.Host = host
	}
	return u.String()
}

func onPublicDomain(host string) bool {
	host = strings.Trim(strings.ToLower(host), "[]")
	return host == publicDomain || strings.HasSuffix(host, "."+publicDomain)
}

// Loopback reports whether origin is localhost or a loopback address.
func Loopback(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return false
	}
	host := strings.Trim(strings.ToLower(u.Hostname()), "[]")
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func lanHost(host string) bool {
	host = strings.Trim(strings.ToLower(host), "[]")
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return net.ParseIP(host) != nil
}
