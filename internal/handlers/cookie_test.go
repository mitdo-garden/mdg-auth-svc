package handlers

import "testing"

func TestSessionCookieDomain(t *testing.T) {
	cases := []struct {
		configured string
		host       string
		want       string
	}{
		{"localhost", "localhost", "localhost"},
		{"localhost", "localhost:8080", "localhost"},
		{"localhost", "192.168.88.165", ""},
		{"localhost", "192.168.88.165:8080", ""},
		{"localhost", "mitdo.tech", "mitdo.tech"},
		{"localhost", "mitdo.tech:8080", "mitdo.tech"},
		{"", "www.mitdo.tech", "mitdo.tech"},
		{"", "192.168.88.165", ""},
		{"example.com", "app.example.com", "example.com"},
	}
	for _, tc := range cases {
		if got := sessionCookieDomain(tc.configured, tc.host); got != tc.want {
			t.Errorf("configured %q host %q: got %q want %q", tc.configured, tc.host, got, tc.want)
		}
	}
}
