package origin

import "testing"

func TestAllowed(t *testing.T) {
	const frontend = "http://localhost:5173"
	cases := []struct {
		origin  string
		lan     bool
		allowed bool
	}{
		{"http://localhost:5173", false, true},
		{"http://192.168.88.165:5173", false, false},
		{"http://192.168.88.165:5173", true, true},
		{"http://127.0.0.1:5173", true, true},
		{"http://10.0.0.8:5173", true, true},
		{"http://192.168.88.165:5174", true, false},
		{"https://192.168.88.165:5173", true, false},
		{"http://mitdo.tech:5173", true, true},
		{"https://mitdo.tech", true, true},
		{"https://www.mitdo.tech", true, true},
		{"http://mitdo.tech:5173", false, false},
		{"http://evil.example:5173", true, false},
		{"", true, false},
	}
	for _, tc := range cases {
		if got := Allowed(tc.origin, frontend, tc.lan); got != tc.allowed {
			t.Errorf("origin %q lan=%v: got %v want %v", tc.origin, tc.lan, got, tc.allowed)
		}
	}
}

func TestRewriteCallback(t *testing.T) {
	const configured = "http://localhost:8080/v1/auth/google/callback"
	if got := RewriteCallback(configured, "mitdo.tech"); got != "http://mitdo.tech:8080/v1/auth/google/callback" {
		t.Fatalf("domain: %s", got)
	}
	if got := RewriteCallback(configured, "localhost"); got != configured {
		t.Fatalf("localhost: %s", got)
	}
}

func TestReturnOrigin(t *testing.T) {
	const frontend = "http://localhost:5173"
	if got := ReturnOrigin("http://mitdo.tech:5173/login", frontend, true); got != "http://mitdo.tech:5173" {
		t.Fatalf("domain: %s", got)
	}
	if got := ReturnOrigin("https://evil.example/phish", frontend, true); got != "" {
		t.Fatalf("rejected: %s", got)
	}
	if got := ReturnOrigin("javascript:alert(1)", frontend, true); got != "" {
		t.Fatalf("scheme: %s", got)
	}
}
