package handlers

import "testing"

func TestFrontendTarget(t *testing.T) {
	if got := frontendTarget("http://mitdo.tech:5173", ""); got != "http://mitdo.tech:5173/" {
		t.Fatalf("ok: %s", got)
	}
	if got := frontendTarget("http://mitdo.tech:5173/", "access_denied"); got != "http://mitdo.tech:5173/?error=access_denied" {
		t.Fatalf("error: %s", got)
	}
}
