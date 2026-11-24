package auth

import (
	"context"
	"crypto/ecdsa"
	"testing"
	"time"
)

func testRingAndSigner(t *testing.T) (*KeyRing, *localES256Signer) {
	t.Helper()
	active := mustP256Key()
	prev := mustP256Key()
	ring, err := NewPublicKeyRing("v1", map[string]*ecdsa.PublicKey{
		"v1": &active.PublicKey,
		"v0": &prev.PublicKey,
	})
	if err != nil {
		t.Fatalf("NewPublicKeyRing: %v", err)
	}
	return ring, &localES256Signer{kid: "v1", priv: active}
}

func TestIssueAndVerifyWithPublicKey(t *testing.T) {
	ring, signer := testRingAndSigner(t)
	svc := NewTokenService(ring, signer, time.Hour, "mdg-auth-svc")
	const uid = "550e8400-e29b-41d4-a716-446655440000"
	tok, _, err := svc.Issue(context.Background(), uid, "google", "a@b.com", "Ada")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := svc.Parse(tok)
	if err != nil {
		t.Fatal(err)
	}
	if claims.UserID != uid || claims.Provider != "google" {
		t.Fatalf("claims=%+v", claims)
	}
}

func TestJWKSContainsActiveAndPrevious(t *testing.T) {
	ring, _ := testRingAndSigner(t)
	jwks := ring.JWKS()
	if len(jwks.Keys) != 2 {
		t.Fatalf("keys=%d", len(jwks.Keys))
	}
	kids := map[string]bool{}
	for _, k := range jwks.Keys {
		if k.Kty != "EC" || k.Alg != "ES256" || k.Crv != "P-256" || k.X == "" || k.Y == "" {
			t.Fatalf("bad jwk: %+v", k)
		}
		kids[k.Kid] = true
	}
	if !kids["v1"] || !kids["v0"] {
		t.Fatalf("kids=%v", kids)
	}
}

func TestRejectUnknownKid(t *testing.T) {
	ring, signer := testRingAndSigner(t)
	svc := NewTokenService(ring, signer, time.Hour, "mdg-auth-svc")
	tok, _, err := svc.Issue(context.Background(), "550e8400-e29b-41d4-a716-446655440001", "github", "", "x")
	if err != nil {
		t.Fatal(err)
	}

	other := mustP256Key()
	empty, err := NewPublicKeyRing("v9", map[string]*ecdsa.PublicKey{"v9": &other.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewTokenService(empty, &localES256Signer{kid: "v9", priv: other}, time.Hour, "mdg-auth-svc").Parse(tok); err == nil {
		t.Fatal("expected unknown kid to fail")
	}
}
