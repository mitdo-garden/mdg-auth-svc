package auth

import (
	"testing"
)

func TestHashRefreshTokenStable(t *testing.T) {
	h1 := HashRefreshToken("abc")
	h2 := HashRefreshToken("abc")
	if h1 != h2 || len(h1) != 64 {
		t.Fatalf("hash=%s", h1)
	}
	if HashRefreshToken("abd") == h1 {
		t.Fatal("expected different hash")
	}
}

func TestNewRefreshTokenUnique(t *testing.T) {
	a, fa, err := NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	b, fb, err := NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	if a == b || fa == fb || a == "" || fa == "" {
		t.Fatalf("a=%s fa=%s b=%s fb=%s", a, fa, b, fb)
	}
	rotated, err := NewRefreshTokenInFamily()
	if err != nil || rotated == "" || rotated == a {
		t.Fatalf("rotated=%s err=%v", rotated, err)
	}
}
