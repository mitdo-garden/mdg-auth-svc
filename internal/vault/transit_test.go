package vault

import "testing"

func TestKidVersionRoundTrip(t *testing.T) {
	if kidFromVersion(3) != "v3" {
		t.Fatal(kidFromVersion(3))
	}
	n, err := versionFromKid("v12")
	if err != nil || n != 12 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if _, err := versionFromKid("2026-10"); err == nil {
		t.Fatal("expected error")
	}
}

func TestJWSSignatureSegment(t *testing.T) {
	seg, err := jwsSignatureSegment("vault:v2:abcDEFghi")
	if err != nil || seg != "abcDEFghi" {
		t.Fatalf("seg=%q err=%v", seg, err)
	}
	seg, err = jwsSignatureSegment("plainSegment")
	if err != nil || seg != "plainSegment" {
		t.Fatalf("seg=%q err=%v", seg, err)
	}
}
