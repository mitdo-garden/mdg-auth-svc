package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/golang-jwt/jwt/v5"
)

// localES256Signer is a test-only JWTSigner (production uses Vault Transit / KMS).
type localES256Signer struct {
	kid  string
	priv *ecdsa.PrivateKey
}

func (s *localES256Signer) ActiveKid() string { return s.kid }
func (s *localES256Signer) Algorithm() string { return jwt.SigningMethodES256.Alg() }

func (s *localES256Signer) Sign(ctx context.Context, signingInput string) (kid, alg, sigSegment string, err error) {
	if err := ctx.Err(); err != nil {
		return "", "", "", err
	}
	sum := sha256.Sum256([]byte(signingInput))
	r, ss, err := ecdsa.Sign(rand.Reader, s.priv, sum[:])
	if err != nil {
		return "", "", "", fmt.Errorf("ecdsa sign: %w", err)
	}
	sig, err := joseECDSASig(r, ss, 32)
	if err != nil {
		return "", "", "", err
	}
	return s.kid, s.Algorithm(), base64.RawURLEncoding.EncodeToString(sig), nil
}

func joseECDSASig(r, s *big.Int, byteLen int) ([]byte, error) {
	if r == nil || s == nil {
		return nil, fmt.Errorf("ecdsa: nil signature component")
	}
	rb := r.Bytes()
	sb := s.Bytes()
	if len(rb) > byteLen || len(sb) > byteLen {
		return nil, fmt.Errorf("ecdsa: signature component too large")
	}
	out := make([]byte, 2*byteLen)
	copy(out[byteLen-len(rb):byteLen], rb)
	copy(out[2*byteLen-len(sb):], sb)
	return out, nil
}

func mustP256Key() *ecdsa.PrivateKey {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return priv
}
