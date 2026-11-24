package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("expired token")
)

// Claims are the application session claims minted after OAuth login.
type Claims struct {
	UserID   string `json:"uid"`
	Provider string `json:"provider"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	jwt.RegisteredClaims
}

// TokenService signs via JWTSigner and verifies using public keys only
// (via kid → KeyRing), matching how other services use JWKS.
type TokenService struct {
	keys   *KeyRing
	signer JWTSigner
	ttl    time.Duration
	issuer string
}

func NewTokenService(keys *KeyRing, signer JWTSigner, ttl time.Duration, issuer string) *TokenService {
	if issuer == "" {
		issuer = "mdg-auth-svc"
	}
	return &TokenService{keys: keys, signer: signer, ttl: ttl, issuer: issuer}
}

func (t *TokenService) TTL() time.Duration { return t.ttl }
func (t *TokenService) Keys() *KeyRing     { return t.keys }

func signingMethod(alg string) (jwt.SigningMethod, error) {
	switch alg {
	case jwt.SigningMethodES256.Alg():
		return jwt.SigningMethodES256, nil
	default:
		return nil, fmt.Errorf("unsupported signing alg %q", alg)
	}
}

// Issue signs a new access JWT with the active signer (kid + alg from signer).
func (t *TokenService) Issue(ctx context.Context, userID, provider, email, name string) (string, time.Time, error) {
	now := time.Now().UTC()
	expires := now.Add(t.ttl)
	claims := Claims{
		UserID:   userID,
		Provider: provider,
		Email:    email,
		Name:     name,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    t.issuer,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expires),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	kid := t.signer.ActiveKid()
	alg := t.signer.Algorithm()
	if kid == "" || alg == "" {
		return "", time.Time{}, fmt.Errorf("sign jwt: empty active kid or alg")
	}
	method, err := signingMethod(alg)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign jwt: %w", err)
	}
	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = kid

	signingInput, err := token.SigningString()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("jwt signing string: %w", err)
	}
	gotKid, gotAlg, sigSeg, err := t.signer.Sign(ctx, signingInput)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign jwt: %w", err)
	}
	if gotKid != kid || gotAlg != alg {
		return "", time.Time{}, fmt.Errorf("sign jwt: signer returned kid/alg mismatch")
	}
	return signingInput + "." + sigSeg, expires, nil
}

// Parse verifies the JWT with the matching public key only (never the private key).
// Unknown kid / wrong alg / bad signature → ErrInvalidToken.
func (t *TokenService) Parse(raw string) (*Claims, error) {
	parsed, err := jwt.ParseWithClaims(raw, &Claims{}, func(token *jwt.Token) (any, error) {
		alg, _ := token.Header["alg"].(string)
		if _, err := signingMethod(alg); err != nil {
			return nil, fmt.Errorf("%w: unexpected signing method %v", ErrInvalidToken, token.Header["alg"])
		}
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("%w: missing kid", ErrInvalidToken)
		}
		pub, err := t.keys.PublicForVerify(kid)
		if err != nil {
			return nil, err
		}
		return pub, nil
	}, jwt.WithIssuer(t.issuer), jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}))
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	claims, ok := parsed.Claims.(*Claims)
	if !ok || !parsed.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil
}
