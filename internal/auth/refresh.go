package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
)

// HashRefreshToken returns the SHA-256 hex digest stored in the database.
func HashRefreshToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func mintRefreshToken() (raw string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate refresh token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// NewRefreshToken generates a high-entropy opaque refresh token and its family id.
// The raw token is shown to the client once; only the hash is persisted.
func NewRefreshToken() (raw string, familyID string, err error) {
	raw, err = mintRefreshToken()
	if err != nil {
		return "", "", err
	}
	return raw, uuid.NewString(), nil
}

// NewRefreshTokenInFamily mints a rotated opaque token.
// The caller keeps the existing family id on the new refresh_tokens row.
func NewRefreshTokenInFamily() (raw string, err error) {
	return mintRefreshToken()
}
