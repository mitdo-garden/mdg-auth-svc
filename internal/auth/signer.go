package auth

import "context"

// JWTSigner signs the JWT signing-input (base64url(header) + "." + base64url(payload)).
// Implementations may call a remote KMS (Vault Transit, AWS KMS, …).
type JWTSigner interface {
	// ActiveKid is the kid stamped on newly issued tokens.
	ActiveKid() string
	// Algorithm is the JWA name for new tokens (e.g. "ES256").
	Algorithm() string
	// Sign returns kid, alg, and the base64url signature segment (no padding).
	Sign(ctx context.Context, signingInput string) (kid, alg, sigSegment string, err error)
}
