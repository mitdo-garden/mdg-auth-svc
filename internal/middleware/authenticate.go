package middleware

import (
	"strings"

	"github.com/gofiber/fiber/v3"

	"github.com/mitdo-garden/mdg-auth-svc/internal/auth"
)

const UserClaimsKey = "userClaims"

// TokenVerifier verifies JWTs using public keys only (ES256 + kid / JWKS).
type TokenVerifier interface {
	Parse(raw string) (*auth.Claims, error)
}

// Authenticate requires exactly one valid credential:
//   - Authorization: Bearer <jwt>  (mobile / API / non-browser), or
//   - HttpOnly session cookie      (Mitdo web SPA)
//
// Verification uses public keys only (same path other services take via JWKS).
// If both are sent, Bearer wins. Missing or invalid → 401.
func Authenticate(verifier TokenVerifier, cookieName string) fiber.Handler {
	return func(c fiber.Ctx) error {
		raw, source := extractToken(c, cookieName)
		if raw == "" {
			return writeAuthError(c, fiber.StatusUnauthorized, "unauthenticated", "Sign in required.")
		}

		claims, err := verifier.Parse(raw)
		if err != nil || claims == nil || claims.UserID == "" {
			return writeAuthError(c, fiber.StatusUnauthorized, "unauthenticated", "Sign in required.")
		}

		c.Locals(UserClaimsKey, claims)
		c.Locals("authSource", source)
		return c.Next()
	}
}

// ClaimsFromLocals returns the verified session claims, if present.
func ClaimsFromLocals(c fiber.Ctx) (*auth.Claims, bool) {
	claims, ok := c.Locals(UserClaimsKey).(*auth.Claims)
	return claims, ok
}

func extractToken(c fiber.Ctx, cookieName string) (token string, source string) {
	if authz := strings.TrimSpace(c.Get("Authorization")); authz != "" {
		const prefix = "Bearer "
		if strings.HasPrefix(authz, prefix) {
			tok := strings.TrimSpace(authz[len(prefix):])
			if tok != "" {
				return tok, "bearer"
			}
		}
		// Authorization present but not a usable Bearer → do not fall back to
		// cookie; the client explicitly chose header auth and failed it.
		return "", "bearer"
	}
	if cookie := c.Cookies(cookieName); cookie != "" {
		return cookie, "cookie"
	}
	return "", ""
}

func writeAuthError(c fiber.Ctx, status int, code, message string) error {
	return c.Status(status).JSON(fiber.Map{
		"error": fiber.Map{
			"code":    code,
			"message": message,
		},
	})
}
