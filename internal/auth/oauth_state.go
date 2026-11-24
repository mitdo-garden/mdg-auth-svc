package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
)

const (
	oauthStateCookie = "mdg_oauth_state"
	oauthStateTTL    = 10 * time.Minute
)

var (
	ErrStateMissing   = errors.New("oauth state missing")
	ErrStateMismatch  = errors.New("oauth state mismatch")
	ErrStateExpired   = errors.New("oauth state expired")
	ErrStateMalformed = errors.New("oauth state malformed")
)

// OAuthState protects the Authorization Code Flow against CSRF.
// We store a random nonce in an HttpOnly cookie and echo the same value
// (HMAC-bound to expiry) as the OAuth "state" query parameter.
type OAuthState struct {
	secret []byte
	secure bool
}

func NewOAuthState(secret []byte, secureCookie bool) *OAuthState {
	return &OAuthState{secret: secret, secure: secureCookie}
}

// Create mints a fresh state token and sets the matching HttpOnly cookie.
func (o *OAuthState) Create(c fiber.Ctx) (string, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate state nonce: %w", err)
	}
	nonceHex := hex.EncodeToString(nonce)
	expires := time.Now().UTC().Add(oauthStateTTL).Unix()
	payload := fmt.Sprintf("%s.%d", nonceHex, expires)
	mac := o.sign(payload)
	state := base64.RawURLEncoding.EncodeToString([]byte(payload + "." + mac))

	c.Cookie(&fiber.Cookie{
		Name:     oauthStateCookie,
		Value:    state,
		Path:     "/",
		MaxAge:   int(oauthStateTTL.Seconds()),
		HTTPOnly: true, // JS must never read the CSRF token
		Secure:   o.secure,
		SameSite: "Lax", // allows top-level redirect back from Google
	})
	return state, nil
}

// Validate compares the callback "state" query value to the cookie and
// verifies the HMAC + expiry. Clears the cookie whether success or failure
// so a state token is single-use from the browser's perspective.
func (o *OAuthState) Validate(c fiber.Ctx, incoming string) error {
	defer o.clear(c)

	if incoming == "" {
		return ErrStateMissing
	}
	cookie := c.Cookies(oauthStateCookie)
	if cookie == "" {
		return ErrStateMissing
	}
	// Constant-time compare prevents timing attacks on the state value.
	if !hmac.Equal([]byte(cookie), []byte(incoming)) {
		return ErrStateMismatch
	}
	return o.verifySigned(incoming)
}

func (o *OAuthState) verifySigned(state string) error {
	raw, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		return ErrStateMalformed
	}
	parts := strings.Split(string(raw), ".")
	if len(parts) != 3 {
		return ErrStateMalformed
	}
	payload := parts[0] + "." + parts[1]
	if !hmac.Equal([]byte(o.sign(payload)), []byte(parts[2])) {
		return ErrStateMismatch
	}
	expires, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return ErrStateMalformed
	}
	if time.Now().UTC().Unix() > expires {
		return ErrStateExpired
	}
	return nil
}

func (o *OAuthState) sign(payload string) string {
	mac := hmac.New(sha256.New, o.secret)
	_, _ = mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func (o *OAuthState) clear(c fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name:     oauthStateCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HTTPOnly: true,
		Secure:   o.secure,
		SameSite: "Lax",
	})
}
