package handlers

import (
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/mitdo-garden/mdg-auth-svc/internal/auth"
	"github.com/mitdo-garden/mdg-auth-svc/internal/config"
	"github.com/mitdo-garden/mdg-auth-svc/internal/middleware"
	"github.com/mitdo-garden/mdg-auth-svc/internal/models"
	"github.com/mitdo-garden/mdg-auth-svc/internal/origin"
	"github.com/mitdo-garden/mdg-auth-svc/internal/repository"
	"github.com/mitdo-garden/mdg-auth-svc/internal/session"
)

// AuthHandler serves shared OAuth begin/callback for all registered providers.
type AuthHandler struct {
	cfg      *config.Config
	registry *auth.Registry
	state    *auth.OAuthState
	sessions *session.Service
	users    *repository.UserRepository
	logger   *slog.Logger
}

func NewAuthHandler(
	cfg *config.Config,
	registry *auth.Registry,
	state *auth.OAuthState,
	sessions *session.Service,
	users *repository.UserRepository,
	logger *slog.Logger,
) *AuthHandler {
	return &AuthHandler{
		cfg:      cfg,
		registry: registry,
		state:    state,
		sessions: sessions,
		users:    users,
		logger:   logger,
	}
}

// Begin — GET /auth/:provider
func (h *AuthHandler) Begin(c fiber.Ctx) error {
	providerName := c.Params("provider")
	provider, err := h.registry.Get(providerName)
	if err != nil {
		return h.failAuth(c, "provider_not_configured")
	}

	h.rememberReturn(c)
	state, err := h.state.Create(c)
	if err != nil {
		h.logger.Error("failed to create oauth state", "err", err)
		return h.failAuth(c, "server")
	}
	provider = h.withRequestHost(c, provider)
	return c.Redirect().Status(fiber.StatusFound).To(provider.AuthCodeURL(state))
}

// Callback — GET /auth/:provider/callback
func (h *AuthHandler) Callback(c fiber.Ctx) error {
	providerName := c.Params("provider")
	provider, err := h.registry.Get(providerName)
	if err != nil {
		return h.failAuth(c, "provider_not_configured")
	}

	if oauthErr := c.Query("error"); oauthErr != "" {
		code := "token_exchange"
		if oauthErr == "access_denied" {
			code = "access_denied"
		}
		_ = h.state.Validate(c, c.Query("state"))
		return h.failAuth(c, code)
	}

	if err := h.state.Validate(c, c.Query("state")); err != nil {
		h.logger.Warn("oauth state validation failed", "provider", providerName, "err", err)
		return h.failAuth(c, "invalid_state")
	}

	code := c.Query("code")
	if code == "" {
		return h.failAuth(c, "token_exchange")
	}

	return h.completeOAuth(c, h.withRequestHost(c, provider), code)
}

// ExchangeToken — POST /auth/:provider/token
func (h *AuthHandler) ExchangeToken(c fiber.Ctx) error {
	providerName := c.Params("provider")
	provider, err := h.registry.Get(providerName)
	if err != nil {
		return writeJSONError(c, fiber.StatusBadRequest, "provider_not_configured", "OAuth provider is not configured.")
	}

	var body struct {
		Code string `json:"code"`
	}
	if err := c.Bind().Body(&body); err != nil || strings.TrimSpace(body.Code) == "" {
		return writeJSONError(c, fiber.StatusBadRequest, "invalid_request", "JSON body with non-empty code is required.")
	}

	return h.completeOAuth(c, h.withRequestHost(c, provider), body.Code)
}

func (h *AuthHandler) completeOAuth(c fiber.Ctx, provider auth.OAuthProvider, code string) error {
	ctx := c.Context()
	identity, err := provider.Exchange(ctx, code)
	if err != nil {
		h.logger.Error("oauth exchange failed", "provider", provider.Name(), "err", err)
		return h.failAuth(c, "token_exchange")
	}

	user, err := h.users.UpsertFromIdentity(ctx, identity)
	if err != nil {
		h.logger.Error("user upsert failed", "provider", provider.Name(), "err", err)
		return h.failAuth(c, "server")
	}

	pair, err := h.sessions.Issue(ctx, user)
	if err != nil {
		h.logger.Error("session issue failed", "err", err)
		return h.failAuth(c, "server")
	}

	h.setAccessCookie(c, pair.AccessToken)
	h.setRefreshCookie(c, pair.RefreshToken)

	if wantsJSON(c) || c.Method() == fiber.MethodPost {
		return c.Status(fiber.StatusOK).JSON(tokenResponse(pair, user))
	}
	return h.redirectFrontend(c, "")
}

// Refresh — POST /auth/refresh
// Same dual transport as access: refresh cookie OR Authorization: Bearer <refresh>
// OR JSON body { "refreshToken": "..." }. Bearer/body wins over cookie when present.
func (h *AuthHandler) Refresh(c fiber.Ctx) error {
	raw := extractRefreshToken(c, h.cfg.RefreshCookieName)
	if raw == "" {
		return writeJSONError(c, fiber.StatusUnauthorized, "unauthenticated", "Refresh token required.")
	}

	pair, user, err := h.sessions.Refresh(c.Context(), raw)
	if err != nil {
		if errors.Is(err, repository.ErrRefreshInvalid) || errors.Is(err, repository.ErrRefreshNotFound) ||
			errors.Is(err, repository.ErrNotFound) {
			h.clearSessionCookies(c)
			return writeJSONError(c, fiber.StatusUnauthorized, "unauthenticated", "Sign in required.")
		}
		h.logger.Error("refresh failed", "err", err)
		return writeJSONError(c, fiber.StatusInternalServerError, "server", "Could not refresh session.")
	}

	h.setAccessCookie(c, pair.AccessToken)
	h.setRefreshCookie(c, pair.RefreshToken)
	return c.Status(fiber.StatusOK).JSON(tokenResponse(pair, user))
}

// Me — GET /me (access cookie or Bearer access JWT)
func (h *AuthHandler) Me(c fiber.Ctx) error {
	claims, ok := middleware.ClaimsFromLocals(c)
	if !ok {
		return writeJSONError(c, fiber.StatusUnauthorized, "unauthenticated", "Sign in required.")
	}

	user, err := h.users.FindByID(c.Context(), claims.UserID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return writeJSONError(c, fiber.StatusUnauthorized, "unauthenticated", "Sign in required.")
		}
		h.logger.Error("load user for /me failed", "err", err)
		return writeJSONError(c, fiber.StatusInternalServerError, "server", "Could not load profile.")
	}

	return c.Status(fiber.StatusOK).JSON(user.ToPublic())
}

// Logout — POST /auth/logout
// Revokes the presented refresh token family and clears cookies.
func (h *AuthHandler) Logout(c fiber.Ctx) error {
	raw := extractRefreshToken(c, h.cfg.RefreshCookieName)
	if err := h.sessions.RevokeRefresh(c.Context(), raw); err != nil {
		h.logger.Warn("logout revoke failed", "err", err)
	}
	h.clearSessionCookies(c)
	return c.SendStatus(fiber.StatusNoContent)
}

// JWKS — GET /.well-known/jwks.json
func (h *AuthHandler) JWKS(c fiber.Ctx) error {
	c.Set("Cache-Control", "public, max-age=60, must-revalidate")
	c.Set("Content-Type", "application/json")
	return c.JSON(h.sessions.Tokens().Keys().JWKS())
}

func extractRefreshToken(c fiber.Ctx, cookieName string) string {
	if authz := strings.TrimSpace(c.Get("Authorization")); authz != "" {
		const prefix = "Bearer "
		if strings.HasPrefix(authz, prefix) {
			if tok := strings.TrimSpace(authz[len(prefix):]); tok != "" {
				return tok
			}
		}
	}
	var body struct {
		RefreshToken string `json:"refreshToken"`
	}
	if err := c.Bind().Body(&body); err == nil {
		if tok := strings.TrimSpace(body.RefreshToken); tok != "" {
			return tok
		}
	}
	return c.Cookies(cookieName)
}

func (h *AuthHandler) setAccessCookie(c fiber.Ctx, jwt string) {
	h.setCookie(c, h.cfg.CookieName, jwt, int(h.cfg.AccessTTL.Seconds()), "/")
}

func (h *AuthHandler) setRefreshCookie(c fiber.Ctx, raw string) {
	// Path=/ so SPA credentialed calls to /auth/refresh and /auth/logout send it.
	h.setCookie(c, h.cfg.RefreshCookieName, raw, int(h.cfg.RefreshTTL.Seconds()), "/")
}

func (h *AuthHandler) clearSessionCookies(c fiber.Ctx) {
	h.setCookie(c, h.cfg.CookieName, "", -1, "/")
	h.setCookie(c, h.cfg.RefreshCookieName, "", -1, "/")
}

func (h *AuthHandler) setCookie(c fiber.Ctx, name, value string, maxAge int, path string) {
	cookie := &fiber.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		Domain:   sessionCookieDomain(h.cfg.CookieDomain, c.Hostname()),
		HTTPOnly: true,
		Secure:   h.cfg.EffectiveCookieSecure(),
		SameSite: "Lax",
		MaxAge:   maxAge,
	}
	if maxAge < 0 || value == "" {
		cookie.MaxAge = -1
		cookie.Expires = time.Unix(0, 0)
		cookie.Value = ""
	}
	c.Cookie(cookie)
}

func (h *AuthHandler) failAuth(c fiber.Ctx, errCode string) error {
	if wantsJSON(c) || c.Method() == fiber.MethodPost {
		msg := errCode
		status := fiber.StatusBadRequest
		switch errCode {
		case "unauthenticated":
			status = fiber.StatusUnauthorized
		case "server":
			status = fiber.StatusInternalServerError
			msg = "Sign-in failed."
		case "provider_not_configured":
			msg = "OAuth provider is not configured."
		case "invalid_state":
			msg = "OAuth state is invalid or expired."
		case "access_denied":
			msg = "Sign-in was cancelled."
		case "token_exchange":
			msg = "OAuth token exchange failed."
		}
		return writeJSONError(c, status, errCode, msg)
	}
	return h.redirectFrontend(c, errCode)
}

func (h *AuthHandler) redirectFrontend(c fiber.Ctx, errCode string) error {
	base := h.takeReturn(c)
	// A localhost return target drops the user off the public site.
	if base == "" || origin.Loopback(base) {
		base = h.cfg.FrontendURL
	}
	return c.Redirect().Status(fiber.StatusFound).To(frontendTarget(base, errCode))
}

func wantsJSON(c fiber.Ctx) bool {
	if c.Query("format") == "json" {
		return true
	}
	accept := strings.ToLower(c.Get("Accept"))
	return strings.Contains(accept, "application/json") && !strings.Contains(accept, "text/html")
}

func tokenResponse(pair *session.Pair, user *models.User) fiber.Map {
	expiresIn := int(time.Until(pair.AccessExpires).Seconds())
	if expiresIn < 0 {
		expiresIn = 0
	}
	return fiber.Map{
		"accessToken":  pair.AccessToken,
		"refreshToken": pair.RefreshToken,
		"tokenType":    "Bearer",
		"expiresIn":    expiresIn,
		"user":         user.ToPublic(),
	}
}

func writeJSONError(c fiber.Ctx, status int, code, message string) error {
	return c.Status(status).JSON(fiber.Map{
		"error": fiber.Map{
			"code":    code,
			"message": message,
		},
	})
}
