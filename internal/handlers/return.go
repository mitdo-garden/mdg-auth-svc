package handlers

import (
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v3"

	"github.com/mitdo-garden/mdg-auth-svc/internal/auth"
	"github.com/mitdo-garden/mdg-auth-svc/internal/origin"
)

const returnCookie = "mdg_return_to"

// rememberReturn stores the UI origin that started sign-in. The OAuth callback
// lands on the auth host, which is often localhost, and this cookie is how we
// send the browser back to mitdo.tech.
func (h *AuthHandler) rememberReturn(c fiber.Ctx) {
	raw := strings.TrimSpace(c.Query("next"))
	if raw == "" {
		raw = c.Get("Referer")
	}
	target := origin.ReturnOrigin(raw, h.cfg.FrontendURL, h.cfg.IsDev())
	if target == "" {
		return
	}
	c.Cookie(&fiber.Cookie{
		Name:     returnCookie,
		Value:    target,
		Path:     "/",
		MaxAge:   600,
		HTTPOnly: true,
		Secure:   h.cfg.EffectiveCookieSecure(),
		SameSite: "Lax",
	})
}

func (h *AuthHandler) takeReturn(c fiber.Ctx) string {
	raw := c.Cookies(returnCookie)
	c.Cookie(&fiber.Cookie{
		Name:     returnCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HTTPOnly: true,
		Secure:   h.cfg.EffectiveCookieSecure(),
		SameSite: "Lax",
	})
	return origin.ReturnOrigin(raw, h.cfg.FrontendURL, h.cfg.IsDev())
}

func (h *AuthHandler) withRequestHost(c fiber.Ctx, provider auth.OAuthProvider) auth.OAuthProvider {
	if !h.cfg.IsDev() || provider == nil {
		return provider
	}
	switch p := provider.(type) {
	case *auth.GoogleOAuth:
		return p.WithCallback(origin.RewriteCallback(p.CallbackURL(), c.Hostname()))
	case *auth.GitHubOAuth:
		return p.WithCallback(origin.RewriteCallback(p.CallbackURL(), c.Hostname()))
	default:
		return provider
	}
}

func frontendTarget(base, errCode string) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	target := base + "/"
	if errCode == "" {
		return target
	}
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	q := u.Query()
	q.Set("error", errCode)
	u.RawQuery = q.Encode()
	return u.String()
}
