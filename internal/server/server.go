package server

import (
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/cors"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/gofiber/fiber/v3/middleware/requestid"

	"github.com/mitdo-garden/mdg-auth-svc/internal/auth"
	"github.com/mitdo-garden/mdg-auth-svc/internal/config"
	"github.com/mitdo-garden/mdg-auth-svc/internal/handlers"
	"github.com/mitdo-garden/mdg-auth-svc/internal/middleware"
	"github.com/mitdo-garden/mdg-auth-svc/internal/origin"
)

// New builds the Fiber app with public OAuth routes and protected APIs.
func New(cfg *config.Config, authHandler *handlers.AuthHandler, tokens *auth.TokenService, log *slog.Logger) *fiber.App {
	app := fiber.New(fiber.Config{
		AppName:      "mdg-auth-svc",
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
		ErrorHandler: func(c fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			// Incomplete / idle client reads (e.g. browser TLS to HTTP, open socket) —
			// not an application failure; avoid ERROR spam.
			if code == fiber.StatusRequestTimeout {
				return c.SendStatus(code)
			}
			log.Error("request error", "err", err, "path", c.Path(), "status", code)
			return c.Status(code).JSON(fiber.Map{
				"error": fiber.Map{
					"code":    "server",
					"message": "Request failed.",
				},
			})
		},
	})

	app.Use(requestid.New())
	app.Use(recover.New())
	app.Use(logger.New(logger.Config{
		Format: "{\"time\":\"${time}\",\"request_id\":\"${requestid}\",\"status\":${status},\"method\":\"${method}\",\"path\":\"${path}\",\"latency\":\"${latency}\"}\n",
	}))
	app.Use(cors.New(cors.Config{
		AllowOriginsFunc: func(originHeader string) bool {
			return origin.Allowed(originHeader, cfg.FrontendURL, cfg.IsDev())
		},
		AllowMethods:     []string{fiber.MethodGet, fiber.MethodPost, fiber.MethodOptions},
		AllowHeaders:     []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	requireAuth := middleware.Authenticate(tokens, cfg.CookieName)

	app.Get("/healthz", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok", "service": "mdg-auth-svc"})
	})

	authAPI := app.Group("/auth")
	authAPI.Get("/.well-known/jwks.json", authHandler.JWKS)
	authAPI.Get("/me", requireAuth, authHandler.Me)

	registerPublicAuth := func(r fiber.Router) {
		r.Post("/refresh", authHandler.Refresh)
		r.Post("/logout", authHandler.Logout)
		r.Post("/:provider/token", authHandler.ExchangeToken)
		r.Get("/:provider/callback", authHandler.Callback)
		r.Get("/:provider", authHandler.Begin)
	}
	registerPublicAuth(authAPI)

	return app
}
