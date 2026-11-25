package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/mitdo-garden/mdg-auth-svc/internal/auth"
	"github.com/mitdo-garden/mdg-auth-svc/internal/awskms"
	"github.com/mitdo-garden/mdg-auth-svc/internal/config"
	"github.com/mitdo-garden/mdg-auth-svc/internal/db"
	"github.com/mitdo-garden/mdg-auth-svc/internal/handlers"
	"github.com/mitdo-garden/mdg-auth-svc/internal/repository"
	"github.com/mitdo-garden/mdg-auth-svc/internal/server"
	"github.com/mitdo-garden/mdg-auth-svc/internal/session"
	mdgvault "github.com/mitdo-garden/mdg-auth-svc/internal/vault"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("config load failed", "err", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		keyRing *auth.KeyRing
		signer  auth.JWTSigner
	)

	switch cfg.JWTSigner {
	case config.JWTSignerKMS:
		ks, err := awskms.New(ctx, cfg.KMS, logger)
		if err != nil {
			logger.Error("kms client failed", "err", err)
			os.Exit(1)
		}
		if err := awskms.LoadAppSecrets(ctx, cfg); err != nil {
			logger.Error("secrets manager failed", "err", err)
			os.Exit(1)
		}
		keyRing, err = ks.LoadPublicKeys(ctx)
		if err != nil {
			logger.Error("kms public keys failed", "err", err)
			os.Exit(1)
		}
		go ks.StartReloadLoop(ctx, keyRing, cfg.KMS.ReloadInterval)
		signer = ks

	default: // vault
		vc, err := mdgvault.New(cfg.Vault, logger)
		if err != nil {
			logger.Error("vault client failed", "err", err)
			os.Exit(1)
		}
		if err := vc.LoadAppSecrets(cfg); err != nil {
			logger.Error("vault app secrets failed", "err", err)
			os.Exit(1)
		}
		keyRing, err = vc.LoadPublicKeys()
		if err != nil {
			logger.Error("vault transit keys failed", "err", err)
			os.Exit(1)
		}
		go vc.StartReloadLoop(ctx, keyRing, cfg.Vault.ReloadInterval)
		signer = vc.Signer()
	}

	if err := cfg.ValidateSecrets(); err != nil {
		logger.Error("config secrets invalid", "err", err)
		os.Exit(1)
	}

	if err := cfg.ValidateMySQL(); err != nil {
		logger.Error("mysql config invalid", "err", err)
		os.Exit(1)
	}

	gdb, err := db.Connect(cfg.MySQLDSN)
	if err != nil {
		logger.Error("database connect failed", "err", err)
		os.Exit(1)
	}
	sqlDB, err := gdb.DB()
	if err != nil {
		logger.Error("database pool failed", "err", err)
		os.Exit(1)
	}
	defer sqlDB.Close()

	var providers []auth.OAuthProvider
	if cfg.Google.Configured() {
		providers = append(providers, auth.NewGoogleOAuth(
			cfg.Google.ClientID, cfg.Google.ClientSecret, cfg.Google.CallbackURL,
		))
	}
	if cfg.GitHub.Configured() {
		providers = append(providers, auth.NewGitHubOAuth(
			cfg.GitHub.ClientID, cfg.GitHub.ClientSecret, cfg.GitHub.CallbackURL,
		))
	}
	registry := auth.NewRegistry(providers...)

	users := repository.NewUserRepository(gdb)
	refreshRepo := repository.NewRefreshTokenRepository(gdb)
	oauthState := auth.NewOAuthState(cfg.SessionSecret, cfg.EffectiveCookieSecure())
	tokens := auth.NewTokenService(keyRing, signer, cfg.AccessTTL, cfg.JWTIssuer)
	sessions := session.New(tokens, refreshRepo, users, cfg.RefreshTTL)

	authHandler := handlers.NewAuthHandler(cfg, registry, oauthState, sessions, users, logger)
	app := server.New(cfg, authHandler, tokens, logger)

	go func() {
		addr := ":" + cfg.Port
		logger.Info("mdg-auth-svc listening",
			"addr", addr,
			"env", cfg.AppEnv,
			"jwt_signer", cfg.JWTSigner,
			"jwt_kid", signer.ActiveKid(),
			"access_ttl", cfg.AccessTTL.String(),
			"refresh_ttl", cfg.RefreshTTL.String(),
			"google", cfg.Google.Configured(),
			"github", cfg.GitHub.Configured(),
		)
		if err := app.Listen(addr); err != nil {
			logger.Error("server failed", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	if err := app.Shutdown(); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
		os.Exit(1)
	}
	logger.Info("mdg-auth-svc stopped")
}
