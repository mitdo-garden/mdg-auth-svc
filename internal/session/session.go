package session

import (
	"context"
	"errors"
	"time"

	"github.com/mitdo-garden/mdg-auth-svc/internal/auth"
	"github.com/mitdo-garden/mdg-auth-svc/internal/models"
	"github.com/mitdo-garden/mdg-auth-svc/internal/repository"
)

// Pair is a newly issued access JWT + opaque refresh token.
type Pair struct {
	AccessToken     string
	AccessExpires   time.Time
	RefreshToken    string
	RefreshExpires  time.Time
	RefreshFamilyID string
}

// Service issues access JWTs and opaque refresh tokens (hash stored in DB).
type Service struct {
	tokens     *auth.TokenService
	refresh    *repository.RefreshTokenRepository
	users      *repository.UserRepository
	refreshTTL time.Duration
}

func New(
	tokens *auth.TokenService,
	refresh *repository.RefreshTokenRepository,
	users *repository.UserRepository,
	refreshTTL time.Duration,
) *Service {
	return &Service{
		tokens:     tokens,
		refresh:    refresh,
		users:      users,
		refreshTTL: refreshTTL,
	}
}

func (s *Service) AccessTTL() time.Duration   { return s.tokens.TTL() }
func (s *Service) RefreshTTL() time.Duration  { return s.refreshTTL }
func (s *Service) Tokens() *auth.TokenService { return s.tokens }

// Issue creates a new access JWT and refresh token for the user (new family).
func (s *Service) Issue(ctx context.Context, user *models.User) (*Pair, error) {
	access, accessExp, err := s.tokens.Issue(ctx, user.ID, user.LastProvider, user.Email, user.FullName)
	if err != nil {
		return nil, err
	}
	raw, familyID, err := auth.NewRefreshToken()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	refreshExp := now.Add(s.refreshTTL)
	row := &models.RefreshToken{
		UserID:    user.ID,
		TokenHash: auth.HashRefreshToken(raw),
		FamilyID:  familyID,
		ExpiresAt: refreshExp,
		CreatedAt: now,
	}
	if err := s.refresh.Create(ctx, row); err != nil {
		return nil, err
	}
	return &Pair{
		AccessToken:     access,
		AccessExpires:   accessExp,
		RefreshToken:    raw,
		RefreshExpires:  refreshExp,
		RefreshFamilyID: familyID,
	}, nil
}

// Refresh validates the opaque refresh token, rotates it, and returns a new pair.
func (s *Service) Refresh(ctx context.Context, rawRefresh string) (*Pair, *models.User, error) {
	if rawRefresh == "" {
		return nil, nil, repository.ErrRefreshInvalid
	}
	hash := auth.HashRefreshToken(rawRefresh)
	current, err := s.refresh.FindByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, repository.ErrRefreshNotFound) {
			return nil, nil, repository.ErrRefreshInvalid
		}
		return nil, nil, err
	}

	now := time.Now().UTC()
	if current.RevokedAt != nil {
		// Reuse after rotate: concurrent refresh (grace) vs theft (revoke family).
		if time.Since(current.RevokedAt.UTC()) > 10*time.Second {
			_ = s.refresh.RevokeFamily(ctx, current.FamilyID, now)
		}
		return nil, nil, repository.ErrRefreshInvalid
	}
	if now.After(current.ExpiresAt) {
		return nil, nil, repository.ErrRefreshInvalid
	}

	user, err := s.users.FindByID(ctx, current.UserID)
	if err != nil {
		return nil, nil, err
	}

	newRaw, err := auth.NewRefreshTokenInFamily()
	if err != nil {
		return nil, nil, err
	}
	refreshExp := now.Add(s.refreshTTL)
	next := &models.RefreshToken{
		UserID:    current.UserID,
		TokenHash: auth.HashRefreshToken(newRaw),
		FamilyID:  current.FamilyID,
		ExpiresAt: refreshExp,
		CreatedAt: now,
	}
	if err := s.refresh.Rotate(ctx, current, next, now); err != nil {
		return nil, nil, err
	}

	access, accessExp, err := s.tokens.Issue(ctx, user.ID, user.LastProvider, user.Email, user.FullName)
	if err != nil {
		return nil, nil, err
	}
	return &Pair{
		AccessToken:     access,
		AccessExpires:   accessExp,
		RefreshToken:    newRaw,
		RefreshExpires:  refreshExp,
		RefreshFamilyID: current.FamilyID,
	}, user, nil
}

// RevokeRefresh invalidates one presented refresh token (and its family).
func (s *Service) RevokeRefresh(ctx context.Context, rawRefresh string) error {
	if rawRefresh == "" {
		return nil
	}
	row, err := s.refresh.FindByHash(ctx, auth.HashRefreshToken(rawRefresh))
	if err != nil {
		if errors.Is(err, repository.ErrRefreshNotFound) {
			return nil
		}
		return err
	}
	return s.refresh.RevokeFamily(ctx, row.FamilyID, time.Now().UTC())
}

// RevokeAllForUser logs the user out of every device.
func (s *Service) RevokeAllForUser(ctx context.Context, userID string) error {
	return s.refresh.RevokeAllForUser(ctx, userID, time.Now().UTC())
}
