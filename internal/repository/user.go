package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"github.com/mitdo-garden/mdg-auth-svc/internal/auth"
	"github.com/mitdo-garden/mdg-auth-svc/internal/models"
)

var ErrNotFound = errors.New("user not found")

// UserRepository persists OAuth-linked identities via GORM.
type UserRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

// UpsertFromIdentity finds by provider subject, else by email (account link),
// else creates. Updates profile and last_provider.
func (r *UserRepository) UpsertFromIdentity(ctx context.Context, id *auth.Identity) (*models.User, error) {
	if id == nil || id.Subject == "" {
		return nil, fmt.Errorf("identity subject is required")
	}

	user, err := r.findByProviderSubject(ctx, id.Provider, id.Subject)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	if errors.Is(err, ErrNotFound) && strings.TrimSpace(id.Email) != "" {
		linked, linkErr := r.FindByEmail(ctx, id.Email)
		if linkErr == nil {
			user = linked
		} else if !errors.Is(linkErr, ErrNotFound) {
			return nil, linkErr
		}
	}

	var picture *string
	if id.AvatarURL != "" {
		p := id.AvatarURL
		picture = &p
	}

	if user == nil {
		user = &models.User{
			Email:          id.Email,
			FullName:       id.Name,
			ProfilePicture: picture,
			LastProvider:   id.Provider,
		}
		setProviderSubject(user, id.Provider, id.Subject)
		if err := r.db.WithContext(ctx).Create(user).Error; err != nil {
			return nil, fmt.Errorf("create user: %w", err)
		}
		return user, nil
	}

	setProviderSubject(user, id.Provider, id.Subject)
	if id.Email != "" {
		user.Email = id.Email
	}
	if id.Name != "" {
		user.FullName = id.Name
	}
	if picture != nil {
		user.ProfilePicture = picture
	}
	user.LastProvider = id.Provider

	if err := r.db.WithContext(ctx).Save(user).Error; err != nil {
		return nil, fmt.Errorf("update user: %w", err)
	}
	return user, nil
}

func (r *UserRepository) findByProviderSubject(ctx context.Context, provider, subject string) (*models.User, error) {
	var user models.User
	q := r.db.WithContext(ctx)
	switch provider {
	case auth.ProviderGoogle:
		q = q.Where("google_id = ?", subject)
	case auth.ProviderGitHub:
		q = q.Where("github_id = ?", subject)
	default:
		return nil, fmt.Errorf("unsupported provider %q", provider)
	}
	err := q.Take(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find by provider: %w", err)
	}
	return &user, nil
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return nil, ErrNotFound
	}
	var user models.User
	err := r.db.WithContext(ctx).Where("LOWER(email) = ?", email).Take(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find by email: %w", err)
	}
	return &user, nil
}

func (r *UserRepository) FindByID(ctx context.Context, id string) (*models.User, error) {
	if id == "" {
		return nil, ErrNotFound
	}
	var user models.User
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find user: %w", err)
	}
	return &user, nil
}

func setProviderSubject(user *models.User, provider, subject string) {
	s := subject
	switch provider {
	case auth.ProviderGoogle:
		user.GoogleID = &s
	case auth.ProviderGitHub:
		user.GithubID = &s
	}
}
