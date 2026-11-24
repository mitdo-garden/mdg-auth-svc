package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/mitdo-garden/mdg-auth-svc/internal/models"
)

var (
	ErrRefreshNotFound = errors.New("refresh token not found")
	ErrRefreshInvalid  = errors.New("refresh token invalid")
)

// RefreshTokenRepository persists hashed refresh tokens.
type RefreshTokenRepository struct {
	db *gorm.DB
}

func NewRefreshTokenRepository(db *gorm.DB) *RefreshTokenRepository {
	return &RefreshTokenRepository{db: db}
}

func (r *RefreshTokenRepository) Create(ctx context.Context, row *models.RefreshToken) error {
	if err := r.db.WithContext(ctx).Create(row).Error; err != nil {
		return fmt.Errorf("create refresh token: %w", err)
	}
	return nil
}

func (r *RefreshTokenRepository) FindByHash(ctx context.Context, hash string) (*models.RefreshToken, error) {
	var row models.RefreshToken
	err := r.db.WithContext(ctx).Where("token_hash = ?", hash).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrRefreshNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find refresh token: %w", err)
	}
	return &row, nil
}

// Revoke marks a single token revoked.
func (r *RefreshTokenRepository) Revoke(ctx context.Context, id string, at time.Time) error {
	res := r.db.WithContext(ctx).Model(&models.RefreshToken{}).
		Where("id = ? AND revoked_at IS NULL", id).
		Update("revoked_at", at)
	if res.Error != nil {
		return fmt.Errorf("revoke refresh token: %w", res.Error)
	}
	return nil
}

// RevokeFamily revokes all tokens in a rotation family (reuse / logout-all-device-chain).
func (r *RefreshTokenRepository) RevokeFamily(ctx context.Context, familyID string, at time.Time) error {
	res := r.db.WithContext(ctx).Model(&models.RefreshToken{}).
		Where("family_id = ? AND revoked_at IS NULL", familyID).
		Update("revoked_at", at)
	if res.Error != nil {
		return fmt.Errorf("revoke refresh family: %w", res.Error)
	}
	return nil
}

// RevokeAllForUser revokes every active refresh token for the user (logout everywhere).
func (r *RefreshTokenRepository) RevokeAllForUser(ctx context.Context, userID string, at time.Time) error {
	res := r.db.WithContext(ctx).Model(&models.RefreshToken{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Update("revoked_at", at)
	if res.Error != nil {
		return fmt.Errorf("revoke user refresh tokens: %w", res.Error)
	}
	return nil
}

// Rotate atomically revokes the presented token and inserts the replacement.
// If the presented token was already revoked, revokes the whole family (theft).
func (r *RefreshTokenRepository) Rotate(
	ctx context.Context,
	current *models.RefreshToken,
	next *models.RefreshToken,
	now time.Time,
) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var locked models.RefreshToken
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ?", current.ID).First(&locked).Error; err != nil {
			return fmt.Errorf("lock refresh token: %w", err)
		}
		if locked.RevokedAt != nil {
			// Outside a short grace window, treat as theft and kill the family.
			if now.Sub(locked.RevokedAt.UTC()) > 10*time.Second {
				_ = tx.Model(&models.RefreshToken{}).
					Where("family_id = ? AND revoked_at IS NULL", locked.FamilyID).
					Update("revoked_at", now)
			}
			return ErrRefreshInvalid
		}
		if now.After(locked.ExpiresAt) {
			return ErrRefreshInvalid
		}
		if err := tx.Model(&locked).Update("revoked_at", now).Error; err != nil {
			return err
		}
		if err := tx.Create(next).Error; err != nil {
			return fmt.Errorf("insert rotated refresh: %w", err)
		}
		return nil
	})
}
