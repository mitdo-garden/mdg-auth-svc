package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RefreshToken is an opaque session credential. Only the SHA-256 hash is stored.
// Raw token is returned once to the client (cookie and/or JSON).
type RefreshToken struct {
	ID        string     `gorm:"primaryKey;size:36"`
	UserID    string     `gorm:"size:36;not null;index:idx_refresh_tokens_user"`
	TokenHash string     `gorm:"size:64;not null;uniqueIndex:uq_refresh_token_hash"`
	FamilyID  string     `gorm:"size:36;not null;index:idx_refresh_tokens_family"`
	ExpiresAt time.Time  `gorm:"not null;index:idx_refresh_tokens_expires"`
	RevokedAt *time.Time `gorm:""`
	CreatedAt time.Time  `gorm:"not null"`
}

func (RefreshToken) TableName() string { return "refresh_tokens" }

func (t *RefreshToken) BeforeCreate(tx *gorm.DB) error {
	if t.ID == "" {
		t.ID = uuid.NewString()
	}
	return nil
}

func (t *RefreshToken) Active(now time.Time) bool {
	return t.RevokedAt == nil && now.Before(t.ExpiresAt)
}
