package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// User is the durable garden owner. Google and GitHub identities can link to
// the same row when emails match (Mitdo contract).
type User struct {
	ID             string    `gorm:"primaryKey;size:36" json:"id"`
	GoogleID       *string   `gorm:"size:255;uniqueIndex:uq_users_google_id" json:"googleId"`
	GithubID       *string   `gorm:"size:255;uniqueIndex:uq_users_github_id" json:"githubId"`
	Email          string    `gorm:"size:320;not null;default:'';index:idx_users_email" json:"email"`
	FullName       string    `gorm:"size:255;not null;default:''" json:"fullName"`
	ProfilePicture *string   `gorm:"size:2048" json:"profilePicture"`
	LastProvider   string    `gorm:"size:32;not null;default:google" json:"lastProvider"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

func (User) TableName() string { return "users" }

func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	return nil
}

// PublicID is the stable garden account id (UUID).
func (u *User) PublicID() string {
	return u.ID
}

// PublicProfile is the JSON shape returned to the browser / API clients.
type PublicProfile struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Email     *string `json:"email"`
	AvatarURL *string `json:"avatarUrl"`
	Provider  string  `json:"provider"`
}

func (u *User) ToPublic() PublicProfile {
	var email *string
	if u.Email != "" {
		e := u.Email
		email = &e
	}
	provider := u.LastProvider
	if provider == "" {
		provider = "google"
	}
	return PublicProfile{
		ID:        u.PublicID(),
		Name:      u.FullName,
		Email:     email,
		AvatarURL: u.ProfilePicture,
		Provider:  provider,
	}
}
