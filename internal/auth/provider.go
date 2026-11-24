package auth

import (
	"context"
	"fmt"
)

const (
	ProviderGoogle = "google"
	ProviderGitHub = "github"
)

// Identity is the normalized profile returned by any OAuth provider.
type Identity struct {
	Provider  string // google | github
	Subject   string // stable provider user id (Google sub / GitHub numeric id)
	Email     string // may be empty (e.g. private GitHub email)
	Name      string
	AvatarURL string
}

// OAuthProvider is the Authorization Code Flow surface shared by Google and GitHub.
type OAuthProvider interface {
	Name() string
	AuthCodeURL(state string) string
	Exchange(ctx context.Context, code string) (*Identity, error)
}

// Registry maps provider name → implementation.
type Registry struct {
	providers map[string]OAuthProvider
}

func NewRegistry(providers ...OAuthProvider) *Registry {
	r := &Registry{providers: make(map[string]OAuthProvider, len(providers))}
	for _, p := range providers {
		if p == nil {
			continue
		}
		r.providers[p.Name()] = p
	}
	return r
}

func (r *Registry) Get(name string) (OAuthProvider, error) {
	p, ok := r.providers[name]
	if !ok {
		return nil, fmt.Errorf("unknown or unconfigured oauth provider %q", name)
	}
	return p, nil
}

func (r *Registry) Has(name string) bool {
	_, ok := r.providers[name]
	return ok
}
