package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	githubAuthURL  = "https://github.com/login/oauth/authorize"
	githubTokenURL = "https://github.com/login/oauth/access_token"
	githubUserURL  = "https://api.github.com/user"
	githubEmailURL = "https://api.github.com/user/emails"
	githubScopes   = "read:user user:email"
)

// GitHubOAuth performs Authorization Code Flow against GitHub.
type GitHubOAuth struct {
	clientID     string
	clientSecret string
	callbackURL  string
	httpClient   *http.Client
}

func NewGitHubOAuth(clientID, clientSecret, callbackURL string) *GitHubOAuth {
	return &GitHubOAuth{
		clientID:     clientID,
		clientSecret: clientSecret,
		callbackURL:  callbackURL,
		httpClient:   &http.Client{Timeout: 15 * time.Second},
	}
}

func (g *GitHubOAuth) Name() string { return ProviderGitHub }

func (g *GitHubOAuth) CallbackURL() string { return g.callbackURL }

// WithCallback returns a copy that exchanges the code against this redirect URI.
func (g *GitHubOAuth) WithCallback(callbackURL string) *GitHubOAuth {
	if strings.TrimSpace(callbackURL) == "" || callbackURL == g.callbackURL {
		return g
	}
	next := *g
	next.callbackURL = callbackURL
	return &next
}

func (g *GitHubOAuth) AuthCodeURL(state string) string {
	q := url.Values{}
	q.Set("client_id", g.clientID)
	q.Set("redirect_uri", g.callbackURL)
	q.Set("scope", githubScopes)
	q.Set("state", state)
	return githubAuthURL + "?" + q.Encode()
}

func (g *GitHubOAuth) Exchange(ctx context.Context, code string) (*Identity, error) {
	if strings.TrimSpace(code) == "" {
		return nil, fmt.Errorf("%w: empty authorization code", ErrTokenExchange)
	}

	accessToken, err := g.exchangeCode(ctx, code)
	if err != nil {
		return nil, err
	}

	user, err := g.fetchUser(ctx, accessToken)
	if err != nil {
		return nil, err
	}

	email := user.Email
	if email == "" {
		email, _ = g.fetchPrimaryEmail(ctx, accessToken)
	}

	name := user.Name
	if name == "" {
		name = user.Login
	}
	if name == "" {
		name = "GitHub account"
	}

	return &Identity{
		Provider:  ProviderGitHub,
		Subject:   strconv.FormatInt(user.ID, 10),
		Email:     email,
		Name:      name,
		AvatarURL: user.AvatarURL,
	}, nil
}

type githubTokenResponse struct {
	AccessToken string `json:"access_token"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

func (g *GitHubOAuth) exchangeCode(ctx context.Context, code string) (string, error) {
	form := url.Values{}
	form.Set("client_id", g.clientID)
	form.Set("client_secret", g.clientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", g.callbackURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, githubTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("%w: build request: %v", ErrTokenExchange, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	res, err := g.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: http: %v", ErrTokenExchange, err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("%w: read body: %v", ErrTokenExchange, err)
	}

	var token githubTokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return "", fmt.Errorf("%w: decode json: %v", ErrTokenExchange, err)
	}
	if res.StatusCode != http.StatusOK || token.Error != "" || token.AccessToken == "" {
		msg := token.Error
		if token.ErrorDesc != "" {
			msg = token.Error + ": " + token.ErrorDesc
		}
		if msg == "" {
			msg = fmt.Sprintf("status %d", res.StatusCode)
		}
		return "", fmt.Errorf("%w: %s", ErrTokenExchange, msg)
	}
	return token.AccessToken, nil
}

type githubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

func (g *GitHubOAuth) fetchUser(ctx context.Context, accessToken string) (*githubUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubUserURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build user request: %v", ErrTokenExchange, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	res, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: user http: %v", ErrTokenExchange, err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: read user: %v", ErrTokenExchange, err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: user status %d", ErrTokenExchange, res.StatusCode)
	}

	var user githubUser
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("%w: decode user: %v", ErrTokenExchange, err)
	}
	if user.ID == 0 {
		return nil, fmt.Errorf("%w: missing github user id", ErrTokenExchange)
	}
	return &user, nil
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func (g *GitHubOAuth) fetchPrimaryEmail(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubEmailURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	res, err := g.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("emails status %d", res.StatusCode)
	}

	var emails []githubEmail
	if err := json.Unmarshal(body, &emails); err != nil {
		return "", err
	}
	var fallback string
	for _, e := range emails {
		if !e.Verified || e.Email == "" {
			continue
		}
		if e.Primary {
			return e.Email, nil
		}
		if fallback == "" {
			fallback = e.Email
		}
	}
	return fallback, nil
}
