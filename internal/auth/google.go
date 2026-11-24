package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"google.golang.org/api/idtoken"
)

const (
	googleAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL = "https://oauth2.googleapis.com/token"
	googleScopes   = "openid email profile"
)

var (
	ErrTokenExchange = errors.New("oauth token exchange failed")
	ErrIDTokenVerify = errors.New("google id token verification failed")
)

type googleTokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// GoogleOAuth performs Authorization Code Flow against Google (OIDC).
type GoogleOAuth struct {
	clientID     string
	clientSecret string
	callbackURL  string
	httpClient   *http.Client
}

func NewGoogleOAuth(clientID, clientSecret, callbackURL string) *GoogleOAuth {
	return &GoogleOAuth{
		clientID:     clientID,
		clientSecret: clientSecret,
		callbackURL:  callbackURL,
		httpClient:   &http.Client{Timeout: 15 * time.Second},
	}
}

func (g *GoogleOAuth) Name() string { return ProviderGoogle }

func (g *GoogleOAuth) CallbackURL() string { return g.callbackURL }

// WithCallback returns a copy that exchanges the code against this redirect URI.
func (g *GoogleOAuth) WithCallback(callbackURL string) *GoogleOAuth {
	if strings.TrimSpace(callbackURL) == "" || callbackURL == g.callbackURL {
		return g
	}
	next := *g
	next.callbackURL = callbackURL
	return &next
}

func (g *GoogleOAuth) AuthCodeURL(state string) string {
	q := url.Values{}
	q.Set("client_id", g.clientID)
	q.Set("redirect_uri", g.callbackURL)
	q.Set("response_type", "code")
	q.Set("scope", googleScopes)
	q.Set("state", state)
	q.Set("access_type", "online")
	q.Set("prompt", "select_account")
	return googleAuthURL + "?" + q.Encode()
}

// Exchange trades the auth code for tokens and verifies the ID token.
func (g *GoogleOAuth) Exchange(ctx context.Context, code string) (*Identity, error) {
	if strings.TrimSpace(code) == "" {
		return nil, fmt.Errorf("%w: empty authorization code", ErrTokenExchange)
	}

	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", g.clientID)
	form.Set("client_secret", g.clientSecret)
	form.Set("redirect_uri", g.callbackURL)
	form.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, googleTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %v", ErrTokenExchange, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	res, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: http: %v", ErrTokenExchange, err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %v", ErrTokenExchange, err)
	}

	var token googleTokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("%w: decode json: %v", ErrTokenExchange, err)
	}
	if res.StatusCode != http.StatusOK || token.Error != "" || token.IDToken == "" {
		msg := token.Error
		if token.ErrorDesc != "" {
			msg = token.Error + ": " + token.ErrorDesc
		}
		if msg == "" {
			msg = fmt.Sprintf("status %d", res.StatusCode)
		}
		return nil, fmt.Errorf("%w: %s", ErrTokenExchange, msg)
	}

	payload, err := idtoken.Validate(ctx, token.IDToken, g.clientID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIDTokenVerify, err)
	}

	claims := payload.Claims
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, fmt.Errorf("%w: missing sub", ErrIDTokenVerify)
	}
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	picture, _ := claims["picture"].(string)
	if name == "" {
		name = email
	}
	if name == "" {
		name = "Google account"
	}

	return &Identity{
		Provider:  ProviderGoogle,
		Subject:   sub,
		Email:     email,
		Name:      name,
		AvatarURL: picture,
	}, nil
}
