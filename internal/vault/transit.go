package vault

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mitdo-garden/mdg-auth-svc/internal/auth"
)

// TransitSigner signs JWTs via Vault Transit (private key never leaves Vault).
type TransitSigner struct {
	client *Client
	key    string
	kid    atomic.Value // string, e.g. "v1"
}

func NewTransitSigner(c *Client, keyName string) *TransitSigner {
	s := &TransitSigner{client: c, key: keyName}
	s.kid.Store("")
	return s
}

func (s *TransitSigner) ActiveKid() string {
	v, _ := s.kid.Load().(string)
	return v
}

func (s *TransitSigner) setActiveKid(kid string) { s.kid.Store(kid) }

func kidFromVersion(v int) string { return "v" + strconv.Itoa(v) }

func versionFromKid(kid string) (int, error) {
	kid = strings.TrimSpace(kid)
	if !strings.HasPrefix(kid, "v") {
		return 0, fmt.Errorf("unexpected kid %q", kid)
	}
	n, err := strconv.Atoi(kid[1:])
	if err != nil || n < 1 {
		return 0, fmt.Errorf("unexpected kid %q", kid)
	}
	return n, nil
}

func (s *TransitSigner) Algorithm() string { return "ES256" }

// Sign asks Transit to ECDSA-P256-SHA256 the JWT signing input (JWS marshaling).
func (s *TransitSigner) Sign(ctx context.Context, signingInput string) (kid, alg, sigSegment string, err error) {
	kid = s.ActiveKid()
	alg = s.Algorithm()
	if kid == "" {
		return "", "", "", fmt.Errorf("vault transit: no active kid (keys not loaded)")
	}
	ver, err := versionFromKid(kid)
	if err != nil {
		return "", "", "", err
	}
	// Vault expects standard base64 of the input bytes; it hashes with sha2-256.
	input := base64.StdEncoding.EncodeToString([]byte(signingInput))
	secret, err := s.client.api.Logical().WriteWithContext(ctx, "transit/sign/"+s.key, map[string]any{
		"input":                input,
		"hash_algorithm":       "sha2-256",
		"marshaling_algorithm": "jws",
		"key_version":          ver,
	})
	if err != nil {
		return "", "", "", fmt.Errorf("vault transit sign: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return "", "", "", fmt.Errorf("vault transit sign: empty response")
	}
	raw, _ := secret.Data["signature"].(string)
	sigSeg, err := jwsSignatureSegment(raw)
	if err != nil {
		return "", "", "", err
	}
	return kid, alg, sigSeg, nil
}

// jwsSignatureSegment normalizes Vault's signature field to a JWS segment.
func jwsSignatureSegment(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("vault transit sign: empty signature")
	}
	// vault:vN:<payload> — with marshaling=jws the payload is already base64url.
	if strings.HasPrefix(raw, "vault:") {
		parts := strings.SplitN(raw, ":", 3)
		if len(parts) != 3 || parts[2] == "" {
			return "", fmt.Errorf("vault transit sign: bad signature format")
		}
		return parts[2], nil
	}
	return raw, nil
}

// LoadPublicKeys reads Transit key versions into a public KeyRing and sets active kid.
func (c *Client) LoadPublicKeys() (*auth.KeyRing, error) {
	active, pubs, err := c.fetchTransitPublics()
	if err != nil {
		return nil, err
	}
	ring, err := auth.NewPublicKeyRing(active, pubs)
	if err != nil {
		return nil, err
	}
	c.signer.setActiveKid(active)
	return ring, nil
}

// ReloadPublicKeys refreshes the ring from Transit (rotation without restart).
func (c *Client) ReloadPublicKeys(ring *auth.KeyRing) error {
	active, pubs, err := c.fetchTransitPublics()
	if err != nil {
		return err
	}
	if err := ring.SwapPublics(active, pubs); err != nil {
		return err
	}
	c.signer.setActiveKid(active)
	return nil
}

func (c *Client) fetchTransitPublics() (activeKid string, pubs map[string]*ecdsa.PublicKey, err error) {
	secret, err := c.api.Logical().Read("transit/keys/" + c.cfg.TransitKey)
	if err != nil {
		return "", nil, fmt.Errorf("vault transit read key: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return "", nil, fmt.Errorf("vault transit key %q not found", c.cfg.TransitKey)
	}
	typeName, _ := secret.Data["type"].(string)
	if typeName != "" && typeName != "ecdsa-p256" {
		return "", nil, fmt.Errorf("vault transit key %q type %q (want ecdsa-p256 for ES256)", c.cfg.TransitKey, typeName)
	}
	latest, err := asInt(secret.Data["latest_version"])
	if err != nil || latest < 1 {
		return "", nil, fmt.Errorf("vault transit: bad latest_version")
	}
	keysRaw, ok := secret.Data["keys"].(map[string]any)
	if !ok || len(keysRaw) == 0 {
		return "", nil, fmt.Errorf("vault transit: no key versions")
	}
	pubs = make(map[string]*ecdsa.PublicKey, len(keysRaw))
	for verStr, meta := range keysRaw {
		ver, err := strconv.Atoi(verStr)
		if err != nil {
			continue
		}
		m, ok := meta.(map[string]any)
		if !ok {
			continue
		}
		pemStr, _ := m["public_key"].(string)
		pub, err := parseECDSAPublicPEM(pemStr)
		if err != nil {
			return "", nil, fmt.Errorf("vault transit version %d: %w", ver, err)
		}
		pubs[kidFromVersion(ver)] = pub
	}
	if len(pubs) == 0 {
		return "", nil, fmt.Errorf("vault transit: no usable public keys")
	}
	activeKid = kidFromVersion(latest)
	if pubs[activeKid] == nil {
		return "", nil, fmt.Errorf("vault transit: latest version %d missing public key", latest)
	}
	return activeKid, pubs, nil
}

func asInt(v any) (int, error) {
	switch n := v.(type) {
	case int:
		return n, nil
	case int64:
		return int(n), nil
	case float64:
		return int(n), nil
	case json.Number:
		i64, err := n.Int64()
		return int(i64), err
	default:
		return strconv.Atoi(fmt.Sprint(v))
	}
}

func parseECDSAPublicPEM(pemStr string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not ECDSA public key")
	}
	if pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("want P-256 curve for ES256, got %s", pub.Curve.Params().Name)
	}
	return pub, nil
}

// StartReloadLoop periodically refreshes public keys until ctx is cancelled.
func (c *Client) StartReloadLoop(ctx context.Context, ring *auth.KeyRing, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.ReloadPublicKeys(ring); err != nil {
				c.log.Error("vault transit key reload failed", "err", err)
				continue
			}
			c.log.Info("vault transit keys reloaded", "active_kid", c.signer.ActiveKid())
		}
	}
}
