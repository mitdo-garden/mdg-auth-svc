package awskms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/mitdo-garden/mdg-auth-svc/internal/auth"
	"github.com/mitdo-garden/mdg-auth-svc/internal/config"
)

// Signer signs JWTs via AWS KMS asymmetric ECDSA P-256 (private key never leaves KMS).
type Signer struct {
	api    *kms.Client
	cfg    config.KMSConfig
	log    *slog.Logger
	kid    atomic.Value // string
	keyARN atomic.Value // string, resolved key id/arn from GetPublicKey
}

// New builds a KMS client (default AWS credential chain: env, shared config, IAM role).
func New(ctx context.Context, cfg config.KMSConfig, log *slog.Logger) (*Signer, error) {
	if log == nil {
		log = slog.Default()
	}
	if cfg.KeyID == "" {
		return nil, fmt.Errorf("awskms: key_id is required")
	}
	if cfg.Kid == "" {
		cfg.Kid = "kms-1"
	}
	awsCfg, err := loadAWSConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("awskms: %w", err)
	}
	s := &Signer{api: kms.NewFromConfig(awsCfg), cfg: cfg, log: log}
	s.kid.Store(cfg.Kid)
	s.keyARN.Store(cfg.KeyID)
	return s, nil
}

func (s *Signer) ActiveKid() string {
	v, _ := s.kid.Load().(string)
	return v
}

func (s *Signer) Algorithm() string { return "ES256" }

func (s *Signer) keyID() string {
	v, _ := s.keyARN.Load().(string)
	if v != "" {
		return v
	}
	return s.cfg.KeyID
}

// Sign asks KMS to ECDSA-SHA256 the JWT signing input, then converts DER → JOSE (r||s).
func (s *Signer) Sign(ctx context.Context, signingInput string) (kid, alg, sigSegment string, err error) {
	kid = s.ActiveKid()
	alg = s.Algorithm()
	if kid == "" {
		return "", "", "", fmt.Errorf("awskms: empty kid")
	}
	sum := sha256.Sum256([]byte(signingInput))
	out, err := s.api.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(s.keyID()),
		Message:          sum[:],
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return "", "", "", fmt.Errorf("awskms sign: %w", err)
	}
	if len(out.Signature) == 0 {
		return "", "", "", fmt.Errorf("awskms sign: empty signature")
	}
	jose, err := ecdsaDERToJOSE(out.Signature, 32)
	if err != nil {
		return "", "", "", fmt.Errorf("awskms sign: %w", err)
	}
	return kid, alg, base64.RawURLEncoding.EncodeToString(jose), nil
}

// ecdsaDERToJOSE converts an ASN.1 DER ECDSA signature to JWS r||s (fixed-width).
func ecdsaDERToJOSE(der []byte, byteLen int) ([]byte, error) {
	var parsed struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(der, &parsed); err != nil {
		return nil, fmt.Errorf("parse DER ECDSA signature: %w", err)
	}
	if parsed.R == nil || parsed.S == nil {
		return nil, fmt.Errorf("invalid DER ECDSA signature")
	}
	rb := parsed.R.Bytes()
	sb := parsed.S.Bytes()
	if len(rb) > byteLen || len(sb) > byteLen {
		return nil, fmt.Errorf("ECDSA signature component too large")
	}
	out := make([]byte, 2*byteLen)
	copy(out[byteLen-len(rb):byteLen], rb)
	copy(out[2*byteLen-len(sb):], sb)
	return out, nil
}

// LoadPublicKeys fetches the KMS public key into a verify KeyRing.
func (s *Signer) LoadPublicKeys(ctx context.Context) (*auth.KeyRing, error) {
	pub, err := s.fetchPublic(ctx)
	if err != nil {
		return nil, err
	}
	kid := s.ActiveKid()
	return auth.NewPublicKeyRing(kid, map[string]*ecdsa.PublicKey{kid: pub})
}

// ReloadPublicKeys refreshes the ring from KMS (rotation / key replace).
func (s *Signer) ReloadPublicKeys(ctx context.Context, ring *auth.KeyRing) error {
	pub, err := s.fetchPublic(ctx)
	if err != nil {
		return err
	}
	kid := s.ActiveKid()
	return ring.SwapPublics(kid, map[string]*ecdsa.PublicKey{kid: pub})
}

func (s *Signer) fetchPublic(ctx context.Context) (*ecdsa.PublicKey, error) {
	out, err := s.api.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(s.cfg.KeyID),
	})
	if err != nil {
		return nil, fmt.Errorf("awskms get public key: %w", err)
	}
	if out.KeyId != nil && *out.KeyId != "" {
		s.keyARN.Store(*out.KeyId)
	}
	parsed, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("awskms parse public key: %w", err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("awskms: public key is not ECDSA (need ECC_NIST_P256 SIGN_VERIFY key)")
	}
	if pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("awskms: want P-256 curve for ES256, got %s", pub.Curve.Params().Name)
	}
	return pub, nil
}

// StartReloadLoop periodically refreshes the public key until ctx is cancelled.
func (s *Signer) StartReloadLoop(ctx context.Context, ring *auth.KeyRing, interval time.Duration) {
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
			if err := s.ReloadPublicKeys(ctx, ring); err != nil {
				s.log.Error("awskms public key reload failed", "err", err)
				continue
			}
			s.log.Info("awskms public key reloaded", "active_kid", s.ActiveKid())
		}
	}
}
