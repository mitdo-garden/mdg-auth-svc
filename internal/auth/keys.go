package auth

import (
	"crypto/ecdsa"
	"fmt"
	"sync"
)

// KeyMaterial is one ECDSA P-256 public key version identified by kid.
type KeyMaterial struct {
	Kid    string
	Public *ecdsa.PublicKey
}

// KeyRing holds verify keys for JWKS / Parse (active first). Signing is via JWTSigner.
type KeyRing struct {
	mu        sync.RWMutex
	activeKid string
	byKid     map[string]*KeyMaterial
}

func (r *KeyRing) ActiveKid() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.activeKid
}

// PublicForVerify returns the public key for a JWT kid (active or previous).
func (r *KeyRing) PublicForVerify(kid string) (*ecdsa.PublicKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.byKid[kid]
	if !ok || m.Public == nil {
		return nil, fmt.Errorf("%w: unknown kid %q", ErrInvalidToken, kid)
	}
	return m.Public, nil
}

// PublicKeys returns all verify keys for JWKS (order: active first).
func (r *KeyRing) PublicKeys() []*KeyMaterial {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*KeyMaterial, 0, len(r.byKid))
	if active, ok := r.byKid[r.activeKid]; ok {
		out = append(out, active)
	}
	for kid, m := range r.byKid {
		if kid == r.activeKid {
			continue
		}
		out = append(out, m)
	}
	return out
}

// NewPublicKeyRing builds a verify-only ring (Vault Transit / hot-reload).
func NewPublicKeyRing(activeKid string, pubs map[string]*ecdsa.PublicKey) (*KeyRing, error) {
	if activeKid == "" {
		return nil, fmt.Errorf("active kid is required")
	}
	if len(pubs) == 0 {
		return nil, fmt.Errorf("at least one public key is required")
	}
	if pubs[activeKid] == nil {
		return nil, fmt.Errorf("active kid %q missing from public keys", activeKid)
	}
	ring := &KeyRing{
		activeKid: activeKid,
		byKid:     make(map[string]*KeyMaterial, len(pubs)),
	}
	for kid, pub := range pubs {
		if kid == "" || pub == nil {
			return nil, fmt.Errorf("invalid public key entry")
		}
		ring.byKid[kid] = &KeyMaterial{Kid: kid, Public: pub}
	}
	return ring, nil
}

// SwapPublics atomically replaces verify keys and active kid (Vault hot-reload).
func (r *KeyRing) SwapPublics(activeKid string, pubs map[string]*ecdsa.PublicKey) error {
	if activeKid == "" {
		return fmt.Errorf("active kid is required")
	}
	if len(pubs) == 0 {
		return fmt.Errorf("at least one public key is required")
	}
	if pubs[activeKid] == nil {
		return fmt.Errorf("active kid %q missing from public keys", activeKid)
	}
	next := make(map[string]*KeyMaterial, len(pubs))
	for kid, pub := range pubs {
		if kid == "" || pub == nil {
			return fmt.Errorf("invalid public key entry")
		}
		next[kid] = &KeyMaterial{Kid: kid, Public: pub}
	}
	r.mu.Lock()
	r.activeKid = activeKid
	r.byKid = next
	r.mu.Unlock()
	return nil
}
