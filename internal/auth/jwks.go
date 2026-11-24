package auth

import (
	"crypto/ecdsa"
	"encoding/base64"
	"math/big"
)

// JWKS is the JSON Web Key Set published for other services.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK is one ECDSA public key in JWK form (RFC 7517).
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// JWKS builds the public key set. Other services fetch this and verify
// ES256 JWTs without ever seeing private keys.
func (r *KeyRing) JWKS() JWKS {
	mats := r.PublicKeys()
	keys := make([]JWK, 0, len(mats))
	for _, m := range mats {
		if m.Public == nil {
			continue
		}
		keys = append(keys, ecdsaPublicToJWK(m.Kid, m.Public))
	}
	return JWKS{Keys: keys}
}

func ecdsaPublicToJWK(kid string, pub *ecdsa.PublicKey) JWK {
	return JWK{
		Kty: "EC",
		Use: "sig",
		Alg: "ES256",
		Kid: kid,
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(padCoord(pub.X, 32)),
		Y:   base64.RawURLEncoding.EncodeToString(padCoord(pub.Y, 32)),
	}
}

func padCoord(v *big.Int, size int) []byte {
	b := v.Bytes()
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
