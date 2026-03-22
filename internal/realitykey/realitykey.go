// Package realitykey generates X25519 key material compatible with Xray REALITY
// (same algorithm as `xray x25519`: RawURLEncoding, clamped scalar).
package realitykey

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
)

// Pair holds server private key and client public key (pbk) as base64.RawURLEncoding strings.
type Pair struct {
	PrivateKey string
	PublicKey  string
}

// Generate returns a fresh REALITY key pair.
func Generate() (Pair, error) {
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return Pair{}, err
	}
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	key, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return Pair{}, err
	}
	pub := key.PublicKey().Bytes()

	enc := base64.RawURLEncoding
	return Pair{
		PrivateKey: enc.EncodeToString(privateKey),
		PublicKey:  enc.EncodeToString(pub),
	}, nil
}
