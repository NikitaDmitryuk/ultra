// Package subscriptionkey encrypts recoverable subscription credentials. Keys never live in the database.
package subscriptionkey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
)

var ErrUnavailable = errors.New("subscription encryption key unavailable")

type Ring struct {
	Active string            `json:"active"`
	Keys   map[string]string `json:"keys"`
}

func Load(path string) (*Ring, error) {
	if path == "" {
		return nil, ErrUnavailable
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm()&0007 != 0 {
		return nil, ErrUnavailable
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrUnavailable
	}
	var r Ring
	if json.Unmarshal(data, &r) != nil {
		return nil, ErrUnavailable
	}
	if _, err = r.aead(r.Active); err != nil {
		return nil, err
	}
	return &r, nil
}
func (r *Ring) aead(version string) (cipher.AEAD, error) {
	if r == nil || version == "" {
		return nil, ErrUnavailable
	}
	key, err := base64.StdEncoding.DecodeString(r.Keys[version])
	if err != nil || len(key) != 32 {
		return nil, ErrUnavailable
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrUnavailable
	}
	return cipher.NewGCM(block)
}
func (r *Ring) Seal(owner, secret string) ([]byte, string, error) {
	if r == nil {
		return nil, "", ErrUnavailable
	}
	a, err := r.aead(r.Active)
	if err != nil {
		return nil, "", err
	}
	nonce := make([]byte, a.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, "", err
	}
	return a.Seal(nonce, nonce, []byte(secret), []byte(owner)), r.Active, nil
}
func (r *Ring) Open(owner string, data []byte, version string) (string, error) {
	a, err := r.aead(version)
	if err != nil {
		return "", err
	}
	if len(data) < a.NonceSize() {
		return "", ErrUnavailable
	}
	plain, err := a.Open(nil, data[:a.NonceSize()], data[a.NonceSize():], []byte(owner))
	if err != nil {
		return "", ErrUnavailable
	}
	return string(plain), nil
}
