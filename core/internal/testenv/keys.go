// Package testenv starts in-process VPN servers (AmneziaWG and VLESS +
// REALITY) and plain test services for end-to-end tests.
package testenv

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
)

// X25519 returns a private/public key pair as raw bytes.
func X25519() (priv, pub []byte) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return k.Bytes(), k.PublicKey().Bytes()
}

func b64(b []byte) string    { return base64.StdEncoding.EncodeToString(b) }
func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
