package profile

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// Generators for throwaway credentials. All randomness comes from crypto/rand.

const passwordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

// NewWGKeypair returns a WireGuard private and public key (base64), formatted
// like `wg genkey` / `wg pubkey` (private key clamped per RFC 7748).
func NewWGKeypair() (priv, pub string, err error) {
	var k [32]byte
	if _, err = rand.Read(k[:]); err != nil {
		return "", "", err
	}
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	priv = base64.StdEncoding.EncodeToString(k[:])
	pub, err = WGPublicFromPrivate(priv)
	return priv, pub, err
}

// WGPublicFromPrivate derives the public key for a base64 private key.
func WGPublicFromPrivate(priv string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(priv)
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("private key must be 32 bytes of base64")
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// RandomPassword returns n random characters without look-alike glyphs.
func RandomPassword(n int) (string, error) {
	if n < 1 || n > 128 {
		return "", fmt.Errorf("length must be 1-128")
	}
	var b strings.Builder
	max := big.NewInt(int64(len(passwordAlphabet)))
	for i := 0; i < n; i++ {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b.WriteByte(passwordAlphabet[idx.Int64()])
	}
	return b.String(), nil
}

// RandomSSKey returns a Shadowsocks secret suited to the cipher: a base64 key
// of the exact size for the 2022 ciphers, an ordinary password otherwise.
func RandomSSKey(method string) (string, error) {
	size := 0
	switch method {
	case "2022-blake3-aes-128-gcm":
		size = 16
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		size = 32
	}
	if size == 0 {
		return RandomPassword(24)
	}
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// RandomName returns a throwaway profile name such as "tmp-3fa91c".
func RandomName(prefix string) string {
	raw := make([]byte, 3)
	if _, err := rand.Read(raw); err != nil {
		raw = []byte{0, 0, 0}
	}
	if prefix == "" {
		prefix = "tmp"
	}
	return prefix + "-" + hex.EncodeToString(raw)
}
