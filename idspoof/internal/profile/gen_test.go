package profile

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestWGPublicFromPrivateKnownAnswer(t *testing.T) {
	// RFC 7748 section 6.1, Alice's key pair.
	priv, _ := hex.DecodeString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	want, _ := hex.DecodeString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	got, err := WGPublicFromPrivate(base64.StdEncoding.EncodeToString(priv))
	if err != nil {
		t.Fatal(err)
	}
	if got != base64.StdEncoding.EncodeToString(want) {
		t.Errorf("public key = %s; want RFC 7748 vector", got)
	}
}

func TestNewWGKeypair(t *testing.T) {
	priv, pub, err := NewWGKeypair()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(priv)
	if err != nil || len(raw) != 32 {
		t.Fatalf("private key is not 32 base64 bytes: %v", err)
	}
	if raw[0]&7 != 0 || raw[31]&128 != 0 || raw[31]&64 == 0 {
		t.Errorf("private key is not clamped: % x ... % x", raw[0], raw[31])
	}
	if again, _ := WGPublicFromPrivate(priv); again != pub {
		t.Errorf("public key does not match private key")
	}
	if priv2, _, _ := NewWGKeypair(); priv2 == priv {
		t.Errorf("two keypairs were identical")
	}
	// The generated key must be accepted by the WireGuard preset.
	for _, p := range allPresets() {
		if p.ID != "wg-client" {
			continue
		}
		v := sampleValues(p)
		v["privkey"], v["pubkey"] = priv, pub
		if _, err := p.Render(v); err != nil {
			t.Errorf("generated keys rejected by the preset: %v", err)
		}
	}
}

func TestRandomPassword(t *testing.T) {
	a, err := RandomPassword(24)
	if err != nil || len(a) != 24 {
		t.Fatalf("RandomPassword(24) = %q, %v", a, err)
	}
	if b, _ := RandomPassword(24); a == b {
		t.Errorf("two passwords were identical")
	}
	for _, c := range a {
		if !containsRune(passwordAlphabet, c) {
			t.Errorf("unexpected character %q", c)
		}
	}
	for _, bad := range []int{0, -1, 129} {
		if _, err := RandomPassword(bad); err == nil {
			t.Errorf("length %d accepted", bad)
		}
	}
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}

func TestRandomSSKey(t *testing.T) {
	cases := map[string]int{
		"2022-blake3-aes-128-gcm":       16,
		"2022-blake3-aes-256-gcm":       32,
		"2022-blake3-chacha20-poly1305": 32,
	}
	for method, size := range cases {
		k, err := RandomSSKey(method)
		raw, derr := base64.StdEncoding.DecodeString(k)
		if err != nil || derr != nil || len(raw) != size {
			t.Errorf("%s: key %q is not %d base64 bytes", method, k, size)
		}
	}
	if k, _ := RandomSSKey("chacha20-ietf-poly1305"); len(k) != 24 {
		t.Errorf("classic cipher should get a 24-char password, got %q", k)
	}
}

func TestRandomNameIsValid(t *testing.T) {
	for i := 0; i < 50; i++ {
		if n := RandomName("tmp"); !ValidName(n) {
			t.Fatalf("%q is not a valid profile name", n)
		}
	}
	if !ValidName(RandomName("")) {
		t.Errorf("empty prefix should fall back to tmp")
	}
}
