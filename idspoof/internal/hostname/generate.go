package hostname

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

var (
	prefixes = []string{"WIN", "PC", "DESKTOP", "LAPTOP", "SYSTEM", "WORKSTATION"}
	// validHostnameRE matches RFC-compliant hostnames.
	validHostnameRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$`)
)

// GenerateRandom produces a Windows-style random hostname, e.g. "WIN-A3F9KL".
func GenerateRandom() string {
	prefix := pick(prefixes)
	suffix := randomAlphaNum(6)
	return fmt.Sprintf("%s-%s", prefix, suffix)
}

// Validate returns true if name is a valid RFC-1123 hostname.
func Validate(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	if !validHostnameRE.MatchString(name) {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) > 63 {
			return false
		}
	}
	return true
}

func pick(list []string) string {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(list))))
	if err != nil {
		return list[0]
	}
	return list[n.Int64()]
}

func randomAlphaNum(length int) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			b[i] = 'A'
			continue
		}
		b[i] = charset[n.Int64()]
	}
	return string(b)
}
