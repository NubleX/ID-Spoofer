package sysinfo

import (
	"crypto/rand"
	"math/big"
)

var (
	manufacturers = []string{"Dell Inc.", "HP", "Lenovo", "ASUS", "Acer", "Microsoft Corporation"}
	products      = []string{"Latitude", "Inspiron", "ProBook", "ThinkPad", "Surface", "ROG", "Predator"}
	versions      = []string{"A01", "1.0", "2.3.4", "3.1"}
)

// GenerateWindowsInfo produces a random Windows-like hardware profile.
func GenerateWindowsInfo() Info {
	return Info{
		Manufacturer: pick(manufacturers),
		Product:      pick(products),
		Version:      pick(versions),
		Serial:       randomAlphaNum(10),
	}
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
