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

	macPrefixes = []string{"MacBook-Pro", "MacBook-Air", "iMac", "Mac-mini", "Mac-Studio", "Mac-Pro"}
	iosPrefixes = []string{"iPhone", "iPad"}
	// Common first names for Apple-style hostnames ("Admins-MacBook-Pro").
	appleNames = []string{"Admin", "User", "Guest", "Office", "Home", "Work", "Dev"}

	// Linux distro-style hostnames: "distro-descriptor" patterns typical of
	// default installs. Installer-generated or user-set during setup.
	linuxHostnames = []string{
		// Ubuntu/Debian style
		"ubuntu-desktop", "ubuntu-laptop", "ubuntu-server",
		"debian-pc", "debian-laptop", "debian-workstation",
		// Fedora/RHEL style
		"fedora-workstation", "fedora-laptop", "fedora-desktop",
		"localhost-localdomain",
		// Arch/Manjaro style
		"archlinux", "arch-desktop", "arch-laptop",
		"manjaro-desktop", "manjaro-laptop",
		// Mint/Pop!_OS/EndeavourOS
		"mint-desktop", "mint-laptop",
		"pop-os", "endeavouros",
		// Generic
		"linux-desktop", "linux-laptop", "workstation",
		"thinkpad", "latitude", "xps-laptop", "spectre-laptop",
	}
)

// GenerateRandom produces a Windows-style random hostname, e.g. "WIN-A3F9KL".
func GenerateRandom() string {
	prefix := pick(prefixes)
	suffix := randomAlphaNum(6)
	return fmt.Sprintf("%s-%s", prefix, suffix)
}

// GenerateRandomMacOS produces a macOS-style hostname, e.g. "Admins-MacBook-Pro".
func GenerateRandomMacOS() string {
	name := pick(appleNames)
	model := pick(macPrefixes)
	return fmt.Sprintf("%ss-%s", name, model)
}

// GenerateRandomIOS produces an iOS-style hostname, e.g. "Admins-iPhone".
func GenerateRandomIOS() string {
	name := pick(appleNames)
	device := pick(iosPrefixes)
	return fmt.Sprintf("%ss-%s", name, device)
}

// GenerateRandomLinux produces a hostname matching common Linux distro naming
// patterns used by default installers (Ubuntu, Fedora, Arch, Debian, etc.).
func GenerateRandomLinux() string {
	return pick(linuxHostnames)
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
