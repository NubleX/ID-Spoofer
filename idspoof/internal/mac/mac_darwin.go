//go:build darwin

package mac

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

type darwinSpoofer struct{}

// NewLinuxSpoofer is the shared factory name used by platform.linuxPlatform.
// On Darwin, this returns the darwinSpoofer.
func NewLinuxSpoofer() Spoofer  { return &darwinSpoofer{} }
func NewDarwinSpoofer() Spoofer { return &darwinSpoofer{} }

// ListInterfaces parses `ifconfig -a` to enumerate physical network interfaces.
// Skips loopback (lo0), virtual tunnels (utun*, gif*, stf*), bridges, and
// awdl/llw interfaces. Only returns interfaces that have an ether (MAC) line.
func (s *darwinSpoofer) ListInterfaces() ([]InterfaceMAC, error) {
	out, err := exec.Command("ifconfig", "-a").Output()
	if err != nil {
		return nil, fmt.Errorf("ifconfig -a: %w", err)
	}

	var ifaces []InterfaceMAC
	var currentName string

	for _, line := range strings.Split(string(out), "\n") {
		// Interface header: "en0: flags=8863<UP,BROADCAST,...> mtu 1500"
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			colonIdx := strings.Index(line, ":")
			if colonIdx > 0 {
				currentName = line[:colonIdx]
			}
			continue
		}

		// Skip interfaces we don't want to touch.
		if currentName == "" {
			continue
		}
		if skipDarwinIface(currentName) {
			continue
		}

		// MAC address line: "\tether aa:bb:cc:dd:ee:ff"
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "ether ") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				ifaces = append(ifaces, InterfaceMAC{
					Name: currentName,
					MAC:  parts[1],
				})
			}
		}
	}

	if len(ifaces) == 0 {
		return nil, fmt.Errorf("no eligible network interfaces found")
	}
	return ifaces, nil
}

// Apply randomises the MAC address on each interface using `ifconfig <iface> ether <mac>`.
// Returns the list of new (interface, newMAC) pairs so the caller can save them
// for Restore. On failure mid-way, already-applied interfaces are rolled back.
func (s *darwinSpoofer) Apply(origIfaces []InterfaceMAC) ([]InterfaceMAC, error) {
	var applied []InterfaceMAC

	for _, iface := range origIfaces {
		newMAC := GenerateRandom()
		if err := exec.Command("ifconfig", iface.Name, "ether", newMAC).Run(); err != nil {
			// Roll back already-applied changes before returning.
			for _, a := range applied {
				exec.Command("ifconfig", a.Name, "ether", iface.MAC).Run() //nolint:errcheck
			}
			return nil, fmt.Errorf("set MAC on %s: %w", iface.Name, err)
		}
		applied = append(applied, InterfaceMAC{Name: iface.Name, MAC: newMAC})
	}

	return applied, nil
}

// Restore sets each interface back to its original MAC address.
func (s *darwinSpoofer) Restore(ifaces []InterfaceMAC) error {
	var errs []string
	for _, iface := range ifaces {
		if err := exec.Command("ifconfig", iface.Name, "ether", iface.MAC).Run(); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", iface.Name, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("restore errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// Verify reads the current MAC of iface via `ifconfig` and compares it to expected.
func (s *darwinSpoofer) Verify(iface string, expected net.HardwareAddr) error {
	out, err := exec.Command("ifconfig", iface).Output()
	if err != nil {
		return fmt.Errorf("ifconfig %s: %w", iface, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "ether ") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				got, err := net.ParseMAC(parts[1])
				if err != nil {
					return fmt.Errorf("parse MAC %q: %w", parts[1], err)
				}
				if got.String() != expected.String() {
					return fmt.Errorf("MAC mismatch on %s: got %s, want %s",
						iface, got, expected)
				}
				return nil
			}
		}
	}
	return fmt.Errorf("no ether line found for interface %s", iface)
}

// skipDarwinIface returns true for interfaces that should not be touched.
func skipDarwinIface(name string) bool {
	skip := []string{"lo", "utun", "gif", "stf", "bridge", "awdl", "llw", "ap", "p2p"}
	for _, prefix := range skip {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
