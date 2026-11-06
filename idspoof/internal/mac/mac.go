// Package mac provides MAC address spoofing functionality.
package mac

import (
	"fmt"
	"net"
	"strings"
)

// InterfaceMAC holds an interface name and its MAC address.
type InterfaceMAC struct {
	Name string
	MAC  string // colon-separated hex, e.g. "02:ab:cd:ef:12:34"
}

// Spoofer is the interface for platform-specific MAC operations.
type Spoofer interface {
	ListInterfaces() ([]InterfaceMAC, error)
	Apply(interfaces []InterfaceMAC) ([]InterfaceMAC, error)
	Restore(interfaces []InterfaceMAC) error
	Verify(iface string, expected net.HardwareAddr) error
}

// MergeOriginals combines the originals already saved with the interfaces
// seen now. A saved entry always wins: re-applying while MACs are already
// spoofed must not replace the true hardware address with a spoofed one.
// Interfaces that appeared since (a USB NIC, say) are added.
func MergeOriginals(saved, current []InterfaceMAC) []InterfaceMAC {
	have := make(map[string]bool, len(saved))
	out := make([]InterfaceMAC, 0, len(saved)+len(current))
	for _, i := range saved {
		have[i.Name] = true
		out = append(out, i)
	}
	for _, i := range current {
		if !have[i.Name] {
			out = append(out, i)
		}
	}
	return out
}

// InterfacesToStateString serialises a slice of InterfaceMAC to the bash-
// compatible state format: "eth0:02:ab:cd:ef:12:34;wlan0:02:..."
func InterfacesToStateString(ifaces []InterfaceMAC) string {
	parts := make([]string, 0, len(ifaces))
	for _, i := range ifaces {
		parts = append(parts, i.Name+":"+i.MAC)
	}
	return strings.Join(parts, ";")
}

// InterfacesFromStateString parses the bash-compatible state string.
func InterfacesFromStateString(s string) []InterfaceMAC {
	if s == "" {
		return nil
	}
	entries := strings.Split(s, ";")
	ifaces := make([]InterfaceMAC, 0, len(entries))
	for _, e := range entries {
		// Format: name:XX:XX:XX:XX:XX:XX — split only on first colon.
		idx := strings.IndexByte(e, ':')
		if idx < 0 {
			continue
		}
		name := e[:idx]
		macStr := e[idx+1:]
		if name == "" || macStr == "" {
			continue
		}
		ifaces = append(ifaces, InterfaceMAC{Name: name, MAC: macStr})
	}
	return ifaces
}

// ParseMAC parses a colon-delimited MAC string, returning an error on invalid input.
func ParseMAC(s string) (net.HardwareAddr, error) {
	hw, err := net.ParseMAC(s)
	if err != nil {
		return nil, fmt.Errorf("invalid MAC address %q: %w", s, err)
	}
	return hw, nil
}
