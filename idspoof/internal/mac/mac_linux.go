//go:build linux

package mac

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
)

var macRegex = regexp.MustCompile(`([0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}`)

type linuxSpoofer struct{}

// NewLinuxSpoofer returns the Linux MAC spoofer.
func NewLinuxSpoofer() Spoofer { return &linuxSpoofer{} }

// ListInterfaces returns all non-loopback interfaces and their current MACs.
func (s *linuxSpoofer) ListInterfaces() ([]InterfaceMAC, error) {
	out, err := exec.Command("ip", "-o", "link", "show").Output()
	if err != nil {
		return nil, fmt.Errorf("ip link show: %w", err)
	}

	var ifaces []InterfaceMAC
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			continue
		}
		// Format: "2: eth0: <FLAGS> mtu ... link/ether 02:... brd ..."
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimSuffix(fields[1], ":")
		if name == "lo" || strings.HasPrefix(name, "lo@") {
			continue
		}

		macStr := currentMAC(name)
		if macStr == "" {
			continue
		}
		ifaces = append(ifaces, InterfaceMAC{Name: name, MAC: macStr})
	}
	return ifaces, nil
}

// Apply brings each interface down, changes its MAC, and brings it back up.
// On failure it attempts to restore the original MACs.
func (s *linuxSpoofer) Apply(origIfaces []InterfaceMAC) ([]InterfaceMAC, error) {
	hasNMCLI := commandExists("nmcli")

	// Disconnect from NetworkManager before taking interfaces down.
	if hasNMCLI {
		for _, iface := range origIfaces {
			exec.Command("nmcli", "device", "disconnect", iface.Name).Run()
		}
	}

	// Bring all interfaces down.
	for _, iface := range origIfaces {
		exec.Command("ip", "link", "set", iface.Name, "down").Run()
	}

	// Change MACs, collect results.
	var changed []InterfaceMAC
	var failed bool
	for _, iface := range origIfaces {
		newMAC := GenerateRandom()
		if err := exec.Command("macchanger", "-m", newMAC, iface.Name).Run(); err != nil {
			failed = true
			break
		}

		hw, _ := net.ParseMAC(newMAC)
		if err := s.Verify(iface.Name, hw); err != nil {
			failed = true
			break
		}
		changed = append(changed, InterfaceMAC{Name: iface.Name, MAC: newMAC})
	}

	if failed {
		// Rollback.
		s.Restore(origIfaces)
		// Bring interfaces back up anyway.
		for _, iface := range origIfaces {
			exec.Command("ip", "link", "set", iface.Name, "up").Run()
		}
		return nil, fmt.Errorf("MAC change failed; original addresses restored")
	}

	// Bring interfaces back up.
	for _, iface := range origIfaces {
		exec.Command("ip", "link", "set", iface.Name, "up").Run()
		if hasNMCLI {
			exec.Command("nmcli", "device", "connect", iface.Name).Run()
		}
	}

	return changed, nil
}

// Restore sets each interface back to its saved MAC.
func (s *linuxSpoofer) Restore(ifaces []InterfaceMAC) error {
	var lastErr error
	for _, iface := range ifaces {
		exec.Command("ip", "link", "set", iface.Name, "down").Run()
		if err := exec.Command("macchanger", "-m", iface.MAC, iface.Name).Run(); err != nil {
			lastErr = fmt.Errorf("restore MAC for %s: %w", iface.Name, err)
			continue
		}
		exec.Command("ip", "link", "set", iface.Name, "up").Run()
	}
	return lastErr
}

// Verify reads the current MAC of iface and compares it to expected.
func (s *linuxSpoofer) Verify(iface string, expected net.HardwareAddr) error {
	current := currentMAC(iface)
	if current == "" {
		return fmt.Errorf("could not read MAC for interface %s", iface)
	}
	if !strings.EqualFold(current, expected.String()) {
		return fmt.Errorf("MAC mismatch on %s: expected %s, got %s", iface, expected, current)
	}
	return nil
}

// currentMAC reads the current MAC of an interface via `ip link show`.
func currentMAC(iface string) string {
	out, err := exec.Command("ip", "link", "show", iface).Output()
	if err != nil {
		return ""
	}
	m := macRegex.FindString(string(out))
	return m
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
