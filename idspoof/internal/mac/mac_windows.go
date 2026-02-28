//go:build windows

// mac_windows.go — Windows MAC address spoofing via the registry.
//
// On Windows, MAC addresses are changed by writing the "NetworkAddress" value
// (as REG_SZ, without colons) to the adapter's class registry key under:
//
//	HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-...}\<index>\NetworkAddress
//
// After writing, the adapter must be disabled and re-enabled for the change to
// take effect. We use `netsh interface set interface` for that since it doesn't
// require PowerShell.
//
// Finding the registry subkey for a named adapter requires correlating the
// adapter name (e.g. "Ethernet") with the registry index (e.g. "0005").
// We do this by checking the "DriverDesc" value in each subkey.

package mac

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	adapterClassKeyPath = `SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}`
)

type windowsSpoofer struct{}

// NewLinuxSpoofer is the shared factory name. On Windows, returns windowsSpoofer.
func NewLinuxSpoofer() Spoofer   { return &windowsSpoofer{} }
func NewWindowsSpoofer() Spoofer { return &windowsSpoofer{} }

// ListInterfaces uses `netsh interface show interface` to enumerate adapters,
// then reads each adapter's current MAC from `ipconfig /all`.
func (s *windowsSpoofer) ListInterfaces() ([]InterfaceMAC, error) {
	out, err := exec.Command("netsh", "interface", "show", "interface").Output()
	if err != nil {
		return nil, fmt.Errorf("netsh interface show interface: %w", err)
	}

	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		// Lines look like: "Enabled  Connected  Dedicated  Ethernet"
		fields := strings.Fields(line)
		if len(fields) >= 4 && strings.EqualFold(fields[0], "enabled") {
			names = append(names, fields[len(fields)-1])
		}
	}

	if len(names) == 0 {
		return nil, fmt.Errorf("no enabled network interfaces found")
	}

	// Get MACs from ipconfig /all.
	macMap, err := windowsMACMap()
	if err != nil {
		return nil, fmt.Errorf("reading MACs: %w", err)
	}

	var ifaces []InterfaceMAC
	for _, name := range names {
		mac, ok := macMap[strings.ToLower(name)]
		if !ok {
			continue
		}
		ifaces = append(ifaces, InterfaceMAC{Name: name, MAC: mac})
	}
	return ifaces, nil
}

// Apply writes a new MAC to the registry for each interface and bounces the adapter.
func (s *windowsSpoofer) Apply(origIfaces []InterfaceMAC) ([]InterfaceMAC, error) {
	var applied []InterfaceMAC

	for _, iface := range origIfaces {
		newMAC := GenerateRandom()
		if err := setWindowsMAC(iface.Name, newMAC); err != nil {
			// Roll back already-applied changes.
			for _, a := range applied {
				setWindowsMAC(a.Name, iface.MAC) //nolint:errcheck
			}
			return nil, fmt.Errorf("set MAC on %s: %w", iface.Name, err)
		}
		applied = append(applied, InterfaceMAC{Name: iface.Name, MAC: newMAC})
	}

	return applied, nil
}

// Restore sets each interface back to its original MAC.
func (s *windowsSpoofer) Restore(ifaces []InterfaceMAC) error {
	var errs []string
	for _, iface := range ifaces {
		if err := setWindowsMAC(iface.Name, iface.MAC); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", iface.Name, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("restore errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// Verify reads the current MAC of iface via ipconfig and compares to expected.
func (s *windowsSpoofer) Verify(iface string, expected net.HardwareAddr) error {
	macMap, err := windowsMACMap()
	if err != nil {
		return fmt.Errorf("reading MACs: %w", err)
	}
	got, ok := macMap[strings.ToLower(iface)]
	if !ok {
		return fmt.Errorf("interface %s not found in ipconfig output", iface)
	}
	parsedGot, err := net.ParseMAC(strings.ReplaceAll(got, "-", ":"))
	if err != nil {
		return fmt.Errorf("parse MAC %q: %w", got, err)
	}
	if parsedGot.String() != expected.String() {
		return fmt.Errorf("MAC mismatch on %s: got %s, want %s", iface, parsedGot, expected)
	}
	return nil
}

// setWindowsMAC writes NetworkAddress to the adapter's registry key and
// disables/re-enables the adapter for the change to take effect.
func setWindowsMAC(ifaceName, newMAC string) error {
	// Find the registry subkey index for this adapter.
	subkeyIndex, err := findAdapterSubkeyIndex(ifaceName)
	if err != nil {
		return fmt.Errorf("find adapter registry key for %q: %w", ifaceName, err)
	}

	// Write NetworkAddress (no colons or dashes — Windows accepts bare hex).
	bare := strings.ReplaceAll(strings.ReplaceAll(newMAC, ":", ""), "-", "")
	keyPath := fmt.Sprintf(`%s\%s`, adapterClassKeyPath, subkeyIndex)
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open registry key %s: %w", keyPath, err)
	}
	defer k.Close()

	if err := k.SetStringValue("NetworkAddress", bare); err != nil {
		return fmt.Errorf("set NetworkAddress: %w", err)
	}

	// Bounce the adapter: disable then enable.
	exec.Command("netsh", "interface", "set", "interface", ifaceName, "disabled").Run() //nolint:errcheck
	exec.Command("netsh", "interface", "set", "interface", ifaceName, "enabled").Run()  //nolint:errcheck
	return nil
}

// findAdapterSubkeyIndex enumerates adapter class registry subkeys and returns
// the zero-padded index (e.g. "0005") whose DriverDesc matches ifaceName.
func findAdapterSubkeyIndex(ifaceName string) (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, adapterClassKeyPath, registry.READ)
	if err != nil {
		return "", fmt.Errorf("open adapter class key: %w", err)
	}
	defer k.Close()

	subkeys, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return "", fmt.Errorf("list adapter subkeys: %w", err)
	}

	for _, sub := range subkeys {
		subPath := fmt.Sprintf(`%s\%s`, adapterClassKeyPath, sub)
		sk, err := registry.OpenKey(registry.LOCAL_MACHINE, subPath, registry.READ)
		if err != nil {
			continue
		}
		desc, _, err := sk.GetStringValue("DriverDesc")
		sk.Close()
		if err != nil {
			continue
		}
		if strings.EqualFold(desc, ifaceName) {
			return sub, nil
		}
	}
	return "", fmt.Errorf("adapter %q not found in registry", ifaceName)
}

// windowsMACMap parses `ipconfig /all` to build a lowercase-name → MAC map.
func windowsMACMap() (map[string]string, error) {
	out, err := exec.Command("ipconfig", "/all").Output()
	if err != nil {
		return nil, fmt.Errorf("ipconfig /all: %w", err)
	}

	result := make(map[string]string)
	var currentAdapter string

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimRight(line, "\r")

		// Adapter header: "Ethernet adapter Ethernet:" or "Wireless LAN adapter Wi-Fi:"
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(strings.TrimSpace(line), ":") {
			// Extract adapter name: remove leading "Ethernet adapter " etc.
			name := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), ":"))
			for _, prefix := range []string{"Ethernet adapter ", "Wireless LAN adapter ", "Tunnel adapter "} {
				name = strings.TrimPrefix(name, prefix)
			}
			currentAdapter = strings.ToLower(name)
			continue
		}

		// MAC line: "   Physical Address. . . . . . . . . : AA-BB-CC-DD-EE-FF"
		if currentAdapter != "" && strings.Contains(line, "Physical Address") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				mac := strings.TrimSpace(parts[1])
				result[currentAdapter] = mac
			}
		}
	}

	return result, nil
}
