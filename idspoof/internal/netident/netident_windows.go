//go:build windows

// netident_windows.go — Windows network identity projection via the registry.
//
// Windows exposes TCP/IP stack parameters through the registry under:
//
//	HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
//
// Key values:
//   - DefaultTTL    (DWORD) — IP time-to-live (default 128 on Windows)
//   - Tcp1323Opts   (DWORD) — bitmask: bit 0 = TCP timestamps, bit 1 = window scaling
//
// Changes require a TCP/IP stack restart or reboot to take full effect.
// Unlike Linux sysctl, there is no NFQUEUE equivalent in userspace without
// third-party kernel drivers (WinDivert). Packet-level rewriting is out of
// scope for Phase 6.

package netident

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

const tcpipParamsPath = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`

type windowsSpoofer struct{}

// NewLinuxSpoofer is the shared factory name. On Windows, returns windowsSpoofer.
func NewLinuxSpoofer() Spoofer   { return &windowsSpoofer{} }
func NewWindowsSpoofer() Spoofer { return &windowsSpoofer{} }

// Current reads the active Tcpip\Parameters registry values.
func (s *windowsSpoofer) Current() (*Snapshot, error) {
	ttl, err := winRegGetDWORD(tcpipParamsPath, "DefaultTTL")
	if err != nil {
		ttl = 128 // Windows default
	}

	tcp1323, _ := winRegGetDWORD(tcpipParamsPath, "Tcp1323Opts")
	timestamps := int(tcp1323 & 0x1)
	winscale := int((tcp1323 >> 1) & 0x1)

	return &Snapshot{
		TTL:              ttl,
		TCPTimestamps:    timestamps,
		TCPWindowScaling: winscale,
		TCPSACK:          -1, // not independently settable via Tcpip\Parameters
		TCPECN:           -1,
		TCPRFC1337:       -1,
	}, nil
}

// Apply writes the persona's TCP/IP parameters to the registry.
// Changes take effect after the network stack is restarted (or on reboot).
func (s *windowsSpoofer) Apply(p Persona) error {
	if err := winRegSetDWORD(tcpipParamsPath, "DefaultTTL", uint32(p.TTL)); err != nil {
		return fmt.Errorf("set DefaultTTL: %w", err)
	}

	var tcp1323 uint32
	if p.TCPTimestamps == 1 {
		tcp1323 |= 0x1
	}
	if p.TCPWindowScaling == 1 {
		tcp1323 |= 0x2
	}
	if err := winRegSetDWORD(tcpipParamsPath, "Tcp1323Opts", tcp1323); err != nil {
		return fmt.Errorf("set Tcp1323Opts: %w", err)
	}

	return nil
}

// Restore reverts the Tcpip\Parameters values to the snapshot.
func (s *windowsSpoofer) Restore(snap *Snapshot) error {
	if snap == nil {
		return nil
	}
	if snap.TTL > 0 {
		winRegSetDWORD(tcpipParamsPath, "DefaultTTL", uint32(snap.TTL)) //nolint:errcheck
	}

	var tcp1323 uint32
	if snap.TCPTimestamps == 1 {
		tcp1323 |= 0x1
	}
	if snap.TCPWindowScaling == 1 {
		tcp1323 |= 0x2
	}
	winRegSetDWORD(tcpipParamsPath, "Tcp1323Opts", tcp1323) //nolint:errcheck

	return nil
}

// winRegGetDWORD reads a DWORD value from HKLM.
func winRegGetDWORD(keyPath, valueName string) (int, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.READ)
	if err != nil {
		return 0, fmt.Errorf("open registry key %s: %w", keyPath, err)
	}
	defer k.Close()

	val, _, err := k.GetIntegerValue(valueName)
	if err != nil {
		return 0, fmt.Errorf("get %s\\%s: %w", keyPath, valueName, err)
	}
	return int(val), nil
}

// winRegSetDWORD writes a DWORD value to HKLM.
func winRegSetDWORD(keyPath, valueName string, value uint32) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open registry key %s: %w", keyPath, err)
	}
	defer k.Close()

	if err := k.SetDWordValue(valueName, value); err != nil {
		return fmt.Errorf("set %s\\%s: %w", keyPath, valueName, err)
	}
	return nil
}
