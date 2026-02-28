//go:build darwin

// netident_darwin.go — macOS network identity projection.
//
// macOS does not have iptables or NFQUEUE so the five-layer Linux approach
// is not available. This implementation covers what is achievable without
// kernel extensions or SIP bypass:
//
//  1. sysctl: net.inet.ip.ttl (TTL is writable; TCP timestamps/window scaling
//     are kernel-managed on macOS and not writable via sysctl).
//  2. DHCP hostname: announced via `networksetup -setcomputername` which
//     updates the ComputerName used in DHCP Option 12.
//  3. mDNS/Bonjour: left running (mDNSResponder is tightly integrated;
//     stopping it breaks too many system services).
//
// Packet-level fingerprint rewriting (IP ID, TCP options order) requires
// PF (macOS packet filter) or a kernel extension — out of scope for Phase 5.

package netident

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type darwinSpoofer struct{}

// NewLinuxSpoofer is the shared factory name. On Darwin, returns darwinSpoofer.
func NewLinuxSpoofer() Spoofer  { return &darwinSpoofer{} }
func NewDarwinSpoofer() Spoofer { return &darwinSpoofer{} }

// Current reads the macOS sysctl values we can inspect. TCP timestamp and
// window-scaling fields return -1 (not independently readable on macOS).
func (s *darwinSpoofer) Current() (*Snapshot, error) {
	ttl, err := darwinSysctlGetInt("net.inet.ip.ttl")
	if err != nil {
		ttl = 64 // macOS default
	}
	return &Snapshot{
		TTL:              ttl,
		TCPTimestamps:    -1, // not independently readable on macOS
		TCPWindowScaling: -1,
		TCPSACK:          -1,
		TCPECN:           -1,
		TCPRFC1337:       -1,
	}, nil
}

// Apply sets TTL via sysctl and announces the persona hostname via networksetup.
// No iptables/NFQUEUE — partial fingerprint only (TTL + DHCP hostname).
func (s *darwinSpoofer) Apply(p Persona) error {
	var errs []string

	// Layer 1: TTL via sysctl.
	if err := darwinSysctlSetInt("net.inet.ip.ttl", p.TTL); err != nil {
		errs = append(errs, fmt.Sprintf("sysctl ttl: %v", err))
	}

	// Layer 2: DHCP/ComputerName hostname via networksetup.
	// networksetup -setcomputername sets the Bonjour/DHCP name.
	if p.Hostname != "" {
		if err := exec.Command("networksetup", "-setcomputername", p.Hostname).Run(); err != nil {
			errs = append(errs, fmt.Sprintf("networksetup -setcomputername: %v", err))
		}
		// Also update the local hostname used by mDNS.
		exec.Command("scutil", "--set", "LocalHostName", p.Hostname).Run() //nolint:errcheck
	}

	if len(errs) > 0 {
		// Non-fatal: log warnings but don't abort.
		return fmt.Errorf("partial apply (macOS): %s", strings.Join(errs, "; "))
	}
	return nil
}

// Restore reverts sysctl values captured in snap.
func (s *darwinSpoofer) Restore(snap *Snapshot) error {
	if snap == nil {
		return nil
	}
	if snap.TTL > 0 {
		darwinSysctlSetInt("net.inet.ip.ttl", snap.TTL) //nolint:errcheck
	}
	return nil
}

// darwinSysctlGetInt reads a numeric sysctl key on macOS.
func darwinSysctlGetInt(key string) (int, error) {
	out, err := exec.Command("sysctl", "-n", key).Output()
	if err != nil {
		return 0, fmt.Errorf("sysctl -n %s: %w", key, err)
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return 0, fmt.Errorf("parse sysctl %s value %q: %w", key, string(out), err)
	}
	return v, nil
}

// darwinSysctlSetInt writes a numeric sysctl key on macOS.
func darwinSysctlSetInt(key string, value int) error {
	arg := fmt.Sprintf("%s=%d", key, value)
	if out, err := exec.Command("sysctl", "-w", arg).CombinedOutput(); err != nil {
		return fmt.Errorf("sysctl -w %s: %w (output: %s)", arg, err, strings.TrimSpace(string(out)))
	}
	return nil
}
