//go:build linux

package netident

import (
	"fmt"
	"os/exec"
	"strings"
)

// Chain name used for our rules so we can cleanly add/remove without
// disturbing existing firewall config.
const chainName = "IDSPOOF_NETEMU"

// applyIPTables creates a mangle chain with rules that make outgoing packets
// match the target OS persona:
//   - TTL set to persona value (128 for Windows, 64 for macOS/iOS)
//   - MSS clamped to 1460 on SYN packets
func applyIPTables(p *Persona) error {
	// Create our chain (ignore error if already exists).
	exec.Command("iptables", "-t", "mangle", "-N", chainName).Run()

	// Flush our chain to start clean.
	if err := run("iptables", "-t", "mangle", "-F", chainName); err != nil {
		return fmt.Errorf("flush chain: %w", err)
	}

	// Add rules to our chain.
	rules := [][]string{
		// TTL → 128 on all outgoing.
		{"-t", "mangle", "-A", chainName, "-j", "TTL", "--ttl-set", fmt.Sprintf("%d", p.TTL)},
		// MSS → 1460 on SYN packets (matches Windows Ethernet default).
		{"-t", "mangle", "-A", chainName, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS", "--set-mss", fmt.Sprintf("%d", p.MSS)},
	}

	for _, r := range rules {
		if err := run("iptables", r...); err != nil {
			return fmt.Errorf("adding rule %v: %w", r, err)
		}
	}

	// Jump from POSTROUTING to our chain (add only if not already present).
	if !jumpExists() {
		if err := run("iptables", "-t", "mangle", "-A", "POSTROUTING", "-j", chainName); err != nil {
			return fmt.Errorf("adding jump: %w", err)
		}
	}

	return nil
}

// removeIPTables cleans up all iptables rules added by applyIPTables.
func removeIPTables() error {
	// Remove the jump from POSTROUTING.
	exec.Command("iptables", "-t", "mangle", "-D", "POSTROUTING", "-j", chainName).Run()

	// Flush and delete our chain.
	exec.Command("iptables", "-t", "mangle", "-F", chainName).Run()
	exec.Command("iptables", "-t", "mangle", "-X", chainName).Run()

	// Backward compat: also clean up old v2.0.0 chain name if present.
	exec.Command("iptables", "-t", "mangle", "-D", "POSTROUTING", "-j", "IDSPOOF_WINEMU").Run()
	exec.Command("iptables", "-t", "mangle", "-F", "IDSPOOF_WINEMU").Run()
	exec.Command("iptables", "-t", "mangle", "-X", "IDSPOOF_WINEMU").Run()

	return nil
}

// jumpExists checks if POSTROUTING already has a jump to our chain.
func jumpExists() bool {
	out, err := exec.Command("iptables", "-t", "mangle", "-S", "POSTROUTING").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), chainName)
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %s: %w", name, args, strings.TrimSpace(string(out)), err)
	}
	return nil
}
