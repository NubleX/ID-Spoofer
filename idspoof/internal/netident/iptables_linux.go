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
	// MSS uses --clamp-mss-to-pmtu instead of --set-mss: on physical Ethernet
	// (1500 MTU) this produces MSS=1460 — matching the persona's advertised
	// value — but on a WireGuard/OpenVPN interface with a smaller MTU it clamps
	// to the actual path, so inner SYN packets don't get silently dropped for
	// being oversized. Modern Windows/macOS clients do path MTU discovery too,
	// so a VPN-adjusted MSS is indistinguishable from native behavior.
	rules := [][]string{
		{"-t", "mangle", "-A", chainName, "-j", "TTL", "--ttl-set", fmt.Sprintf("%d", p.TTL)},
		{"-t", "mangle", "-A", chainName, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS", "--clamp-mss-to-pmtu"},
	}

	for _, r := range rules {
		if err := run("iptables", r...); err != nil {
			return fmt.Errorf("adding rule %v: %w", r, err)
		}
	}

	// A plain apply scopes the chain to everyone, so sweep any
	// owner-scoped jumps a crashed `serve --owner` left behind before
	// the global jump gate below.
	removeOwnerScopedJumps()

	// Jump from POSTROUTING to our chain (add only if not already
	// present). Check the exact global jump, not any jump to the chain:
	// a stale owner-scoped jump left by a crashed `serve --owner` must
	// not make a plain apply inherit the old single-user scoping.
	if exec.Command("iptables", "-t", "mangle", "-C", "POSTROUTING", "-j", chainName).Run() != nil {
		if err := run("iptables", "-t", "mangle", "-A", "POSTROUTING", "-j", chainName); err != nil {
			return fmt.Errorf("adding jump: %w", err)
		}
	}

	return nil
}

// removeIPTables cleans up all iptables rules added by applyIPTables.
func removeIPTables() error {
	// Remove every jump into our chain from POSTROUTING — the plain global
	// jump as well as any owner-scoped jump added by `serve --owner`.
	if out, err := exec.Command("iptables", "-t", "mangle", "-S", "POSTROUTING").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[0] != "-A" || fields[1] != "POSTROUTING" {
				continue
			}
			if !strings.Contains(line, chainName) {
				continue
			}
			args := append([]string{"-t", "mangle", "-D", "POSTROUTING"}, fields[2:]...)
			exec.Command("iptables", args...).Run()
		}
	}

	// Flush and delete our chain.
	exec.Command("iptables", "-t", "mangle", "-F", chainName).Run()
	exec.Command("iptables", "-t", "mangle", "-X", chainName).Run()

	// Backward compat: also clean up old v2.0.0 chain name if present.
	exec.Command("iptables", "-t", "mangle", "-D", "POSTROUTING", "-j", "IDSPOOF_WINEMU").Run()
	exec.Command("iptables", "-t", "mangle", "-F", "IDSPOOF_WINEMU").Run()
	exec.Command("iptables", "-t", "mangle", "-X", "IDSPOOF_WINEMU").Run()

	return nil
}

// removeOwnerScopedJumps removes every owner-scoped jump to the chain
// from POSTROUTING — the `-m owner --uid-owner` form that only a
// scoped serve installs. Crashed scoped sessions leave these behind,
// and they must not survive a plain apply (next to the global jump
// they would double-divert the old owner's traffic into the chain)
// or a re-scope to another owner.
func removeOwnerScopedJumps() {
	if out, err := exec.Command("iptables", "-t", "mangle", "-S", "POSTROUTING").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[0] != "-A" || fields[1] != "POSTROUTING" {
				continue
			}
			if !strings.Contains(line, chainName) || !strings.Contains(line, "-m owner") {
				continue
			}
			args := append([]string{"-t", "mangle", "-D", "POSTROUTING"}, fields[2:]...)
			exec.Command("iptables", args...).Run()
		}
	}
}

// ScopeToOwners narrows the mangle chain to the listed users' traffic:
// the global POSTROUTING jump is replaced with one uid-owner-scoped
// jump per user, so packets from every other user pass through
// unmodified.
func ScopeToOwners(owners []string) error {
	// Drop the global jump (may already be gone).
	exec.Command("iptables", "-t", "mangle", "-D", "POSTROUTING", "-j", chainName).Run()
	// Drop every owner-scoped jump a previous session left behind —
	// including owners not in this list — so the scope is exactly the
	// users given here.
	removeOwnerScopedJumps()
	// One jump per user, deduped: iptables allows duplicate identical
	// rules, and a duplicate would double-queue that user's SYNs.
	seen := make(map[string]struct{}, len(owners))
	for _, owner := range owners {
		if _, dup := seen[owner]; dup {
			continue
		}
		seen[owner] = struct{}{}
		// iptables resolves the user name to a UID at install time; a
		// missing user is an error.
		if err := run("iptables", "-t", "mangle", "-A", "POSTROUTING", "-m", "owner", "--uid-owner", owner, "-j", chainName); err != nil {
			return fmt.Errorf("scoping to user %q: %w", owner, err)
		}
	}
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
