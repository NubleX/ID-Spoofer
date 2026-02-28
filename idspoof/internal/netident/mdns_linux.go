//go:build linux

package netident

import (
	"os/exec"
)

// handleMDNS manages Avahi based on the persona.
// Windows persona: suppress Avahi (Windows 10+ has mDNS but OPSEC is better
// with it silenced).
// macOS/iOS persona: leave Avahi running — Apple devices use Bonjour heavily,
// and suppressing it would be a fingerprinting tell.
func handleMDNS(p *Persona, snap *Snapshot) {
	if p.SuppressMDNS {
		suppressMDNS(snap)
	}
	// When SuppressMDNS is false (macOS/iOS), we leave Avahi as-is.
}

// suppressMDNS stops Avahi from broadcasting the real hostname.
func suppressMDNS(snap *Snapshot) {
	// Check if avahi-daemon is running.
	if exec.Command("systemctl", "is-active", "--quiet", "avahi-daemon").Run() != nil {
		return // Not running, nothing to do.
	}

	// Stop avahi-daemon temporarily. It will restart on next boot.
	if err := exec.Command("systemctl", "stop", "avahi-daemon").Run(); err != nil {
		return
	}
	snap.AvahiWasStopped = true
}

// restoreMDNS restarts Avahi if we stopped it.
func restoreMDNS(snap *Snapshot) {
	if snap.AvahiWasStopped {
		exec.Command("systemctl", "start", "avahi-daemon").Run()
	}
}
