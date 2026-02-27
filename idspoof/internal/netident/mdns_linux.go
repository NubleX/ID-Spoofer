//go:build linux

package netident

import (
	"os/exec"
)

// suppressMDNS stops Avahi from broadcasting the real hostname.
// Windows 10+ does have mDNS, but for OPSEC it's better to silence
// Avahi entirely rather than try to make it announce a fake name.
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
