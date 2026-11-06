//go:build windows

package tunnel

import "fmt"

// Windows support needs the wintun-based detachment story worked out
// (no SIGTERM/setsid equivalent, Windows services instead of systemd) —
// tracked alongside the rest of idspoof's Windows-native work (CLAUDE.md
// Phase 6). The embedded tun2socks engine itself already builds for
// windows via wintun; only the detached-helper supervision below is
// Linux/macOS-only for now.

func (t *tun2socksTunnel) Start(mode Mode, cfg map[string]string) error {
	return fmt.Errorf("tun2socks: not yet supported on Windows (detached-helper supervision is unix-only)")
}

func (t *tun2socksTunnel) Stop() error {
	return nil
}

func (t *tun2socksTunnel) Status() Status {
	return Status{Running: false, Protocol: "tun2socks"}
}
