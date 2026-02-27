package tunnel

import (
	"fmt"
	"os/exec"
	"sync"
)

// lwoTunnel implements WireGuard with Lightweight Obfuscation (LWO).
// LWO scrambles WireGuard packet headers to defeat DPI that specifically
// blocks WireGuard traffic. Requires an obfuscation-capable endpoint.
type lwoTunnel struct {
	mu       sync.Mutex
	confPath string
	running  bool
}

func (t *lwoTunnel) Name() string { return "WireGuard LWO" }

func (t *lwoTunnel) Available() bool { return binaryExists("wg-quick") && binaryExists("wg") }

func (t *lwoTunnel) Start(mode Mode, cfg map[string]string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	confPath := cfg["config"]
	if confPath == "" {
		return fmt.Errorf("LWO requires --tunnel-config pointing to a WireGuard .conf file with ObfuscateKey set")
	}

	t.confPath = confPath

	// LWO uses standard wg-quick but the config must contain ObfuscateKey.
	// The obfuscation is handled by the WireGuard implementation if it
	// supports the ObfuscateKey option (e.g., Mullvad's fork).
	cmd := exec.Command("wg-quick", "up", confPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("wg-quick up (LWO): %s: %w", string(out), err)
	}

	t.running = true
	return nil
}

func (t *lwoTunnel) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.running {
		return nil
	}

	cmd := exec.Command("wg-quick", "down", t.confPath)
	cmd.CombinedOutput()
	t.running = false
	return nil
}

func (t *lwoTunnel) Status() Status {
	t.mu.Lock()
	defer t.mu.Unlock()

	return Status{
		Running:  t.running,
		Protocol: "lwo",
		Mode:     ModeTransparent,
		Endpoint: "wg interface (LWO obfuscated)",
		Details:  "WireGuard with Lightweight Obfuscation — defeats DPI WireGuard blocking",
	}
}
