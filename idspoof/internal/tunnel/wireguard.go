package tunnel

import (
	"fmt"
	"os/exec"
	"sync"
)

type wireguardTunnel struct {
	mu       sync.Mutex
	iface    string
	mode     Mode
	confPath string
	running  bool
}

func (t *wireguardTunnel) Name() string { return "WireGuard" }

func (t *wireguardTunnel) Available() bool { return binaryExists("wg-quick") }

func (t *wireguardTunnel) Start(mode Mode, cfg map[string]string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	confPath := cfg["config"]
	if confPath == "" {
		return fmt.Errorf("WireGuard requires --tunnel-config pointing to a .conf file")
	}

	t.confPath = confPath
	t.mode = mode
	t.iface = "wg-idspoof"

	// WireGuard is always transparent (routes all traffic via wg interface).
	cmd := exec.Command("wg-quick", "up", confPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("wg-quick up: %s: %w", string(out), err)
	}

	t.running = true
	return nil
}

func (t *wireguardTunnel) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.running {
		return nil
	}

	cmd := exec.Command("wg-quick", "down", t.confPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("wg-quick down: %s: %w", string(out), err)
	}

	t.running = false
	return nil
}

func (t *wireguardTunnel) Status() Status {
	t.mu.Lock()
	defer t.mu.Unlock()

	return Status{
		Running:  t.running,
		Protocol: "wireguard",
		Mode:     ModeTransparent,
		Endpoint: "wg interface (all traffic routed)",
		Details:  "WireGuard VPN — ChaCha20-Poly1305 encrypted tunnel",
	}
}
