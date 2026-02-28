package tunnel

import (
	"fmt"
	"sync"
	"time"
)

// ── Tor over VPN ─────────────────────────────────────────────────────────────
// Connect VPN first, then route Tor through it.
// ISP sees: WireGuard traffic. VPN sees: Tor entry. Tor sees: VPN exit IP.

type torOverVPN struct {
	mu  sync.Mutex
	wg  *wireguardTunnel
	tor *torTunnel
}

func (t *torOverVPN) Name() string { return "Tor over VPN" }

func (t *torOverVPN) Available() bool {
	return binaryExists("wg-quick") && binaryExists("tor")
}

func (t *torOverVPN) Start(mode Mode, cfg map[string]string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	confPath := cfg["config"]
	if confPath == "" {
		return fmt.Errorf("Tor-over-VPN requires --tunnel-config pointing to a WireGuard .conf file")
	}

	// Step 1: Start VPN.
	t.wg = &wireguardTunnel{}
	if err := t.wg.Start(ModeTransparent, cfg); err != nil {
		return fmt.Errorf("VPN layer: %w", err)
	}

	// Give VPN time to establish.
	time.Sleep(2 * time.Second)

	// Step 2: Start Tor (traffic goes through VPN).
	t.tor = &torTunnel{}
	if err := t.tor.Start(mode, nil); err != nil {
		t.wg.Stop()
		return fmt.Errorf("Tor layer: %w", err)
	}

	return nil
}

func (t *torOverVPN) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Reverse order: stop Tor first, then VPN.
	if t.tor != nil {
		t.tor.Stop()
	}
	if t.wg != nil {
		t.wg.Stop()
	}
	return nil
}

func (t *torOverVPN) Status() Status {
	t.mu.Lock()
	defer t.mu.Unlock()

	return Status{
		Running:  t.tor != nil,
		Protocol: "tor-over-vpn",
		Mode:     ModeTransparent,
		Endpoint: "VPN → Tor → destination",
		Details:  "ISP sees VPN only. VPN sees Tor entry. Maximum layering.",
	}
}

// ── VPN over Tor ─────────────────────────────────────────────────────────────
// Connect Tor first, then route VPN through Tor.
// ISP sees: Tor traffic. Tor exit sees: VPN handshake. Destination sees: VPN exit.

type vpnOverTor struct {
	mu  sync.Mutex
	tor *torTunnel
	wg  *wireguardTunnel
}

func (t *vpnOverTor) Name() string { return "VPN over Tor" }

func (t *vpnOverTor) Available() bool {
	return binaryExists("tor") && binaryExists("wg-quick")
}

func (t *vpnOverTor) Start(mode Mode, cfg map[string]string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	confPath := cfg["config"]
	if confPath == "" {
		return fmt.Errorf("VPN-over-Tor requires --tunnel-config pointing to a WireGuard .conf file")
	}

	// Step 1: Start Tor (SOCKS mode so VPN can connect through it).
	t.tor = &torTunnel{}
	if err := t.tor.Start(ModeSocks, nil); err != nil {
		return fmt.Errorf("Tor layer: %w", err)
	}

	// Give Tor time to bootstrap.
	time.Sleep(5 * time.Second)

	// Step 2: Start WireGuard.
	// The WireGuard config should be set up to route through Tor's SOCKS proxy.
	// This requires the WireGuard endpoint to be reachable through Tor.
	t.wg = &wireguardTunnel{}
	if err := t.wg.Start(ModeTransparent, cfg); err != nil {
		t.tor.Stop()
		return fmt.Errorf("VPN layer: %w", err)
	}

	return nil
}

func (t *vpnOverTor) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Reverse order: stop VPN first, then Tor.
	if t.wg != nil {
		t.wg.Stop()
	}
	if t.tor != nil {
		t.tor.Stop()
	}
	return nil
}

func (t *vpnOverTor) Status() Status {
	t.mu.Lock()
	defer t.mu.Unlock()

	return Status{
		Running:  t.wg != nil,
		Protocol: "vpn-over-tor",
		Mode:     ModeTransparent,
		Endpoint: "Tor → VPN → destination",
		Details:  "ISP sees Tor only. VPN server never knows your real IP. Very slow.",
	}
}
