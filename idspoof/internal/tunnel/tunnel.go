// Package tunnel provides traffic encapsulation through various protocols.
// Each tunnel wraps an existing system binary (tor, wg-quick, i2pd, etc.)
// and manages its lifecycle, iptables rules, and cleanup.
package tunnel

import (
	"net"
	"os/exec"
	"time"
)

// Mode controls how traffic is routed through the tunnel.
type Mode string

const (
	// ModeTransparent redirects all system traffic through the tunnel
	// using iptables nat rules.
	ModeTransparent Mode = "transparent"
	// ModeSocks exposes a local SOCKS5 proxy. The user configures
	// applications to use it manually.
	ModeSocks Mode = "socks"
)

// Status reports the current state of a tunnel.
type Status struct {
	Running  bool
	Protocol string
	Mode     Mode
	Endpoint string // e.g., "socks5://127.0.0.1:9050"
	Details  string
}

// Tunnel is the interface all protocol implementations must satisfy.
type Tunnel interface {
	// Name returns the human-readable protocol name.
	Name() string

	// Available checks whether the required system binary exists.
	Available() bool

	// Start launches the tunnel process and configures routing.
	// cfg holds protocol-specific settings (config file path, etc.).
	Start(mode Mode, cfg map[string]string) error

	// Stop tears down the tunnel, kills processes, and removes iptables rules.
	Stop() error

	// Status returns the current tunnel state.
	Status() Status
}

// binaryExists checks if a binary is available in PATH.
func binaryExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// waitForPort polls addr (host:port) until it accepts a TCP connection
// or the timeout elapses. Used to wait for tunnel daemons to become ready.
func waitForPort(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(time.Second)
	}
	return net.ErrClosed
}

// Registry maps protocol names to tunnel constructors.
var Registry = map[string]func() Tunnel{
	"tor":          func() Tunnel { return &torTunnel{} },
	"wireguard":    func() Tunnel { return &wireguardTunnel{} },
	"lwo":          func() Tunnel { return &lwoTunnel{} },
	"i2p":          func() Tunnel { return &i2pTunnel{} },
	"shadowsocks":  func() Tunnel { return &shadowsocksTunnel{} },
	"quic":         func() Tunnel { return &quicTunnel{} },
	"tor-over-vpn": func() Tunnel { return &torOverVPN{} },
	"vpn-over-tor": func() Tunnel { return &vpnOverTor{} },
}

// Get returns a tunnel instance by protocol name, or nil if unknown.
func Get(name string) Tunnel {
	if fn, ok := Registry[name]; ok {
		return fn()
	}
	return nil
}

// AvailableProtocols returns a map of protocol name → available (binary exists).
func AvailableProtocols() map[string]bool {
	result := make(map[string]bool, len(Registry))
	for name, fn := range Registry {
		result[name] = fn().Available()
	}
	return result
}
