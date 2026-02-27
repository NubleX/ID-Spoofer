// Package netrecon probes the current network state — interfaces, listening
// ports, active VPNs/tunnels, and default route — to provide situational
// awareness before identity spoofing operations. Cross-platform via build tags.
package netrecon

import "time"

// InterfaceInfo describes a network interface.
type InterfaceInfo struct {
	Name  string
	Type  string // "ethernet", "wifi", "wireguard", "tun", "loopback", "bridge"
	State string // "UP", "DOWN"
	MAC   string
	IPs   []string // IPv4 + IPv6 addresses
	MTU   int
}

// ListeningPort describes a process listening on a network port.
type ListeningPort struct {
	Protocol string // "tcp", "udp", "tcp6", "udp6"
	Address  string // "127.0.0.1:9050"
	PID      int
	Process  string // "tor", "sshd", etc.
}

// VPNStatus describes a detected VPN connection.
type VPNStatus struct {
	Active   bool
	Name     string // "WireGuard", "Mullvad", "OpenVPN"
	Iface    string // "wg0", "tun0", "mullvad-wg"
	Endpoint string // remote endpoint
}

// TunnelStatus describes a detected anonymity/proxy tunnel.
type TunnelStatus struct {
	Active   bool
	Protocol string // "tor", "i2p", "shadowsocks", "hysteria"
	Port     string // listen port
	Process  string
}

// RouteInfo describes the system's default route.
type RouteInfo struct {
	Default    string // default gateway IP
	DefaultDev string // device for default route
	VPNRouted  bool   // default route goes through a VPN/tunnel device
}

// NetworkState is the full snapshot of network conditions.
type NetworkState struct {
	Interfaces []InterfaceInfo
	Ports      []ListeningPort
	VPNs       []VPNStatus
	Tunnels    []TunnelStatus
	Route      RouteInfo
	Warnings   []string // conflict / safety warnings
	Timestamp  time.Time
}

// Prober queries the OS for current network state.
type Prober interface {
	Probe() (*NetworkState, error)
}

// NewProber returns the platform-appropriate prober.
// Implemented per-platform via build tags in probe_*.go files.
func NewProber() Prober { return newProber() }
