//go:build windows

package netrecon

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func newProber() Prober { return &windowsProber{} }

type windowsProber struct{}

func (p *windowsProber) Probe() (*NetworkState, error) {
	ns := &NetworkState{Timestamp: time.Now()}

	p.probeInterfaces(ns)
	p.probePorts(ns)
	p.probeRoute(ns)
	p.detectVPNs(ns)
	p.detectTunnels(ns)
	p.generateWarnings(ns)

	return ns, nil
}

// --- Interfaces via `ipconfig /all` ---

func (p *windowsProber) probeInterfaces(ns *NetworkState) {
	out, err := exec.Command("ipconfig", "/all").Output()
	if err != nil {
		return
	}

	var current *InterfaceInfo
	for _, line := range strings.Split(string(out), "\r\n") {
		trimmed := strings.TrimSpace(line)

		// New adapter header (no leading whitespace).
		if !strings.HasPrefix(line, " ") && strings.Contains(line, "adapter") && strings.HasSuffix(trimmed, ":") {
			if current != nil {
				ns.Interfaces = append(ns.Interfaces, *current)
			}
			name := strings.TrimSuffix(trimmed, ":")
			// Remove "Ethernet adapter " / "Wireless LAN adapter " prefix.
			for _, prefix := range []string{"Ethernet adapter ", "Wireless LAN adapter ", "Unknown adapter "} {
				name = strings.TrimPrefix(name, prefix)
			}
			current = &InterfaceInfo{
				Name:  name,
				Type:  classifyWindowsAdapter(trimmed),
				State: "UP",
			}
			continue
		}
		if current == nil {
			continue
		}

		if strings.Contains(trimmed, "Media disconnected") {
			current.State = "DOWN"
		}
		if strings.HasPrefix(trimmed, "Physical Address") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				current.MAC = strings.TrimSpace(parts[1])
			}
		}
		if strings.HasPrefix(trimmed, "IPv4 Address") || strings.HasPrefix(trimmed, "IP Address") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				addr := strings.TrimSpace(parts[1])
				addr = strings.TrimSuffix(addr, "(Preferred)")
				current.IPs = append(current.IPs, strings.TrimSpace(addr))
			}
		}
		if strings.HasPrefix(trimmed, "IPv6 Address") || strings.HasPrefix(trimmed, "Link-local IPv6") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				addr := strings.TrimSpace(parts[1])
				addr = strings.TrimSuffix(addr, "(Preferred)")
				current.IPs = append(current.IPs, strings.TrimSpace(addr))
			}
		}
	}
	if current != nil {
		ns.Interfaces = append(ns.Interfaces, *current)
	}
}

// --- Listening ports via `netstat -an` ---

func (p *windowsProber) probePorts(ns *NetworkState) {
	out, err := exec.Command("netstat", "-an").Output()
	if err != nil {
		return
	}

	for _, line := range strings.Split(string(out), "\r\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		proto := strings.ToLower(fields[0])
		if proto != "tcp" && proto != "udp" {
			continue
		}
		state := ""
		if len(fields) >= 4 {
			state = fields[3]
		}
		if proto == "tcp" && state != "LISTENING" {
			continue
		}

		ns.Ports = append(ns.Ports, ListeningPort{
			Protocol: proto,
			Address:  fields[1],
		})
	}
}

// --- Default route via `route print` ---

func (p *windowsProber) probeRoute(ns *NetworkState) {
	out, err := exec.Command("route", "print", "0.0.0.0").Output()
	if err != nil {
		return
	}

	for _, line := range strings.Split(string(out), "\r\n") {
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			ns.Route.Default = fields[2]
			// metric is fields[4]; interface is fields[3]
			if idx, err := strconv.Atoi(fields[3]); err == nil {
				ns.Route.DefaultDev = fmt.Sprintf("if%d", idx)
			}
			break
		}
	}
}

// --- VPN detection ---

func (p *windowsProber) detectVPNs(ns *NetworkState) {
	// Check for WireGuard service.
	if serviceRunning("WireGuardTunnel$wg0") || serviceRunning("WireGuardManager") {
		ns.VPNs = append(ns.VPNs, VPNStatus{Active: true, Name: "WireGuard"})
	}

	// Check for Mullvad.
	if serviceRunning("MullvadVPN") || processRunningWindows("mullvad-daemon") {
		ns.VPNs = append(ns.VPNs, VPNStatus{Active: true, Name: "Mullvad VPN"})
	}

	// Check for OpenVPN.
	if processRunningWindows("openvpn") {
		ns.VPNs = append(ns.VPNs, VPNStatus{Active: true, Name: "OpenVPN"})
	}

	// Check for TAP/TUN adapters in interfaces.
	for _, iface := range ns.Interfaces {
		if iface.State == "UP" && (strings.Contains(strings.ToLower(iface.Name), "tap") ||
			strings.Contains(strings.ToLower(iface.Name), "tun")) {
			found := false
			for _, v := range ns.VPNs {
				if v.Iface == iface.Name {
					found = true
					break
				}
			}
			if !found {
				ns.VPNs = append(ns.VPNs, VPNStatus{Active: true, Name: "VPN Adapter", Iface: iface.Name})
			}
		}
	}
}

// --- Tunnel detection ---

func (p *windowsProber) detectTunnels(ns *NetworkState) {
	tunnelProcs := []struct {
		process  string
		protocol string
	}{
		{"tor", "tor"},
		{"i2pd", "i2p"},
		{"sslocal", "shadowsocks"},
		{"hysteria", "hysteria/quic"},
	}
	for _, tp := range tunnelProcs {
		if processRunningWindows(tp.process) {
			ns.Tunnels = append(ns.Tunnels, TunnelStatus{
				Active:   true,
				Protocol: tp.protocol,
				Process:  tp.process,
			})
		}
	}
}

// --- Warnings ---

func (p *windowsProber) generateWarnings(ns *NetworkState) {
	for _, vpn := range ns.VPNs {
		iface := vpn.Iface
		if iface == "" {
			iface = "(service)"
		}
		ns.Warnings = append(ns.Warnings,
			fmt.Sprintf("%s active (%s) — applying a tunnel may cause routing conflicts", vpn.Name, iface))
	}
	for _, t := range ns.Tunnels {
		ns.Warnings = append(ns.Warnings,
			fmt.Sprintf("%s already running — starting another instance may fail", t.Protocol))
	}
}

// --- Helpers ---

func classifyWindowsAdapter(header string) string {
	lower := strings.ToLower(header)
	switch {
	case strings.Contains(lower, "wireless"):
		return "wifi"
	case strings.Contains(lower, "ethernet"):
		return "ethernet"
	case strings.Contains(lower, "loopback"):
		return "loopback"
	default:
		return "other"
	}
}

func serviceRunning(name string) bool {
	out, err := exec.Command("sc", "query", name).Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "RUNNING")
}

func processRunningWindows(name string) bool {
	out, err := exec.Command("tasklist", "/FI", fmt.Sprintf("IMAGENAME eq %s.exe", name)).Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), name)
}
