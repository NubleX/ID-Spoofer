//go:build darwin

package netrecon

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func newProber() Prober { return &darwinProber{} }

type darwinProber struct{}

func (p *darwinProber) Probe() (*NetworkState, error) {
	ns := &NetworkState{Timestamp: time.Now()}

	p.probeInterfaces(ns)
	p.probePorts(ns)
	p.probeRoute(ns)
	p.detectVPNs(ns)
	p.detectTunnels(ns)
	p.generateWarnings(ns)

	return ns, nil
}

// --- Interfaces via `ifconfig -a` ---

func (p *darwinProber) probeInterfaces(ns *NetworkState) {
	out, err := exec.Command("ifconfig", "-a").Output()
	if err != nil {
		return
	}

	var current *InterfaceInfo
	for _, line := range strings.Split(string(out), "\n") {
		if len(line) > 0 && line[0] != '\t' && line[0] != ' ' {
			// New interface line: "en0: flags=8863<UP,..."
			if current != nil {
				ns.Interfaces = append(ns.Interfaces, *current)
			}
			parts := strings.SplitN(line, ":", 2)
			name := parts[0]
			current = &InterfaceInfo{
				Name:  name,
				Type:  classifyDarwinInterface(name),
				State: "DOWN",
			}
			if strings.Contains(line, "<UP") || strings.Contains(line, ",UP") {
				current.State = "UP"
			}
			if i := strings.Index(line, "mtu "); i >= 0 {
				mtuStr := strings.Fields(line[i+4:])[0]
				current.MTU, _ = strconv.Atoi(mtuStr)
			}
		} else if current != nil {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "ether ") {
				current.MAC = strings.Fields(trimmed)[1]
			} else if strings.HasPrefix(trimmed, "inet ") {
				fields := strings.Fields(trimmed)
				if len(fields) >= 2 {
					addr := fields[1]
					// Check for netmask.
					for i, f := range fields {
						if f == "netmask" && i+1 < len(fields) {
							addr += "/" + fields[i+1]
							break
						}
					}
					current.IPs = append(current.IPs, addr)
				}
			} else if strings.HasPrefix(trimmed, "inet6 ") {
				fields := strings.Fields(trimmed)
				if len(fields) >= 2 {
					addr := fields[1]
					for i, f := range fields {
						if f == "prefixlen" && i+1 < len(fields) {
							addr += "/" + fields[i+1]
							break
						}
					}
					current.IPs = append(current.IPs, addr)
				}
			}
		}
	}
	if current != nil {
		ns.Interfaces = append(ns.Interfaces, *current)
	}
}

// --- Listening ports via `netstat -an` ---

func (p *darwinProber) probePorts(ns *NetworkState) {
	out, err := exec.Command("netstat", "-an", "-p", "tcp").Output()
	if err == nil {
		p.parseNetstat(ns, string(out), "tcp")
	}
	out, err = exec.Command("netstat", "-an", "-p", "udp").Output()
	if err == nil {
		p.parseNetstat(ns, string(out), "udp")
	}
}

func (p *darwinProber) parseNetstat(ns *NetworkState, output, proto string) {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if !strings.HasPrefix(fields[0], proto) {
			continue
		}
		// Only listening sockets.
		if proto == "tcp" && (len(fields) < 6 || fields[5] != "LISTEN") {
			continue
		}
		addr := fields[3]
		if addr == "" {
			continue
		}
		ns.Ports = append(ns.Ports, ListeningPort{
			Protocol: fields[0],
			Address:  addr,
		})
	}
}

// --- Default route via `netstat -rn` ---

func (p *darwinProber) probeRoute(ns *NetworkState) {
	out, err := exec.Command("netstat", "-rn").Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == "default" {
			ns.Route.Default = fields[1]
			ns.Route.DefaultDev = fields[3]
			ns.Route.VPNRouted = isDarwinVPNDevice(fields[3])
			break
		}
	}
}

// --- VPN detection ---

func (p *darwinProber) detectVPNs(ns *NetworkState) {
	for _, iface := range ns.Interfaces {
		if iface.State != "UP" {
			continue
		}
		switch {
		case strings.HasPrefix(iface.Name, "utun"):
			vpn := VPNStatus{Active: true, Name: "Tunnel (utun)", Iface: iface.Name}
			if processRunningDarwin("WireGuard") || processRunningDarwin("wireguard-go") {
				vpn.Name = "WireGuard"
			} else if processRunningDarwin("openvpn") {
				vpn.Name = "OpenVPN"
			} else if processRunningDarwin("mullvad-daemon") {
				vpn.Name = "Mullvad VPN"
			}
			ns.VPNs = append(ns.VPNs, vpn)
		}
	}

	// Check scutil for VPN connections.
	out, err := exec.Command("scutil", "--nc", "list").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "Connected") {
				parts := strings.SplitN(line, "\"", 3)
				if len(parts) >= 2 {
					name := parts[1]
					found := false
					for _, v := range ns.VPNs {
						if v.Name == name {
							found = true
							break
						}
					}
					if !found {
						ns.VPNs = append(ns.VPNs, VPNStatus{Active: true, Name: name, Iface: "scutil"})
					}
				}
			}
		}
	}
}

// --- Tunnel detection ---

func (p *darwinProber) detectTunnels(ns *NetworkState) {
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
		if processRunningDarwin(tp.process) {
			ns.Tunnels = append(ns.Tunnels, TunnelStatus{
				Active:   true,
				Protocol: tp.protocol,
				Process:  tp.process,
			})
		}
	}
}

// --- Warnings ---

func (p *darwinProber) generateWarnings(ns *NetworkState) {
	for _, vpn := range ns.VPNs {
		ns.Warnings = append(ns.Warnings,
			fmt.Sprintf("%s active on %s — applying a tunnel may cause routing conflicts", vpn.Name, vpn.Iface))
	}
	for _, t := range ns.Tunnels {
		ns.Warnings = append(ns.Warnings,
			fmt.Sprintf("%s already running — starting another instance may fail", t.Protocol))
	}
	if ns.Route.VPNRouted {
		ns.Warnings = append(ns.Warnings,
			fmt.Sprintf("Default route via %s (VPN/tunnel) — netident changes may not reach local network", ns.Route.DefaultDev))
	}
}

// --- Helpers ---

func classifyDarwinInterface(name string) string {
	switch {
	case name == "lo0":
		return "loopback"
	case strings.HasPrefix(name, "en"):
		return "ethernet"
	case strings.HasPrefix(name, "utun"):
		return "tun"
	case strings.HasPrefix(name, "bridge"):
		return "bridge"
	case strings.HasPrefix(name, "awdl"):
		return "wifi-direct"
	default:
		return "other"
	}
}

func isDarwinVPNDevice(dev string) bool {
	return strings.HasPrefix(dev, "utun") || strings.HasPrefix(dev, "tun")
}

func processRunningDarwin(name string) bool {
	out, err := exec.Command("pgrep", "-x", name).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) != ""
}
