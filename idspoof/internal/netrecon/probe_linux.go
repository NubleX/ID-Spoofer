//go:build linux

package netrecon

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func newProber() Prober { return &linuxProber{} }

type linuxProber struct{}

func (p *linuxProber) Probe() (*NetworkState, error) {
	ns := &NetworkState{Timestamp: time.Now()}

	p.probeInterfaces(ns)
	p.probeAddresses(ns)
	p.probePorts(ns)
	p.probeRoute(ns)
	p.detectVPNs(ns)
	p.detectTunnels(ns)
	p.generateWarnings(ns)

	return ns, nil
}

// --- Interfaces via `ip -j link show` ---

type ipLink struct {
	Ifname   string `json:"ifname"`
	LinkType string `json:"link_type"`
	Operstate string `json:"operstate"`
	Address  string `json:"address"`
	MTU      int    `json:"mtu"`
	Flags    []string `json:"flags"`
}

func (p *linuxProber) probeInterfaces(ns *NetworkState) {
	out, err := exec.Command("ip", "-j", "link", "show").Output()
	if err != nil {
		// Fallback to non-JSON.
		p.probeInterfacesFallback(ns)
		return
	}

	var links []ipLink
	if err := json.Unmarshal(out, &links); err != nil {
		p.probeInterfacesFallback(ns)
		return
	}

	for _, l := range links {
		iface := InterfaceInfo{
			Name:  l.Ifname,
			Type:  classifyInterface(l.Ifname, l.LinkType),
			State: strings.ToUpper(l.Operstate),
			MAC:   l.Address,
			MTU:   l.MTU,
		}
		if iface.State == "" || iface.State == "UNKNOWN" {
			for _, f := range l.Flags {
				if f == "UP" {
					iface.State = "UP"
					break
				}
			}
			if iface.State == "" || iface.State == "UNKNOWN" {
				iface.State = "DOWN"
			}
		}
		ns.Interfaces = append(ns.Interfaces, iface)
	}
}

func (p *linuxProber) probeInterfacesFallback(ns *NetworkState) {
	out, err := exec.Command("ip", "-o", "link", "show").Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimSuffix(fields[1], ":")
		iface := InterfaceInfo{
			Name:  name,
			Type:  classifyInterface(name, ""),
			State: "UP",
		}
		for i, f := range fields {
			if f == "link/ether" && i+1 < len(fields) {
				iface.MAC = fields[i+1]
			}
			if f == "mtu" && i+1 < len(fields) {
				iface.MTU, _ = strconv.Atoi(fields[i+1])
			}
			if f == "state" && i+1 < len(fields) {
				iface.State = strings.ToUpper(fields[i+1])
			}
		}
		ns.Interfaces = append(ns.Interfaces, iface)
	}
}

// --- IP addresses via `ip -j addr show` ---

type ipAddr struct {
	Ifname   string `json:"ifname"`
	AddrInfo []struct {
		Local     string `json:"local"`
		Prefixlen int    `json:"prefixlen"`
		Family    string `json:"family"`
	} `json:"addr_info"`
}

func (p *linuxProber) probeAddresses(ns *NetworkState) {
	out, err := exec.Command("ip", "-j", "addr", "show").Output()
	if err != nil {
		return
	}

	var addrs []ipAddr
	if err := json.Unmarshal(out, &addrs); err != nil {
		return
	}

	// Build name→index map.
	ifMap := make(map[string]int)
	for i := range ns.Interfaces {
		ifMap[ns.Interfaces[i].Name] = i
	}

	for _, a := range addrs {
		idx, ok := ifMap[a.Ifname]
		if !ok {
			continue
		}
		for _, ai := range a.AddrInfo {
			addr := fmt.Sprintf("%s/%d", ai.Local, ai.Prefixlen)
			ns.Interfaces[idx].IPs = append(ns.Interfaces[idx].IPs, addr)
		}
	}
}

// --- Listening ports via `ss` ---

func (p *linuxProber) probePorts(ns *NetworkState) {
	for _, proto := range []string{"tcp", "udp"} {
		out, err := exec.Command("ss", "-"+proto[:1]+"lnp").Output()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "Netid") || strings.HasPrefix(line, "State") || line == "" {
				continue
			}
			port := parseSSLine(line, proto)
			if port.Address != "" {
				ns.Ports = append(ns.Ports, port)
			}
		}
	}
}

func parseSSLine(line, proto string) ListeningPort {
	fields := strings.Fields(line)
	// ss output: Netid State Recv-Q Send-Q Local:Port Peer:Port Process
	// or:        State Recv-Q Send-Q Local:Port Peer:Port Process
	var localAddr, procInfo string
	if len(fields) >= 5 {
		localAddr = fields[4]
		if len(fields) >= 7 {
			procInfo = fields[6]
		} else if len(fields) >= 6 {
			procInfo = fields[5]
		}
	} else if len(fields) >= 4 {
		localAddr = fields[3]
		if len(fields) >= 5 {
			procInfo = fields[4]
		}
	}
	if localAddr == "" {
		return ListeningPort{}
	}

	// Determine protocol (check for IPv6).
	p := proto
	if strings.HasPrefix(localAddr, "[") || strings.Count(localAddr, ":") > 1 {
		p = proto + "6"
	}

	pid, proc := parseProcInfo(procInfo)

	return ListeningPort{
		Protocol: p,
		Address:  localAddr,
		PID:      pid,
		Process:  proc,
	}
}

// parseProcInfo extracts PID and process name from ss process info.
// Format: users:(("tor",pid=1234,fd=6))
func parseProcInfo(s string) (int, string) {
	if s == "" {
		return 0, ""
	}
	// Extract process name.
	var name string
	if i := strings.Index(s, "((\""); i >= 0 {
		rest := s[i+3:]
		if j := strings.Index(rest, "\""); j >= 0 {
			name = rest[:j]
		}
	}
	// Extract PID.
	var pid int
	if i := strings.Index(s, "pid="); i >= 0 {
		rest := s[i+4:]
		if j := strings.IndexAny(rest, ",)"); j >= 0 {
			pid, _ = strconv.Atoi(rest[:j])
		} else {
			pid, _ = strconv.Atoi(rest)
		}
	}
	return pid, name
}

// --- Default route via `ip -j route show default` ---

type ipRoute struct {
	Dst     string `json:"dst"`
	Gateway string `json:"gateway"`
	Dev     string `json:"dev"`
}

func (p *linuxProber) probeRoute(ns *NetworkState) {
	out, err := exec.Command("ip", "-j", "route", "show", "default").Output()
	if err != nil {
		return
	}

	var routes []ipRoute
	if err := json.Unmarshal(out, &routes); err != nil {
		return
	}

	if len(routes) > 0 {
		r := routes[0]
		ns.Route.Default = r.Gateway
		ns.Route.DefaultDev = r.Dev
		ns.Route.VPNRouted = isVPNDevice(r.Dev)
	}
}

// --- VPN detection ---

func (p *linuxProber) detectVPNs(ns *NetworkState) {
	for _, iface := range ns.Interfaces {
		if iface.State != "UP" {
			continue
		}
		switch {
		case strings.HasPrefix(iface.Name, "wg") || iface.Type == "wireguard":
			vpn := VPNStatus{Active: true, Name: "WireGuard", Iface: iface.Name}
			vpn.Endpoint = wgEndpoint(iface.Name)
			// Check if it's Mullvad specifically.
			if strings.Contains(iface.Name, "mullvad") || isMullvadEndpoint(vpn.Endpoint) {
				vpn.Name = "Mullvad VPN"
			}
			ns.VPNs = append(ns.VPNs, vpn)
		case strings.HasPrefix(iface.Name, "tun"):
			vpn := VPNStatus{Active: true, Name: "OpenVPN/Tunnel", Iface: iface.Name}
			if processRunning("openvpn") {
				vpn.Name = "OpenVPN"
			}
			ns.VPNs = append(ns.VPNs, vpn)
		case strings.HasPrefix(iface.Name, "tailscale") || iface.Name == "ts0":
			ns.VPNs = append(ns.VPNs, VPNStatus{Active: true, Name: "Tailscale", Iface: iface.Name})
		}
	}

	// Check for Mullvad daemon process even without wg interface visible.
	if processRunning("mullvad-daemon") {
		found := false
		for _, v := range ns.VPNs {
			if strings.Contains(v.Name, "Mullvad") {
				found = true
				break
			}
		}
		if !found {
			ns.VPNs = append(ns.VPNs, VPNStatus{Active: true, Name: "Mullvad VPN", Iface: "(daemon)"})
		}
	}
}

// wgEndpoint returns the endpoint for a WireGuard interface.
func wgEndpoint(iface string) string {
	out, err := exec.Command("wg", "show", iface, "endpoints").Output()
	if err != nil {
		return ""
	}
	lines := strings.Fields(string(out))
	if len(lines) >= 2 {
		return lines[1]
	}
	return strings.TrimSpace(string(out))
}

// isMullvadEndpoint checks if the endpoint IP belongs to Mullvad's known ranges.
func isMullvadEndpoint(endpoint string) bool {
	// Mullvad endpoints are typically on well-known ports 51820 or 53.
	return strings.Contains(endpoint, ":51820") || strings.Contains(endpoint, "mullvad")
}

// --- Tunnel detection ---

func (p *linuxProber) detectTunnels(ns *NetworkState) {
	knownTunnels := []struct {
		process  string
		protocol string
		ports    []string
	}{
		{"tor", "tor", []string{"9050", "9040", "9051"}},
		{"i2pd", "i2p", []string{"4447", "4444"}},
		{"sslocal", "shadowsocks", []string{"1080", "1081"}},
		{"ss-local", "shadowsocks", []string{"1080", "1081"}},
		{"hysteria", "hysteria/quic", []string{"1080"}},
		{"obfs4proxy", "obfs4", []string{}},
	}

	for _, kt := range knownTunnels {
		for _, port := range ns.Ports {
			if port.Process == kt.process {
				ns.Tunnels = append(ns.Tunnels, TunnelStatus{
					Active:   true,
					Protocol: kt.protocol,
					Port:     port.Address,
					Process:  kt.process,
				})
				break
			}
		}
		// Also check if the process is running even without a matching port.
		if processRunning(kt.process) {
			found := false
			for _, t := range ns.Tunnels {
				if t.Process == kt.process {
					found = true
					break
				}
			}
			if !found {
				ns.Tunnels = append(ns.Tunnels, TunnelStatus{
					Active:   true,
					Protocol: kt.protocol,
					Process:  kt.process,
				})
			}
		}
	}
}

// --- Warnings ---

func (p *linuxProber) generateWarnings(ns *NetworkState) {
	for _, vpn := range ns.VPNs {
		ns.Warnings = append(ns.Warnings,
			fmt.Sprintf("%s active on %s — applying a tunnel may cause routing conflicts", vpn.Name, vpn.Iface))
	}
	for _, t := range ns.Tunnels {
		ns.Warnings = append(ns.Warnings,
			fmt.Sprintf("%s already running (port %s) — starting another instance may fail", t.Protocol, t.Port))
	}
	if ns.Route.VPNRouted {
		ns.Warnings = append(ns.Warnings,
			fmt.Sprintf("Default route via %s (VPN/tunnel) — netident DHCP changes may not reach the local network", ns.Route.DefaultDev))
	}
}

// --- Helpers ---

func classifyInterface(name, linkType string) string {
	switch {
	case name == "lo":
		return "loopback"
	case strings.HasPrefix(name, "wg") || linkType == "wireguard":
		return "wireguard"
	case strings.HasPrefix(name, "tun") || strings.HasPrefix(name, "tap"):
		return "tun"
	case strings.HasPrefix(name, "br") || strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "veth"):
		return "bridge"
	case strings.HasPrefix(name, "wl"):
		return "wifi"
	case strings.HasPrefix(name, "en") || strings.HasPrefix(name, "eth"):
		return "ethernet"
	default:
		if linkType != "" {
			return linkType
		}
		return "other"
	}
}

func isVPNDevice(dev string) bool {
	return strings.HasPrefix(dev, "wg") || strings.HasPrefix(dev, "tun") ||
		strings.HasPrefix(dev, "tap") || strings.Contains(dev, "mullvad")
}

func processRunning(name string) bool {
	out, err := exec.Command("pgrep", "-x", name).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) != ""
}
