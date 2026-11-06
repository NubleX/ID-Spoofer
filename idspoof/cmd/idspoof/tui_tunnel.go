package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/NubleX/ID-Spoofer/idspoof/internal/config"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/profile"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/tunnel"
)

var tunnelItems = []checkItem{
	{
		label: "None", opKey: "tunnel-none", group: "tunnel",
		descTitle: "No Tunnel",
		separator: true, section: "Traffic Encapsulation",
		description: "No traffic encapsulation. Packets leave\nyour interface directly with the\nspoofed identity.",
		checked:     true,
	},
	{
		label: "Tor", opKey: "tunnel-tor", group: "tunnel",
		descTitle:   "Tor Network",
		description: "Routes all traffic through Tor\n(3-hop onion routing).\n\n\u2022 Transparent proxy via iptables\n  or SOCKS5 on 127.0.0.1:9050\n\u2022 High anonymity, moderate speed\n\nRequires: tor binary",
	},
	{
		label: "WireGuard", opKey: "tunnel-wireguard", group: "tunnel",
		descTitle:   "WireGuard VPN",
		description: "Fast kernel-level VPN tunnel.\n\n\u2022 ChaCha20 + Poly1305 encryption\n\u2022 Minimal attack surface\n\nRequires: wg-quick binary\nUse --tunnel-config for .conf",
	},
	{
		label: "I2P / PurpleI2P", opKey: "tunnel-i2p", group: "tunnel",
		descTitle:   "I2P Anonymity Network",
		description: "Garlic routing network.\n\n\u2022 SOCKS5 on 127.0.0.1:4447\n\u2022 HTTP proxy on 127.0.0.1:4444\n\u2022 Designed for hidden services\n\nRequires: i2pd binary",
	},
	{
		label: "Shadowsocks", opKey: "tunnel-shadowsocks", group: "tunnel",
		descTitle:   "Shadowsocks Proxy",
		description: "AEAD encrypted proxy.\n\n\u2022 Looks like normal HTTPS\n\u2022 Defeats DPI censorship\n\u2022 Transparent or SOCKS5 mode\n\nRequires: sslocal binary\nUse --tunnel-config for JSON",
	},
	{
		label: "QUIC Tunnel", opKey: "tunnel-quic", group: "tunnel",
		descTitle:   "QUIC-based Tunnel",
		description: "UDP-based encrypted tunnel\n(Hysteria2).\n\n\u2022 Anti-DPI obfuscation\n\u2022 Brutal congestion control\n\nRequires: hysteria2 binary\nUse --tunnel-config for YAML",
	},
	{
		label: "LWO (WireGuard Obfs)", opKey: "tunnel-lwo", group: "tunnel",
		descTitle:   "Lightweight WG Obfuscation",
		description: "WireGuard with header obfuscation\n(Mullvad-compatible).\n\n\u2022 Defeats WireGuard DPI blocks\n\u2022 Minimal overhead (~0.01ms)\n\nRequires: wg binary + obfuscation\ncapable endpoint",
	},
	{
		label: "Tor over VPN", opKey: "tunnel-tor-over-vpn", group: "tunnel",
		descTitle:   "Tor over VPN",
		description: "VPN first, then Tor through it.\n\nISP sees: VPN traffic only\nVPN sees: Tor entry node\nTor sees: VPN exit IP\n\nRequires: wg-quick + tor",
	},
	{
		label: "VPN over Tor", opKey: "tunnel-vpn-over-tor", group: "tunnel",
		descTitle:   "VPN over Tor",
		description: "Tor first, then VPN through Tor.\n\nISP sees: Tor traffic only\nTor exit sees: VPN handshake\nVPN server never learns real IP\n\nRequires: tor + wg-quick",
	},
	{
		label: "tun2socks (embedded)", opKey: "tunnel-tun2socks", group: "tunnel",
		descTitle:   "tun2socks — raw packet pivot",
		description: "Embeds the tun2socks Go engine directly\n(no external process, no setcap dance).\n\n• Creates a TUN device, bridges it to a\n  SOCKS5/HTTP/Shadowsocks/SSH proxy\n• Lets nmap and other raw-socket tools\n  through a proxy the kernel would\n  otherwise refuse (crafted/raw packets)\n• One code path for tun0 (Linux), utun\n  (macOS), wintun (Windows)\n\nRequires: --tunnel-config YAML\n(proxy, device, mtu, fwmark, tun-post-up)",
	},
}

type tunnelModel struct {
	items  []checkItem
	cursor int
	avail  map[string]bool // protocol → binary exists

	store    *profile.Store
	storeErr string
	profiles []profile.Profile
	picked   map[string]string // tunnel -> picked profile name
	mode     string            // routing mode for new profiles and profile-less tunnels
	note     string
	noteOK   bool
	delArm   string // profile name armed for deletion (press d again)
	live     liveMsg
}

// Messages the tunnel tab sends to the main model.
type (
	openFormMsg    struct{ tunnel string }
	openPasteMsg   struct{ tunnel string }
	openGenMsg     struct{}
	startTunnelMsg struct{}
	stopTunnelMsg  struct{}
)

func newTunnelModel() tunnelModel {
	items := make([]checkItem, len(tunnelItems))
	copy(items, tunnelItems)
	m := tunnelModel{
		items:  items,
		avail:  tunnel.AvailableProtocols(),
		picked: map[string]string{},
		mode:   string(tunnel.ModeTransparent),
	}
	dir := cfg.StateDir
	if dir == "" {
		dir = config.DefaultStateDir
	}
	st, err := profile.NewStore(filepath.Join(dir, "profiles"))
	if err != nil {
		m.storeErr = err.Error()
	} else {
		m.store = st
		m.reload()
	}
	return m
}

func (m *tunnelModel) reload() {
	if m.store == nil {
		return
	}
	list, err := m.store.List()
	if err != nil {
		m.storeErr = err.Error()
		return
	}
	m.profiles = list
}

func (m tunnelModel) cursorProto() string {
	it := m.items[m.cursor]
	if it.opKey == "tunnel-none" {
		return ""
	}
	return strings.TrimPrefix(it.opKey, "tunnel-")
}

func (m tunnelModel) profilesFor(proto string) []profile.Profile {
	var out []profile.Profile
	for _, p := range m.profiles {
		if p.Tunnel == proto {
			out = append(out, p)
		}
	}
	return out
}

// pickedProfile returns the profile chosen for proto, defaulting to the
// first one, or nil if the tunnel has none.
func (m tunnelModel) pickedProfile(proto string) *profile.Profile {
	list := m.profilesFor(proto)
	if len(list) == 0 {
		return nil
	}
	for i := range list {
		if list[i].Name == m.picked[proto] {
			return &list[i]
		}
	}
	return &list[0]
}

// needsConfig reports whether a tunnel cannot start without a config file.
func needsConfig(proto string) bool { return profile.NeedsConfig(proto) }

// modeFor is the routing mode that will be used for proto.
func (m tunnelModel) modeFor(proto string) string {
	if p := m.pickedProfile(proto); p != nil && p.Mode != "" {
		return p.Mode
	}
	return m.mode
}

func (m *tunnelModel) say(ok bool, s string) { m.note, m.noteOK = s, ok }

func (m tunnelModel) Update(msg tea.Msg) (tunnelModel, tea.Cmd) {
	key, isKey := msg.(tea.KeyMsg)
	if !isKey {
		return m, nil
	}
	if k := key.String(); k != "d" {
		m.delArm = ""
	}
	proto := m.cursorProto()
	switch key.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.items)-1 {
			m.cursor++
		}
	case " ":
		it := &m.items[m.cursor]
		for i := range m.items {
			if m.items[i].group == it.group {
				m.items[i].checked = false
			}
		}
		it.checked = true
	case "left", "h", "right", "l":
		list := m.profilesFor(proto)
		if len(list) < 2 {
			break
		}
		cur := 0
		if p := m.pickedProfile(proto); p != nil {
			for i := range list {
				if list[i].Name == p.Name {
					cur = i
				}
			}
		}
		if key.String() == "left" || key.String() == "h" {
			cur = (cur - 1 + len(list)) % len(list)
		} else {
			cur = (cur + 1) % len(list)
		}
		m.picked[proto] = list[cur].Name
	case "m":
		next := string(tunnel.ModeSocks)
		if m.modeFor(proto) == next {
			next = string(tunnel.ModeTransparent)
		}
		if p := m.pickedProfile(proto); p != nil && m.store != nil {
			if err := m.store.SetMode(p.Name, next); err != nil {
				m.say(false, "could not change mode: "+err.Error())
				break
			}
			m.reload()
		} else {
			m.mode = next
		}
		m.say(true, "routing mode: "+next)
	case "n":
		if proto == "" {
			m.say(false, "select a tunnel first (move to one with j/k)")
		} else if m.store == nil {
			m.say(false, "profiles unavailable: "+m.storeErr)
		} else {
			return m, func() tea.Msg { return openFormMsg{proto} }
		}
	case "p":
		if proto == "" {
			m.say(false, "select a tunnel first (move to one with j/k)")
		} else if m.store == nil {
			m.say(false, "profiles unavailable: "+m.storeErr)
		} else {
			return m, func() tea.Msg { return openPasteMsg{proto} }
		}
	case "d":
		p := m.pickedProfile(proto)
		switch {
		case p == nil:
			m.say(false, "no profile to delete")
		case m.delArm != p.Name:
			m.delArm = p.Name
			m.say(false, "press d again to delete profile "+p.Name)
		default:
			if err := m.store.Delete(p.Name); err != nil {
				m.say(false, "delete failed: "+err.Error())
			} else {
				m.say(true, "deleted profile "+p.Name)
			}
			m.delArm = ""
			m.reload()
		}
	case "g":
		return m, func() tea.Msg { return openGenMsg{} }
	case "t":
		m.say(m.testProfile(proto))
	case "u":
		return m, func() tea.Msg { return startTunnelMsg{} }
	case "x":
		return m, func() tea.Msg { return stopTunnelMsg{} }
	}
	return m, nil
}

// testProfile validates the picked profile's config without starting it.
func (m tunnelModel) testProfile(proto string) (bool, string) {
	if proto == "" {
		return false, "select a tunnel first"
	}
	p := m.pickedProfile(proto)
	if p == nil {
		if needsConfig(proto) {
			return false, "no profile for " + proto + " (press n to create one)"
		}
		return true, proto + " needs no config"
	}
	raw, err := os.ReadFile(p.ConfigPath)
	if err != nil {
		return false, "cannot read config: " + err.Error()
	}
	if err := profile.ValidateBody(proto, string(raw)); err != nil {
		return false, p.Name + ": " + err.Error()
	}
	if proto == "tun2socks" {
		if _, err := tunnel.ParseTun2socksConfig(p.ConfigPath); err != nil {
			return false, p.Name + ": " + err.Error()
		}
	}
	return true, p.Name + ": config is well-formed (not started)"
}

func (m tunnelModel) View(width int) string {
	var leftLines []string
	for i, it := range m.items {
		if it.separator {
			if i > 0 {
				leftLines = append(leftLines, "")
			}
			leftLines = append(leftLines, sSectionTitle.Render(it.section))
			leftLines = append(leftLines, sSeparator.Render(strings.Repeat("─", 30)))
		}

		indicator := "( )"
		if it.checked {
			indicator = "(●)"
		}

		labelSt := sUnchecked
		if it.checked {
			labelSt = sChecked
		}

		ind := sUnchecked.Render(indicator)
		if i == m.cursor {
			ind = sCursor.Render(indicator)
			labelSt = sCursor
		}

		// Show availability indicator for non-"none" tunnels.
		avail := ""
		if it.opKey != "tunnel-none" {
			proto := strings.TrimPrefix(it.opKey, "tunnel-")
			if a, ok := m.avail[proto]; ok && a {
				avail = sOK.Render(" ✓")
			} else {
				avail = sUnavail.Render(" ✗")
			}
		}

		leftLines = append(leftLines, fmt.Sprintf("%s %s%s", ind, labelSt.Render(it.label), avail))
	}

	for len(leftLines) < 13 {
		leftLines = append(leftLines, "")
	}
	left := strings.Join(leftLines, "\n")

	// Right: short description of the focused tunnel.
	focused := m.items[m.cursor]
	var rightLines []string
	rightLines = append(rightLines, sDescTitle.Render(focused.descTitle))
	rightLines = append(rightLines, sSeparator.Render(strings.Repeat("─", 42)))
	desc := strings.Split(focused.description, "\n")
	if len(desc) > 8 {
		desc = append(desc[:8], "...")
	}
	for _, line := range desc {
		rightLines = append(rightLines, sDescBody.Render(line))
	}
	if focused.opKey != "tunnel-none" {
		proto := strings.TrimPrefix(focused.opKey, "tunnel-")
		if proto == "tun2socks" {
			rightLines = append(rightLines, "", sOK.Render("✓ Built in, no binary needed"))
		} else if a, ok := m.avail[proto]; ok && a {
			rightLines = append(rightLines, "", sOK.Render("✓ Binary found in PATH"))
		} else {
			rightLines = append(rightLines, "", sFail.Render("✗ Binary not found — install it first"))
		}
	}
	right := sDescBox.Render(strings.Join(rightLines, "\n"))

	top := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(36).Render(left),
		lipgloss.NewStyle().PaddingLeft(2).Render(right),
	)
	return top + "\n" + m.profilePanel() + "\n" + m.livePanel()
}

func (m tunnelModel) profilePanel() string {
	var b strings.Builder
	b.WriteString(sPanelTitle.Render("  PROFILE") + "\n")
	proto := m.cursorProto()
	switch {
	case proto == "":
		b.WriteString(sTableDim.Render("  No tunnel selected: traffic leaves directly.") + "\n")
	case m.store == nil:
		b.WriteString(sFail.Render("  profiles unavailable: "+m.storeErr) + "\n")
	default:
		list := m.profilesFor(proto)
		p := m.pickedProfile(proto)
		switch {
		case p == nil && needsConfig(proto):
			b.WriteString(sWarn.Render("  No profile yet. Press n to create one, p to paste a config.") + "\n")
		case p == nil:
			b.WriteString(sTableDim.Render("  "+proto+" needs no config.") + fmt.Sprintf("  mode: %s\n", m.modeFor(proto)))
		default:
			b.WriteString(fmt.Sprintf("  %s %s   mode: %s   (%d of %d, ←/→ to switch)\n",
				sCursor.Render("▸"), sChecked.Render(p.Name), m.modeFor(proto), indexOf(list, p.Name)+1, len(list)))
			b.WriteString(sTableDim.Render("  "+p.ConfigPath) + "\n")
		}
	}
	if m.note != "" {
		st := sFail
		if m.noteOK {
			st = sOK
		}
		b.WriteString(st.Render("  "+m.note) + "\n")
	}
	b.WriteString(sTableDim.Render("  [n]ew  [p]aste  [g]enerate keys  [d]elete  [t]est  [m]ode  [u]p  [x] stop") + "\n")
	return b.String()
}

func indexOf(list []profile.Profile, name string) int {
	for i := range list {
		if list[i].Name == name {
			return i
		}
	}
	return 0
}

func (m tunnelModel) livePanel() string {
	var b strings.Builder
	b.WriteString(sPanelTitle.Render("  LIVE TUNNEL") + "\n")
	st := m.live.status
	if st.Running {
		b.WriteString(fmt.Sprintf("  %s %s   %s\n", sUp.Render("● running"), sChecked.Render(st.Protocol), sTableRow.Render(st.Endpoint)))
	} else {
		b.WriteString(sDown.Render("  ○ no active tunnel") + "\n")
	}
	if len(m.live.log) > 0 {
		if !st.Running {
			b.WriteString(sTableDim.Render("  last log:") + "\n")
		}
		for _, l := range m.live.log {
			b.WriteString(sTableDim.Render("  "+truncate(l, 110)) + "\n")
		}
	}
	return b.String()
}

// selectedTunnel returns the selected (checked) tunnel protocol name (or "").
func (m tunnelModel) selectedTunnel() string {
	for _, it := range m.items {
		if it.checked && it.opKey != "tunnel-none" {
			return strings.TrimPrefix(it.opKey, "tunnel-")
		}
	}
	return ""
}
