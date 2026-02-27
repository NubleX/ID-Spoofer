package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/NubleX/idspoof/internal/tunnel"
)

var tunnelItems = []checkItem{
	{
		label: "None", opKey: "tunnel-none", group: "tunnel",
		descTitle: "No Tunnel",
		separator: true, section: "Traffic Encapsulation",
		description: "No traffic encapsulation. Packets leave\nyour interface directly with the\nspoofed identity.",
		checked: true,
	},
	{
		label: "Tor", opKey: "tunnel-tor", group: "tunnel",
		descTitle: "Tor Network",
		description: "Routes all traffic through Tor\n(3-hop onion routing).\n\n\u2022 Transparent proxy via iptables\n  or SOCKS5 on 127.0.0.1:9050\n\u2022 High anonymity, moderate speed\n\nRequires: tor binary",
	},
	{
		label: "WireGuard", opKey: "tunnel-wireguard", group: "tunnel",
		descTitle: "WireGuard VPN",
		description: "Fast kernel-level VPN tunnel.\n\n\u2022 ChaCha20 + Poly1305 encryption\n\u2022 Minimal attack surface\n\nRequires: wg-quick binary\nUse --tunnel-config for .conf",
	},
	{
		label: "I2P / PurpleI2P", opKey: "tunnel-i2p", group: "tunnel",
		descTitle: "I2P Anonymity Network",
		description: "Garlic routing network.\n\n\u2022 SOCKS5 on 127.0.0.1:4447\n\u2022 HTTP proxy on 127.0.0.1:4444\n\u2022 Designed for hidden services\n\nRequires: i2pd binary",
	},
	{
		label: "Shadowsocks", opKey: "tunnel-shadowsocks", group: "tunnel",
		descTitle: "Shadowsocks Proxy",
		description: "AEAD encrypted proxy.\n\n\u2022 Looks like normal HTTPS\n\u2022 Defeats DPI censorship\n\u2022 Transparent or SOCKS5 mode\n\nRequires: sslocal binary\nUse --tunnel-config for JSON",
	},
	{
		label: "QUIC Tunnel", opKey: "tunnel-quic", group: "tunnel",
		descTitle: "QUIC-based Tunnel",
		description: "UDP-based encrypted tunnel\n(Hysteria2).\n\n\u2022 Anti-DPI obfuscation\n\u2022 Brutal congestion control\n\nRequires: hysteria2 binary\nUse --tunnel-config for YAML",
	},
	{
		label: "LWO (WireGuard Obfs)", opKey: "tunnel-lwo", group: "tunnel",
		descTitle: "Lightweight WG Obfuscation",
		description: "WireGuard with header obfuscation\n(Mullvad-compatible).\n\n\u2022 Defeats WireGuard DPI blocks\n\u2022 Minimal overhead (~0.01ms)\n\nRequires: wg binary + obfuscation\ncapable endpoint",
	},
	{
		label: "Tor over VPN", opKey: "tunnel-tor-over-vpn", group: "tunnel",
		descTitle: "Tor over VPN",
		description: "VPN first, then Tor through it.\n\nISP sees: VPN traffic only\nVPN sees: Tor entry node\nTor sees: VPN exit IP\n\nRequires: wg-quick + tor",
	},
	{
		label: "VPN over Tor", opKey: "tunnel-vpn-over-tor", group: "tunnel",
		descTitle: "VPN over Tor",
		description: "Tor first, then VPN through Tor.\n\nISP sees: Tor traffic only\nTor exit sees: VPN handshake\nVPN server never learns real IP\n\nRequires: tor + wg-quick",
	},
}

type tunnelModel struct {
	items  []checkItem
	cursor int
	avail  map[string]bool // protocol → binary exists
}

func newTunnelModel() tunnelModel {
	items := make([]checkItem, len(tunnelItems))
	copy(items, tunnelItems)
	return tunnelModel{
		items: items,
		avail: tunnel.AvailableProtocols(),
	}
}

func (m tunnelModel) Update(msg tea.Msg) (tunnelModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
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
		}
	}
	return m, nil
}

func (m tunnelModel) View(width int) string {
	var leftLines []string
	for i, it := range m.items {
		if it.separator {
			if i > 0 {
				leftLines = append(leftLines, "")
			}
			leftLines = append(leftLines, sSectionTitle.Render(it.section))
			leftLines = append(leftLines, sSeparator.Render(strings.Repeat("\u2500", 30)))
		}

		indicator := "( )"
		if it.checked {
			indicator = "(\u25cf)"
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
				avail = sOK.Render(" \u2713")
			} else {
				avail = sUnavail.Render(" \u2717")
			}
		}

		leftLines = append(leftLines, fmt.Sprintf("%s %s%s", ind, labelSt.Render(it.label), avail))
	}

	for len(leftLines) < 18 {
		leftLines = append(leftLines, "")
	}
	left := strings.Join(leftLines, "\n")

	// Right: description.
	focused := m.items[m.cursor]
	var rightLines []string
	rightLines = append(rightLines, sDescTitle.Render(focused.descTitle))
	rightLines = append(rightLines, sSeparator.Render(strings.Repeat("\u2500", 42)))
	rightLines = append(rightLines, "")
	for _, line := range strings.Split(focused.description, "\n") {
		rightLines = append(rightLines, sDescBody.Render(line))
	}

	// Availability detail.
	if focused.opKey != "tunnel-none" {
		proto := strings.TrimPrefix(focused.opKey, "tunnel-")
		if a, ok := m.avail[proto]; ok && a {
			rightLines = append(rightLines, "", sOK.Render("\u2713 Binary found in PATH"))
		} else {
			rightLines = append(rightLines, "", sFail.Render("\u2717 Binary not found — install it first"))
		}
	}

	right := sDescBox.Render(strings.Join(rightLines, "\n"))

	leftWidth := 36
	leftStyled := lipgloss.NewStyle().Width(leftWidth).Render(left)
	return lipgloss.JoinHorizontal(lipgloss.Top,
		leftStyled,
		lipgloss.NewStyle().PaddingLeft(2).Render(right),
	)
}

// selectedTunnel returns the selected tunnel protocol name (or "").
func (m tunnelModel) selectedTunnel() string {
	for _, it := range m.items {
		if it.checked && it.opKey != "tunnel-none" {
			return strings.TrimPrefix(it.opKey, "tunnel-")
		}
	}
	return ""
}
