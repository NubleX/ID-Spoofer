package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// statusModel displays the current system fingerprint and spoofing state.
type statusModel struct{}

func newStatusModel() statusModel {
	return statusModel{}
}

func (m statusModel) Update(msg tea.Msg) (statusModel, tea.Cmd) {
	return m, nil
}

func (m statusModel) View(width int) string {
	var b strings.Builder

	// ── Hostname ──
	b.WriteString(sPanelTitle.Render("  SYSTEM IDENTITY") + "\n")
	b.WriteString(sSeparator.Render("  " + strings.Repeat("\u2500", min(width-4, 76))) + "\n\n")

	hostname := runCmd("hostname")
	b.WriteString(fmt.Sprintf("  %-22s %s  %s\n",
		sTableHeader.Render("Hostname"),
		sTableRow.Render(hostname),
		sTableDim.Render("[not modified]")))

	// ── Persona state ──
	personaType := "none"
	if pt, ok := stateM.Get("PERSONA_TYPE"); ok && pt != "" {
		personaType = pt
	}
	b.WriteString(fmt.Sprintf("  %-22s %s\n",
		sTableHeader.Render("Active Persona"),
		sSpoofed.Render(personaType)))

	b.WriteString("\n")

	// ── Network Interfaces + MACs ──
	b.WriteString(sPanelTitle.Render("  INTERFACES") + "\n")
	b.WriteString(sSeparator.Render("  " + strings.Repeat("\u2500", min(width-4, 76))) + "\n")

	origMACs, _ := stateM.Get("ORIG_MACS")
	origMap := parseMACState(origMACs)
	for name, mac := range currentMACMap() {
		orig := origMap[name]
		tag := sTableDim.Render("[original]")
		if orig != "" && !strings.EqualFold(orig, mac) {
			tag = sSpoofed.Render("[spoofed]")
		}
		b.WriteString(fmt.Sprintf("  %-14s %-20s %s\n",
			sTableRow.Render(name), sTableRow.Render(mac), tag))
	}
	b.WriteString("\n")

	// ── TCP/IP Fingerprint ──
	b.WriteString(sPanelTitle.Render("  TCP/IP FINGERPRINT") + "\n")
	b.WriteString(sSeparator.Render("  " + strings.Repeat("\u2500", min(width-4, 76))) + "\n")

	type fpRow struct {
		label string
		key   string
		hint  string
	}
	rows := []fpRow{
		{"TTL", "net.ipv4.ip_default_ttl", "128=Windows, 64=Linux/macOS"},
		{"tcp_timestamps", "net.ipv4.tcp_timestamps", "0=Windows, 1=Linux/macOS"},
		{"tcp_window_scaling", "net.ipv4.tcp_window_scaling", ""},
		{"tcp_sack", "net.ipv4.tcp_sack", ""},
		{"tcp_ecn", "net.ipv4.tcp_ecn", "0=off, 1=on, 2=passive"},
	}

	origKeys := map[string]string{
		"net.ipv4.ip_default_ttl":   "ORIG_TTL",
		"net.ipv4.tcp_timestamps":   "ORIG_TCP_TIMESTAMPS",
		"net.ipv4.tcp_window_scaling": "ORIG_TCP_WINDOW_SCALING",
		"net.ipv4.tcp_sack":          "ORIG_TCP_SACK",
		"net.ipv4.tcp_ecn":           "ORIG_TCP_ECN",
	}

	for _, r := range rows {
		val := runCmd("sysctl", "-n", r.key)
		tag := ""
		if sk, ok := origKeys[r.key]; ok {
			if orig, found := stateM.Get(sk); found && orig != "" && orig != val {
				tag = sSpoofed.Render(" [modified]")
			}
		}
		hint := ""
		if r.hint != "" {
			hint = sTableDim.Render("  (" + r.hint + ")")
		}
		b.WriteString(fmt.Sprintf("  %-22s %s%s%s\n",
			sTableHeader.Render(r.label), sTableRow.Render(val), tag, hint))
	}
	b.WriteString("\n")

	// ── iptables ──
	b.WriteString(sPanelTitle.Render("  IPTABLES") + "\n")
	b.WriteString(sSeparator.Render("  " + strings.Repeat("\u2500", min(width-4, 76))) + "\n")

	iptOut := runCmd("iptables", "-t", "mangle", "-S", "IDSPOOF_NETEMU")
	if strings.Contains(iptOut, "IDSPOOF_NETEMU") {
		b.WriteString(sOK.Render("  IDSPOOF_NETEMU chain active") + "\n")
		for _, line := range strings.Split(iptOut, "\n") {
			if line != "" {
				b.WriteString(sTableDim.Render("    "+line) + "\n")
			}
		}
	} else {
		// Check old chain name for backward compat.
		iptOutOld := runCmd("iptables", "-t", "mangle", "-S", "IDSPOOF_WINEMU")
		if strings.Contains(iptOutOld, "IDSPOOF_WINEMU") {
			sWarn.Render("  IDSPOOF_WINEMU chain (legacy) active")
		} else {
			b.WriteString(sTableDim.Render("  No ID-Spoofer iptables rules") + "\n")
		}
	}

	// ── NFQUEUE ──
	if strings.Contains(iptOut, "NFQUEUE") {
		b.WriteString(sOK.Render("  NFQUEUE rewriter active (queue 42)") + "\n")
	} else {
		b.WriteString(sTableDim.Render("  NFQUEUE not active") + "\n")
	}

	// ── Tunnel ──
	b.WriteString("\n")
	b.WriteString(sPanelTitle.Render("  TUNNEL") + "\n")
	b.WriteString(sSeparator.Render("  " + strings.Repeat("\u2500", min(width-4, 76))) + "\n")

	tunnelProto, _ := stateM.Get("TUNNEL_PROTOCOL")
	tunnelMode, _ := stateM.Get("TUNNEL_MODE")
	if tunnelProto != "" {
		b.WriteString(fmt.Sprintf("  %s  mode: %s\n",
			sSpoofed.Render(tunnelProto),
			sTableRow.Render(tunnelMode)))
	} else {
		b.WriteString(sTableDim.Render("  No active tunnel") + "\n")
	}

	// ── State version ──
	if v, ok := stateM.Get("STATE_VERSION"); ok {
		b.WriteString(fmt.Sprintf("\n  %s %s\n",
			sTableDim.Render("State version:"), sTableRow.Render(v)))
	}

	return b.String()
}
