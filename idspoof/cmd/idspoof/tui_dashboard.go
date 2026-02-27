package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/NubleX/idspoof/internal/netrecon"
)

// Messages for async probe.
type netProbeResult struct {
	state *netrecon.NetworkState
	err   error
}

type netProbeTick struct{}

// dashboardModel displays network recon results.
type dashboardModel struct {
	state    *netrecon.NetworkState
	spinner  spinner.Model
	scanning bool
	err      error
}

func newDashboardModel() dashboardModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(colorCyan)
	return dashboardModel{spinner: s, scanning: true}
}

func (m dashboardModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, probeNetwork)
}

func probeNetwork() tea.Msg {
	prober := netrecon.NewProber()
	state, err := prober.Probe()
	return netProbeResult{state: state, err: err}
}

func scheduleProbe() tea.Cmd {
	return tea.Tick(5*time.Second, func(t time.Time) tea.Msg {
		return netProbeTick{}
	})
}

func (m dashboardModel) Update(msg tea.Msg) (dashboardModel, tea.Cmd) {
	switch msg := msg.(type) {
	case netProbeResult:
		m.scanning = false
		m.state = msg.state
		m.err = msg.err
		return m, scheduleProbe()

	case netProbeTick:
		m.scanning = true
		return m, tea.Batch(m.spinner.Tick, probeNetwork)

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m dashboardModel) View(width int) string {
	if m.scanning && m.state == nil {
		return fmt.Sprintf("\n  %s Scanning network...\n", m.spinner.View())
	}
	if m.err != nil {
		return sFail.Render(fmt.Sprintf("\n  Error: %v\n", m.err))
	}
	if m.state == nil {
		return sUnavail.Render("\n  No network data yet.\n")
	}

	ns := m.state
	var sections []string

	// ── Interfaces table ──
	sections = append(sections, m.renderInterfaces(ns, width))

	// ── Side-by-side: VPNs + Tunnels ──
	vpnPanel := m.renderVPNs(ns)
	tunnelPanel := m.renderTunnelDetection(ns)
	sideBySide := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(width/2-2).Render(vpnPanel),
		lipgloss.NewStyle().Width(width/2-2).PaddingLeft(1).Render(tunnelPanel),
	)
	sections = append(sections, sideBySide)

	// ── Side-by-side: Route + Ports ──
	routePanel := m.renderRoute(ns)
	portsPanel := m.renderPorts(ns, width/2-2)
	sideBySide2 := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(width/2-2).Render(routePanel),
		lipgloss.NewStyle().Width(width/2-2).PaddingLeft(1).Render(portsPanel),
	)
	sections = append(sections, sideBySide2)

	// ── Warnings ──
	if len(ns.Warnings) > 0 {
		sections = append(sections, m.renderWarnings(ns))
	}

	// Scanning indicator.
	scanStatus := ""
	if m.scanning {
		scanStatus = fmt.Sprintf("  %s Refreshing...", m.spinner.View())
	} else {
		scanStatus = sTableDim.Render(fmt.Sprintf("  Last scan: %s", ns.Timestamp.Format("15:04:05")))
	}
	sections = append(sections, scanStatus)

	return strings.Join(sections, "\n\n")
}

func (m dashboardModel) renderInterfaces(ns *netrecon.NetworkState, width int) string {
	var b strings.Builder
	b.WriteString(sPanelTitle.Render("  INTERFACES") + "\n")
	b.WriteString(sSeparator.Render("  " + strings.Repeat("\u2500", min(width-4, 76))) + "\n")

	// Header.
	hdr := fmt.Sprintf("  %-18s %-7s %-22s %-19s %s",
		sTableHeader.Render("NAME"),
		sTableHeader.Render("STATE"),
		sTableHeader.Render("IP ADDRESS"),
		sTableHeader.Render("MAC"),
		sTableHeader.Render("TYPE"))
	b.WriteString(hdr + "\n")

	for _, iface := range ns.Interfaces {
		state := sDown.Render("\u25cb DOWN")
		if iface.State == "UP" {
			state = sUp.Render("\u25cf UP  ")
		}

		ip := "\u2014"
		if len(iface.IPs) > 0 {
			ip = iface.IPs[0]
		}

		mac := "\u2014"
		if iface.MAC != "" && iface.MAC != "00:00:00:00:00:00" {
			mac = iface.MAC
		}

		typeSt := sTableDim.Render(iface.Type)

		b.WriteString(fmt.Sprintf("  %-18s %s %-22s %-19s %s\n",
			sTableRow.Render(iface.Name),
			state,
			sTableRow.Render(truncate(ip, 22)),
			sTableRow.Render(mac),
			typeSt))

		// Show additional IPs indented.
		for i := 1; i < len(iface.IPs) && i < 3; i++ {
			b.WriteString(fmt.Sprintf("  %-18s %7s %-22s\n",
				"", "", sTableDim.Render(iface.IPs[i])))
		}
	}
	return b.String()
}

func (m dashboardModel) renderVPNs(ns *netrecon.NetworkState) string {
	var b strings.Builder
	b.WriteString(sPanelTitle.Render("\u26a1 ACTIVE VPNs") + "\n")
	b.WriteString(sSeparator.Render(strings.Repeat("\u2500", 30)) + "\n")

	if len(ns.VPNs) == 0 {
		b.WriteString(sTableDim.Render("  No VPNs detected") + "\n")
	} else {
		for _, vpn := range ns.VPNs {
			b.WriteString(fmt.Sprintf("  %s on %s\n",
				sOK.Render(vpn.Name),
				sTableRow.Render(vpn.Iface)))
			if vpn.Endpoint != "" {
				b.WriteString(fmt.Sprintf("  %s %s\n",
					sTableDim.Render("\u2192 endpoint:"),
					sTableRow.Render(vpn.Endpoint)))
			}
		}
	}
	return b.String()
}

func (m dashboardModel) renderTunnelDetection(ns *netrecon.NetworkState) string {
	var b strings.Builder
	b.WriteString(sPanelTitle.Render("\U0001f512 TUNNELS") + "\n")
	b.WriteString(sSeparator.Render(strings.Repeat("\u2500", 30)) + "\n")

	if len(ns.Tunnels) == 0 {
		b.WriteString(sTableDim.Render("  No tunnels detected") + "\n")
	} else {
		for _, t := range ns.Tunnels {
			port := t.Port
			if port == "" {
				port = "(process only)"
			}
			b.WriteString(fmt.Sprintf("  %s on %s\n",
				sSpoofed.Render(t.Protocol),
				sTableRow.Render(port)))
			if t.Process != "" {
				b.WriteString(fmt.Sprintf("  %s %s\n",
					sTableDim.Render("process:"),
					sTableRow.Render(t.Process)))
			}
		}
	}
	return b.String()
}

func (m dashboardModel) renderRoute(ns *netrecon.NetworkState) string {
	var b strings.Builder
	b.WriteString(sPanelTitle.Render("\U0001f310 DEFAULT ROUTE") + "\n")
	b.WriteString(sSeparator.Render(strings.Repeat("\u2500", 30)) + "\n")

	if ns.Route.Default == "" {
		b.WriteString(sTableDim.Render("  No default route") + "\n")
	} else {
		b.WriteString(fmt.Sprintf("  via %s dev %s\n",
			sTableRow.Render(ns.Route.Default),
			sTableRow.Render(ns.Route.DefaultDev)))
		if ns.Route.VPNRouted {
			b.WriteString(sWarn.Render("  VPN routed: Yes") + "\n")
		} else {
			b.WriteString(sTableDim.Render("  VPN routed: No") + "\n")
		}
	}
	return b.String()
}

func (m dashboardModel) renderPorts(ns *netrecon.NetworkState, maxWidth int) string {
	var b strings.Builder
	b.WriteString(sPanelTitle.Render("LISTENING PORTS") + "\n")
	b.WriteString(sSeparator.Render(strings.Repeat("\u2500", 30)) + "\n")

	if len(ns.Ports) == 0 {
		b.WriteString(sTableDim.Render("  No listening ports detected") + "\n")
	} else {
		shown := 0
		for _, p := range ns.Ports {
			if shown >= 8 {
				b.WriteString(sTableDim.Render(fmt.Sprintf("  ... and %d more", len(ns.Ports)-8)) + "\n")
				break
			}
			proc := ""
			if p.Process != "" {
				proc = fmt.Sprintf("%s (%d)", p.Process, p.PID)
			}
			b.WriteString(fmt.Sprintf("  %-5s %-22s %s\n",
				sTableDim.Render(p.Protocol),
				sTableRow.Render(truncate(p.Address, 22)),
				sTableDim.Render(proc)))
			shown++
		}
	}
	return b.String()
}

func (m dashboardModel) renderWarnings(ns *netrecon.NetworkState) string {
	var lines []string
	lines = append(lines, sWarn.Render("\u26a0 WARNINGS"))
	lines = append(lines, sSeparator.Render(strings.Repeat("\u2500", 60)))
	for _, w := range ns.Warnings {
		lines = append(lines, sWarn.Render("  \u2022 "+w))
	}
	return sWarningBox.Render(strings.Join(lines, "\n"))
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "\u2026"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
