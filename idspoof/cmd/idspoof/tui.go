package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/NubleX/idspoof/internal/config"
	"github.com/NubleX/idspoof/internal/spoofer"
)

// ── Tab identifiers ─────────────────────────────────────────────────────────

type tab int

const (
	tabDashboard tab = iota
	tabIdentity
	tabTunnel
	tabTraffic
	tabStatus
)

var tabNames = []string{"Dashboard", "Identity", "Tunnel", "Traffic", "Status"}

// ── Main TUI model ──────────────────────────────────────────────────────────

type mainModel struct {
	activeTab tab
	width     int
	height    int

	dashboard dashboardModel
	identity  identityModel
	tunnel    tunnelModel
	traffic   trafficModel
	status    statusModel

	lastMsg string
	lastOK  bool

	quitting bool
}

func newMainModel() mainModel {
	return mainModel{
		activeTab: tabDashboard,
		width:     80,
		height:    40,
		dashboard: newDashboardModel(),
		identity:  newIdentityModel(),
		tunnel:    newTunnelModel(),
		traffic:   newTrafficModel(),
		status:    newStatusModel(),
	}
}

func (m mainModel) Init() tea.Cmd {
	return tea.Batch(m.dashboard.Init(), m.traffic.Init())
}

func (m mainModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "Q":
			m.quitting = true
			return m, tea.Quit

		// Tab navigation.
		case "tab":
			m.activeTab = (m.activeTab + 1) % tab(len(tabNames))
			m.lastMsg = ""
			return m, nil
		case "shift+tab":
			m.activeTab = (m.activeTab - 1 + tab(len(tabNames))) % tab(len(tabNames))
			m.lastMsg = ""
			return m, nil
		case "1":
			m.activeTab = tabDashboard
			m.lastMsg = ""
			return m, nil
		case "2":
			m.activeTab = tabIdentity
			m.lastMsg = ""
			return m, nil
		case "3":
			m.activeTab = tabTunnel
			m.lastMsg = ""
			return m, nil
		case "4":
			m.activeTab = tabTraffic
			m.lastMsg = ""
			return m, nil
		case "5":
			m.activeTab = tabStatus
			m.lastMsg = ""
			return m, nil

		// Global actions.
		case "a", "A":
			opts := m.identity.buildOpts()
			opts.Tunnel = m.tunnel.selectedTunnel()
			if !opts.MAC && !opts.NetIdent && !opts.SysInfo {
				m.lastMsg = "Nothing selected \u2014 tick at least one operation."
				m.lastOK = false
			} else {
				results := orch.Apply(opts)
				m.lastMsg, m.lastOK = summariseResults(results)
			}
			return m, nil

		case "r", "R":
			results := orch.Restore(spoofer.Options{MAC: true, NetIdent: true, Quiet: true})
			m.lastMsg, m.lastOK = summariseResults(results)
			return m, nil

		case "s", "S":
			// Manual rescan.
			m.dashboard.scanning = true
			return m, tea.Batch(m.dashboard.spinner.Tick, probeNetwork)
		}

	// Route spinner ticks to both dashboard and traffic (they each have a spinner).
	case spinner.TickMsg:
		var cmd1, cmd2 tea.Cmd
		m.dashboard, cmd1 = m.dashboard.Update(msg)
		m.traffic, cmd2 = m.traffic.Update(msg)
		if cmd1 != nil {
			cmds = append(cmds, cmd1)
		}
		if cmd2 != nil {
			cmds = append(cmds, cmd2)
		}
		return m, tea.Batch(cmds...)

	// Route netrecon probe messages to dashboard.
	case netProbeResult, netProbeTick:
		var cmd tea.Cmd
		m.dashboard, cmd = m.dashboard.Update(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
		return m, tea.Batch(cmds...)

	// Route traffic poll messages to traffic tab.
	case trafficResult, trafficTick:
		var cmd tea.Cmd
		m.traffic, cmd = m.traffic.Update(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
		return m, tea.Batch(cmds...)
	}

	// Route remaining messages to active tab.
	switch m.activeTab {
	case tabDashboard:
		var cmd tea.Cmd
		m.dashboard, cmd = m.dashboard.Update(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	case tabIdentity:
		var cmd tea.Cmd
		m.identity, cmd = m.identity.Update(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	case tabTunnel:
		var cmd tea.Cmd
		m.tunnel, cmd = m.tunnel.Update(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	case tabTraffic:
		var cmd tea.Cmd
		m.traffic, cmd = m.traffic.Update(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	case tabStatus:
		var cmd tea.Cmd
		m.status, cmd = m.status.Update(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	}

	return m, tea.Batch(cmds...)
}

func (m mainModel) View() string {
	if m.quitting {
		return sOK.Render("Goodbye.\n")
	}

	var b strings.Builder
	contentWidth := m.width
	if contentWidth < 80 {
		contentWidth = 80
	}

	// ── Banner ──
	banner := m.renderBanner()
	b.WriteString(banner)
	b.WriteString("\n")

	// ── Tab bar ──
	b.WriteString(m.renderTabBar())
	b.WriteString("\n\n")

	// ── Tab content ──
	switch m.activeTab {
	case tabDashboard:
		b.WriteString(m.dashboard.View(contentWidth))
	case tabIdentity:
		b.WriteString(m.identity.View(contentWidth))
	case tabTunnel:
		b.WriteString(m.tunnel.View(contentWidth))
	case tabTraffic:
		b.WriteString(m.traffic.View(contentWidth))
	case tabStatus:
		b.WriteString(m.status.View(contentWidth))
	}

	b.WriteString("\n")

	// ── Result line ──
	if m.lastMsg != "" {
		if m.lastOK {
			b.WriteString(sOK.Render("  \u2713 " + m.lastMsg))
		} else {
			b.WriteString(sFail.Render("  \u2717 " + m.lastMsg))
		}
		b.WriteString("\n")
	}

	// ── Help bar ──
	b.WriteString("\n")
	b.WriteString(m.renderHelpBar())
	b.WriteString("\n")

	return b.String()
}

// ── Rendering helpers ───────────────────────────────────────────────────────

func (m mainModel) renderBanner() string {
	ver := strings.TrimPrefix(config.Version, "v")

	// ASCII banner with gradient chars.
	line1 := sTitle.Render(fmt.Sprintf("  \u2591\u2592\u2593 ID-SPOOFER v%s \u2593\u2592\u2591", ver))
	line2 := sSubtitle.Render("  Identity Spoofing Toolkit")

	return sBanner.Render(line1 + "\n" + line2)
}

func (m mainModel) renderTabBar() string {
	var tabs []string
	for i, name := range tabNames {
		if tab(i) == m.activeTab {
			tabs = append(tabs, sTabActive.Render(fmt.Sprintf("\u25b8 %s", name)))
		} else {
			tabs = append(tabs, sTabInactive.Render(fmt.Sprintf("  %s", name)))
		}
	}
	return lipgloss.JoinHorizontal(lipgloss.Bottom, tabs...)
}

func (m mainModel) renderHelpBar() string {
	keys := []struct{ key, desc string }{
		{"A", "Apply"},
		{"R", "Restore"},
		{"S", "Scan"},
		{"Tab", "Switch"},
		{"1-5", "Jump"},
		{"\u2191\u2193/jk", "Nav"},
		{"Space", "Toggle"},
		{"Q", "Quit"},
	}
	if m.activeTab == tabTraffic {
		keys = []struct{ key, desc string }{
			{"A", "Apply"},
			{"R", "Restore"},
			{"S", "Scan"},
			{"Tab", "Switch"},
			{"1-5", "Jump"},
			{"j/k", "Scroll conns"},
			{"g/G", "Top/Bottom"},
			{"Q", "Quit"},
		}
	}
	var parts []string
	for _, k := range keys {
		parts = append(parts,
			sCursor.Render("["+k.key+"]")+sHelpBar.Render(k.desc))
	}
	return "  " + strings.Join(parts, "  ")
}

// summariseResults collapses results into a single status line.
func summariseResults(results []spoofer.Result) (msg string, ok bool) {
	var parts []string
	allOK := true
	for _, r := range results {
		if r.Err != nil {
			parts = append(parts, fmt.Sprintf("%s: %v", r.Operation, r.Err))
			allOK = false
		} else {
			parts = append(parts, r.Operation+": "+r.Details)
		}
	}
	return strings.Join(parts, " | "), allOK
}

// runTUI starts the Bubble Tea program.
func runTUI() error {
	p := tea.NewProgram(newMainModel(), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
