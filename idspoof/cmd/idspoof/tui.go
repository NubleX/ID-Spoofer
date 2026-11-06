package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/NubleX/ID-Spoofer/idspoof/internal/config"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/profile"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/spoofer"
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

	flow     flowModel
	liveLoop bool // a live-tunnel refresh loop is running

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
		flow:      newFlowModel(),
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
		if msg.String() == "ctrl+c" {
			m.quitting = true
			return m, tea.Quit
		}
		if m.flow.kind != ovNone {
			return m.updateOverlay(msg)
		}
		switch msg.String() {
		case "q", "Q":
			m.quitting = true
			return m, tea.Quit

		// Tab navigation.
		case "tab":
			m.activeTab = (m.activeTab + 1) % tab(len(tabNames))
			m.lastMsg = ""
			return m, m.enterTab()
		case "shift+tab":
			m.activeTab = (m.activeTab - 1 + tab(len(tabNames))) % tab(len(tabNames))
			m.lastMsg = ""
			return m, m.enterTab()
		case "1":
			m.activeTab = tabDashboard
			m.lastMsg = ""
			return m, m.enterTab()
		case "2":
			m.activeTab = tabIdentity
			m.lastMsg = ""
			return m, m.enterTab()
		case "3":
			m.activeTab = tabTunnel
			m.lastMsg = ""
			return m, m.enterTab()
		case "4":
			m.activeTab = tabTraffic
			m.lastMsg = ""
			return m, m.enterTab()
		case "5":
			m.activeTab = tabStatus
			m.lastMsg = ""
			return m, m.enterTab()

		// Global actions.
		case "a", "A":
			return m.beginApply()

		case "r", "R":
			m.flow.kind = ovRestore
			return m, nil

		case "l", "L":
			if m.activeTab == tabTunnel && msg.String() == "l" {
				break // l cycles profiles on the tunnel tab
			}
			if len(m.flow.last) > 0 {
				m.flow.kind = ovResult
				m.flow.title = m.flow.lastTitle + " result"
				m.flow.lines = m.flow.last
				m.flow.scroll = 0
			}
			return m, nil

		case "s", "S":
			// Manual rescan.
			m.dashboard.scanning = true
			return m, tea.Batch(m.dashboard.spinner.Tick, probeNetwork)
		}

	// Route spinner ticks only to the active tab to avoid ~10Hz re-renders
	// of invisible tabs (which caused interface row flickering).
	case spinner.TickMsg:
		if m.flow.kind == ovRunning {
			var cmd tea.Cmd
			m.flow.spin, cmd = m.flow.spin.Update(msg)
			cmds = append(cmds, cmd)
		}
		switch m.activeTab {
		case tabDashboard:
			var cmd tea.Cmd
			m.dashboard, cmd = m.dashboard.Update(msg)
			if cmd != nil {
				cmds = append(cmds, cmd)
			}
		case tabTraffic:
			var cmd tea.Cmd
			m.traffic, cmd = m.traffic.Update(msg)
			if cmd != nil {
				cmds = append(cmds, cmd)
			}
		}
		return m, tea.Batch(cmds...)

	case opDoneMsg:
		return m.handleOpDone(msg)
	case guardTickMsg:
		return m.handleGuardTick()
	case liveMsg:
		m.tunnel.live = msg
		return m, nil
	case liveTickMsg:
		if m.activeTab != tabTunnel {
			m.liveLoop = false
			return m, nil
		}
		return m, tea.Batch(fetchLiveCmd(), liveTickCmd())
	case openFormMsg:
		return m.openPresets(msg.tunnel), nil
	case openGenMsg:
		return m.openGen(), nil
	case openPasteMsg:
		return m.openPaste(msg.tunnel), nil
	case startTunnelMsg:
		proto := m.tunnel.cursorProto()
		if proto == "" {
			m.lastMsg, m.lastOK = "select a tunnel first", false
			return m, nil
		}
		opts, prof, errMsg := m.withTunnel(spoofer.Options{}, proto)
		if errMsg != "" {
			m.lastMsg, m.lastOK = errMsg, false
			return m, nil
		}
		return m.openConfirm("Start tunnel", opts, prof), nil
	case stopTunnelMsg:
		m.flow.kind = ovRunning
		m.flow.title = "Stopping tunnel"
		return m, tea.Batch(m.flow.spin.Tick, runRestoreCmd("Stop tunnel", spoofer.Options{}))

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

	// ── Tab content (a modal replaces it while open) ──
	switch {
	case m.flow.kind != ovNone:
		b.WriteString(m.viewOverlay(contentWidth))
	case m.activeTab == tabDashboard:
		b.WriteString(m.dashboard.View(contentWidth))
	case m.activeTab == tabIdentity:
		b.WriteString(m.identity.View(contentWidth))
	case m.activeTab == tabTunnel:
		b.WriteString(m.tunnel.View(contentWidth))
	case m.activeTab == tabTraffic:
		b.WriteString(m.traffic.View(contentWidth))
	case m.activeTab == tabStatus:
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

// enterTab runs whenever the active tab changes: it restarts a frozen
// spinner and starts the live-tunnel refresh loop on the Tunnel tab.
func (m *mainModel) enterTab() tea.Cmd {
	cmds := []tea.Cmd{m.restartSpinnerIfNeeded()}
	if m.activeTab == tabTunnel && !m.liveLoop {
		m.liveLoop = true
		cmds = append(cmds, fetchLiveCmd(), liveTickCmd())
	}
	return tea.Batch(cmds...)
}

// withTunnel adds the tunnel (and its profile) to opts, or explains why not.
func (m mainModel) withTunnel(opts spoofer.Options, proto string) (spoofer.Options, *profile.Profile, string) {
	prof := m.tunnel.pickedProfile(proto)
	if needsConfig(proto) && prof == nil {
		return opts, nil, proto + " needs a profile: open the Tunnel tab (3) and press n"
	}
	opts.Tunnel = proto
	opts.TunnelMode = m.tunnel.modeFor(proto)
	if prof != nil {
		opts.TunnelCfg = prof.ConfigPath
	}
	return opts, prof, ""
}

// beginApply builds the options from the tabs and opens the preview.
func (m mainModel) beginApply() (tea.Model, tea.Cmd) {
	opts := m.identity.buildOpts()
	var prof *profile.Profile
	if proto := m.tunnel.selectedTunnel(); proto != "" {
		var errMsg string
		opts, prof, errMsg = m.withTunnel(opts, proto)
		if errMsg != "" {
			m.lastMsg, m.lastOK = errMsg, false
			return m, nil
		}
	}
	if !opts.MAC && !opts.NetIdent && !opts.SysInfo && opts.Tunnel == "" {
		m.lastMsg, m.lastOK = "Nothing selected \u2014 tick at least one operation or pick a tunnel.", false
		return m, nil
	}
	return m.openConfirm("Apply", opts, prof), nil
}

// restartSpinnerIfNeeded re-kicks the spinner tick loop when switching to a
// tab that has an active scanning state. Without this, the spinner would stay
// frozen because tick messages were only routed to the previously active tab.
func (m mainModel) restartSpinnerIfNeeded() tea.Cmd {
	switch m.activeTab {
	case tabDashboard:
		if m.dashboard.scanning {
			return m.dashboard.spinner.Tick
		}
	case tabTraffic:
		if m.traffic.scanning {
			return m.traffic.spinner.Tick
		}
	}
	return nil
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
		{"L", "Last result"},
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
			parts = append(parts, r.Operation+": "+strings.Join(strings.Fields(r.Details), " "))
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
