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

// ── Async messages ──────────────────────────────────────────────────────────

type trafficResult struct {
	snap  *netrecon.TrafficSnapshot
	conns []netrecon.ActiveConn
	err   error
}

type trafficTick struct{}

// ── Model ───────────────────────────────────────────────────────────────────

type trafficModel struct {
	prev     *netrecon.TrafficSnapshot
	curr     *netrecon.TrafficSnapshot
	conns    []netrecon.ActiveConn
	spinner  spinner.Model
	scanning bool
	err      error
}

func newTrafficModel() trafficModel {
	s := spinner.New()
	s.Spinner = spinner.MiniDot
	s.Style = lipgloss.NewStyle().Foreground(colorCyan)
	return trafficModel{spinner: s, scanning: true}
}

func (m trafficModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, pollTraffic)
}

func pollTraffic() tea.Msg {
	snap, _ := netrecon.ReadTraffic()
	conns, _ := netrecon.ReadConnections()
	return trafficResult{snap: snap, conns: conns}
}

func scheduleTrafficPoll() tea.Cmd {
	return tea.Tick(2*time.Second, func(t time.Time) tea.Msg {
		return trafficTick{}
	})
}

func (m trafficModel) Update(msg tea.Msg) (trafficModel, tea.Cmd) {
	switch msg := msg.(type) {
	case trafficResult:
		m.scanning = false
		m.err = msg.err
		if msg.snap != nil {
			m.prev = m.curr
			m.curr = msg.snap
		}
		m.conns = msg.conns
		return m, scheduleTrafficPoll()

	case trafficTick:
		m.scanning = true
		return m, tea.Batch(m.spinner.Tick, pollTraffic)

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
	return m, nil
}

// ── View ────────────────────────────────────────────────────────────────────

func (m trafficModel) View(width int) string {
	if m.scanning && m.curr == nil {
		return fmt.Sprintf("\n  %s Reading traffic counters...\n", m.spinner.View())
	}
	if m.err != nil {
		return sFail.Render(fmt.Sprintf("\n  Error: %v\n", m.err))
	}
	if m.curr == nil {
		return sUnavail.Render("\n  No traffic data yet.\n")
	}

	var sections []string

	// ── Bandwidth table ──
	sections = append(sections, m.renderBandwidth(width))

	// ── Connection summary ──
	sections = append(sections, m.renderConnSummary(width))

	// ── Active connections table ──
	sections = append(sections, m.renderConnTable(width))

	// ── Scan status ──
	scanLine := ""
	if m.scanning {
		scanLine = fmt.Sprintf("  %s Refreshing...", m.spinner.View())
	} else if m.curr != nil {
		scanLine = sTableDim.Render(fmt.Sprintf("  Updated: %s  (every 2s)", m.curr.Timestamp.Format("15:04:05")))
	}
	sections = append(sections, scanLine)

	return strings.Join(sections, "\n\n")
}

func (m trafficModel) renderBandwidth(width int) string {
	var b strings.Builder
	b.WriteString(sPanelTitle.Render("  INTERFACE BANDWIDTH") + "\n")
	b.WriteString(sSeparator.Render("  "+strings.Repeat("\u2500", min(width-4, 76))) + "\n")

	// Header.
	hdr := fmt.Sprintf("  %-16s %12s %12s %12s %12s",
		sTableHeader.Render("INTERFACE"),
		sTableHeader.Render("RX/s"),
		sTableHeader.Render("TX/s"),
		sTableHeader.Render("TOTAL RX"),
		sTableHeader.Render("TOTAL TX"))
	b.WriteString(hdr + "\n")

	elapsed := float64(0)
	if m.prev != nil {
		elapsed = m.curr.Timestamp.Sub(m.prev.Timestamp).Seconds()
	}

	prevMap := make(map[string]netrecon.IfaceTraffic)
	if m.prev != nil {
		for _, it := range m.prev.Interfaces {
			prevMap[it.Name] = it
		}
	}

	for _, it := range m.curr.Interfaces {
		if it.Name == "lo" {
			continue
		}

		rxRate := ""
		txRate := ""
		if prev, ok := prevMap[it.Name]; ok && elapsed > 0 {
			rxDelta := it.RxBytes - prev.RxBytes
			txDelta := it.TxBytes - prev.TxBytes
			rxRate = humanRate(float64(rxDelta) / elapsed)
			txRate = humanRate(float64(txDelta) / elapsed)
		} else {
			rxRate = sTableDim.Render("--")
			txRate = sTableDim.Render("--")
		}

		// Color the rates: green if non-zero, dim if zero.
		totalRx := humanBytes(it.RxBytes)
		totalTx := humanBytes(it.TxBytes)

		b.WriteString(fmt.Sprintf("  %-16s %12s %12s %12s %12s\n",
			sTableRow.Render(it.Name),
			rxRate,
			txRate,
			sTableDim.Render(totalRx),
			sTableDim.Render(totalTx)))

		// Error indicators.
		if it.RxErrors > 0 || it.TxErrors > 0 {
			b.WriteString(fmt.Sprintf("  %-16s %s\n",
				"",
				sWarn.Render(fmt.Sprintf("errors: rx=%d tx=%d", it.RxErrors, it.TxErrors))))
		}
	}

	return b.String()
}

func (m trafficModel) renderConnSummary(width int) string {
	var b strings.Builder
	b.WriteString(sPanelTitle.Render("  CONNECTION SUMMARY") + "\n")
	b.WriteString(sSeparator.Render("  "+strings.Repeat("\u2500", min(width-4, 76))) + "\n")

	counts := make(map[string]int)
	for _, c := range m.conns {
		counts[c.State]++
	}

	if len(counts) == 0 {
		b.WriteString(sTableDim.Render("  No active connections") + "\n")
		return b.String()
	}

	// Order: ESTABLISHED first, then rest.
	order := []string{"ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2", "LAST_ACK", "CLOSING"}
	var parts []string
	for _, state := range order {
		if n, ok := counts[state]; ok {
			style := sTableRow
			if state == "ESTABLISHED" {
				style = sOK
			} else if state == "TIME_WAIT" || state == "CLOSE_WAIT" {
				style = sSpoofed
			}
			parts = append(parts, style.Render(fmt.Sprintf("%s: %d", state, n)))
		}
	}
	b.WriteString("  " + strings.Join(parts, sTableDim.Render("  |  ")) + "\n")
	b.WriteString(sTableDim.Render(fmt.Sprintf("  Total: %d connections", len(m.conns))) + "\n")

	return b.String()
}

func (m trafficModel) renderConnTable(width int) string {
	var b strings.Builder
	b.WriteString(sPanelTitle.Render("  ACTIVE CONNECTIONS") + "\n")
	b.WriteString(sSeparator.Render("  "+strings.Repeat("\u2500", min(width-4, 76))) + "\n")

	if len(m.conns) == 0 {
		b.WriteString(sTableDim.Render("  No active connections") + "\n")
		return b.String()
	}

	hdr := fmt.Sprintf("  %-6s %-24s %-24s %s",
		sTableHeader.Render("PROTO"),
		sTableHeader.Render("LOCAL"),
		sTableHeader.Render("REMOTE"),
		sTableHeader.Render("STATE"))
	b.WriteString(hdr + "\n")

	shown := 0
	for _, c := range m.conns {
		if shown >= 15 {
			b.WriteString(sTableDim.Render(fmt.Sprintf("  ... and %d more", len(m.conns)-15)) + "\n")
			break
		}

		stateStyle := sTableRow
		switch c.State {
		case "ESTABLISHED":
			stateStyle = sOK
		case "TIME_WAIT", "CLOSE_WAIT":
			stateStyle = sSpoofed
		case "SYN_SENT":
			stateStyle = sWarn
		}

		b.WriteString(fmt.Sprintf("  %-6s %-24s %-24s %s\n",
			sTableDim.Render(c.Protocol),
			sTableRow.Render(truncate(c.Local, 24)),
			sTableRow.Render(truncate(c.Remote, 24)),
			stateStyle.Render(c.State)))
		shown++
	}

	return b.String()
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func humanBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func humanRate(bytesPerSec float64) string {
	if bytesPerSec < 1 {
		return sTableDim.Render("0 B/s")
	}
	switch {
	case bytesPerSec >= 1<<20:
		return sOK.Render(fmt.Sprintf("%.1f MB/s", bytesPerSec/float64(1<<20)))
	case bytesPerSec >= 1<<10:
		return sOK.Render(fmt.Sprintf("%.1f KB/s", bytesPerSec/float64(1<<10)))
	default:
		return sTableRow.Render(fmt.Sprintf("%.0f B/s", bytesPerSec))
	}
}
