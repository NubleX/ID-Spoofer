package main

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/NubleX/idspoof/internal/netrecon"
)

// ── Constants ────────────────────────────────────────────────────────────────

const (
	maxSparkHistory = 40 // bandwidth samples kept per interface
	sparkWidth      = 20 // sparkline character width
	barWidth        = 16 // horizontal bar character width
	visConns        = 12 // connections visible per page
)

// sparkChars provides 8-level Unicode block characters for sparkline rendering.
var sparkChars = []rune("▁▂▃▄▅▆▇█")

// wellKnownPorts maps port numbers to short service names.
var wellKnownPorts = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	80:    "http",
	110:   "pop3",
	143:   "imap",
	443:   "https",
	465:   "smtps",
	587:   "smtp-sub",
	993:   "imaps",
	995:   "pop3s",
	1080:  "socks5",
	1194:  "openvpn",
	3306:  "mysql",
	5432:  "postgres",
	6379:  "redis",
	8080:  "http-alt",
	8443:  "https-alt",
	9050:  "tor",
	9150:  "tor-browser",
	51820: "wireguard",
}

// ── Async messages ───────────────────────────────────────────────────────────

type trafficResult struct {
	snap  *netrecon.TrafficSnapshot
	conns []netrecon.ActiveConn
	err   error
}

type trafficTick struct{}

// ── Per-interface history ────────────────────────────────────────────────────

type ifaceHistory struct {
	rx     []float64 // bytes/sec RX history
	tx     []float64 // bytes/sec TX history
	rxPeak float64   // session peak RX rate (for bar scaling)
	txPeak float64   // session peak TX rate
	rxLast float64   // most recent RX rate
	txLast float64   // most recent TX rate
}

func (h *ifaceHistory) push(rx, tx float64) {
	h.rxLast = rx
	h.txLast = tx

	h.rx = append(h.rx, rx)
	if len(h.rx) > maxSparkHistory {
		h.rx = h.rx[len(h.rx)-maxSparkHistory:]
	}
	h.tx = append(h.tx, tx)
	if len(h.tx) > maxSparkHistory {
		h.tx = h.tx[len(h.tx)-maxSparkHistory:]
	}
	if rx > h.rxPeak {
		h.rxPeak = rx
	}
	if tx > h.txPeak {
		h.txPeak = tx
	}
}

// ── Model ────────────────────────────────────────────────────────────────────

type trafficModel struct {
	prev    *netrecon.TrafficSnapshot
	curr    *netrecon.TrafficSnapshot
	conns   []netrecon.ActiveConn
	history map[string]*ifaceHistory

	connOffset int // scroll offset for connections table

	spinner  spinner.Model
	scanning bool
	err      error
}

func newTrafficModel() trafficModel {
	s := spinner.New()
	s.Spinner = spinner.MiniDot
	s.Style = lipgloss.NewStyle().Foreground(colorCyan)
	return trafficModel{
		spinner:  s,
		scanning: true,
		history:  make(map[string]*ifaceHistory),
	}
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
			// Compute per-interface rates and feed history.
			elapsed := 0.0
			if m.curr != nil {
				elapsed = msg.snap.Timestamp.Sub(m.curr.Timestamp).Seconds()
			}
			prevMap := make(map[string]netrecon.IfaceTraffic)
			if m.curr != nil {
				for _, it := range m.curr.Interfaces {
					prevMap[it.Name] = it
				}
			}
			for _, it := range msg.snap.Interfaces {
				if it.Name == "lo" {
					continue
				}
				h, ok := m.history[it.Name]
				if !ok {
					h = &ifaceHistory{}
					m.history[it.Name] = h
				}
				rx, tx := 0.0, 0.0
				if prev, ok2 := prevMap[it.Name]; ok2 && elapsed > 0 {
					rxDelta := it.RxBytes - prev.RxBytes
					txDelta := it.TxBytes - prev.TxBytes
					rx = float64(rxDelta) / elapsed
					tx = float64(txDelta) / elapsed
					if rx < 0 {
						rx = 0
					}
					if tx < 0 {
						tx = 0
					}
				}
				h.push(rx, tx)
			}
			m.prev = m.curr
			m.curr = msg.snap
		}
		m.conns = msg.conns
		return m, scheduleTrafficPoll()

	case trafficTick:
		m.scanning = true
		return m, tea.Batch(m.spinner.Tick, pollTraffic)

	case tea.KeyMsg:
		// Scroll connections table when Traffic tab is active.
		total := len(m.conns)
		maxOff := total - visConns
		if maxOff < 0 {
			maxOff = 0
		}
		switch msg.String() {
		case "j", "down":
			if m.connOffset < maxOff {
				m.connOffset++
			}
		case "k", "up":
			if m.connOffset > 0 {
				m.connOffset--
			}
		case "g":
			m.connOffset = 0
		case "G":
			m.connOffset = maxOff
		case "d":
			m.connOffset += visConns / 2
			if m.connOffset > maxOff {
				m.connOffset = maxOff
			}
		case "u":
			m.connOffset -= visConns / 2
			if m.connOffset < 0 {
				m.connOffset = 0
			}
		}
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
	return m, nil
}

// ── View ─────────────────────────────────────────────────────────────────────

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

	// ── Interface bandwidth with sparklines ──
	sections = append(sections, m.renderBandwidth(width))

	// ── Connection state bars ──
	sections = append(sections, m.renderConnState(width))

	// ── Top remote ports ──
	sections = append(sections, m.renderTopPorts(width))

	// ── Scrollable connections table ──
	sections = append(sections, m.renderConnTable(width))

	// ── Footer ──
	footer := ""
	if m.scanning {
		footer = fmt.Sprintf("  %s Refreshing...", m.spinner.View())
	} else if m.curr != nil {
		footer = sTableDim.Render(fmt.Sprintf(
			"  ⟳ %s  ·  2s interval",
			m.curr.Timestamp.Format("15:04:05"),
		))
	}
	sections = append(sections, footer)

	return strings.Join(sections, "\n\n")
}

// renderBandwidth renders per-interface bandwidth rows with sparklines and bars.
func (m trafficModel) renderBandwidth(width int) string {
	var b strings.Builder
	b.WriteString(sPanelTitle.Render("  INTERFACE BANDWIDTH") + "\n")
	b.WriteString(sSeparator.Render("  "+strings.Repeat("─", min(width-4, 76))) + "\n")

	hasAny := false
	for _, it := range m.curr.Interfaces {
		if it.Name == "lo" {
			continue
		}
		hasAny = true
		h := m.history[it.Name]

		rxRate := 0.0
		txRate := 0.0
		rxPeak := 1.0
		txPeak := 1.0
		if h != nil {
			rxRate = h.rxLast
			txRate = h.txLast
			rxPeak = h.rxPeak
			txPeak = h.txPeak
		}
		if rxPeak <= 0 {
			rxPeak = 1
		}
		if txPeak <= 0 {
			txPeak = 1
		}

		// Interface header line: name + packet totals.
		pktInfo := ""
		if it.RxPackets > 0 || it.TxPackets > 0 {
			pktInfo = sTableDim.Render(fmt.Sprintf(
				"pkts  ↓%-8s  ↑%-8s",
				humanCount(it.RxPackets),
				humanCount(it.TxPackets),
			))
		}
		b.WriteString(fmt.Sprintf("  %s  %s\n",
			sTableHeader.Render(fmt.Sprintf("%-14s", it.Name)),
			pktInfo,
		))

		// RX row: sparkline + bar + rate + total.
		var rxSpark, rxBar string
		if h != nil && len(h.rx) > 0 {
			rxSpark = lipgloss.NewStyle().Foreground(colorCyan).Render(
				sparkline(h.rx, sparkWidth, h.rxPeak))
			rxBar = barChart(rxRate, rxPeak, barWidth,
				lipgloss.NewStyle().Foreground(colorCyan))
		} else {
			rxSpark = strings.Repeat(" ", sparkWidth)
			rxBar = sTableDim.Render(strings.Repeat("░", barWidth))
		}
		b.WriteString(fmt.Sprintf("  %s  %s  %s  %s  %s\n",
			sTableDim.Render("RX"),
			rxSpark,
			rxBar,
			rateLabel(rxRate),
			sTableDim.Render("↓ "+humanBytes(it.RxBytes)),
		))

		// TX row: sparkline + bar + rate + total.
		var txSpark, txBar string
		if h != nil && len(h.tx) > 0 {
			txSpark = lipgloss.NewStyle().Foreground(colorBlue).Render(
				sparkline(h.tx, sparkWidth, h.txPeak))
			txBar = barChart(txRate, txPeak, barWidth,
				lipgloss.NewStyle().Foreground(colorBlue))
		} else {
			txSpark = strings.Repeat(" ", sparkWidth)
			txBar = sTableDim.Render(strings.Repeat("░", barWidth))
		}
		b.WriteString(fmt.Sprintf("  %s  %s  %s  %s  %s\n",
			sTableDim.Render("TX"),
			txSpark,
			txBar,
			rateLabel(txRate),
			sTableDim.Render("↑ "+humanBytes(it.TxBytes)),
		))

		// Error indicator.
		if it.RxErrors > 0 || it.TxErrors > 0 {
			b.WriteString(fmt.Sprintf("  %s\n",
				sWarn.Render(fmt.Sprintf("  ⚠  errors  rx:%d  tx:%d",
					it.RxErrors, it.TxErrors))))
		}
		b.WriteString("\n")
	}
	if !hasAny {
		b.WriteString(sTableDim.Render("  No interfaces found") + "\n")
	}
	return b.String()
}

// renderConnState renders a proportional bar chart of TCP connection states.
func (m trafficModel) renderConnState(width int) string {
	var b strings.Builder
	b.WriteString(sPanelTitle.Render("  CONNECTION STATE") + "\n")
	b.WriteString(sSeparator.Render("  "+strings.Repeat("─", min(width-4, 76))) + "\n")

	total := len(m.conns)
	if total == 0 {
		b.WriteString(sTableDim.Render("  No active connections") + "\n")
		return b.String()
	}

	counts := make(map[string]int)
	for _, c := range m.conns {
		counts[c.State]++
	}

	order := []string{
		"ESTABLISHED", "SYN_SENT", "SYN_RECV",
		"TIME_WAIT", "CLOSE_WAIT",
		"FIN_WAIT1", "FIN_WAIT2", "LAST_ACK", "CLOSING",
	}
	stateColors := map[string]lipgloss.Color{
		"ESTABLISHED": colorGreen,
		"SYN_SENT":    colorYellow,
		"SYN_RECV":    colorYellow,
		"TIME_WAIT":   colorOrange,
		"CLOSE_WAIT":  colorOrange,
		"FIN_WAIT1":   colorDim,
		"FIN_WAIT2":   colorDim,
		"LAST_ACK":    colorDim,
		"CLOSING":     colorDim,
	}

	usableBar := min(width-22, 50)
	for _, state := range order {
		n, ok := counts[state]
		if !ok {
			continue
		}
		color, cok := stateColors[state]
		if !cok {
			color = colorDim
		}
		style := lipgloss.NewStyle().Foreground(color)
		pct := float64(n) / float64(total)
		filled := int(math.Round(pct * float64(usableBar)))
		if filled < 1 {
			filled = 1
		}
		bar := style.Render(strings.Repeat("█", filled)) +
			sTableDim.Render(strings.Repeat("░", usableBar-filled))
		b.WriteString(fmt.Sprintf("  %-12s  %s  %s\n",
			style.Render(state),
			bar,
			style.Render(strconv.Itoa(n)),
		))
	}
	b.WriteString(sTableDim.Render(fmt.Sprintf("  Total: %d connections\n", total)))
	return b.String()
}

// renderTopPorts renders a bar chart of the top 5 remote ports by connection count.
func (m trafficModel) renderTopPorts(width int) string {
	var b strings.Builder
	b.WriteString(sPanelTitle.Render("  TOP REMOTE PORTS") + "\n")
	b.WriteString(sSeparator.Render("  "+strings.Repeat("─", min(width-4, 76))) + "\n")

	portCounts := make(map[int]int)
	for _, c := range m.conns {
		if p := remotePort(c.Remote); p > 0 {
			portCounts[p]++
		}
	}

	if len(portCounts) == 0 {
		b.WriteString(sTableDim.Render("  No connection data") + "\n")
		return b.String()
	}

	type portEntry struct {
		port  int
		count int
	}
	entries := make([]portEntry, 0, len(portCounts))
	for p, n := range portCounts {
		entries = append(entries, portEntry{p, n})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].count > entries[j].count
	})
	if len(entries) > 5 {
		entries = entries[:5]
	}

	maxCount := entries[0].count
	usableBar := min(width-28, 40)
	portStyle := lipgloss.NewStyle().Foreground(colorLightCyan)
	for _, e := range entries {
		svc := portService(e.port)
		label := fmt.Sprintf("%d/%s", e.port, svc)
		filled := int(math.Round(float64(e.count) / float64(maxCount) * float64(usableBar)))
		if filled < 1 {
			filled = 1
		}
		bar := portStyle.Render(strings.Repeat("█", filled)) +
			sTableDim.Render(strings.Repeat("░", usableBar-filled))
		b.WriteString(fmt.Sprintf("  %-18s  %s  %s\n",
			sTableRow.Render(label),
			bar,
			sTableDim.Render(strconv.Itoa(e.count)),
		))
	}
	return b.String()
}

// renderConnTable renders the scrollable active connections table.
func (m trafficModel) renderConnTable(width int) string {
	var b strings.Builder

	total := len(m.conns)
	maxOff := total - visConns
	if maxOff < 0 {
		maxOff = 0
	}
	offset := m.connOffset
	if offset > maxOff {
		offset = maxOff
	}

	navHint := ""
	if total > visConns {
		navHint = sTableDim.Render(fmt.Sprintf(
			"j/k  ·  %d–%d of %d",
			offset+1, min(offset+visConns, total), total,
		))
	}

	b.WriteString(sPanelTitle.Render("  ACTIVE CONNECTIONS") + "  " + navHint + "\n")
	b.WriteString(sSeparator.Render("  "+strings.Repeat("─", min(width-4, 76))) + "\n")

	if total == 0 {
		b.WriteString(sTableDim.Render("  No active connections") + "\n")
		return b.String()
	}

	hdr := fmt.Sprintf("  %-3s  %-22s  %-24s  %-10s  %s",
		sTableHeader.Render("ST"),
		sTableHeader.Render("LOCAL"),
		sTableHeader.Render("REMOTE"),
		sTableHeader.Render("SERVICE"),
		sTableHeader.Render("STATE"),
	)
	b.WriteString(hdr + "\n")

	end := offset + visConns
	if end > total {
		end = total
	}
	for _, c := range m.conns[offset:end] {
		stateStyle := sTableRow
		icon := "○"
		switch c.State {
		case "ESTABLISHED":
			stateStyle = sOK
			icon = "●"
		case "TIME_WAIT", "CLOSE_WAIT":
			stateStyle = sSpoofed
			icon = "◐"
		case "SYN_SENT", "SYN_RECV":
			stateStyle = sWarn
			icon = "◌"
		case "FIN_WAIT1", "FIN_WAIT2":
			stateStyle = sTableDim
			icon = "◑"
		}

		svc := portService(remotePort(c.Remote))
		b.WriteString(fmt.Sprintf("  %s  %-22s  %-24s  %-10s  %s\n",
			stateStyle.Render(icon),
			sTableRow.Render(truncate(c.Local, 22)),
			sTableRow.Render(truncate(c.Remote, 24)),
			sTableDim.Render(truncate(svc, 10)),
			stateStyle.Render(c.State),
		))
	}

	if total > visConns && end < total {
		remaining := total - end
		b.WriteString(sTableDim.Render(fmt.Sprintf(
			"  ↓ %d more  (j to scroll down, g/G to jump)",
			remaining,
		)) + "\n")
	}

	return b.String()
}

// ── Visual helpers ───────────────────────────────────────────────────────────

// sparkline renders a right-aligned Unicode block sparkline of given width.
func sparkline(samples []float64, width int, peak float64) string {
	display := make([]float64, width)
	if len(samples) >= width {
		copy(display, samples[len(samples)-width:])
	} else {
		copy(display[width-len(samples):], samples)
	}
	var sb strings.Builder
	for _, v := range display {
		if peak <= 0 || v <= 0 {
			sb.WriteRune('▁')
		} else {
			idx := int(v / peak * float64(len(sparkChars)-1))
			if idx >= len(sparkChars) {
				idx = len(sparkChars) - 1
			}
			sb.WriteRune(sparkChars[idx])
		}
	}
	return sb.String()
}

// barChart renders a proportional filled/unfilled horizontal bar.
func barChart(value, maxVal float64, width int, style lipgloss.Style) string {
	if maxVal <= 0 || value <= 0 {
		return sTableDim.Render(strings.Repeat("░", width))
	}
	filled := int(math.Round(value / maxVal * float64(width)))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	return style.Render(strings.Repeat("█", filled)) +
		sTableDim.Render(strings.Repeat("░", width-filled))
}

// rateLabel formats a bytes/sec rate with right-aligned fixed width and colour.
func rateLabel(bytesPerSec float64) string {
	if bytesPerSec < 1 {
		return sTableDim.Render(fmt.Sprintf("%9s", "0 B/s"))
	}
	switch {
	case bytesPerSec >= 1<<20:
		return sOK.Render(fmt.Sprintf("%9s",
			fmt.Sprintf("%.1f MB/s", bytesPerSec/float64(1<<20))))
	case bytesPerSec >= 1<<10:
		return lipgloss.NewStyle().Foreground(colorCyan).Render(fmt.Sprintf("%9s",
			fmt.Sprintf("%.1f KB/s", bytesPerSec/float64(1<<10))))
	default:
		return sTableRow.Render(fmt.Sprintf("%9s",
			fmt.Sprintf("%.0f B/s", bytesPerSec)))
	}
}

// ── Data helpers ─────────────────────────────────────────────────────────────

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

func humanCount(n uint64) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	case n >= 1_000:
		return fmt.Sprintf("%.1fK", float64(n)/1_000)
	default:
		return strconv.FormatUint(n, 10)
	}
}

// humanRate is kept for any external callers; delegates to rateLabel.
func humanRate(bytesPerSec float64) string {
	return rateLabel(bytesPerSec)
}

// remotePort parses the port from "host:port" or "[::1]:port".
func remotePort(addr string) int {
	idx := strings.LastIndex(addr, ":")
	if idx < 0 {
		return 0
	}
	port, err := strconv.Atoi(addr[idx+1:])
	if err != nil {
		return 0
	}
	return port
}

// portService returns a short service name for the port, or "port/<n>".
func portService(port int) string {
	if port <= 0 {
		return ""
	}
	if name, ok := wellKnownPorts[port]; ok {
		return name
	}
	return fmt.Sprintf("port/%d", port)
}
