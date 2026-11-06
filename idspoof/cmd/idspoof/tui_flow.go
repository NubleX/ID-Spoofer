package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/NubleX/ID-Spoofer/idspoof/internal/netident"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/profile"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/spoofer"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/tunnel"
)

// guardSeconds is how long the auto-revert guard waits for a confirmation.
const guardSeconds = 30

type overlayKind int

const (
	ovNone overlayKind = iota
	ovConfirm
	ovRunning
	ovResult
	ovGuard
	ovRestore
	ovForm
	ovPaste
)

// flowModel is the modal layer drawn over the tabs: previews, progress,
// results, the revert guard and the profile forms.
type flowModel struct {
	kind  overlayKind
	title string
	lines []string // body of confirm and result overlays
	// scroll is the first visible body line of a result overlay.
	scroll   int
	pending  spoofer.Options // options waiting for confirmation
	revert   spoofer.Options // what the guard restores on timeout
	deadline time.Time
	spin     spinner.Model

	// last result, reopened with L.
	lastTitle string
	last      []string
	lastOK    bool

	// profile form / paste box.
	inputs  []lineInput
	labels  []string
	focus   int
	area    pasteBox
	formErr string
	tunnel  string
}

func newFlowModel() flowModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(colorCyan)
	return flowModel{spin: s}
}

// Messages produced by background work.
type (
	opDoneMsg struct {
		title   string
		results []spoofer.Result
		opts    spoofer.Options
		restore bool
	}
	guardTickMsg struct{}
	liveTickMsg  struct{}
	liveMsg      struct {
		status tunnel.Status
		log    []string
	}
)

// runApplyCmd runs Apply off the UI goroutine so the TUI stays responsive.
func runApplyCmd(opts spoofer.Options) tea.Cmd {
	opts.Quiet = true
	return func() tea.Msg {
		return opDoneMsg{title: "Apply", results: orch.Apply(opts), opts: opts}
	}
}

func runRestoreCmd(title string, opts spoofer.Options) tea.Cmd {
	opts.Quiet = true
	return func() tea.Msg {
		return opDoneMsg{title: title, results: orch.Restore(opts), opts: opts, restore: true}
	}
}

func guardTickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(time.Time) tea.Msg { return guardTickMsg{} })
}

func liveTickCmd() tea.Cmd {
	return tea.Tick(2*time.Second, func(time.Time) tea.Msg { return liveTickMsg{} })
}

// fetchLiveCmd reads tunnel state and the log tail in the background.
func fetchLiveCmd() tea.Cmd {
	return func() tea.Msg {
		st := orch.TunnelStatus()
		proto := st.Protocol
		if proto == "" || proto == "none" {
			proto = "tun2socks" // show why a tunnel is not up
		}
		return liveMsg{status: st, log: tunnel.LogTail(proto, 5)}
	}
}

// formatResults renders every result in full, one line per detail line.
func formatResults(results []spoofer.Result) (lines []string, ok bool) {
	ok = true
	for _, r := range results {
		if r.Err != nil || !r.Success {
			ok = false
		}
		if r.Err != nil {
			lines = append(lines, fmt.Sprintf("[FAIL] %s: %v", r.Operation, r.Err))
			continue
		}
		det := strings.Split(strings.TrimRight(r.Details, "\n"), "\n")
		lines = append(lines, fmt.Sprintf("[OK]   %s: %s", r.Operation, det[0]))
		for _, d := range det[1:] {
			lines = append(lines, "         "+d)
		}
	}
	if len(lines) == 0 {
		lines = []string{"nothing was done"}
	}
	return lines, ok
}

// anyApplied reports whether at least one connectivity-affecting operation
// succeeded, which is what the revert guard protects.
func anyApplied(opts spoofer.Options, results []spoofer.Result) bool {
	for _, r := range results {
		if r.Err != nil || !r.Success {
			continue
		}
		switch r.Operation {
		case spoofer.OpMAC, spoofer.OpNetIdent:
			return true
		case spoofer.OpTunnel:
			if opts.Tunnel != "" {
				return true
			}
		}
	}
	return false
}

func isWireless(iface string) bool {
	_, err := os.Stat("/sys/class/net/" + iface + "/wireless")
	return err == nil
}

// buildPreview describes exactly what Apply will do, without touching state.
func buildPreview(opts spoofer.Options, prof *profile.Profile, warnings []string) []string {
	var l []string
	if opts.MAC {
		names := orch.MACTargets()
		if len(names) == 0 {
			l = append(l, "MAC addresses: no interfaces found")
		} else {
			l = append(l, "MAC addresses: randomise on "+strings.Join(names, ", "))
			for _, n := range names {
				if isWireless(n) {
					l = append(l, "  ! "+n+" is wireless: the link will drop and reconnect")
				}
			}
		}
	}
	if opts.NetIdent {
		pt := opts.PersonaType
		if pt == "" {
			pt = netident.PersonaWindows
		}
		l = append(l, fmt.Sprintf("TCP/IP persona: %s", pt))
		l = append(l, "  sysctl values, iptables chain IDSPOOF_NETEMU, NFQUEUE 42, DHCP hostname")
	}
	if opts.SysInfo {
		l = append(l, "System profile: generate a random hardware profile (display only)")
	}
	if opts.Tunnel != "" {
		mode := opts.TunnelMode
		if mode == "" {
			mode = string(tunnel.ModeTransparent)
		}
		l = append(l, fmt.Sprintf("Tunnel: %s, %s mode", opts.Tunnel, mode))
		if prof != nil {
			l = append(l, "  profile "+prof.Name+" ("+prof.ConfigPath+")")
		}
		if mode == string(tunnel.ModeTransparent) && opts.Tunnel != "tun2socks" {
			l = append(l, "  ! transparent mode redirects all system traffic through the tunnel")
		}
	}
	for _, w := range warnings {
		if opts.Tunnel == "" && strings.Contains(strings.ToLower(w), "tunnel") {
			continue
		}
		l = append(l, "! "+w)
	}
	return l
}

func (m mainModel) dashboardWarnings() []string {
	if m.dashboard.state == nil {
		return nil
	}
	return m.dashboard.state.Warnings
}

// openConfirm shows the preview and waits for Y/N.
func (m mainModel) openConfirm(title string, opts spoofer.Options, prof *profile.Profile) mainModel {
	m.flow.kind = ovConfirm
	m.flow.title = title
	m.flow.pending = opts
	m.flow.lines = buildPreview(opts, prof, m.dashboardWarnings())
	m.flow.scroll = 0
	return m
}

// guardRevert is what the guard restores if the user does not confirm.
func guardRevert(opts spoofer.Options) spoofer.Options {
	return spoofer.Options{
		MAC:        opts.MAC,
		NetIdent:   opts.NetIdent,
		SkipTunnel: opts.Tunnel == "",
	}
}

// updateOverlay handles keys while a modal is open.
func (m mainModel) updateOverlay(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	k := msg.String()
	switch m.flow.kind {
	case ovConfirm:
		switch k {
		case "y", "Y", "enter":
			m.flow.kind = ovRunning
			m.flow.title = "Applying"
			return m, tea.Batch(m.flow.spin.Tick, runApplyCmd(m.flow.pending))
		case "n", "N", "esc":
			m.flow.kind = ovNone
		}
	case ovResult:
		switch k {
		case "esc", "enter", " ":
			m.flow.kind = ovNone
		case "up", "k":
			if m.flow.scroll > 0 {
				m.flow.scroll--
			}
		case "down", "j":
			if m.flow.scroll < len(m.flow.lines)-1 {
				m.flow.scroll++
			}
		}
	case ovGuard:
		switch k {
		case "y", "Y", "enter":
			m.flow.kind = ovNone
			m.lastMsg, m.lastOK = "changes kept", true
		case "n", "N", "esc":
			return m.startRevert("Reverted")
		}
	case ovRestore:
		var opts spoofer.Options
		switch k {
		case "a", "A":
			opts = spoofer.Options{MAC: true, NetIdent: true}
		case "m", "M":
			opts = spoofer.Options{MAC: true, SkipTunnel: true}
		case "p", "P":
			opts = spoofer.Options{NetIdent: true, SkipTunnel: true}
		case "t", "T":
			opts = spoofer.Options{}
		case "esc":
			m.flow.kind = ovNone
			return m, nil
		default:
			return m, nil
		}
		m.flow.kind = ovRunning
		m.flow.title = "Restoring"
		return m, tea.Batch(m.flow.spin.Tick, runRestoreCmd("Restore", opts))
	case ovForm, ovPaste:
		return m.updateForm(msg)
	}
	return m, nil
}

func (m mainModel) startRevert(title string) (tea.Model, tea.Cmd) {
	m.flow.kind = ovRunning
	m.flow.title = "Reverting"
	return m, tea.Batch(m.flow.spin.Tick, runRestoreCmd(title, m.flow.revert))
}

// handleOpDone shows the result and, after a risky change, arms the guard.
func (m mainModel) handleOpDone(msg opDoneMsg) (tea.Model, tea.Cmd) {
	lines, ok := formatResults(msg.results)
	m.flow.last, m.flow.lastOK, m.flow.lastTitle = lines, ok, msg.title
	m.lastMsg, m.lastOK = summariseResults(msg.results)

	rescan := tea.Batch(m.dashboard.spinner.Tick, probeNetwork)
	m.dashboard.scanning = true

	if !msg.restore && m.identity.guardEnabled() && anyApplied(msg.opts, msg.results) {
		m.flow.kind = ovGuard
		m.flow.title = "Keep these changes?"
		m.flow.lines = lines
		m.flow.revert = guardRevert(msg.opts)
		m.flow.deadline = time.Now().Add(guardSeconds * time.Second)
		return m, tea.Batch(guardTickCmd(), rescan)
	}
	m.flow.kind = ovResult
	m.flow.title = msg.title + " result"
	m.flow.lines = lines
	m.flow.scroll = 0
	return m, rescan
}

func (m mainModel) handleGuardTick() (tea.Model, tea.Cmd) {
	if m.flow.kind != ovGuard {
		return m, nil
	}
	if time.Until(m.flow.deadline) <= 0 {
		return m.startRevert("Auto-reverted")
	}
	return m, guardTickCmd()
}

// ── Profile form and paste box ──────────────────────────────────────────────

func newInput(placeholder, value string, width int) lineInput {
	return lineInput{text: value, placeholder: placeholder, width: width}
}

func (m mainModel) openForm(proto string) mainModel {
	m.flow.tunnel = proto
	m.flow.formErr = ""
	m.flow.focus = 0
	m.flow.kind = ovForm
	m.flow.title = "New tun2socks profile"
	m.flow.labels = []string{"Name", "Proxy URL", "TUN device", "MTU", "Fwmark (hex)", "Pivot user (optional)"}
	m.flow.inputs = []lineInput{
		newInput("lab", "", 40),
		newInput("socks5://127.0.0.1:1080", "", 40),
		newInput("tun2socks0", "", 40),
		newInput("1500", "", 40),
		newInput("0x2323", "", 40),
		newInput("empty = do not route any user into the TUN", "", 40),
	}
	m.flow.inputs[0].focused = true
	return m
}

func (m mainModel) openPaste(proto string) mainModel {
	m.flow.tunnel = proto
	m.flow.formErr = ""
	m.flow.focus = 0
	m.flow.kind = ovPaste
	m.flow.title = "Paste " + proto + " config"
	m.flow.labels = []string{"Name"}
	m.flow.inputs = []lineInput{newInput("lab", "", 40)}
	m.flow.inputs[0].focused = true
	m.flow.area = pasteBox{}
	return m
}

func (m *flowModel) setFocus(i int) {
	n := len(m.inputs)
	if m.kind == ovPaste {
		n++ // the textarea is the last stop
	}
	if n == 0 {
		return
	}
	m.focus = (i + n) % n
	for j := range m.inputs {
		m.inputs[j].focused = false
	}
	m.area.focused = false
	if m.focus < len(m.inputs) {
		m.inputs[m.focus].focused = true
	} else {
		m.area.focused = true
	}
}

func (m mainModel) updateForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	k := msg.String()
	if k != "ctrl+s" {
		m.flow.formErr = ""
	}
	last := len(m.flow.inputs) - 1
	if m.flow.kind == ovPaste {
		last++
	}
	switch k {
	case "esc":
		m.flow.kind = ovNone
		return m, nil
	case "ctrl+s":
		return m.submitForm()
	case "tab", "down":
		if !(m.flow.kind == ovPaste && m.flow.focus == last && k == "down") {
			m.flow.setFocus(m.flow.focus + 1)
			return m, nil
		}
	case "shift+tab", "up":
		if !(m.flow.kind == ovPaste && m.flow.focus == last && k == "up") {
			m.flow.setFocus(m.flow.focus - 1)
			return m, nil
		}
	case "enter":
		if m.flow.kind == ovForm {
			if m.flow.focus == last {
				return m.submitForm()
			}
			m.flow.setFocus(m.flow.focus + 1)
			return m, nil
		}
		if m.flow.focus < len(m.flow.inputs) { // name field in the paste box
			m.flow.setFocus(m.flow.focus + 1)
			return m, nil
		}
	}
	if m.flow.focus < len(m.flow.inputs) {
		m.flow.inputs[m.flow.focus] = m.flow.inputs[m.flow.focus].Update(msg)
	} else {
		m.flow.area = m.flow.area.Update(msg)
	}
	return m, nil
}

func (m mainModel) submitForm() (tea.Model, tea.Cmd) {
	name := strings.TrimSpace(m.flow.inputs[0].Value())
	var body string
	if m.flow.kind == ovForm {
		mtu := 0
		if s := strings.TrimSpace(m.flow.inputs[3].Value()); s != "" {
			v, err := strconv.Atoi(s)
			if err != nil {
				m.flow.formErr = "MTU must be a number"
				return m, nil
			}
			mtu = v
		}
		var err error
		body, err = profile.RenderTun2socks(profile.Tun2socksForm{
			Proxy:     m.flow.inputs[1].Value(),
			Device:    strings.TrimSpace(m.flow.inputs[2].Value()),
			MTU:       mtu,
			Mark:      strings.TrimSpace(m.flow.inputs[4].Value()),
			PivotUser: strings.TrimSpace(m.flow.inputs[5].Value()),
		})
		if err != nil {
			m.flow.formErr = err.Error()
			return m, nil
		}
	} else {
		body = m.flow.area.text
	}
	if m.tunnel.store == nil {
		m.flow.formErr = "profiles unavailable: " + m.tunnel.storeErr
		return m, nil
	}
	p, err := m.tunnel.store.Save(profile.Profile{Name: name, Tunnel: m.flow.tunnel, Mode: m.tunnel.mode}, body)
	if err != nil {
		m.flow.formErr = err.Error()
		return m, nil
	}
	m.tunnel.reload()
	m.tunnel.picked[p.Tunnel] = p.Name
	m.tunnel.say(true, "saved profile "+p.Name)
	m.flow.kind = ovNone
	return m, nil
}

// ── Overlay rendering ───────────────────────────────────────────────────────

func boxStyle(border lipgloss.Color, width int) lipgloss.Style {
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(border).
		Padding(0, 2).
		Width(width)
}

// viewOverlay renders the active modal in place of the tab content.
func (m mainModel) viewOverlay(width int) string {
	w := min(max(width-8, 60), 110)
	f := m.flow
	var b strings.Builder
	switch f.kind {
	case ovConfirm:
		b.WriteString(sPanelTitle.Render(f.title+": review before applying") + "\n\n")
		b.WriteString(strings.Join(wrapLines(f.lines, w-6), "\n") + "\n\n")
		b.WriteString(sCursor.Render("[Y]") + sHelpBar.Render(" apply   ") + sCursor.Render("[N/Esc]") + sHelpBar.Render(" cancel"))
		return boxStyle(colorYellow, w).Render(b.String())
	case ovRunning:
		b.WriteString(f.spin.View() + " " + sPanelTitle.Render(f.title+"...") + "\n\n")
		b.WriteString(sTableDim.Render("Running in the background. The operation cannot be cancelled once started."))
		return boxStyle(colorCyan, w).Render(b.String())
	case ovResult:
		b.WriteString(sPanelTitle.Render(f.title) + "\n\n")
		body := wrapLines(f.lines, w-6)
		end := min(len(body), f.scroll+16)
		start := min(f.scroll, max(len(body)-1, 0))
		for _, l := range body[start:end] {
			st := sTableRow
			switch {
			case strings.HasPrefix(l, "[FAIL]"):
				st = sFail
			case strings.HasPrefix(l, "[OK]"):
				st = sOK
			}
			b.WriteString(st.Render(l) + "\n")
		}
		if end < len(body) {
			b.WriteString(sTableDim.Render(fmt.Sprintf("... %d more lines (j/k to scroll)", len(body)-end)) + "\n")
		}
		b.WriteString("\n" + sCursor.Render("[Esc/Enter]") + sHelpBar.Render(" close"))
		col := colorGreen
		if !f.lastOK {
			col = colorRed
		}
		return boxStyle(col, w).Render(b.String())
	case ovGuard:
		left := int(time.Until(f.deadline).Seconds()) + 1
		if left < 0 {
			left = 0
		}
		b.WriteString(sPanelTitle.Render(f.title) + "\n\n")
		for _, l := range wrapLines(f.lines, w-6) {
			b.WriteString(sTableRow.Render(l) + "\n")
		}
		b.WriteString("\n" + sWarn.Render(fmt.Sprintf("Check your connection. Reverting everything in %d s unless you confirm.", left)) + "\n")
		b.WriteString(sCursor.Render("[Y]") + sHelpBar.Render(" keep   ") + sCursor.Render("[N/Esc]") + sHelpBar.Render(" revert now"))
		return boxStyle(colorYellow, w).Render(b.String())
	case ovRestore:
		b.WriteString(sPanelTitle.Render("Restore what?") + "\n\n")
		for _, o := range [][2]string{
			{"A", "everything (MAC, persona, tunnel)"},
			{"M", "MAC addresses only"},
			{"P", "network persona only"},
			{"T", "stop the tunnel only"},
		} {
			b.WriteString(sCursor.Render("["+o[0]+"]") + " " + sTableRow.Render(o[1]) + "\n")
		}
		b.WriteString("\n" + sCursor.Render("[Esc]") + sHelpBar.Render(" cancel"))
		return boxStyle(colorCyan, w).Render(b.String())
	case ovForm, ovPaste:
		b.WriteString(sPanelTitle.Render(f.title) + "\n\n")
		for i, in := range f.inputs {
			b.WriteString(fmt.Sprintf("%-22s %s\n", sTableHeader.Render(f.labels[i]), in.View()))
		}
		if f.kind == ovPaste {
			b.WriteString("\n" + f.area.View(w-6, 10) + "\n")
		}
		if f.formErr != "" {
			b.WriteString("\n" + sFail.Render("x "+f.formErr) + "\n")
		}
		hint := "[Tab] next  [Enter] next/save  [Ctrl+S] save  [Ctrl+U] clear field  [Esc] cancel"
		b.WriteString("\n" + sHelpBar.Render(hint))
		return boxStyle(colorCyan, w).Render(b.String())
	}
	return ""
}

// wrapLines hard-wraps each line to width, keeping continuation lines indented.
func wrapLines(lines []string, width int) []string {
	var out []string
	for _, l := range lines {
		r := []rune(l)
		for len(r) > width {
			out = append(out, string(r[:width]))
			r = append([]rune("    "), r[width:]...)
		}
		out = append(out, string(r))
	}
	return out
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// pasteBox is a minimal append-only multi-line buffer. Terminal (bracketed)
// paste arrives as one rune message, which is the case that matters here;
// it deliberately has no cursor movement so there is nothing to get wrong.
type pasteBox struct {
	text    string
	focused bool
}

func (p pasteBox) Update(msg tea.KeyMsg) pasteBox {
	switch msg.Type {
	case tea.KeyRunes:
		in := strings.ReplaceAll(string(msg.Runes), "\r\n", "\n")
		p.text += strings.ReplaceAll(in, "\r", "\n")
	case tea.KeySpace:
		p.text += " "
	case tea.KeyEnter:
		p.text += "\n"
	case tea.KeyBackspace:
		if r := []rune(p.text); len(r) > 0 {
			p.text = string(r[:len(r)-1])
		}
	case tea.KeyCtrlU:
		p.text = ""
	}
	return p
}

// View shows the last height lines, each cut to width.
func (p pasteBox) View(width, height int) string {
	lines := strings.Split(p.text, "\n")
	if len(lines) > height {
		lines = lines[len(lines)-height:]
	}
	for i, l := range lines {
		lines[i] = truncate(l, width)
	}
	if p.focused {
		lines[len(lines)-1] += "_"
	}
	if p.text == "" && !p.focused {
		lines = []string{sTableDim.Render("(paste the config here)")}
	}
	return lipgloss.NewStyle().Border(lipgloss.NormalBorder()).BorderForeground(colorDim).Width(width).Render(strings.Join(lines, "\n"))
}

// lineInput is a minimal single-line field: typed or pasted text is appended,
// Backspace removes the last rune, Ctrl+U clears. No cursor movement.
type lineInput struct {
	text        string
	placeholder string
	width       int
	focused     bool
}

func (l lineInput) Value() string { return l.text }

func (l lineInput) Update(msg tea.KeyMsg) lineInput {
	switch msg.Type {
	case tea.KeyRunes:
		in := strings.NewReplacer("\r", "", "\n", "", "\t", " ").Replace(string(msg.Runes))
		if len([]rune(l.text))+len([]rune(in)) <= 256 {
			l.text += in
		}
	case tea.KeySpace:
		l.text += " "
	case tea.KeyBackspace:
		if r := []rune(l.text); len(r) > 0 {
			l.text = string(r[:len(r)-1])
		}
	case tea.KeyCtrlU:
		l.text = ""
	}
	return l
}

func (l lineInput) View() string {
	shown := l.text
	if l.focused {
		shown += "_"
	} else if shown == "" {
		return sTableDim.Render(truncate(l.placeholder, l.width))
	}
	r := []rune(shown)
	if len(r) > l.width {
		shown = string(r[len(r)-l.width:])
	}
	st := sTableRow
	if l.focused {
		st = sCursor
	}
	return st.Render(shown)
}
