package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/NubleX/idspoof/internal/config"
	"github.com/NubleX/idspoof/internal/spoofer"
)

// ── Styles ────────────────────────────────────────────────────────────────────

var (
	styleTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("12")) // bright blue

	styleSection = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("10")) // bright green

	styleDim = lipgloss.NewStyle().
			Foreground(lipgloss.Color("8")) // dark grey

	styleChecked = lipgloss.NewStyle().
			Foreground(lipgloss.Color("10")).Bold(true) // green bold

	styleUnchecked = lipgloss.NewStyle().
			Foreground(lipgloss.Color("8")) // dim

	styleCursor = lipgloss.NewStyle().
			Foreground(lipgloss.Color("14")).Bold(true) // cyan bold

	styleDesc = lipgloss.NewStyle().
			Foreground(lipgloss.Color("7")). // white
			Width(44)

	styleDescTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("14")) // cyan

	styleOK = lipgloss.NewStyle().
		Foreground(lipgloss.Color("10")).Bold(true)

	styleFail = lipgloss.NewStyle().
			Foreground(lipgloss.Color("9")).Bold(true)

	styleHelp = lipgloss.NewStyle().
			Foreground(lipgloss.Color("8"))

	styleSpoofed = lipgloss.NewStyle().
			Foreground(lipgloss.Color("11")) // yellow

	styleBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("12")).
			Padding(0, 1)
)

// ── Data ──────────────────────────────────────────────────────────────────────

type checkItem struct {
	label       string
	opKey       string // "mac" | "netident" | "sysinfo"
	descTitle   string
	description string
	checked     bool
}

var tuiItems = []checkItem{
	{
		label:     "MAC Address Spoofing",
		opKey:     "mac",
		descTitle: "MAC Address Spoofing",
		description: `Randomizes the hardware (MAC) address on
every network interface using locally-
administered unicast addresses (02:xx:…).

Defeats MAC-based device tracking on the
LAN. No external tools required — uses
a direct kernel ioctl (SIOCSIFHWADDR).`,
		checked: true,
	},
	{
		label:     "Windows Network Persona",
		opKey:     "netident",
		descTitle: "Windows Network Persona",
		description: `Projects a Windows 10/11 TCP/IP identity
at the wire level. Five layers activate:

• sysctl: TTL=128, timestamps=0,
  wscale=8, SACK=1, ECN=0
• iptables IDSPOOF_WINEMU chain:
  MSS clamped to 1460 on SYN packets
• NFQUEUE queue 42: rewrites IP ID
  (0→incrementing) and TCP option
  order to match Windows exactly
• DHCP: Windows hostname + vendor
  class "MSFT 5.0" (Option 60)
• mDNS: Avahi stopped to hide the
  real hostname from the LAN

System hostname is NEVER changed.
p0f: *:128:0:*:65535,8:mss,nop,ws,
     nop,nop,sok:df,id+:0`,
		checked: true,
	},
	{
		label:     "System Info Display",
		opKey:     "sysinfo",
		descTitle: "System Info Display",
		description: `Generates a randomized Windows hardware
profile: manufacturer, product name,
and serial number — then logs it.

Display-only: DMI/SMBIOS tables are
read-only in Linux without specialized
firmware tools. Useful for documenting
what identity was projected during a
test or assessment.`,
		checked: false,
	},
}

// ── Model ─────────────────────────────────────────────────────────────────────

type tuiModel struct {
	items    []checkItem
	cursor   int
	lastMsg  string // result of last Apply/Restore
	lastOK   bool
	quitting bool
}

func newTUIModel() tuiModel {
	items := make([]checkItem, len(tuiItems))
	copy(items, tuiItems)
	return tuiModel{items: items}
}

func (m tuiModel) Init() tea.Cmd { return nil }

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "Q":
			m.quitting = true
			return m, tea.Quit

		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}

		case "down", "j":
			if m.cursor < len(m.items)-1 {
				m.cursor++
			}

		case " ":
			m.items[m.cursor].checked = !m.items[m.cursor].checked
			m.lastMsg = ""

		case "a", "A":
			opts := spoofer.Options{Quiet: true}
			for _, it := range m.items {
				switch it.opKey {
				case "mac":
					opts.MAC = it.checked
				case "netident":
					opts.NetIdent = it.checked
				case "sysinfo":
					opts.SysInfo = it.checked
				}
			}
			if !opts.MAC && !opts.NetIdent && !opts.SysInfo {
				m.lastMsg = "Nothing selected — tick at least one operation."
				m.lastOK = false
			} else {
				results := orch.Apply(opts)
				m.lastMsg, m.lastOK = summariseTUIResults(results)
			}

		case "r", "R":
			results := orch.Restore(spoofer.Options{MAC: true, NetIdent: true, Quiet: true})
			m.lastMsg, m.lastOK = summariseTUIResults(results)
		}
	}
	return m, nil
}

func (m tuiModel) View() string {
	if m.quitting {
		return styleOK.Render("Goodbye.\n")
	}

	var b strings.Builder

	// ── Banner ────────────────────────────────────────────────────────────────
	ver := strings.TrimPrefix(config.Version, "v")
	banner := styleBox.Render(
		styleTitle.Render("ID-Spoofer v"+ver) + "\n" +
			styleDim.Render("Identity Spoofing Tool"),
	)
	b.WriteString(banner + "\n\n")

	// ── Two-column: checkboxes | description ─────────────────────────────────
	leftLines := []string{
		styleSection.Render("Select Operations"),
		strings.Repeat("─", 28),
	}
	for i, it := range m.items {
		checkbox := "[ ]"
		labelStyle := styleUnchecked
		if it.checked {
			checkbox = "[✓]"
			labelStyle = styleChecked
		}
		cb := styleDim.Render(checkbox)
		if i == m.cursor {
			cb = styleCursor.Render(checkbox)
			labelStyle = styleCursor
		}
		leftLines = append(leftLines, fmt.Sprintf("%s %s", cb, labelStyle.Render(it.label)))
	}
	// pad left column to 30 lines so desc aligns
	for len(leftLines) < 10 {
		leftLines = append(leftLines, "")
	}
	left := strings.Join(leftLines, "\n")

	// Right: description of focused item
	focused := m.items[m.cursor]
	rightLines := []string{
		styleSection.Render("Description"),
		strings.Repeat("─", 44),
		styleDescTitle.Render(focused.descTitle),
		"",
	}
	for _, line := range strings.Split(focused.description, "\n") {
		rightLines = append(rightLines, styleDesc.Render(line))
	}
	right := strings.Join(rightLines, "\n")

	// Side by side
	leftWidth := 30
	leftStyled := lipgloss.NewStyle().Width(leftWidth).Render(left)
	cols := lipgloss.JoinHorizontal(lipgloss.Top,
		leftStyled,
		lipgloss.NewStyle().PaddingLeft(2).Render(right),
	)
	b.WriteString(cols + "\n\n")

	// ── Status ────────────────────────────────────────────────────────────────
	b.WriteString(styleSection.Render("Current Status") + "\n")
	b.WriteString(strings.Repeat("─", 76) + "\n")

	// Hostname
	hostname := runCmd("hostname")
	b.WriteString(fmt.Sprintf("  %-12s %-24s %s\n",
		styleDim.Render("Hostname"),
		hostname,
		styleDim.Render("[not modified]")))

	// Interfaces + MACs
	origMACs, _ := stateM.Get("ORIG_MACS")
	origMap := parseMACState(origMACs)
	for name, mac := range currentMACMap() {
		orig := origMap[name]
		tag := styleDim.Render("[original]")
		if orig != "" && !strings.EqualFold(orig, mac) {
			tag = styleSpoofed.Render("[spoofed]")
		}
		b.WriteString(fmt.Sprintf("  %-12s %-24s %s\n",
			styleDim.Render(name), mac, tag))
	}

	// TTL
	ttl := runCmd("sysctl", "-n", "net.ipv4.ip_default_ttl")
	ttlTag := styleDim.Render("[original]")
	if ttl == "128" {
		ttlTag = styleSpoofed.Render("[Windows TTL]")
	}
	b.WriteString(fmt.Sprintf("  %-12s %-24s %s\n",
		styleDim.Render("TTL"), ttl, ttlTag))

	b.WriteString("\n")

	// ── Last result ───────────────────────────────────────────────────────────
	if m.lastMsg != "" {
		if m.lastOK {
			b.WriteString(styleOK.Render("✓ "+m.lastMsg) + "\n")
		} else {
			b.WriteString(styleFail.Render("✗ "+m.lastMsg) + "\n")
		}
		b.WriteString("\n")
	}

	// ── Help ──────────────────────────────────────────────────────────────────
	b.WriteString(styleHelp.Render(
		"[A]pply   [R]estore   [Q]uit     ↑↓/jk navigate   Space toggle",
	) + "\n")

	return b.String()
}

// summariseTUIResults collapses results into a single status line.
func summariseTUIResults(results []spoofer.Result) (msg string, ok bool) {
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
	p := tea.NewProgram(newTUIModel(), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
