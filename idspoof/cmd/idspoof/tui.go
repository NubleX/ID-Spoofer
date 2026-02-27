package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/NubleX/idspoof/internal/config"
	"github.com/NubleX/idspoof/internal/netident"
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

	styleUnavail = lipgloss.NewStyle().
			Foreground(lipgloss.Color("8")).Italic(true)
)

// ── Data ──────────────────────────────────────────────────────────────────────

// checkItem represents a single TUI menu item.
// Items with the same non-empty group are mutually exclusive (radio behaviour).
type checkItem struct {
	label       string
	opKey       string // "mac", "sysinfo", "persona-windows", "tunnel-tor", etc.
	group       string // "" = checkbox, "persona" or "tunnel" = radio group
	descTitle   string
	description string
	checked     bool
	separator   bool // render a section header before this item
	section     string
}

var tuiItems = []checkItem{
	// ── Identity ──────────────────────────────────────────────────────────
	{
		label:     "MAC Address Spoofing",
		opKey:     "mac",
		descTitle: "MAC Address Spoofing",
		separator: true, section: "Identity",
		description: `Randomizes the hardware (MAC) address on
every network interface using locally-
administered unicast addresses (02:xx:…).

Defeats MAC-based device tracking on the
LAN. No external tools required — uses
a direct kernel ioctl (SIOCSIFHWADDR).`,
		checked: true,
	},
	{
		label:     "System Info Display",
		opKey:     "sysinfo",
		descTitle: "System Info Display",
		description: `Generates a randomized hardware profile:
manufacturer, product name, and serial
number — then logs it.

Display-only: DMI/SMBIOS tables are
read-only in Linux without specialized
firmware tools. Useful for documenting
what identity was projected.`,
	},

	// ── Network Persona (radio) ──────────────────────────────────────────
	{
		label:     "Windows 10/11",
		opKey:     "persona-windows",
		group:     "persona",
		descTitle: "Windows 10/11 Persona",
		separator: true, section: "Network Persona (select one)",
		description: `Projects a Windows 10/11 TCP/IP identity
at the wire level. Five layers activate:

• sysctl: TTL=128, timestamps=0,
  wscale=8, SACK=1, ECN=0
• iptables IDSPOOF_NETEMU chain:
  MSS clamped to 1460 on SYN packets
• NFQUEUE queue 42: rewrites IP ID
  (0→incrementing) and TCP option
  order to Windows exact layout
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
		label:     "macOS (Sonoma+)",
		opKey:     "persona-macos",
		group:     "persona",
		descTitle: "macOS Persona",
		description: `Projects a macOS Sonoma+ TCP/IP identity.
Key differences from Windows:

• TTL=64 (Apple default)
• TCP timestamps ENABLED
• TCP options: MSS,NOP,WScale,NOP,
  NOP,Timestamps,SACKPermitted
• DHCP: Mac-style hostname, no
  vendor class (no Option 60)
• mDNS/Bonjour: Avahi left running
  (Apple uses Bonjour heavily)

p0f: *:64:0:*:65535,8:mss,nop,ws,
     nop,nop,ts,sok,eol+1:df,id+:0`,
	},
	{
		label:     "Linux (Ubuntu/Arch/Fedora)",
		opKey:     "persona-linux",
		group:     "persona",
		descTitle: "Linux Persona",
		description: `Projects a modern Linux TCP/IP identity.
Five layers activate:

• sysctl: TTL=64, timestamps=1,
  wscale=7, SACK=1, ECN=2
• iptables IDSPOOF_NETEMU chain:
  MSS clamped to 1460 on SYN packets
• NFQUEUE queue 42: rewrites IP ID
  and TCP option order to Linux
  kernel layout:
  MSS, SACK, Timestamps, NOP, WScale
• DHCP: distro-style hostname
  (ubuntu-desktop, archlinux,
  fedora-workstation, debian-laptop…)
• Avahi/mDNS: left running

System hostname is NEVER changed.
p0f: *:64:0:*:29200,7:mss,sackOK,
     ts,nop,ws:df,id+:0`,
	},
	{
		label:     "iOS 17+ (iPhone/iPad)",
		opKey:     "persona-ios",
		group:     "persona",
		descTitle: "iOS Persona",
		description: `Projects an iOS 17+ fingerprint (iPhone
or iPad). Nearly identical to macOS with
one key difference:

• Window scale factor: 16 (vs 8)

This is the only reliable TCP-level
signal that distinguishes iOS from macOS.
DHCP hostname uses iOS-style format
("Users-iPhone", "Admins-iPad").

All other parameters match macOS:
TTL=64, timestamps enabled, Bonjour
running, no DHCP vendor class.`,
	},

	// ── Traffic Encapsulation (radio) ────────────────────────────────────
	{
		label:     "None",
		opKey:     "tunnel-none",
		group:     "tunnel",
		descTitle: "No Tunnel",
		separator: true, section: "Traffic Encapsulation (select one)",
		description: `No traffic encapsulation. Packets leave
your network interface directly with the
spoofed identity.

Select a tunnel below to route traffic
through an encrypted/anonymous channel
in addition to identity spoofing.`,
		checked: true,
	},
	{
		label:     "Tor",
		opKey:     "tunnel-tor",
		group:     "tunnel",
		descTitle: "Tor Network",
		description: `Routes all traffic through the Tor
anonymity network (onion routing).

• 3-hop encrypted circuit
• Transparent proxy via iptables
  or SOCKS5 on 127.0.0.1:9050
• Exit node in random jurisdiction
• High anonymity, moderate speed

Requires: tor binary installed
(apt install tor)`,
	},
	{
		label:     "WireGuard",
		opKey:     "tunnel-wireguard",
		group:     "tunnel",
		descTitle: "WireGuard VPN",
		description: `Routes all traffic through a WireGuard
VPN tunnel.

• Modern, fast kernel-level VPN
• ChaCha20 + Poly1305 encryption
• Minimal attack surface (~4000 LOC)
• Requires config file with endpoint,
  keys, and allowed IPs

Requires: wg-quick / wg binary
(apt install wireguard-tools)
Use --tunnel-config for your .conf`,
	},
	{
		label:     "I2P / PurpleI2P",
		opKey:     "tunnel-i2p",
		group:     "tunnel",
		descTitle: "I2P Anonymity Network",
		description: `Routes traffic through the Invisible
Internet Project (I2P) network.

• Garlic routing (bundled messages)
• Unidirectional tunnels
• Designed for hidden services
• SOCKS5 on 127.0.0.1:4447
• HTTP proxy on 127.0.0.1:4444

Requires: i2pd binary installed
(apt install i2pd)`,
	},
	{
		label:     "Shadowsocks",
		opKey:     "tunnel-shadowsocks",
		group:     "tunnel",
		descTitle: "Shadowsocks Proxy",
		description: `Routes traffic through a Shadowsocks
encrypted proxy.

• AEAD encryption (AES-256-GCM)
• Designed to evade DPI censorship
• Looks like normal HTTPS traffic
• Transparent or SOCKS5 mode
• Requires remote server endpoint

Requires: sslocal binary installed
(apt install shadowsocks-libev)
Use --tunnel-config for server JSON`,
	},
	{
		label:     "QUIC Tunnel",
		opKey:     "tunnel-quic",
		group:     "tunnel",
		descTitle: "QUIC-based Tunnel",
		description: `Routes traffic through a QUIC-based
encrypted tunnel (Hysteria2).

• UDP-based, avoids TCP-in-TCP
• Brutal congestion control for
  high-bandwidth scenarios
• Looks like standard QUIC traffic
• Anti-DPI obfuscation built in

Requires: hysteria2 binary installed
Use --tunnel-config for config YAML`,
	},
	{
		label:     "LWO (WireGuard Obfs)",
		opKey:     "tunnel-lwo",
		group:     "tunnel",
		descTitle: "Lightweight WG Obfuscation",
		description: `WireGuard with Lightweight Obfuscation
(LWO), pioneered by Mullvad VPN.

• Scrambles WireGuard packet headers
• Defeats DPI that blocks WireGuard
• Minimal overhead (~0.01ms latency)
• Same security as standard WireGuard

Requires: wg binary + obfuscation
capable endpoint (Mullvad, etc.)
Use --tunnel-config for .conf`,
	},
	{
		label:     "Tor over VPN",
		opKey:     "tunnel-tor-over-vpn",
		group:     "tunnel",
		descTitle: "Tor over VPN",
		description: `Connects VPN first, then routes Tor
traffic through the VPN tunnel.

Your ISP sees: VPN traffic only
VPN provider sees: Tor entry node
Tor network sees: VPN exit IP

Adds VPN layer before Tor entry.
Useful when ISP blocks Tor, or to
hide Tor usage from local network.

Requires: wg-quick + tor binaries
Use --tunnel-config for WG .conf`,
	},
	{
		label:     "VPN over Tor",
		opKey:     "tunnel-vpn-over-tor",
		group:     "tunnel",
		descTitle: "VPN over Tor",
		description: `Connects Tor first, then routes VPN
traffic through the Tor network.

Your ISP sees: Tor traffic only
Tor exit sees: VPN handshake
Destination sees: VPN exit IP

Hides VPN endpoint from ISP. The
VPN server never learns your real
IP (only sees Tor exit). Very slow
but maximum privacy layering.

Requires: tor + wg-quick binaries`,
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
			it := &m.items[m.cursor]
			if it.group == "" {
				// Checkbox: toggle.
				it.checked = !it.checked
			} else {
				// Radio: select this, deselect others in group.
				for i := range m.items {
					if m.items[i].group == it.group {
						m.items[i].checked = false
					}
				}
				it.checked = true
			}
			m.lastMsg = ""

		case "a", "A":
			opts := m.buildOpts()
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

// buildOpts maps checked TUI items to spoofer.Options.
func (m tuiModel) buildOpts() spoofer.Options {
	opts := spoofer.Options{Quiet: true}
	for _, it := range m.items {
		if !it.checked {
			continue
		}
		switch it.opKey {
		case "mac":
			opts.MAC = true
		case "sysinfo":
			opts.SysInfo = true
		case "persona-windows":
			opts.NetIdent = true
			opts.PersonaType = netident.PersonaWindows
		case "persona-macos":
			opts.NetIdent = true
			opts.PersonaType = netident.PersonaMacOS
		case "persona-ios":
			opts.NetIdent = true
			opts.PersonaType = netident.PersonaiOS
		case "persona-linux":
			opts.NetIdent = true
			opts.PersonaType = netident.PersonaLinux
		case "tunnel-none":
			// no tunnel
		default:
			if strings.HasPrefix(it.opKey, "tunnel-") {
				opts.Tunnel = strings.TrimPrefix(it.opKey, "tunnel-")
			}
		}
	}
	return opts
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

	// ── Two-column: items | description ───────────────────────────────────
	var leftLines []string
	for i, it := range m.items {
		// Section header.
		if it.separator {
			if i > 0 {
				leftLines = append(leftLines, "")
			}
			leftLines = append(leftLines, styleSection.Render(it.section))
			leftLines = append(leftLines, strings.Repeat("─", 28))
		}

		// Checkbox or radio indicator.
		var indicator string
		if it.group != "" {
			// Radio.
			if it.checked {
				indicator = "(●)"
			} else {
				indicator = "( )"
			}
		} else {
			// Checkbox.
			if it.checked {
				indicator = "[✓]"
			} else {
				indicator = "[ ]"
			}
		}

		labelStyle := styleUnchecked
		if it.checked {
			labelStyle = styleChecked
		}
		ind := styleDim.Render(indicator)
		if i == m.cursor {
			ind = styleCursor.Render(indicator)
			labelStyle = styleCursor
		}
		leftLines = append(leftLines, fmt.Sprintf("%s %s", ind, labelStyle.Render(it.label)))
	}
	// Pad to minimum height.
	for len(leftLines) < 20 {
		leftLines = append(leftLines, "")
	}
	left := strings.Join(leftLines, "\n")

	// Right: description of focused item.
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

	// Side by side.
	leftWidth := 34
	leftStyled := lipgloss.NewStyle().Width(leftWidth).Render(left)
	cols := lipgloss.JoinHorizontal(lipgloss.Top,
		leftStyled,
		lipgloss.NewStyle().PaddingLeft(2).Render(right),
	)
	b.WriteString(cols + "\n\n")

	// ── Status ────────────────────────────────────────────────────────────────
	b.WriteString(styleSection.Render("Current Status") + "\n")
	b.WriteString(strings.Repeat("─", 76) + "\n")

	// Hostname.
	hostname := runCmd("hostname")
	b.WriteString(fmt.Sprintf("  %-12s %-24s %s\n",
		styleDim.Render("Hostname"),
		hostname,
		styleDim.Render("[not modified]")))

	// Interfaces + MACs.
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

	// TTL.
	ttl := runCmd("sysctl", "-n", "net.ipv4.ip_default_ttl")
	ttlTag := styleDim.Render("[original]")
	switch ttl {
	case "128":
		ttlTag = styleSpoofed.Render("[Windows TTL]")
	case "64":
		// Could be original Linux or macOS persona — check state.
		if pt, ok := stateM.Get("PERSONA_TYPE"); ok && (pt == "macos" || pt == "ios") {
			ttlTag = styleSpoofed.Render("[" + pt + " TTL]")
		}
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
		"[A]pply   [R]estore   [Q]uit     ↑↓/jk navigate   Space toggle/select",
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
