package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/NubleX/idspoof/internal/netident"
	"github.com/NubleX/idspoof/internal/spoofer"
)

// checkItem represents a TUI menu item.
// Items with a non-empty group are mutually exclusive (radio behaviour).
type checkItem struct {
	label       string
	opKey       string // "mac", "sysinfo", "persona-windows", etc.
	group       string // "" = checkbox, "persona" = radio group
	descTitle   string
	description string
	checked     bool
	separator   bool
	section     string
}

var identityItems = []checkItem{
	// ── Identity ──
	{
		label: "MAC Address Spoofing", opKey: "mac",
		descTitle: "MAC Address Spoofing",
		separator: true, section: "Identity",
		description: "Randomizes the hardware (MAC) address on\nevery network interface using locally-\nadministered unicast addresses (02:xx:...).\n\nDefeats MAC-based device tracking on the\nLAN. No external tools required \u2014 uses\na direct kernel ioctl (SIOCSIFHWADDR).",
		checked: true,
	},
	{
		label: "System Info Display", opKey: "sysinfo",
		descTitle: "System Info Display",
		description: "Generates a randomized hardware profile:\nmanufacturer, product name, and serial\nnumber \u2014 then logs it.\n\nDisplay-only: DMI/SMBIOS tables are\nread-only in Linux without specialized\nfirmware tools.",
	},

	// ── Network Persona (radio) ──
	{
		label: "Windows 10/11", opKey: "persona-windows", group: "persona",
		descTitle: "Windows 10/11 Persona",
		separator: true, section: "Network Persona",
		description: "Projects a Windows 10/11 TCP/IP identity\nat the wire level. Five layers activate:\n\n\u2022 sysctl: TTL=128, timestamps=0,\n  wscale=8, SACK=1, ECN=0\n\u2022 iptables IDSPOOF_NETEMU chain:\n  MSS clamped to 1460 on SYN packets\n\u2022 NFQUEUE queue 42: rewrites IP ID\n  and TCP options to Windows layout\n\u2022 DHCP: Windows hostname + vendor\n  class \"MSFT 5.0\" (Option 60)\n\u2022 mDNS: Avahi stopped\n\np0f: *:128:0:*:65535,8:mss,nop,ws,\n     nop,nop,sok:df,id+:0",
		checked: true,
	},
	{
		label: "macOS (Sonoma+)", opKey: "persona-macos", group: "persona",
		descTitle: "macOS Persona",
		description: "Projects a macOS Sonoma+ TCP/IP identity.\n\n\u2022 TTL=64, TCP timestamps ENABLED\n\u2022 TCP options: MSS,NOP,WScale,NOP,\n  NOP,Timestamps,SACKPermitted\n\u2022 DHCP: Mac-style hostname,\n  no vendor class\n\u2022 mDNS/Bonjour: Avahi left running\n\np0f: *:64:0:*:65535,8:mss,nop,ws,\n     nop,nop,ts,sok,eol+1:df,id+:0",
	},
	{
		label: "Linux (Ubuntu/Arch/Fedora)", opKey: "persona-linux", group: "persona",
		descTitle: "Linux Persona",
		description: "Projects a modern Linux TCP/IP identity.\n\n\u2022 sysctl: TTL=64, timestamps=1,\n  wscale=7, SACK=1, ECN=2\n\u2022 NFQUEUE: TCP options in kernel\n  order: MSS,SACK,TS,NOP,WScale\n\u2022 DHCP: distro-style hostname\n  (ubuntu-desktop, archlinux...)\n\u2022 Avahi/mDNS: left running\n\np0f: *:64:0:*:29200,7:mss,sackOK,\n     ts,nop,ws:df,id+:0",
	},
	{
		label: "iOS 17+ (iPhone/iPad)", opKey: "persona-ios", group: "persona",
		descTitle: "iOS Persona",
		description: "Projects an iOS 17+ fingerprint.\nNearly identical to macOS with\none key difference:\n\n\u2022 Window scale factor: 16 (vs 8)\n\nDHCP hostname uses iOS-style format\n(\"Users-iPhone\", \"Admins-iPad\").\nAll other params match macOS:\nTTL=64, timestamps, Bonjour.",
	},
}

// identityModel manages the identity + persona selection.
type identityModel struct {
	items  []checkItem
	cursor int
}

func newIdentityModel() identityModel {
	items := make([]checkItem, len(identityItems))
	copy(items, identityItems)
	return identityModel{items: items}
}

func (m identityModel) Update(msg tea.Msg) (identityModel, tea.Cmd) {
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
			if it.group == "" {
				it.checked = !it.checked
			} else {
				for i := range m.items {
					if m.items[i].group == it.group {
						m.items[i].checked = false
					}
				}
				it.checked = true
			}
		}
	}
	return m, nil
}

func (m identityModel) View(width int) string {
	// Left column: items.
	var leftLines []string
	for i, it := range m.items {
		if it.separator {
			if i > 0 {
				leftLines = append(leftLines, "")
			}
			leftLines = append(leftLines, sSectionTitle.Render(it.section))
			leftLines = append(leftLines, sSeparator.Render(strings.Repeat("\u2500", 30)))
		}

		indicator, labelSt := m.renderIndicator(i, it)
		leftLines = append(leftLines, fmt.Sprintf("%s %s", indicator, labelSt.Render(it.label)))
	}

	for len(leftLines) < 18 {
		leftLines = append(leftLines, "")
	}
	left := strings.Join(leftLines, "\n")

	// Right column: description of focused item.
	focused := m.items[m.cursor]
	var rightLines []string
	rightLines = append(rightLines, sDescTitle.Render(focused.descTitle))
	rightLines = append(rightLines, sSeparator.Render(strings.Repeat("\u2500", 42)))
	rightLines = append(rightLines, "")
	for _, line := range strings.Split(focused.description, "\n") {
		rightLines = append(rightLines, sDescBody.Render(line))
	}
	right := sDescBox.Render(strings.Join(rightLines, "\n"))

	leftWidth := 36
	leftStyled := lipgloss.NewStyle().Width(leftWidth).Render(left)
	return lipgloss.JoinHorizontal(lipgloss.Top,
		leftStyled,
		lipgloss.NewStyle().PaddingLeft(2).Render(right),
	)
}

func (m identityModel) renderIndicator(i int, it checkItem) (string, lipgloss.Style) {
	var indicator string
	if it.group != "" {
		if it.checked {
			indicator = "(\u25cf)"
		} else {
			indicator = "( )"
		}
	} else {
		if it.checked {
			indicator = "[\u2713]"
		} else {
			indicator = "[ ]"
		}
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

	return ind, labelSt
}

// buildOpts maps checked items to spoofer.Options.
func (m identityModel) buildOpts() spoofer.Options {
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
		}
	}
	return opts
}
