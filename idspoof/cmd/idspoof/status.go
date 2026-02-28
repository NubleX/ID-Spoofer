package main

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/NubleX/ID-Spoofer/idspoof/internal/ui"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current system identifiers vs saved originals",
	RunE:  runStatus,
}

func runStatus(cmd *cobra.Command, args []string) error {
	fmt.Println(ui.Bold("===== ID-Spoofer Status ====="))

	// System hostname (read-only, we never change this).
	fmt.Printf("System hostname: %s %s\n", runCmd("hostname"), ui.Green("[not modified]"))

	// MACs.
	fmt.Println(ui.Bold("\nNetwork interfaces:"))
	ifaces := currentMACMap()
	origMACs, _ := stateM.Get("ORIG_MACS")
	origMap := parseMACState(origMACs)

	for name, mac := range ifaces {
		orig := origMap[name]
		changed := ""
		if orig != "" && !strings.EqualFold(orig, mac) {
			changed = ui.Yellow("  [spoofed]")
		}
		fmt.Printf("  %-12s  current: %-20s  original: %s%s\n", name, mac, orig, changed)
	}

	// TCP/IP fingerprint.
	fmt.Println(ui.Bold("\nTCP/IP fingerprint (what Nmap/p0f sees):"))
	ttl := runCmd("sysctl", "-n", "net.ipv4.ip_default_ttl")
	ts := runCmd("sysctl", "-n", "net.ipv4.tcp_timestamps")
	ws := runCmd("sysctl", "-n", "net.ipv4.tcp_window_scaling")
	sack := runCmd("sysctl", "-n", "net.ipv4.tcp_sack")
	ecn := runCmd("sysctl", "-n", "net.ipv4.tcp_ecn")

	origTTL, _ := stateM.Get("ORIG_TTL")
	origTS, _ := stateM.Get("ORIG_TCP_TIMESTAMPS")

	printFPRow("TTL", ttl, origTTL, "128=Windows, 64=Linux")
	printFPRow("tcp_timestamps", ts, origTS, "0=Windows, 1=Linux")
	printFPRow("tcp_window_scaling", ws, "", "")
	printFPRow("tcp_sack", sack, "", "")
	printFPRow("tcp_ecn", ecn, "", "")

	// iptables rules.
	fmt.Println(ui.Bold("\niptables mangle rules:"))
	iptOut := runCmd("iptables", "-t", "mangle", "-S", "IDSPOOF_WINEMU")
	if strings.Contains(iptOut, "IDSPOOF_WINEMU") {
		fmt.Println(ui.Green("  IDSPOOF_WINEMU chain active"))
		for _, line := range strings.Split(iptOut, "\n") {
			if line != "" {
				fmt.Printf("    %s\n", line)
			}
		}
	} else {
		fmt.Println("  No ID-Spoofer iptables rules active")
	}

	// NFQUEUE status.
	fmt.Println(ui.Bold("\nNFQUEUE packet rewriter:"))
	if strings.Contains(iptOut, "NFQUEUE") {
		fmt.Println(ui.Green("  Active — rewriting IP ID + TCP options on SYN packets"))
	} else {
		fmt.Println("  Not active")
	}

	// State version.
	if v, ok := stateM.Get("STATE_VERSION"); ok {
		fmt.Printf("\nState version: %s\n", v)
	}

	return nil
}

func printFPRow(label, current, original, hint string) {
	changed := ""
	if original != "" && current != original {
		changed = ui.Yellow(" [modified]")
	}
	h := ""
	if hint != "" {
		h = ui.Cyan(fmt.Sprintf("  (%s)", hint))
	}
	fmt.Printf("  %-22s  %s%s%s\n", label, current, changed, h)
}

func runCmd(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return "N/A"
	}
	return strings.TrimSpace(string(out))
}

func currentMACMap() map[string]string {
	out, err := exec.Command("ip", "-o", "link", "show").Output()
	if err != nil {
		return nil
	}
	m := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimSuffix(fields[1], ":")
		if name == "lo" {
			continue
		}
		for i, f := range fields {
			if f == "link/ether" && i+1 < len(fields) {
				m[name] = fields[i+1]
				break
			}
		}
	}
	return m
}

func parseMACState(s string) map[string]string {
	m := make(map[string]string)
	for _, entry := range strings.Split(s, ";") {
		idx := strings.IndexByte(entry, ':')
		if idx < 0 {
			continue
		}
		m[entry[:idx]] = entry[idx+1:]
	}
	return m
}
