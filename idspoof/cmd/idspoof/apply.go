package main

import (
	"fmt"
	"strings"

	"github.com/NubleX/idspoof/internal/config"
	"github.com/NubleX/idspoof/internal/netident"
	"github.com/NubleX/idspoof/internal/spoofer"
	"github.com/NubleX/idspoof/internal/ui"
	"github.com/spf13/cobra"
)

var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply identity spoofing (MAC, network persona, sysinfo, tunnel)",
	Long: `Apply randomises MAC addresses, projects an OS network persona
(TCP/IP stack, DHCP, iptables, NFQUEUE packet rewriting), optionally starts
a traffic tunnel, and generates a fake system hardware profile.

With no operation flags, all three operations run: --mac --netident --sysinfo.
Use individual flags to run a subset (e.g. --mac --netident skips sysinfo).

Supported personas: windows (default), macos, ios.
The system hostname is NEVER changed — the persona hostname is only announced
via DHCP, keeping the internal system stable.`,
	RunE: runApply,
}

var applyOpts struct {
	mac          bool
	netident     bool
	sysinfo      bool
	dryRun       bool
	persona      string
	tunnel       string
	tunnelMode   string
	tunnelConfig string
}

func init() {
	f := applyCmd.Flags()
	f.BoolVar(&applyOpts.mac, "mac", false, "Spoof MAC addresses")
	f.BoolVar(&applyOpts.netident, "netident", false, "Apply network persona (TCP/IP stack, DHCP, NFQUEUE)")
	f.BoolVar(&applyOpts.sysinfo, "sysinfo", false, "Generate fake system hardware profile")
	f.BoolVar(&applyOpts.dryRun, "dry-run", false, "Show what would change without applying")
	f.StringVar(&applyOpts.persona, "persona", "windows", "Network persona to project (windows, macos, ios, linux)")
	f.StringVar(&applyOpts.tunnel, "tunnel", "", "Traffic encapsulation protocol (tor, wireguard, i2p, shadowsocks, quic, lwo, tor-over-vpn, vpn-over-tor)")
	f.StringVar(&applyOpts.tunnelMode, "tunnel-mode", "transparent", "Tunnel routing mode (transparent, socks)")
	f.StringVar(&applyOpts.tunnelConfig, "tunnel-config", "", "Path to tunnel config file (WireGuard conf, Shadowsocks json, etc.)")
}

func runApply(cmd *cobra.Command, args []string) error {
	opts := buildApplyOpts()

	if !cfg.Quiet {
		ui.PrintBanner(config.Version)
		desc := describeOpts(opts)
		if !applyOpts.dryRun && !ui.Confirm(fmt.Sprintf("Proceed with %s?", desc), cfg.Quiet) {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	results := orch.Apply(opts)
	printResults(results)
	return nil
}

func parsePersonaType(s string) netident.PersonaType {
	switch s {
	case "macos":
		return netident.PersonaMacOS
	case "ios":
		return netident.PersonaiOS
	case "linux":
		return netident.PersonaLinux
	default:
		return netident.PersonaWindows
	}
}

func buildApplyOpts() spoofer.Options {
	pt := parsePersonaType(applyOpts.persona)

	// If no individual operation flag is set, default to all three.
	anySet := applyOpts.mac || applyOpts.netident || applyOpts.sysinfo
	mac := applyOpts.mac || !anySet
	netident := applyOpts.netident || !anySet
	sysinfo := applyOpts.sysinfo || !anySet

	return spoofer.Options{
		MAC:        mac,
		NetIdent:   netident,
		SysInfo:    sysinfo,
		PersonaType: pt,
		DryRun:     applyOpts.dryRun,
		Quiet:      cfg.Quiet,
		Tunnel:     applyOpts.tunnel,
		TunnelMode: applyOpts.tunnelMode,
		TunnelCfg:  applyOpts.tunnelConfig,
	}
}

func describeOpts(opts spoofer.Options) string {
	persona := string(opts.PersonaType)
	if persona == "" {
		persona = "windows"
	}

	var parts []string
	if opts.MAC {
		parts = append(parts, "MAC")
	}
	if opts.NetIdent {
		parts = append(parts, persona+" persona")
	}
	if opts.SysInfo {
		parts = append(parts, "sysinfo")
	}
	if opts.Tunnel != "" {
		parts = append(parts, opts.Tunnel+" tunnel")
	}

	if len(parts) == 0 {
		return "no operations selected"
	}
	return strings.Join(parts, " + ")
}
