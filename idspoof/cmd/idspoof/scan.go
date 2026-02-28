package main

import (
	"fmt"
	"strings"

	"github.com/NubleX/ID-Spoofer/idspoof/internal/netrecon"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/ui"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan current network conditions (interfaces, VPNs, tunnels, routes)",
	Long: `Scan probes the system for active network interfaces, listening ports,
VPN connections, anonymity tunnels, and the default route. Useful for
understanding the current network state before applying identity spoofing.`,
	RunE: runScan,
}

func runScan(cmd *cobra.Command, args []string) error {
	prober := netrecon.NewProber()
	state, err := prober.Probe()
	if err != nil {
		return fmt.Errorf("network probe failed: %w", err)
	}

	fmt.Println(ui.Bold("===== Network Recon ====="))
	fmt.Printf("Scan time: %s\n\n", state.Timestamp.Format("2006-01-02 15:04:05"))

	// Interfaces.
	fmt.Println(ui.Bold("Interfaces:"))
	for _, iface := range state.Interfaces {
		stateStr := ui.Red("DOWN")
		if iface.State == "UP" {
			stateStr = ui.Green("UP")
		}
		mac := iface.MAC
		if mac == "" {
			mac = "-"
		}
		fmt.Printf("  %-16s [%s] %-6s  MAC: %-19s  Type: %s\n",
			iface.Name, stateStr, "", mac, iface.Type)
		for _, ip := range iface.IPs {
			fmt.Printf("  %-16s          %s\n", "", ip)
		}
	}

	// VPNs.
	fmt.Printf("\n%s\n", ui.Bold("VPN Connections:"))
	if len(state.VPNs) == 0 {
		fmt.Println("  None detected")
	}
	for _, vpn := range state.VPNs {
		ep := vpn.Endpoint
		if ep == "" {
			ep = "-"
		}
		fmt.Printf("  %s on %s (endpoint: %s)\n", ui.Green(vpn.Name), vpn.Iface, ep)
	}

	// Tunnels.
	fmt.Printf("\n%s\n", ui.Bold("Anonymity Tunnels:"))
	if len(state.Tunnels) == 0 {
		fmt.Println("  None detected")
	}
	for _, t := range state.Tunnels {
		port := t.Port
		if port == "" {
			port = "(process only)"
		}
		fmt.Printf("  %s on %s (process: %s)\n", ui.Yellow(t.Protocol), port, t.Process)
	}

	// Default route.
	fmt.Printf("\n%s\n", ui.Bold("Default Route:"))
	if state.Route.Default == "" {
		fmt.Println("  No default route")
	} else {
		vpnTag := ""
		if state.Route.VPNRouted {
			vpnTag = ui.Yellow(" [VPN routed]")
		}
		fmt.Printf("  via %s dev %s%s\n", state.Route.Default, state.Route.DefaultDev, vpnTag)
	}

	// Listening ports (top 10).
	fmt.Printf("\n%s\n", ui.Bold("Listening Ports:"))
	if len(state.Ports) == 0 {
		fmt.Println("  None detected")
	}
	for i, p := range state.Ports {
		if i >= 15 {
			fmt.Printf("  ... and %d more\n", len(state.Ports)-15)
			break
		}
		proc := ""
		if p.Process != "" {
			proc = fmt.Sprintf("%s (%d)", p.Process, p.PID)
		}
		fmt.Printf("  %-5s %-28s %s\n", p.Protocol, p.Address, proc)
	}

	// Warnings.
	if len(state.Warnings) > 0 {
		fmt.Printf("\n%s\n", ui.Bold(ui.Yellow("Warnings:")))
		for _, w := range state.Warnings {
			fmt.Printf("  %s %s\n", ui.Yellow("!"), w)
		}
	}

	fmt.Println(strings.Repeat("=", 25))
	return nil
}
