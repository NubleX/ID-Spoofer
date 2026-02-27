package main

import (
	"fmt"

	"github.com/NubleX/idspoof/internal/config"
	"github.com/NubleX/idspoof/internal/spoofer"
	"github.com/NubleX/idspoof/internal/ui"
	"github.com/spf13/cobra"
)

var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply identity spoofing (MAC, network persona, sysinfo)",
	Long: `Apply randomises MAC addresses, projects a Windows network persona
(TCP/IP stack, DHCP, iptables, NFQUEUE packet rewriting), and generates a
fake system hardware profile.

The system hostname is NEVER changed — the Windows hostname is only announced
via DHCP and NetBIOS, keeping the internal system stable.`,
	RunE: runApply,
}

var applyOpts struct {
	macOnly      bool
	netidentOnly bool
	dryRun       bool
}

func init() {
	f := applyCmd.Flags()
	f.BoolVar(&applyOpts.macOnly, "mac-only", false, "Only spoof MAC addresses")
	f.BoolVar(&applyOpts.netidentOnly, "netident-only", false, "Only apply network persona (TCP/IP + DHCP + NFQUEUE)")
	f.BoolVar(&applyOpts.dryRun, "dry-run", false, "Show what would change without applying")
}

func runApply(cmd *cobra.Command, args []string) error {
	if applyOpts.macOnly && applyOpts.netidentOnly {
		return fmt.Errorf("--mac-only and --netident-only are mutually exclusive")
	}

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

func buildApplyOpts() spoofer.Options {
	switch {
	case applyOpts.macOnly:
		return spoofer.Options{MAC: true, DryRun: applyOpts.dryRun, Quiet: cfg.Quiet}
	case applyOpts.netidentOnly:
		return spoofer.Options{NetIdent: true, DryRun: applyOpts.dryRun, Quiet: cfg.Quiet}
	default:
		o := spoofer.AllOps()
		o.DryRun = applyOpts.dryRun
		o.Quiet = cfg.Quiet
		return o
	}
}

func describeOpts(opts spoofer.Options) string {
	if opts.MAC && opts.NetIdent && opts.SysInfo {
		return "full identity spoofing (MAC + Windows network persona + sysinfo)"
	}
	if opts.MAC {
		return "MAC address spoofing"
	}
	if opts.NetIdent {
		return "Windows network persona (TCP/IP + DHCP + NFQUEUE)"
	}
	return "selected operations"
}
