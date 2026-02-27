package main

import (
	"fmt"

	"github.com/NubleX/idspoof/internal/spoofer"
	"github.com/NubleX/idspoof/internal/ui"
	"github.com/spf13/cobra"
)

var restoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore original identifiers from saved state",
	Long: `Restore rolls back MAC addresses and network persona to the values
saved before apply was run. Removes iptables rules, stops NFQUEUE rewriter,
restores sysctl values, and cleans up DHCP configuration.`,
	RunE: runRestore,
}

var restoreOpts struct {
	mac      bool
	netident bool
}

func init() {
	f := restoreCmd.Flags()
	f.BoolVar(&restoreOpts.mac, "mac", false, "Only restore MAC addresses")
	f.BoolVar(&restoreOpts.netident, "netident", false, "Only restore network persona")
}

func runRestore(cmd *cobra.Command, args []string) error {
	opts := buildRestoreOpts()

	if !cfg.Quiet {
		if !ui.Confirm("Restore original system identifiers?", cfg.Quiet) {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	results := orch.Restore(opts)
	printResults(results)
	return nil
}

func buildRestoreOpts() spoofer.Options {
	if !restoreOpts.mac && !restoreOpts.netident {
		// Restore everything.
		return spoofer.Options{MAC: true, NetIdent: true, Quiet: cfg.Quiet}
	}
	return spoofer.Options{
		MAC:      restoreOpts.mac,
		NetIdent: restoreOpts.netident,
		Quiet:    cfg.Quiet,
	}
}
