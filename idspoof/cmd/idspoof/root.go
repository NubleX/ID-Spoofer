package main

import (
	"fmt"
	"os"

	"github.com/NubleX/idspoof/internal/config"
	"github.com/NubleX/idspoof/internal/logging"
	"github.com/NubleX/idspoof/internal/platform"
	"github.com/NubleX/idspoof/internal/state"
	"github.com/NubleX/idspoof/internal/spoofer"
	"github.com/spf13/cobra"
)

var (
	cfg      config.Config
	logger   *logging.Logger
	stateM   state.Manager
	orch     *spoofer.Orchestrator
)

var rootCmd = &cobra.Command{
	Use:   "idspoof",
	Short: "ID-Spoofer: cross-platform identity spoofing toolkit",
	Long: `ID-Spoofer randomises MAC addresses, hostname, TCP/IP fingerprint,
and system hardware profile to support penetration testing and security assessments.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Skip privilege check for version/help.
		if cmd.Name() == "version" || cmd.Name() == "help" {
			return nil
		}
		if err := platform.EnsurePrivileged(); err != nil {
			return err
		}

		var err error
		logger, err = logging.New(cfg.Quiet, cfg.Debug, cfg.LogFile)
		if err != nil {
			return fmt.Errorf("initialising logger: %w", err)
		}

		stateDir := cfg.StateDir
		if stateDir == "" {
			stateDir = config.DefaultStateDir
		}
		stateM, err = state.NewFileState(stateDir)
		if err != nil {
			return fmt.Errorf("initialising state: %w", err)
		}

		plat, err := platform.DetectPlatform()
		if err != nil {
			return fmt.Errorf("detecting platform: %w", err)
		}

		orch = spoofer.New(plat, stateM, logger)
		return nil
	},
}

func init() {
	pf := rootCmd.PersistentFlags()
	pf.BoolVarP(&cfg.Quiet, "quiet", "q", false, "Suppress all non-error output")
	pf.BoolVar(&cfg.Debug, "debug", false, "Enable debug logging")
	pf.StringVar(&cfg.LogFile, "log", "", "Path to log file")
	pf.StringVar(&cfg.StateDir, "state-dir", "", "Override state directory (default: /var/log/idspoof)")

	rootCmd.AddCommand(applyCmd)
	rootCmd.AddCommand(restoreCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(menuCmd)
	rootCmd.AddCommand(versionCmd)
}

// printResults prints the result table to stdout.
func printResults(results []spoofer.Result) {
	fmt.Println()
	fmt.Println("===== OPERATION RESULTS =====")
	anyFailed := false
	for _, r := range results {
		status := "OK"
		if !r.Success {
			status = "FAIL"
			anyFailed = true
		}
		if r.Err != nil {
			fmt.Fprintf(os.Stderr, "  [%s] %-12s  %v\n", status, r.Operation, r.Err)
		} else {
			fmt.Printf("  [%s] %-12s  %s\n", status, r.Operation, r.Details)
		}
	}
	fmt.Println("=============================")
	if anyFailed {
		os.Exit(2)
	}
}
