package main

import (
	"fmt"

	"github.com/NubleX/ID-Spoofer/idspoof/internal/config"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/netident"
	"github.com/spf13/cobra"
)

// rewriterCmd is an internal helper spawned by `apply` so the NFQUEUE
// rewriter outlives the CLI process. It is not intended for direct use.
var rewriterCmd = &cobra.Command{
	Use:    "__rewriter",
	Short:  "Run the NFQUEUE rewriter loop (internal, spawned by apply)",
	Hidden: true,
	RunE:   runRewriter,
}

var rewriterOpts struct {
	persona  string
	stateDir string
}

func init() {
	f := rewriterCmd.Flags()
	f.StringVar(&rewriterOpts.persona, "persona", "windows", "network persona for TCP options layout")
	f.StringVar(&rewriterOpts.stateDir, "state-dir", config.DefaultStateDir, "directory holding rewriter.pid")
}

func runRewriter(cmd *cobra.Command, args []string) error {
	if err := netident.RunRewriterDaemon(parsePersonaType(rewriterOpts.persona), rewriterOpts.stateDir, "__rewriter"); err != nil {
		return fmt.Errorf("rewriter: %w", err)
	}
	fmt.Println("rewriter stopped")
	return nil
}
