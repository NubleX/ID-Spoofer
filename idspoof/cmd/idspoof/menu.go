package main

import (
	"github.com/NubleX/idspoof/internal/config"
	"github.com/spf13/cobra"
)

var menuCmd = &cobra.Command{
	Use:   "menu",
	Short: "Launch interactive TUI menu",
	Long:  "Launch an interactive terminal UI with checkboxes, descriptions, and live status.",
	RunE:  runMenu,
}

func runMenu(cmd *cobra.Command, args []string) error {
	_ = config.Version // ensure version is linked
	return runTUI()
}
