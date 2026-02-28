package main

import (
	"fmt"

	"github.com/NubleX/ID-Spoofer/idspoof/internal/config"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		ver := config.Version
		if len(ver) > 0 && ver[0] == 'v' {
			ver = ver[1:]
		}
		fmt.Printf("ID-Spoofer v%s\n", ver)
		fmt.Printf("Commit:     %s\n", config.Commit)
		fmt.Printf("Built:      %s\n", config.BuildDate)
		fmt.Println("License:    GPLv3+")
	},
}
