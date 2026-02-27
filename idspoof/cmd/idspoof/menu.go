package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/NubleX/idspoof/internal/config"
	"github.com/NubleX/idspoof/internal/spoofer"
	"github.com/NubleX/idspoof/internal/ui"
	"github.com/spf13/cobra"
)

var menuCmd = &cobra.Command{
	Use:   "menu",
	Short: "Launch interactive TUI menu",
	RunE:  runMenu,
}

func runMenu(cmd *cobra.Command, args []string) error {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("\033[H\033[2J") // clear screen
		ui.PrintBanner(config.Version)
		printCurrentInfo()

		fmt.Println(ui.Green("Available Options:"))
		fmt.Printf("  %s  Spoof MAC Addresses Only\n", ui.Blue("1)"))
		fmt.Printf("  %s  Apply Windows Network Persona (TCP/IP + DHCP + NFQUEUE)\n", ui.Blue("2)"))
		fmt.Printf("  %s  Full Spoof (MAC + Network Persona + SysInfo)\n", ui.Blue("3)"))
		fmt.Printf("  %s  Show Current Status\n", ui.Blue("4)"))
		fmt.Printf("  %s  Restore Original Identifiers\n", ui.Blue("5)"))
		fmt.Printf("  %s  Exit\n", ui.Blue("0)"))
		fmt.Println()
		fmt.Print(ui.Yellow("Enter your choice [0-5]: "))

		line, _ := reader.ReadString('\n')
		choice := strings.TrimSpace(line)

		switch choice {
		case "1":
			results := orch.Apply(spoofer.Options{MAC: true})
			printResults(results)
			pause(reader)
		case "2":
			results := orch.Apply(spoofer.Options{NetIdent: true})
			printResults(results)
			pause(reader)
		case "3":
			results := orch.Apply(spoofer.AllOps())
			printResults(results)
			pause(reader)
		case "4":
			runStatus(nil, nil)
			pause(reader)
		case "5":
			results := orch.Restore(spoofer.Options{MAC: true, NetIdent: true})
			printResults(results)
			pause(reader)
		case "0":
			fmt.Println(ui.Green("Exiting..."))
			return nil
		default:
			fmt.Println(ui.Red("Invalid option."))
			pause(reader)
		}
	}
}

func printCurrentInfo() {
	fmt.Println(ui.Yellow("Current System Information:"))
	fmt.Printf("  %s %s %s\n", ui.Blue("Hostname:"), runCmd("hostname"), ui.Green("[internal, never modified]"))
	fmt.Printf("  %s\n", ui.Blue("Interfaces:"))
	for name, mac := range currentMACMap() {
		fmt.Printf("    %-12s  %s\n", name, mac)
	}
	fmt.Println()
}

func pause(r *bufio.Reader) {
	fmt.Print(ui.Green("Press Enter to continue..."))
	r.ReadString('\n')
}
