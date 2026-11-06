package main

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/NubleX/ID-Spoofer/idspoof/internal/boot"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/config"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/daemon"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/profile"
)

// bootConfigPath is the boot profile the daemon reads and the TUI writes.
var bootConfigPath = boot.DefaultPath

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Run the boot-time supervisor (started by the idspoof systemd unit)",
	Long: `Runs in the foreground as root. Applies the boot profile (set from the TUI
with B), keeps the tunnel running, and restores the original identity when
stopped. With no boot profile it idles. Normally started by the systemd unit
before the network comes up, not by hand.`,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runDaemon,
}

func runDaemon(cmd *cobra.Command, args []string) error {
	bc, err := boot.Load(bootConfigPath)
	if err != nil {
		return err
	}
	if raw, err := os.ReadFile("/proc/cmdline"); err == nil && daemon.DisabledByCmdline(string(raw)) {
		logger.Warn("idspoof.disable is set on the kernel command line, ignoring the boot profile")
		bc = boot.Config{}
	}

	dir := cfg.StateDir
	if dir == "" {
		dir = config.DefaultStateDir
	}
	store, err := profile.NewStore(filepath.Join(dir, "profiles"))
	if err != nil {
		return err
	}
	lookup := func(name string) (profile.Profile, bool) {
		list, _ := store.List()
		for _, p := range list {
			if p.Name == name {
				return p, true
			}
		}
		return profile.Profile{}, false
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = daemon.Run(ctx, orch, bc, lookup, daemon.Timing{}, logger, func() { daemon.Notify("READY=1") })
	daemon.Notify("STOPPING=1")
	return err
}
