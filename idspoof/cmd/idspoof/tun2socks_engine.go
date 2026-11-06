package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/NubleX/ID-Spoofer/idspoof/internal/tunnel"
	"github.com/spf13/cobra"
	"github.com/xjasonlyu/tun2socks/v2/engine"
)

// tun2socksEngineCmd is a hidden implementation detail, not a user-facing
// verb. internal/tunnel's tun2socksTunnel re-execs the idspoof binary with
// this subcommand to run the embedded tun2socks engine as a detached child
// process — the same way `wg-quick up` or `sslocal` outlive the `idspoof
// apply` invocation that started them. Running the engine here, in its own
// process, also means a bad config (bad proxy URL, device in use, ...) only
// kills this helper — engine.Start()/Stop() call log.Fatalf() internally on
// error, which would otherwise take down the whole idspoof process mid-apply.
var tun2socksEngineCmd = &cobra.Command{
	Use:    "__tun2socks-run <config.yaml>",
	Hidden: true,
	Args:   cobra.ExactArgs(1),
	RunE:   runTun2socksEngine,
}

func runTun2socksEngine(cmd *cobra.Command, args []string) error {
	key, err := tunnel.ParseTun2socksConfig(args[0])
	if err != nil {
		return err
	}

	engine.Insert(key)
	engine.Start()
	fmt.Println("ready")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig

	engine.Stop()
	return nil
}

func init() {
	rootCmd.AddCommand(tun2socksEngineCmd)
}
