package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/NubleX/ID-Spoofer/idspoof/internal/config"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/netident"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/spoofer"
	"github.com/spf13/cobra"
)

// serveCmd is the single-process "managed" mode: apply the netident
// persona, run the NFQUEUE rewriter in the foreground, and restore
// everything when the process exits. It is meant to be supervised by
// systemd (Type=simple + Restart=on-failure): a crash or SIGKILL is
// restarted (re-apply is idempotent), and every clean exit tears the
// persona down, so no state is ever left behind.
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Apply the selected spoofing operations in one foreground process, restore everything on exit",
	Long: `serve owns the whole spoofing lifecycle in one foreground process:

  1. applies the selected operations — MAC, network persona, sysinfo
     (all three by default, like apply; pass individual flags to
     restrict, e.g. --netident for persona + rewriter only)
  2. runs the NFQUEUE rewriter in the foreground (with --netident)
  3. on SIGTERM/SIGINT (systemctl stop, Ctrl-C), restores the system

Run it under a supervisor: after a crash or SIGKILL the supervisor
restarts it and the re-apply is idempotent; a clean stop leaves the
machine in its original state.

The NFQUEUE rewriter is Linux-only; on other platforms the --netident
part is unavailable, but --mac and --sysinfo still work.`,
	RunE: runServe,
}

var serveOpts struct {
	persona  string
	owner    []string
	mac      bool
	netident bool
	sysinfo  bool
}

func init() {
	f := serveCmd.Flags()
	f.StringVar(&serveOpts.persona, "persona", "windows", "Network persona to project (windows, macos, ios, linux, android)")
	f.StringSliceVar(&serveOpts.owner, "owner", nil, "Scope the mangle chain to specific users' traffic (iptables -m owner --uid-owner); repeat the flag or comma-separate; default: all users")
	f.BoolVar(&serveOpts.mac, "mac", false, "Spoof MAC addresses")
	f.BoolVar(&serveOpts.netident, "netident", false, "Apply network persona (TCP/IP stack, DHCP, NFQUEUE)")
	f.BoolVar(&serveOpts.sysinfo, "sysinfo", false, "Generate fake system hardware profile")
}

func runServe(cmd *cobra.Command, args []string) error {
	pt := parsePersonaType(serveOpts.persona)
	stateDir := cfg.StateDir
	if stateDir == "" {
		stateDir = config.DefaultStateDir
	}

	// Operation selection, same convention as apply: with no operation
	// flags all three run; passing any restricts to those selected.
	runMAC, runNetIdent, runSysInfo := selectOps(serveOpts.mac, serveOpts.netident, serveOpts.sysinfo)

	// Watch for the stop signal from the very start of the lifecycle:
	// with the handler registered, a SIGTERM/SIGINT arriving during
	// prepare/apply no longer kills the process by default disposition
	// — the current phase finishes, and the deferred unwind below
	// restores the machine either way.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)

	// This process runs the rewriter itself, so no helper is spawned.
	// Every exit path — clean stop, error, or a crash followed by a
	// supervisor restart (re-apply is idempotent) — stops the engine and
	// restores the machine; no half-applied state is ever left behind.
	var rw *netident.NFQueueRewriter
	defer func() {
		netident.FinishRewriterDaemon(rw, stateDir)
		if !cfg.Quiet {
			fmt.Println("restoring original state...")
		}
		results := orch.Restore(spoofer.Options{MAC: runMAC, NetIdent: runNetIdent, SysInfo: runSysInfo, Quiet: cfg.Quiet})
		printResults(results)
		if !cfg.Quiet {
			fmt.Println("restored; system state clean")
		}
	}()

	// Only this process may own queue 42, so take over first — but only
	// when this serve runs the netident op: stopping a drainer a
	// previous session left running while a non-netident op set (say,
	// serve --mac) neither rebinds nor restores the queue would leave
	// that session's NFQUEUE rule with nobody draining it.
	if runNetIdent {
		if pid, err := netident.StopRewriterDaemon(stateDir); err == nil && pid > 0 {
			if !cfg.Quiet {
				fmt.Printf("stopped previous rewriter (PID %d)\n", pid)
			}
		}

		// Start the rewriter engine BEFORE applying the stack: the apply
		// below (NoDaemon) then sees a live rewriter for the matching
		// persona and stays quiet instead of warning that the queue has
		// no dequeuer yet. Binding before the iptables NFQUEUE rule exists
		// is safe — nothing is diverted to the queue until the rule lands.
		var err error
		rw, err = netident.PrepareRewriterDaemon(pt, stateDir, "serve")
		if err != nil {
			// The deferred unwind restores the machine, including any
			// NFQUEUE rule a previous session left installed.
			return fmt.Errorf("rewriter: %w", err)
		}
	}

	// Install the selected stack: the rewriter engine is already bound,
	// so this process owns the queue and no helper is spawned.
	applyResults := orch.Apply(spoofer.Options{
		MAC:         runMAC,
		NetIdent:    runNetIdent,
		SysInfo:     runSysInfo,
		PersonaType: pt,
		NoDaemon:    true,
		Quiet:       cfg.Quiet,
	})

	// Any failure: nothing usable is installed, and the deferred
	// unwind stops the engine and restores the machine — so report
	// which operation(s) failed before handing back to cobra.
	var failed []string
	for _, r := range applyResults {
		if !r.Success {
			failed = append(failed, r.Operation)
		}
	}
	if len(failed) > 0 {
		if !cfg.Quiet {
			printResults(applyResults)
		}
		return fmt.Errorf("apply failed: %s", strings.Join(failed, ", "))
	}
	printResults(applyResults)

	// Optionally narrow the mangle chain to specific users' traffic.
	if len(serveOpts.owner) > 0 && runNetIdent {
		if err := netident.ScopeToOwners(serveOpts.owner); err != nil {
			// The deferred unwind stops the engine and restores the stack.
			return err
		}
		if !cfg.Quiet {
			fmt.Printf("mangle chain scoped to user(s): %s\n", strings.Join(serveOpts.owner, ", "))
		}
	} else if len(serveOpts.owner) > 0 {
		if !cfg.Quiet {
			fmt.Println("note: --owner scopes the mangle chain, which requires --netident")
		}
	}

	if !cfg.Quiet && runNetIdent {
		fmt.Printf("rewriter running as PID %d — SIGTERM or Ctrl-C stops it and restores the system\n", os.Getpid())
	}

	// Block until the stop signal arrives; the deferred unwind restores
	// the machine on exit.
	sig := <-sigs
	if !cfg.Quiet {
		fmt.Printf("received %s; restoring\n", sig)
	}

	return nil
}
