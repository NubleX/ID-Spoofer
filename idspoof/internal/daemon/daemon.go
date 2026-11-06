// Package daemon is the boot-time supervisor behind `idspoof daemon`. It
// applies the boot profile as early as the system allows (before the network
// comes up, so the first DHCP request already carries the spoofed identity),
// keeps the tunnel running, and restores everything when it is stopped.
package daemon

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/NubleX/ID-Spoofer/idspoof/internal/boot"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/netident"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/profile"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/spoofer"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/tunnel"
)

// Engine is the part of the orchestrator the daemon drives.
type Engine interface {
	Apply(spoofer.Options) []spoofer.Result
	Restore(spoofer.Options) []spoofer.Result
	TunnelStatus() tunnel.Status
}

// Logger is the subset of the idspoof logger the daemon uses.
type Logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// Timing controls the supervision loop. Zero values get production defaults.
type Timing struct {
	Poll     time.Duration // how often a running tunnel is checked
	Retry    time.Duration // first wait after a failed start
	MaxRetry time.Duration // cap for the exponential backoff
}

func (t Timing) withDefaults() Timing {
	if t.Poll <= 0 {
		t.Poll = 5 * time.Second
	}
	if t.Retry <= 0 {
		t.Retry = 3 * time.Second
	}
	if t.MaxRetry <= 0 {
		t.MaxRetry = time.Minute
	}
	return t
}

// ProfileLookup resolves a saved profile by name.
type ProfileLookup func(name string) (profile.Profile, bool)

func logResults(l Logger, what string, results []spoofer.Result) (failed bool) {
	for _, r := range results {
		if r.Err != nil || !r.Success {
			failed = true
			l.Error(what+" failed", "op", r.Operation, "err", r.Err)
			continue
		}
		l.Info(what+" ok", "op", r.Operation)
	}
	return failed
}

// DisabledByCmdline reports whether the kernel command line carries
// idspoof.disable=1. It is the recovery switch: if a boot profile ever breaks
// the network, add it in the boot loader and the daemon starts idle.
func DisabledByCmdline(cmdline string) bool {
	for _, f := range strings.Fields(cmdline) {
		if f == "idspoof.disable=1" || f == "idspoof.disable" {
			return true
		}
	}
	return false
}

// Run blocks until ctx is cancelled. With no boot profile it idles, so the
// service can be enabled before anything is configured.
func Run(ctx context.Context, e Engine, bc boot.Config, lookup ProfileLookup, tm Timing, l Logger, ready func()) error {
	if ready == nil {
		ready = func() {}
	}
	tm = tm.withDefaults()
	if err := bc.Validate(); err != nil {
		return fmt.Errorf("boot profile: %w", err)
	}
	if !bc.Enabled() {
		l.Info("no boot profile configured, idling")
		ready()
		<-ctx.Done()
		return nil
	}
	l.Info("applying boot profile", "profile", bc.Summary())

	// Resolve the tunnel profile before touching anything, so a missing
	// profile fails the service instead of leaving a half-applied state.
	var tunnelOpts spoofer.Options
	if bc.Tunnel != "" {
		tunnelOpts = spoofer.Options{Tunnel: bc.Tunnel, TunnelMode: bc.Mode, Quiet: true}
		if bc.Profile != "" {
			p, ok := lookup(bc.Profile)
			if !ok {
				return fmt.Errorf("tunnel profile %q not found", bc.Profile)
			}
			tunnelOpts.TunnelCfg = p.ConfigPath
			if bc.Mode == "" {
				tunnelOpts.TunnelMode = p.Mode
			}
		}
	}

	identity := spoofer.Options{MAC: bc.MAC, SysInfo: bc.SysInfo, Quiet: true}
	if bc.Persona != "" {
		identity.NetIdent = true
		identity.PersonaType = netident.PersonaType(bc.Persona)
	}
	if identity.MAC || identity.NetIdent || identity.SysInfo {
		logResults(l, "identity", e.Apply(identity))
	}
	// Identity is in place: tell systemd, which holds back the network until
	// this point (Type=notify), so the first packets already carry it.
	ready()

	defer func() {
		// Stopping the service un-spoofs: restore identity and stop the tunnel.
		logResults(l, "restore", e.Restore(spoofer.Options{MAC: bc.MAC, NetIdent: identity.NetIdent, Quiet: true}))
	}()

	if bc.Tunnel == "" {
		<-ctx.Done()
		return nil
	}
	return superviseTunnel(ctx, e, tunnelOpts, tm, l)
}

// superviseTunnel starts the tunnel and restarts it whenever it dies. A failed
// start (no network yet, proxy not up) is retried with exponential backoff.
func superviseTunnel(ctx context.Context, e Engine, opts spoofer.Options, tm Timing, l Logger) error {
	wait := tm.Retry
	for {
		if e.TunnelStatus().Running {
			wait = tm.Retry
			if !sleep(ctx, tm.Poll) {
				return nil
			}
			continue
		}
		l.Info("starting tunnel", "tunnel", opts.Tunnel)
		if failed := logResults(l, "tunnel", e.Apply(opts)); failed {
			l.Warn("tunnel did not start, will retry", "in", wait.String())
			if !sleep(ctx, wait) {
				return nil
			}
			if wait *= 2; wait > tm.MaxRetry {
				wait = tm.MaxRetry
			}
			continue
		}
		wait = tm.Retry
	}
}

// sleep waits for d or ctx; it reports whether the wait ran to completion.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Notify sends a state string such as "READY=1" to systemd. It does nothing
// when the process was not started with NOTIFY_SOCKET.
func Notify(state string) {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return
	}
	if addr[0] == '@' { // abstract socket
		addr = "\x00" + addr[1:]
	}
	c, err := net.Dial("unixgram", addr)
	if err != nil {
		return
	}
	defer c.Close()
	c.Write([]byte(state))
}
