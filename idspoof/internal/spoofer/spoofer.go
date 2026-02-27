// Package spoofer orchestrates all spoofing operations across the platform.
package spoofer

import (
	"fmt"
	"strconv"

	"github.com/NubleX/idspoof/internal/hostname"
	"github.com/NubleX/idspoof/internal/logging"
	"github.com/NubleX/idspoof/internal/mac"
	"github.com/NubleX/idspoof/internal/netident"
	"github.com/NubleX/idspoof/internal/platform"
	"github.com/NubleX/idspoof/internal/state"
	"github.com/NubleX/idspoof/internal/ui"
)

// Orchestrator runs selected spoofing operations using the platform's spoofers.
type Orchestrator struct {
	plat   platform.Platform
	state  state.Manager
	logger *logging.Logger
}

// New creates an Orchestrator.
func New(plat platform.Platform, st state.Manager, logger *logging.Logger) *Orchestrator {
	return &Orchestrator{plat: plat, state: st, logger: logger}
}

// Apply runs the spoofing operations described by opts. Returns one Result per operation.
func (o *Orchestrator) Apply(opts Options) []Result {
	var results []Result

	if opts.MAC {
		results = append(results, o.applyMAC(opts.DryRun, opts.Quiet))
	}
	if opts.NetIdent {
		results = append(results, o.applyNetIdent(opts.DryRun, opts.Quiet))
	}
	if opts.SysInfo {
		results = append(results, o.applySysInfo(opts.DryRun, opts.Quiet))
	}
	return results
}

// Restore rolls back saved state for the selected operations.
func (o *Orchestrator) Restore(opts Options) []Result {
	var results []Result

	if opts.MAC {
		results = append(results, o.restoreMAC(opts.Quiet))
	}
	if opts.NetIdent {
		results = append(results, o.restoreNetIdent(opts.Quiet))
	}
	return results
}

// --- MAC ---

func (o *Orchestrator) applyMAC(dry, quiet bool) Result {
	ms := o.plat.MACSpoofer()

	ifaces, err := ms.ListInterfaces()
	if err != nil {
		return Result{Operation: OpMAC, Err: fmt.Errorf("listing interfaces: %w", err)}
	}

	if !quiet {
		ui.Progress("Discovering network interfaces...", 10)
	}

	// Save originals to state before changing.
	origState := mac.InterfacesToStateString(ifaces)
	if err := o.state.Set("ORIG_MACS", origState); err != nil {
		o.logger.Warn("could not persist original MACs", "err", err)
	}

	if dry {
		details := "would change MACs for:"
		for _, i := range ifaces {
			details += fmt.Sprintf("\n  %s (%s)", i.Name, i.MAC)
		}
		return Result{Operation: OpMAC, Success: true, Details: details}
	}

	if !quiet {
		ui.Progress("Changing MAC addresses...", 60)
	}

	changed, err := ms.Apply(ifaces)
	if err != nil {
		o.logger.Error("MAC spoofing failed", "err", err)
		return Result{Operation: OpMAC, Err: err}
	}

	if !quiet {
		ui.Progress("MAC address spoofing complete", 100)
	}

	details := ""
	for _, i := range changed {
		details += fmt.Sprintf("%s -> %s\n", i.Name, i.MAC)
	}
	return Result{Operation: OpMAC, Success: true, Details: details}
}

func (o *Orchestrator) restoreMAC(quiet bool) Result {
	origStr, ok := o.state.Get("ORIG_MACS")
	if !ok || origStr == "" {
		return Result{Operation: OpMAC, Success: true, Details: "no saved MAC state"}
	}

	ifaces := mac.InterfacesFromStateString(origStr)
	if len(ifaces) == 0 {
		return Result{Operation: OpMAC, Success: true, Details: "no saved MAC state"}
	}

	ms := o.plat.MACSpoofer()
	if err := ms.Restore(ifaces); err != nil {
		return Result{Operation: OpMAC, Err: err}
	}
	if !quiet {
		ui.Progress("MAC addresses restored", 100)
	}
	return Result{Operation: OpMAC, Success: true, Details: "restored"}
}

// --- Network Identity (replaces hostname + fingerprint) ---

func (o *Orchestrator) applyNetIdent(dry, quiet bool) Result {
	ns := o.plat.NetIdentSpoofer()

	// Snapshot current state for rollback.
	snap, err := ns.Current()
	if err != nil {
		return Result{Operation: OpNetIdent, Err: fmt.Errorf("reading current state: %w", err)}
	}

	// Persist snapshot values to state file for later restore.
	o.state.Set("ORIG_TTL", itoa(snap.TTL))
	o.state.Set("ORIG_TCP_TIMESTAMPS", itoa(snap.TCPTimestamps))
	o.state.Set("ORIG_TCP_WINDOW_SCALING", itoa(snap.TCPWindowScaling))
	o.state.Set("ORIG_TCP_SACK", itoa(snap.TCPSACK))
	o.state.Set("ORIG_TCP_ECN", itoa(snap.TCPECN))
	o.state.Set("ORIG_RMEM_DEFAULT", itoa(snap.RmemDefault))
	o.state.Set("ORIG_RMEM_MAX", itoa(snap.RmemMax))
	o.state.Set("ORIG_WMEM_DEFAULT", itoa(snap.WmemDefault))
	o.state.Set("ORIG_WMEM_MAX", itoa(snap.WmemMax))
	o.state.Set("STATE_VERSION", "2")

	// Generate a Windows-style hostname for DHCP announcement (not set on the OS).
	dhcpHostname := hostname.GenerateRandom()
	persona := netident.WindowsPersona(dhcpHostname)

	if !quiet {
		ui.Progress("Applying Windows network persona...", 20)
		fmt.Printf("  DHCP hostname:   %s (system hostname unchanged)\n", dhcpHostname)
		fmt.Printf("  TTL:             %d\n", persona.TTL)
		fmt.Printf("  TCP timestamps:  disabled\n")
		fmt.Printf("  TCP window:      65535 (wscale=8)\n")
		fmt.Printf("  MSS:             %d\n", persona.MSS)
		fmt.Printf("  DHCP vendor:     %s\n", persona.DHCPVendorClass)
		fmt.Printf("  NFQUEUE:         IP ID rewrite + TCP options reorder\n")
	}

	if dry {
		return Result{Operation: OpNetIdent, Success: true,
			Details: fmt.Sprintf("would apply Windows persona (DHCP: %s, TTL=128, MSS=1460, NFQUEUE IP ID+TCP opts)", dhcpHostname)}
	}

	if !quiet {
		ui.Progress("Configuring TCP/IP stack + iptables + NFQUEUE...", 50)
	}

	if err := ns.Apply(persona); err != nil {
		o.logger.Warn("network persona applied with warnings", "err", err)
		return Result{Operation: OpNetIdent, Success: true,
			Details: fmt.Sprintf("Windows persona active (partial): %v", err)}
	}

	if !quiet {
		ui.Progress("Network persona applied", 100)
	}

	return Result{Operation: OpNetIdent, Success: true,
		Details: fmt.Sprintf("Windows persona active — DHCP hostname: %s, TTL=128, MSS=1460, timestamps=off, NFQUEUE rewriting IP ID + TCP options", dhcpHostname)}
}

func (o *Orchestrator) restoreNetIdent(quiet bool) Result {
	ns := o.plat.NetIdentSpoofer()

	// Rebuild snapshot from saved state.
	snap := &netident.Snapshot{
		IPTablesRulesAdded: true, // assume rules were added
	}
	snap.TTL = atoi(o.stateGet("ORIG_TTL", "64"))
	snap.TCPTimestamps = atoi(o.stateGet("ORIG_TCP_TIMESTAMPS", "1"))
	snap.TCPWindowScaling = atoi(o.stateGet("ORIG_TCP_WINDOW_SCALING", "1"))
	snap.TCPSACK = atoi(o.stateGet("ORIG_TCP_SACK", "1"))
	snap.TCPECN = atoi(o.stateGet("ORIG_TCP_ECN", "0"))
	snap.RmemDefault = atoi(o.stateGet("ORIG_RMEM_DEFAULT", "212992"))
	snap.RmemMax = atoi(o.stateGet("ORIG_RMEM_MAX", "212992"))
	snap.WmemDefault = atoi(o.stateGet("ORIG_WMEM_DEFAULT", "212992"))
	snap.WmemMax = atoi(o.stateGet("ORIG_WMEM_MAX", "212992"))

	if err := ns.Restore(snap); err != nil {
		return Result{Operation: OpNetIdent, Err: err}
	}

	if !quiet {
		ui.Progress("Network persona restored to original", 100)
	}
	return Result{Operation: OpNetIdent, Success: true, Details: "restored original TCP/IP profile"}
}

// --- SysInfo ---

func (o *Orchestrator) applySysInfo(dry, quiet bool) Result {
	ss := o.plat.SystemInfoSpoofer()
	info, err := ss.Generate()
	if err != nil {
		return Result{Operation: OpSysInfo, Err: err}
	}

	if !quiet {
		ui.Progress("Generating system profile...", 50)
	}

	if dry {
		return Result{Operation: OpSysInfo, Success: true, Details: fmt.Sprintf("would display: %s %s", info.Manufacturer, info.Product)}
	}

	if err := ss.Apply(info); err != nil {
		return Result{Operation: OpSysInfo, Err: err}
	}

	if !quiet {
		ui.Progress("System info generation complete", 100)
	}
	return Result{Operation: OpSysInfo, Success: true, Details: fmt.Sprintf("%s %s (serial: %s)", info.Manufacturer, info.Product, info.Serial)}
}

// Helpers.

func (o *Orchestrator) stateGet(key, fallback string) string {
	if v, ok := o.state.Get(key); ok {
		return v
	}
	return fallback
}

func itoa(v int) string      { return strconv.Itoa(v) }
func atoi(s string) int      { v, _ := strconv.Atoi(s); return v }
