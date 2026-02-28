// Package spoofer orchestrates all spoofing operations across the platform.
package spoofer

import (
	"fmt"
	"strconv"

	"github.com/NubleX/idspoof/internal/hostname"
	"github.com/NubleX/idspoof/internal/logging"
	"github.com/NubleX/idspoof/internal/mac"
	"github.com/NubleX/idspoof/internal/netident"
	"github.com/NubleX/idspoof/internal/netrecon"
	"github.com/NubleX/idspoof/internal/platform"
	"github.com/NubleX/idspoof/internal/state"
	"github.com/NubleX/idspoof/internal/tunnel"
	"github.com/NubleX/idspoof/internal/ui"
)

// Orchestrator runs selected spoofing operations using the platform's spoofers.
type Orchestrator struct {
	plat    platform.Platform
	state   state.Manager
	logger  *logging.Logger
	tunnelM *tunnel.Manager
}

// New creates an Orchestrator.
func New(plat platform.Platform, st state.Manager, logger *logging.Logger) *Orchestrator {
	return &Orchestrator{plat: plat, state: st, logger: logger, tunnelM: tunnel.NewManager()}
}

// Apply runs the spoofing operations described by opts. Returns one Result per operation.
// Before executing, it runs a network recon probe and logs any warnings.
func (o *Orchestrator) Apply(opts Options) []Result {
	var results []Result

	// Pre-flight: detect existing VPNs/tunnels that may conflict.
	if warnings := o.preflight(opts); len(warnings) > 0 {
		for _, w := range warnings {
			o.logger.Warn("pre-flight", "warning", w)
			if !opts.Quiet {
				fmt.Printf("  %s %s\n", ui.Yellow("!"), w)
			}
		}
	}

	if opts.MAC {
		results = append(results, o.applyMAC(opts.DryRun, opts.Quiet))
	}
	if opts.NetIdent {
		results = append(results, o.applyNetIdent(opts))
	}
	if opts.SysInfo {
		results = append(results, o.applySysInfo(opts.DryRun, opts.Quiet))
	}
	if opts.Tunnel != "" && opts.Tunnel != "none" {
		results = append(results, o.applyTunnel(opts))
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
	// Always try to stop any active tunnel on restore.
	results = append(results, o.restoreTunnel(opts.Quiet))
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

func (o *Orchestrator) applyNetIdent(opts Options) Result {
	dry, quiet := opts.DryRun, opts.Quiet
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

	// Determine persona type (default to Windows).
	pt := opts.PersonaType
	if pt == "" {
		pt = netident.PersonaWindows
	}

	// Generate OS-appropriate hostname for DHCP announcement.
	var dhcpHostname string
	var persona netident.Persona
	switch pt {
	case netident.PersonaMacOS:
		dhcpHostname = hostname.GenerateRandomMacOS()
		persona = netident.MacOSPersona(dhcpHostname)
	case netident.PersonaiOS:
		dhcpHostname = hostname.GenerateRandomIOS()
		persona = netident.IOSPersona(dhcpHostname)
	case netident.PersonaLinux:
		dhcpHostname = hostname.GenerateRandomLinux()
		persona = netident.LinuxPersona(dhcpHostname)
	case netident.PersonaAndroid:
		dhcpHostname = hostname.GenerateRandomAndroid()
		persona = netident.AndroidPersona(dhcpHostname)
	default:
		dhcpHostname = hostname.GenerateRandom()
		persona = netident.WindowsPersona(dhcpHostname)
	}

	tsStatus := "disabled"
	if persona.TCPTimestamps == 1 {
		tsStatus = "enabled"
	}

	if !quiet {
		ui.Progress(fmt.Sprintf("Applying %s network persona...", pt), 20)
		fmt.Printf("  DHCP hostname:   %s (system hostname unchanged)\n", dhcpHostname)
		fmt.Printf("  TTL:             %d\n", persona.TTL)
		fmt.Printf("  TCP timestamps:  %s\n", tsStatus)
		fmt.Printf("  TCP window:      65535 (wscale=%d)\n", persona.WScale)
		fmt.Printf("  MSS:             %d\n", persona.MSS)
		if persona.DHCPVendorClass != "" {
			fmt.Printf("  DHCP vendor:     %s\n", persona.DHCPVendorClass)
		}
		fmt.Printf("  NFQUEUE:         IP ID rewrite + TCP options reorder (%s layout)\n", pt)
	}

	if dry {
		return Result{Operation: OpNetIdent, Success: true,
			Details: fmt.Sprintf("would apply %s persona (DHCP: %s, TTL=%d, MSS=1460, wscale=%d)", pt, dhcpHostname, persona.TTL, persona.WScale)}
	}

	// Save persona type for restore.
	o.state.Set("PERSONA_TYPE", string(pt))

	if !quiet {
		ui.Progress("Configuring TCP/IP stack + iptables + NFQUEUE...", 50)
	}

	if err := ns.Apply(persona); err != nil {
		o.logger.Warn("network persona applied with warnings", "err", err)
		return Result{Operation: OpNetIdent, Success: true,
			Details: fmt.Sprintf("%s persona active (partial): %v", pt, err)}
	}

	if !quiet {
		ui.Progress("Network persona applied", 100)
	}

	return Result{Operation: OpNetIdent, Success: true,
		Details: fmt.Sprintf("%s persona active — DHCP hostname: %s, TTL=%d, MSS=1460, timestamps=%s, wscale=%d", pt, dhcpHostname, persona.TTL, tsStatus, persona.WScale)}
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

// --- Tunnel ---

func (o *Orchestrator) applyTunnel(opts Options) Result {
	mode := tunnel.ModeTransparent
	if opts.TunnelMode == "socks" {
		mode = tunnel.ModeSocks
	}

	t := tunnel.Get(opts.Tunnel)
	if t == nil {
		return Result{Operation: OpTunnel, Err: fmt.Errorf("unknown tunnel: %s", opts.Tunnel)}
	}

	if !t.Available() {
		return Result{Operation: OpTunnel, Err: fmt.Errorf("%s: required binary not found (install it first)", t.Name())}
	}

	if opts.DryRun {
		return Result{Operation: OpTunnel, Success: true,
			Details: fmt.Sprintf("would start %s tunnel (mode=%s)", t.Name(), mode)}
	}

	if !opts.Quiet {
		ui.Progress(fmt.Sprintf("Starting %s tunnel (%s mode)...", t.Name(), mode), 30)
	}

	cfg := map[string]string{"config": opts.TunnelCfg}
	if err := o.tunnelM.Start(opts.Tunnel, mode, cfg); err != nil {
		return Result{Operation: OpTunnel, Err: err}
	}

	o.state.Set("TUNNEL_PROTOCOL", opts.Tunnel)
	o.state.Set("TUNNEL_MODE", string(mode))

	if !opts.Quiet {
		ui.Progress("Tunnel active", 100)
	}

	st := o.tunnelM.CurrentStatus()
	return Result{Operation: OpTunnel, Success: true,
		Details: fmt.Sprintf("%s active — %s", t.Name(), st.Endpoint)}
}

func (o *Orchestrator) restoreTunnel(quiet bool) Result {
	st := o.tunnelM.CurrentStatus()
	if !st.Running {
		return Result{Operation: OpTunnel, Success: true, Details: "no active tunnel"}
	}

	if err := o.tunnelM.Stop(); err != nil {
		return Result{Operation: OpTunnel, Err: err}
	}

	o.state.Set("TUNNEL_PROTOCOL", "")
	o.state.Set("TUNNEL_MODE", "")

	if !quiet {
		ui.Progress("Tunnel stopped", 100)
	}
	return Result{Operation: OpTunnel, Success: true, Details: "tunnel stopped"}
}

// preflight runs a network probe and returns conflict warnings.
func (o *Orchestrator) preflight(opts Options) []string {
	prober := netrecon.NewProber()
	ns, err := prober.Probe()
	if err != nil {
		o.logger.Warn("pre-flight probe failed", "err", err)
		return nil
	}
	return ns.Warnings
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
