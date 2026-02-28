package spoofer

import "github.com/NubleX/ID-Spoofer/idspoof/internal/netident"

// Operation names for the result set.
const (
	OpMAC      = "mac"
	OpNetIdent = "netident"
	OpSysInfo  = "sysinfo"
	OpTunnel   = "tunnel"
)

// Result captures the outcome of a single spoofing operation.
type Result struct {
	Operation string
	Success   bool
	Details   string
	Err       error
}

// Options controls which operations to run.
type Options struct {
	MAC         bool
	NetIdent    bool
	PersonaType netident.PersonaType // "windows" | "macos" | "ios" (default: "windows")
	SysInfo     bool
	Tunnel      string // tunnel protocol name ("tor", "wireguard", etc.) or "" for none
	TunnelMode  string // "transparent" or "socks" (default: "transparent")
	TunnelCfg   string // path to tunnel config file
	DryRun      bool
	Quiet       bool
}

// AllOps returns an Options that enables every operation (except tunnel).
func AllOps() Options {
	return Options{MAC: true, NetIdent: true, SysInfo: true, PersonaType: netident.PersonaWindows}
}
