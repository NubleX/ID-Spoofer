package spoofer

// Operation names for the result set.
const (
	OpMAC      = "mac"
	OpNetIdent = "netident"
	OpSysInfo  = "sysinfo"
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
	MAC      bool
	NetIdent bool // Network persona: TCP/IP stack + DHCP hostname + iptables + NFQUEUE
	SysInfo  bool
	DryRun   bool
	Quiet    bool
}

// AllOps returns an Options that enables every operation.
func AllOps() Options {
	return Options{MAC: true, NetIdent: true, SysInfo: true}
}
