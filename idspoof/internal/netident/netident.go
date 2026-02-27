// Package netident projects an OS network identity on the wire without
// modifying the internal system hostname. Instead of breaking the OS by
// changing /etc/hostname, it manipulates:
//
//   - TCP/IP stack parameters (sysctl) to match the target OS
//   - iptables/nftables rules to set TTL, clamp MSS
//   - NFQUEUE packet rewriter for IP ID + TCP options ordering
//   - DHCP client config to announce the target OS hostname + vendor class
//   - mDNS/Avahi behaviour matching the target OS
//
// Supported personas: Windows 10/11, macOS (Sonoma+), iOS 17+, Linux (generic).
// The actual system hostname is NEVER changed.
package netident

// PersonaType identifies which OS to impersonate on the wire.
type PersonaType string

const (
	PersonaWindows PersonaType = "windows"
	PersonaMacOS   PersonaType = "macos"
	PersonaiOS     PersonaType = "ios"
	PersonaLinux   PersonaType = "linux"
)

// Persona describes the full network identity to project.
type Persona struct {
	// Type selects the OS fingerprint profile.
	Type PersonaType

	// Hostname is announced via DHCP (never set on the OS).
	Hostname string

	// TCP/IP stack parameters:
	TTL              int // 128 (Windows), 64 (macOS/iOS)
	TCPTimestamps    int // 0=disabled (Windows), 1=enabled (macOS/iOS)
	TCPWindowScaling int // 1 (enabled)
	TCPSACK          int // 1
	TCPECN           int // 0
	TCPRFC1337       int // 0
	MSS              int // 1460

	// WScale is the TCP window scale factor written into SYN options.
	// Windows/macOS: 8, iOS: 16.
	WScale int

	// Buffer sizes tuned to produce the target wscale.
	RmemDefault int
	RmemMax     int
	WmemDefault int
	WmemMax     int

	// DHCPVendorClass is sent as DHCP Option 60. Empty = don't send.
	DHCPVendorClass string // "MSFT 5.0" for Windows, "" for macOS/iOS

	// SuppressMDNS controls Avahi behaviour.
	// true = stop Avahi (Windows persona), false = leave running (macOS — uses Bonjour).
	SuppressMDNS bool
}

// WindowsPersona returns a Persona that matches Windows 10/11 on the wire.
// p0f: *:128:0:*:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
func WindowsPersona(hostname string) Persona {
	return Persona{
		Type:             PersonaWindows,
		Hostname:         hostname,
		TTL:              128,
		TCPTimestamps:    0,
		TCPWindowScaling: 1,
		TCPSACK:          1,
		TCPECN:           0,
		TCPRFC1337:       0,
		MSS:              1460,
		WScale:           8,
		RmemDefault:      65535,
		RmemMax:          16776960,
		WmemDefault:      65535,
		WmemMax:          16776960,
		DHCPVendorClass:  "MSFT 5.0",
		SuppressMDNS:     true,
	}
}

// MacOSPersona returns a Persona that matches macOS Sonoma+ on the wire.
// Key differences from Windows: TTL=64, timestamps enabled, no vendor class,
// Bonjour/mDNS left running.
// p0f: *:64:0:*:65535,8:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0
func MacOSPersona(hostname string) Persona {
	return Persona{
		Type:             PersonaMacOS,
		Hostname:         hostname,
		TTL:              64,
		TCPTimestamps:    1,
		TCPWindowScaling: 1,
		TCPSACK:          1,
		TCPECN:           0,
		TCPRFC1337:       0,
		MSS:              1460,
		WScale:           8,
		RmemDefault:      65535,
		RmemMax:          16776960,
		WmemDefault:      65535,
		WmemMax:          16776960,
		DHCPVendorClass:  "",
		SuppressMDNS:     false,
	}
}

// IOSPersona returns a Persona that matches iOS 17+ (iPhone/iPad) on the wire.
// Identical to macOS except window scale factor is 16.
func IOSPersona(hostname string) Persona {
	p := MacOSPersona(hostname)
	p.Type = PersonaiOS
	p.WScale = 16
	// iOS wscale=16 → 65535 * 65536 = 4294901760.
	p.RmemMax = 4294901760
	p.WmemMax = 4294901760
	return p
}

// LinuxPersona returns a Persona that matches a generic modern Linux machine.
// Useful for blending into a LAN where other Linux hosts are present.
// TCP options order: MSS, SACK, Timestamps, NOP, WScale (Linux kernel default).
// p0f: *:64:0:*:29200,7:mss,sackOK,ts,nop,ws:df,id+:0
func LinuxPersona(hostname string) Persona {
	return Persona{
		Type:             PersonaLinux,
		Hostname:         hostname,
		TTL:              64,
		TCPTimestamps:    1,
		TCPWindowScaling: 1,
		TCPSACK:          1,
		TCPECN:           2, // notify/optional — common on modern Linux kernels
		TCPRFC1337:       0,
		MSS:              1460,
		WScale:           7, // Linux default with 4MB rmem_max (2^7 = 128 multiplier)
		RmemDefault:      212992,
		RmemMax:          4194304,
		WmemDefault:      212992,
		WmemMax:          4194304,
		DHCPVendorClass:  "", // no vendor class
		SuppressMDNS:     false,
	}
}

// Spoofer applies and restores a network persona.
type Spoofer interface {
	// Current reads the active sysctl/iptables/DHCP state.
	Current() (*Snapshot, error)

	// Apply projects the persona on the wire. The system hostname is NOT changed.
	Apply(p Persona) error

	// Restore reverts all changes made by Apply.
	Restore(snap *Snapshot) error
}

// Snapshot captures the original system state before Apply, so Restore
// can revert everything precisely.
type Snapshot struct {
	// Sysctl originals.
	TTL              int
	TCPTimestamps    int
	TCPWindowScaling int
	TCPSACK          int
	TCPECN           int
	TCPRFC1337       int
	RmemDefault      int
	RmemMax          int
	WmemDefault      int
	WmemMax          int

	// Whether iptables rules were added (so Restore can remove them).
	IPTablesRulesAdded bool

	// DHCP config paths that were modified.
	DHCPConfigModified string
	DHCPConfigBackup   string

	// Avahi was stopped/modified.
	AvahiWasStopped bool
}
