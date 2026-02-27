// Package netident projects a Windows network identity on the wire without
// modifying the internal system hostname. Instead of breaking the OS by
// changing /etc/hostname, it manipulates:
//
//   - TCP/IP stack parameters (sysctl) to match Windows 10/11
//   - iptables/nftables rules to set TTL, clamp MSS
//   - DHCP client config to announce a Windows hostname + MSFT 5.0 vendor class
//   - mDNS/Avahi to suppress the real hostname
//
// This makes the host appear as Windows to Nmap, p0f, DHCP fingerprinters,
// and passive network observers while the actual system remains stable.
package netident

// Persona describes the full network identity to project.
type Persona struct {
	// Hostname is the Windows-style name announced via DHCP/NetBIOS (never set on the OS).
	Hostname string

	// TCP/IP stack parameters matching Windows 10/11:
	TTL              int // 128
	TCPTimestamps    int // 0 (disabled)
	TCPWindowScaling int // 1 (enabled, wscale=8)
	TCPSACK          int // 1
	TCPECN           int // 0
	TCPRFC1337       int // 0
	MSS              int // 1460

	// Buffer sizes to produce wscale=8 (65535 * 256 = 16776960).
	RmemDefault int // 65535
	RmemMax     int // 16776960
	WmemDefault int // 65535
	WmemMax     int // 16776960

	// DHCPVendorClass is sent as DHCP Option 60.
	DHCPVendorClass string // "MSFT 5.0"
}

// WindowsPersona returns a Persona that matches Windows 10/11 on the wire.
func WindowsPersona(hostname string) Persona {
	return Persona{
		Hostname:         hostname,
		TTL:              128,
		TCPTimestamps:    0,
		TCPWindowScaling: 1,
		TCPSACK:          1,
		TCPECN:           0,
		TCPRFC1337:       0,
		MSS:              1460,
		RmemDefault:      65535,
		RmemMax:          16776960,
		WmemDefault:      65535,
		WmemMax:          16776960,
		DHCPVendorClass:  "MSFT 5.0",
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
