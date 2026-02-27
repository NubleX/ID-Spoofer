//go:build linux

package netident

import (
	"fmt"
	"strings"
)

type linuxSpoofer struct {
	rewriter *NFQueueRewriter
}

// NewLinuxSpoofer returns the Linux network persona spoofer.
func NewLinuxSpoofer() Spoofer { return &linuxSpoofer{} }

// Current snapshots the active system state so we can restore later.
func (s *linuxSpoofer) Current() (*Snapshot, error) {
	snap := &Snapshot{}
	if err := snapshotSysctl(snap); err != nil {
		return nil, fmt.Errorf("reading sysctl state: %w", err)
	}
	snap.IPTablesRulesAdded = jumpExists()
	return snap, nil
}

// Apply projects the Windows persona on the wire.
// The system hostname is NEVER modified — we only change what goes on the wire.
func (s *linuxSpoofer) Apply(p Persona) error {
	var errs []string

	// 1. Sysctl — TCP/IP stack parameters (TTL, timestamps, SACK, ECN, buffers).
	if sysctlErrs := applySysctl(&p); len(sysctlErrs) > 0 {
		errs = append(errs, sysctlErrs...)
	}

	// 2. iptables — TTL + MSS at the packet level.
	if err := applyIPTables(&p); err != nil {
		errs = append(errs, fmt.Sprintf("iptables: %v", err))
	}

	// 3. NFQUEUE packet rewriter — IP ID + TCP options ordering.
	//    This is the deep evasion layer that defeats Nmap/p0f:
	//      - Rewrites IP ID from 0 (Linux with DF) to incrementing (Windows)
	//      - Reorders TCP options on SYN packets to Windows layout
	if err := installNFQueueRule(); err != nil {
		errs = append(errs, fmt.Sprintf("nfqueue rule: %v", err))
	} else {
		s.rewriter = NewNFQueueRewriter(nfqueueNum)
		if err := s.rewriter.Start(); err != nil {
			errs = append(errs, fmt.Sprintf("nfqueue rewriter: %v", err))
			removeNFQueueRule()
		}
	}

	// 4. DHCP — announce Windows hostname + MSFT 5.0 vendor class.
	snap := &Snapshot{}
	if err := applyDHCP(&p, snap); err != nil {
		errs = append(errs, fmt.Sprintf("dhcp: %v", err))
	}

	// 5. mDNS — suppress Avahi so it doesn't leak the real hostname.
	suppressMDNS(snap)

	if len(errs) > 0 {
		return fmt.Errorf("network persona (partial): %s", strings.Join(errs, "; "))
	}
	return nil
}

// Restore reverts all changes.
func (s *linuxSpoofer) Restore(snap *Snapshot) error {
	var errs []string

	// Stop NFQUEUE rewriter first.
	if s.rewriter != nil {
		s.rewriter.Stop()
		s.rewriter = nil
	}

	if sysctlErrs := restoreSysctl(snap); len(sysctlErrs) > 0 {
		errs = append(errs, sysctlErrs...)
	}

	if err := removeIPTables(); err != nil {
		errs = append(errs, fmt.Sprintf("iptables remove: %v", err))
	}

	restoreDHCP(snap)
	restoreMDNS(snap)

	if len(errs) > 0 {
		return fmt.Errorf("restore errors: %s", strings.Join(errs, "; "))
	}
	return nil
}
