//go:build linux

package netident

import (
	"fmt"
	"strings"
)

type linuxSpoofer struct {
	stateDir string
	noDaemon bool // don't start the rewriter daemon; leave the queue to an external process
}

// NewLinuxSpoofer returns the Linux network persona spoofer.
func NewLinuxSpoofer() Spoofer { return &linuxSpoofer{} }

// SetStateDir implements StateDirAware: the NFQUEUE rewriter daemon is
// tracked via a pid file in the state directory.
func (s *linuxSpoofer) SetStateDir(dir string) { s.stateDir = dir }

// SetNoDaemon implements RewriterSpawnControl: keep the NFQUEUE rule but
// leave the queue to an external process (e.g. a service manager) instead of
// starting the detached helper.
func (s *linuxSpoofer) SetNoDaemon(v bool) { s.noDaemon = v }

// Current snapshots the active system state so we can restore later.
func (s *linuxSpoofer) Current() (*Snapshot, error) {
	snap := &Snapshot{}
	if err := snapshotSysctl(snap); err != nil {
		return nil, fmt.Errorf("reading sysctl state: %w", err)
	}
	snap.IPTablesRulesAdded = jumpExists()
	return snap, nil
}

// Apply projects the selected persona on the wire.
// The system hostname is NEVER modified — we only change what goes on the wire.
func (s *linuxSpoofer) Apply(p Persona) error {
	var errs []string

	// Stop any running rewriter before starting a new one — queue 42 can only
	// have one reader, and switching personas re-enters Apply() with the old
	// rewriter still holding the socket.
	if s.rewriter != nil {
		s.rewriter.Stop()
		s.rewriter = nil
	}

	// Store the active persona type so the NFQUEUE rewriter goroutine can
	// build the correct TCP options layout.
	activePersona.Store(p.Type)

	// 1. Sysctl — TCP/IP stack parameters (TTL, timestamps, SACK, ECN, buffers).
	if sysctlErrs := applySysctl(&p); len(sysctlErrs) > 0 {
		errs = append(errs, sysctlErrs...)
	}

	// 2. iptables — TTL + MSS at the packet level.
	if err := applyIPTables(&p); err != nil {
		errs = append(errs, fmt.Sprintf("iptables: %v", err))
	}

	// 3. NFQUEUE packet rewriter — IP ID + TCP options ordering.
	//    The kernel rule diverts outgoing SYNs to queue 42; a detached
	//    helper process (`idspoof __rewriter`, pid tracked in the state
	//    dir) dequeues and rewrites them, so the persona survives this
	//    CLI process exiting.
	if err := installNFQueueRule(); err != nil {
		errs = append(errs, fmt.Sprintf("nfqueue rule: %v", err))
	} else if s.noDaemon {
		// The queue is expected to be drained by an external process
		// (e.g. a service manager running `idspoof __rewriter`); check
		// what, if anything, currently owns it.
		pid, runningPersona, alive := RewriterStatus(s.stateDir)
		switch {
		case alive && PersonaType(runningPersona) == p.Type:
			// An external rewriter for the matching persona already
			// drains the queue — nothing to do.
		case alive:
			errs = append(errs, fmt.Sprintf(
				"nfqueue rewriter: running rewriter (PID %d) uses persona %s, not %s; stop it (or its service) before applying with an external rewriter",
				pid, runningPersona, p.Type))
			removeNFQueueRule()
		default:
			errs = append(errs, fmt.Sprintf(
				"nfqueue rewriter: not running; expected under an external manager, which starts its own rewriter (manual equivalent: `idspoof __rewriter --persona %s`)",
				p.Type))
		}
	} else if _, err := SpawnRewriterDaemon(s.stateDir, p.Type); err != nil {
		errs = append(errs, fmt.Sprintf("nfqueue rewriter: %v", err))
		removeNFQueueRule()
	}

	// 4. DHCP — announce persona hostname + optional vendor class.
	snap := &Snapshot{}
	if err := applyDHCP(&p, snap); err != nil {
		errs = append(errs, fmt.Sprintf("dhcp: %v", err))
	}

	// 5. mDNS — persona-dependent Avahi handling.
	handleMDNS(&p, snap)

	if len(errs) > 0 {
		return fmt.Errorf("network persona (partial): %s", strings.Join(errs, "; "))
	}
	return nil
}

// Restore reverts all changes.
func (s *linuxSpoofer) Restore(snap *Snapshot) error {
	var errs []string

	// Stop the rewriter daemon first, so the queue is cleanly unbound
	// before the iptables rules are removed.
	if _, err := StopRewriterDaemon(s.stateDir); err != nil {
		errs = append(errs, fmt.Sprintf("rewriter stop: %v", err))
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
