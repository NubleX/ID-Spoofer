//go:build linux

package netident

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// sysctlKeys is the set of fingerprint-relevant sysctls that the persona
// system writes. We deliberately do NOT touch net.core.{r,w}mem_* or
// net.ipv4.tcp_{r,w}mem here: those are global socket-buffer defaults that
// every process on the system inherits, including netlink-heavy daemons like
// Mullvad. Lowering them — or even just rewriting them mid-flight — has been
// observed to break Mullvad's firewall policy upload with EMSGSIZE. The only
// thing those buffers contributed to fingerprinting was the TCP window scale
// factor, and that is now injected directly into outgoing SYN packets by the
// NFQUEUE rewriter (see personaWScale in pktrewrite_linux.go), so changing
// the kernel-wide defaults is unnecessary as well as harmful.
var sysctlKeys = []struct {
	Key       string
	FieldFunc func(p *Persona) int
	SnapFunc  func(s *Snapshot, v int)
}{
	{"net.ipv4.ip_default_ttl", func(p *Persona) int { return p.TTL }, func(s *Snapshot, v int) { s.TTL = v }},
	{"net.ipv4.tcp_timestamps", func(p *Persona) int { return p.TCPTimestamps }, func(s *Snapshot, v int) { s.TCPTimestamps = v }},
	{"net.ipv4.tcp_window_scaling", func(p *Persona) int { return p.TCPWindowScaling }, func(s *Snapshot, v int) { s.TCPWindowScaling = v }},
	{"net.ipv4.tcp_sack", func(p *Persona) int { return p.TCPSACK }, func(s *Snapshot, v int) { s.TCPSACK = v }},
	{"net.ipv4.tcp_ecn", func(p *Persona) int { return p.TCPECN }, func(s *Snapshot, v int) { s.TCPECN = v }},
	{"net.ipv4.tcp_rfc1337", func(p *Persona) int { return p.TCPRFC1337 }, func(s *Snapshot, v int) { s.TCPRFC1337 = v }},
}

// snapshotSysctl reads all relevant sysctl values into a Snapshot.
func snapshotSysctl(snap *Snapshot) error {
	for _, sk := range sysctlKeys {
		v, err := sysctlGet(sk.Key)
		if err != nil {
			v = 0
		}
		sk.SnapFunc(snap, v)
	}
	return nil
}

// applySysctl writes all fingerprint-relevant sysctl values from the Persona.
func applySysctl(p *Persona) []string {
	var errs []string
	for _, sk := range sysctlKeys {
		if err := sysctlSet(sk.Key, sk.FieldFunc(p)); err != nil {
			errs = append(errs, err.Error())
		}
	}
	return errs
}

// restoreSysctl writes all sysctl values from the Snapshot.
func restoreSysctl(snap *Snapshot) []string {
	p := Persona{
		TTL:              snap.TTL,
		TCPTimestamps:    snap.TCPTimestamps,
		TCPWindowScaling: snap.TCPWindowScaling,
		TCPSACK:          snap.TCPSACK,
		TCPECN:           snap.TCPECN,
		TCPRFC1337:       snap.TCPRFC1337,
	}
	return applySysctl(&p)
}

func sysctlGet(key string) (int, error) {
	out, err := exec.Command("sysctl", "-n", key).Output()
	if err != nil {
		return 0, fmt.Errorf("sysctl -n %s: %w", key, err)
	}
	val := strings.TrimSpace(string(out))
	// Handle triplet values like "4096 87380 6291456" — return the middle (default).
	if parts := strings.Fields(val); len(parts) == 3 {
		v, err := strconv.Atoi(parts[1])
		if err != nil {
			return 0, fmt.Errorf("parse %s default: %w", key, err)
		}
		return v, nil
	}
	v, err := strconv.Atoi(val)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	return v, nil
}

func sysctlSet(key string, value int) error {
	arg := fmt.Sprintf("%s=%d", key, value)
	if err := exec.Command("sysctl", "-w", arg).Run(); err != nil {
		return fmt.Errorf("sysctl -w %s: %w", arg, err)
	}
	return nil
}
