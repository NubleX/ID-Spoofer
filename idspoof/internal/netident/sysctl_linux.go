//go:build linux

package netident

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// sysctlMap maps sysctl keys to Persona field values for a Windows profile.
// These are the parameters that matter to p0f, Nmap, and passive fingerprinters.
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
	{"net.core.rmem_default", func(p *Persona) int { return p.RmemDefault }, func(s *Snapshot, v int) { s.RmemDefault = v }},
	{"net.core.rmem_max", func(p *Persona) int { return p.RmemMax }, func(s *Snapshot, v int) { s.RmemMax = v }},
	{"net.core.wmem_default", func(p *Persona) int { return p.WmemDefault }, func(s *Snapshot, v int) { s.WmemDefault = v }},
	{"net.core.wmem_max", func(p *Persona) int { return p.WmemMax }, func(s *Snapshot, v int) { s.WmemMax = v }},
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

// applySysctl writes all sysctl values from the Persona.
func applySysctl(p *Persona) []string {
	var errs []string
	for _, sk := range sysctlKeys {
		if err := sysctlSet(sk.Key, sk.FieldFunc(p)); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// TCP buffer tuning (min/default/max triplet) to produce wscale=8.
	// net.ipv4.tcp_rmem and tcp_wmem take "min default max" space-separated.
	rmem := fmt.Sprintf("4096 %d %d", p.RmemDefault, p.RmemMax)
	wmem := fmt.Sprintf("4096 %d %d", p.WmemDefault, p.WmemMax)
	if err := sysctlSetStr("net.ipv4.tcp_rmem", rmem); err != nil {
		errs = append(errs, err.Error())
	}
	if err := sysctlSetStr("net.ipv4.tcp_wmem", wmem); err != nil {
		errs = append(errs, err.Error())
	}

	return errs
}

// restoreSysctl writes all sysctl values from the Snapshot.
func restoreSysctl(snap *Snapshot) []string {
	// Build a temp persona from snapshot values for the table-driven restore.
	p := Persona{
		TTL:              snap.TTL,
		TCPTimestamps:    snap.TCPTimestamps,
		TCPWindowScaling: snap.TCPWindowScaling,
		TCPSACK:          snap.TCPSACK,
		TCPECN:           snap.TCPECN,
		TCPRFC1337:       snap.TCPRFC1337,
		RmemDefault:      snap.RmemDefault,
		RmemMax:          snap.RmemMax,
		WmemDefault:      snap.WmemDefault,
		WmemMax:          snap.WmemMax,
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

func sysctlSetStr(key, value string) error {
	arg := fmt.Sprintf("%s=%s", key, value)
	if err := exec.Command("sysctl", "-w", arg).Run(); err != nil {
		return fmt.Errorf("sysctl -w %s: %w", arg, err)
	}
	return nil
}
