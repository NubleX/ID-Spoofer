//go:build linux

package fingerprint

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type linuxSpoofer struct{}

// NewLinuxSpoofer returns the Linux fingerprint spoofer.
func NewLinuxSpoofer() Spoofer { return &linuxSpoofer{} }

// Current reads the current sysctl values.
func (s *linuxSpoofer) Current() (Parameters, error) {
	ttl, err := sysctlGet("net.ipv4.ip_default_ttl")
	if err != nil {
		ttl = 64
	}
	ts, err := sysctlGet("net.ipv4.tcp_timestamps")
	if err != nil {
		ts = 1
	}
	ws, err := sysctlGet("net.ipv4.tcp_window_scaling")
	if err != nil {
		ws = 1
	}
	return Parameters{TTL: ttl, TCPTimestamps: ts, TCPWindowScaling: ws}, nil
}

// Apply writes new sysctl values.
func (s *linuxSpoofer) Apply(p *Parameters) error {
	errs := []string{}
	if err := sysctlSet("net.ipv4.ip_default_ttl", p.TTL); err != nil {
		errs = append(errs, err.Error())
	}
	if err := sysctlSet("net.ipv4.tcp_timestamps", p.TCPTimestamps); err != nil {
		errs = append(errs, err.Error())
	}
	if err := sysctlSet("net.ipv4.tcp_window_scaling", p.TCPWindowScaling); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("sysctl errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// Restore restores the original sysctl values.
func (s *linuxSpoofer) Restore(orig *Parameters) error { return s.Apply(orig) }

func sysctlGet(key string) (int, error) {
	out, err := exec.Command("sysctl", "-n", key).Output()
	if err != nil {
		return 0, fmt.Errorf("sysctl -n %s: %w", key, err)
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return 0, fmt.Errorf("parsing sysctl %s output: %w", key, err)
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
