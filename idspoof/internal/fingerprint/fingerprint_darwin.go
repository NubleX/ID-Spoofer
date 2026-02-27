//go:build darwin

package fingerprint

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type darwinSpoofer struct{}

func NewLinuxSpoofer() Spoofer   { return &darwinSpoofer{} }
func NewDarwinSpoofer() Spoofer  { return &darwinSpoofer{} }

func (s *darwinSpoofer) Current() (Parameters, error) {
	ttl, err := macSysctlGet("net.inet.ip.ttl")
	if err != nil {
		ttl = 64
	}
	return Parameters{TTL: ttl, TCPTimestamps: -1, TCPWindowScaling: -1}, nil
}

func (s *darwinSpoofer) Apply(p *Parameters) error {
	return macSysctlSet("net.inet.ip.ttl", p.TTL)
}

func (s *darwinSpoofer) Restore(orig *Parameters) error { return s.Apply(orig) }

func macSysctlGet(key string) (int, error) {
	out, err := exec.Command("sysctl", "-n", key).Output()
	if err != nil {
		return 0, fmt.Errorf("sysctl -n %s: %w", key, err)
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	return v, nil
}

func macSysctlSet(key string, val int) error {
	return exec.Command("sysctl", "-w", fmt.Sprintf("%s=%d", key, val)).Run()
}
