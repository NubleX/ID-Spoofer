//go:build windows

package hostname

import (
	"fmt"
	"os/exec"
	"strings"
)

type windowsSpoofer struct{}

func NewLinuxSpoofer() Spoofer   { return &windowsSpoofer{} }
func NewWindowsSpoofer() Spoofer { return &windowsSpoofer{} }

func (s *windowsSpoofer) Current() (string, error) {
	out, err := exec.Command("hostname").Output()
	if err != nil {
		return "", fmt.Errorf("hostname: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func (s *windowsSpoofer) Apply(newHostname string) error {
	if !Validate(newHostname) {
		return fmt.Errorf("invalid hostname: %q", newHostname)
	}
	if err := exec.Command("wmic", "computersystem", "where", "name='%COMPUTERNAME%'", "call", "rename", newHostname).Run(); err != nil {
		return fmt.Errorf("wmic rename: %w", err)
	}
	return nil
}

func (s *windowsSpoofer) Restore(orig string) error { return s.Apply(orig) }
func (s *windowsSpoofer) UpdateHosts(old, new string) error {
	return UpdateHostsFile(`C:\Windows\System32\drivers\etc\hosts`, "", old, new)
}
