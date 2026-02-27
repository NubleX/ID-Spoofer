//go:build darwin

package hostname

import (
	"fmt"
	"os/exec"
	"strings"
)

type darwinSpoofer struct{}

func NewLinuxSpoofer() Spoofer  { return &darwinSpoofer{} } // reuse factory name
func NewDarwinSpoofer() Spoofer { return &darwinSpoofer{} }

func (s *darwinSpoofer) Current() (string, error) {
	out, err := exec.Command("scutil", "--get", "HostName").Output()
	if err != nil {
		out, err = exec.Command("hostname").Output()
		if err != nil {
			return "", fmt.Errorf("hostname: %w", err)
		}
	}
	return strings.TrimSpace(string(out)), nil
}

func (s *darwinSpoofer) Apply(newHostname string) error {
	if !Validate(newHostname) {
		return fmt.Errorf("invalid hostname: %q", newHostname)
	}
	for _, key := range []string{"HostName", "LocalHostName", "ComputerName"} {
		exec.Command("scutil", "--set", key, newHostname).Run()
	}
	return nil
}

func (s *darwinSpoofer) Restore(orig string) error { return s.Apply(orig) }

func (s *darwinSpoofer) UpdateHosts(old, new string) error {
	return UpdateHostsFile("/etc/hosts", "/var/log/idspoof/hosts.backup", old, new)
}
