//go:build linux

package hostname

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type linuxSpoofer struct{}

// NewLinuxSpoofer returns the Linux hostname spoofer.
func NewLinuxSpoofer() Spoofer { return &linuxSpoofer{} }

// Current returns the current static hostname.
func (s *linuxSpoofer) Current() (string, error) {
	if hostnamectlExists() {
		out, err := exec.Command("hostnamectl", "--static").Output()
		if err == nil {
			return strings.TrimSpace(string(out)), nil
		}
	}
	out, err := exec.Command("hostname").Output()
	if err != nil {
		return "", fmt.Errorf("hostname: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// Apply sets the system hostname using hostnamectl or /etc/hostname fallback.
func (s *linuxSpoofer) Apply(newHostname string) error {
	if !Validate(newHostname) {
		return fmt.Errorf("refusing to set invalid hostname: %q", newHostname)
	}

	if hostnamectlExists() {
		if err := exec.Command("hostnamectl", "set-hostname", newHostname).Run(); err != nil {
			return fmt.Errorf("hostnamectl set-hostname: %w", err)
		}
		return nil
	}

	// Fallback: atomic write to /etc/hostname + hostname command.
	tmp := "/etc/hostname.idspoof.tmp"
	if err := os.WriteFile(tmp, []byte(newHostname+"\n"), 0o644); err != nil {
		return fmt.Errorf("writing temp /etc/hostname: %w", err)
	}
	if err := os.Rename(tmp, "/etc/hostname"); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("replacing /etc/hostname: %w", err)
	}
	if err := exec.Command("hostname", newHostname).Run(); err != nil {
		return fmt.Errorf("hostname command: %w", err)
	}
	return nil
}

// Restore is identical to Apply for Linux (just set the hostname back).
func (s *linuxSpoofer) Restore(originalHostname string) error {
	return s.Apply(originalHostname)
}

// UpdateHosts updates /etc/hosts, backing up to the state dir.
func (s *linuxSpoofer) UpdateHosts(oldHostname, newHostname string) error {
	backupDir := "/var/log/idspoof"
	os.MkdirAll(backupDir, 0o700)
	return UpdateHostsFile("/etc/hosts", filepath.Join(backupDir, "hosts.backup"), oldHostname, newHostname)
}

func hostnamectlExists() bool {
	_, err := exec.LookPath("hostnamectl")
	return err == nil
}
