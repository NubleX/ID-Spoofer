// Package hostname — /etc/hosts manipulation (shared Linux/macOS).
package hostname

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// UpdateHostsFile rewrites /etc/hosts, replacing oldHostname with newHostname
// on 127.0.0.1 and 127.0.1.1 lines. If oldHostname is not found a new
// 127.0.1.1 entry is appended. The original file is backed up to backupPath
// on the first call (backupPath="" skips backup).
func UpdateHostsFile(hostsPath, backupPath, oldHostname, newHostname string) error {
	if _, err := os.Stat(hostsPath); os.IsNotExist(err) {
		return nil // nothing to update
	}

	// Backup once.
	if backupPath != "" {
		if _, err := os.Stat(backupPath); os.IsNotExist(err) {
			if err := copyFile(hostsPath, backupPath); err != nil {
				// Non-fatal; log but continue.
				fmt.Fprintf(os.Stderr, "warn: could not backup %s: %v\n", hostsPath, err)
			}
		}
	}

	in, err := os.Open(hostsPath)
	if err != nil {
		return fmt.Errorf("opening %s: %w", hostsPath, err)
	}
	defer in.Close()

	tmp := hostsPath + ".idspoof.tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("creating temp hosts file: %w", err)
	}

	changed := false
	scanner := bufio.NewScanner(in)
	w := bufio.NewWriter(out)

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "127.0.0.1") || strings.HasPrefix(trimmed, "127.0.1.1") {
			fields := strings.Fields(line)
			for i := 1; i < len(fields); i++ {
				if fields[i] == oldHostname {
					fields[i] = newHostname
					changed = true
				}
			}
			line = strings.Join(fields, "\t")
		}

		fmt.Fprintln(w, line)
	}

	if !changed {
		fmt.Fprintf(w, "127.0.1.1\t%s\n", newHostname)
	}

	if err := scanner.Err(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := w.Flush(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	out.Close()

	return os.Rename(tmp, hostsPath)
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o640)
}
