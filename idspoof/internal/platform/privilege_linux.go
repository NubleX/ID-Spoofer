//go:build linux

package platform

import "os"

// EnsurePrivileged returns ErrNotPrivileged if the process is not running as root.
func EnsurePrivileged() error {
	if os.Getuid() != 0 {
		return ErrNotPrivileged
	}
	return nil
}
