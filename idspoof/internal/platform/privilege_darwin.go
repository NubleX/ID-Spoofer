//go:build darwin

package platform

import "os"

func EnsurePrivileged() error {
	if os.Getuid() != 0 {
		return ErrNotPrivileged
	}
	return nil
}
