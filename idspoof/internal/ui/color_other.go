//go:build !linux

package ui

import "os"

func init() {
	colorsEnabled = isTerminal(os.Stdout.Fd())
}

func isTerminal(fd uintptr) bool {
	// Best-effort: check if stdout is not being redirected.
	// Works on macOS/Windows without unix package.
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
