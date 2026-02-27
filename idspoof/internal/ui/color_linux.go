//go:build linux

package ui

import (
	"os"

	"golang.org/x/sys/unix"
)

func init() {
	colorsEnabled = isTerminal(os.Stdout.Fd())
}

func isTerminal(fd uintptr) bool {
	_, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	return err == nil
}
