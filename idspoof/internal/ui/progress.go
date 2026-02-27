package ui

import "fmt"

// Progress prints a progress line to stdout.
func Progress(message string, percent int) {
	fmt.Printf("%-50s [%3d%%]\n", message, percent)
}
