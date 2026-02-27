package ui

import (
	"fmt"
	"strings"
)

// PrintBanner prints the ASCII art banner.
func PrintBanner(version string) {
	// Strip leading 'v' to avoid "vv1.0.0"
	ver := strings.TrimPrefix(version, "v")

	// Inner width of the box (between the │ characters) = 48 chars.
	const innerWidth = 48

	line1 := "ID-Spoofer v" + ver
	line2 := "Identity Spoofing Tool"

	fmt.Println(Blue("╔" + strings.Repeat("═", innerWidth) + "╗"))
	fmt.Println(Blue("║") + centreIn(Bold(line1), innerWidth) + Blue("║"))
	fmt.Println(Blue("║") + centreIn(line2, innerWidth) + Blue("║"))
	fmt.Println(Blue("╚" + strings.Repeat("═", innerWidth) + "╝"))
	fmt.Println()
}

// centreIn centres text within a field of visibleWidth printable columns.
// ANSI codes don't occupy columns so we pad based on the visible length.
func centreIn(text string, visibleWidth int) string {
	visible := visibleLen(text)
	if visible >= visibleWidth {
		return text
	}
	total := visibleWidth - visible
	left := total / 2
	right := total - left
	return strings.Repeat(" ", left) + text + strings.Repeat(" ", right)
}

// visibleLen returns the number of printable columns in s,
// stripping ANSI escape sequences.
func visibleLen(s string) int {
	inEsc := false
	n := 0
	for i := 0; i < len(s); i++ {
		switch {
		case inEsc:
			if s[i] == 'm' {
				inEsc = false
			}
		case s[i] == '\033' && i+1 < len(s) && s[i+1] == '[':
			inEsc = true
			i++ // skip '['
		default:
			n++
		}
	}
	return n
}
