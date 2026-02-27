package ui

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Confirm prompts the user for a yes/no answer. Returns true for yes.
// If quiet is true it always returns true (non-interactive mode).
func Confirm(prompt string, quiet bool) bool {
	if quiet {
		return true
	}
	fmt.Printf("%s (y/n): ", Yellow(prompt))
	r := bufio.NewReader(os.Stdin)
	line, _ := r.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes"
}
