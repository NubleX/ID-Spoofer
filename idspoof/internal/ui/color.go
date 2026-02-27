package ui

var colorsEnabled bool

// ANSI escape codes.
const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	blue   = "\033[34m"
	cyan   = "\033[36m"
)

func colorize(code, s string) string {
	if !colorsEnabled {
		return s
	}
	return code + s + reset
}

func Bold(s string) string   { return colorize(bold, s) }
func Red(s string) string    { return colorize(red, s) }
func Green(s string) string  { return colorize(green, s) }
func Yellow(s string) string { return colorize(yellow, s) }
func Blue(s string) string   { return colorize(blue, s) }
func Cyan(s string) string   { return colorize(cyan, s) }
