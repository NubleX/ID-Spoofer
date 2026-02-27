// Package sysinfo provides system information display/generation.
package sysinfo

// Info holds generated hardware profile information.
type Info struct {
	Manufacturer string
	Product      string
	Version      string
	Serial       string
}

// Spoofer is the interface for system info operations.
type Spoofer interface {
	Generate() (Info, error)
	Apply(info Info) error
}
