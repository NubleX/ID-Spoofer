// Package hostname provides hostname spoofing functionality.
package hostname

// Spoofer is the interface for platform-specific hostname operations.
type Spoofer interface {
	Current() (string, error)
	Apply(newHostname string) error
	Restore(originalHostname string) error
	UpdateHosts(oldHostname, newHostname string) error
}
