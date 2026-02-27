// Package fingerprint provides OS TCP/IP fingerprint spoofing.
package fingerprint

// Parameters holds the TCP/IP stack settings that identify the OS.
type Parameters struct {
	TTL              int
	TCPTimestamps    int
	TCPWindowScaling int
}

// Spoofer is the interface for platform-specific fingerprint operations.
type Spoofer interface {
	Current() (Parameters, error)
	Apply(params *Parameters) error
	Restore(original *Parameters) error
}
