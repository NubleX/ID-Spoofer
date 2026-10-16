//go:build !linux

// rewriter_daemon_other.go — NFQUEUE is Linux-only. Stubs keep the shared
// command/status code compiling on macOS and Windows, where the packet
// layer of the persona is not implemented.

package netident

import "fmt"

// SpawnRewriterDaemon is unsupported outside Linux.
func SpawnRewriterDaemon(stateDir string, persona PersonaType) (int, error) {
	return 0, fmt.Errorf("NFQUEUE rewriter not supported on this platform")
}

// StopRewriterDaemon is a no-op outside Linux.
func StopRewriterDaemon(stateDir string) (int, error) {
	return 0, nil
}

// RewriterStatus reports that no rewriter can run outside Linux.
func RewriterStatus(stateDir string) (int, string, bool) {
	return 0, "", false
}

// RunRewriterDaemon is unsupported outside Linux.
func RunRewriterDaemon(persona PersonaType, stateDir string, marker string) error {
	return fmt.Errorf("NFQUEUE rewriter not supported on this platform")
}

// ScopeToOwners is unsupported outside Linux.
func ScopeToOwners(owners []string) error {
	return fmt.Errorf("mangle owner scoping not supported on this platform")
}

// NFQueueRewriter is the Linux NFQUEUE engine; off-Linux the type exists
// only so the shared serve command compiles.
type NFQueueRewriter struct{}

// PrepareRewriterDaemon is unsupported outside Linux.
func PrepareRewriterDaemon(persona PersonaType, stateDir string, marker string) (*NFQueueRewriter, error) {
	return nil, fmt.Errorf("NFQUEUE rewriter not supported on this platform")
}

// FinishRewriterDaemon is a no-op outside Linux.
func FinishRewriterDaemon(r *NFQueueRewriter, stateDir string) {}
