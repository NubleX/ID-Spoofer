package tunnel

import (
	"fmt"
	"sync"
)

// Manager controls the lifecycle of a single active tunnel.
// Only one tunnel can be active at a time.
type Manager struct {
	mu     sync.Mutex
	active Tunnel
	mode   Mode
}

// NewManager creates a tunnel manager.
func NewManager() *Manager {
	return &Manager{}
}

// Start launches a tunnel by protocol name.
func (m *Manager) Start(name string, mode Mode, cfg map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Stop any existing tunnel first.
	if m.active != nil {
		m.active.Stop()
		m.active = nil
	}

	t := Get(name)
	if t == nil {
		return fmt.Errorf("unknown tunnel protocol: %s", name)
	}

	if !t.Available() {
		return fmt.Errorf("%s: required binary not found in PATH", t.Name())
	}

	if err := t.Start(mode, cfg); err != nil {
		return fmt.Errorf("%s: %w", t.Name(), err)
	}

	m.active = t
	m.mode = mode
	return nil
}

// Stop tears down the active tunnel.
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.active == nil {
		return nil
	}

	err := m.active.Stop()
	m.active = nil
	return err
}

// CurrentStatus returns the status of the active tunnel, or a "not running" status.
func (m *Manager) CurrentStatus() Status {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.active == nil {
		return Status{Running: false, Protocol: "none"}
	}
	return m.active.Status()
}
