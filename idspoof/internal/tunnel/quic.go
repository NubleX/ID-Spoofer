package tunnel

import (
	"fmt"
	"os/exec"
	"sync"
	"time"
)

type quicTunnel struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	mode    Mode
	running bool
}

func (t *quicTunnel) Name() string { return "QUIC Tunnel (Hysteria2)" }

func (t *quicTunnel) Available() bool { return binaryExists("hysteria") }

func (t *quicTunnel) Start(mode Mode, cfg map[string]string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	confPath := cfg["config"]
	if confPath == "" {
		return fmt.Errorf("QUIC tunnel requires --tunnel-config pointing to a Hysteria2 config YAML")
	}

	t.mode = mode

	args := []string{"client", "-c", confPath}
	t.cmd = exec.Command("hysteria", args...)
	if err := t.cmd.Start(); err != nil {
		return fmt.Errorf("starting hysteria: %w", err)
	}

	time.Sleep(2 * time.Second)

	if mode == ModeTransparent {
		if err := t.setupTransparent(); err != nil {
			t.cmd.Process.Kill()
			return fmt.Errorf("iptables setup: %w", err)
		}
	}

	t.running = true
	return nil
}

func (t *quicTunnel) setupTransparent() error {
	// Hysteria2 supports tproxy mode. Set up iptables accordingly.
	rules := [][]string{
		{"-t", "nat", "-N", "IDSPOOF_QUIC"},
		{"-t", "nat", "-A", "IDSPOOF_QUIC", "-d", "127.0.0.0/8", "-j", "RETURN"},
		{"-t", "nat", "-A", "IDSPOOF_QUIC", "-p", "tcp", "-j", "REDIRECT", "--to-ports", "1080"},
		{"-t", "nat", "-A", "IDSPOOF_QUIC", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "1080"},
		{"-t", "nat", "-A", "OUTPUT", "-j", "IDSPOOF_QUIC"},
	}
	for _, r := range rules {
		exec.Command("iptables", r...).Run()
	}
	return nil
}

func (t *quicTunnel) removeTransparent() {
	exec.Command("iptables", "-t", "nat", "-D", "OUTPUT", "-j", "IDSPOOF_QUIC").Run()
	exec.Command("iptables", "-t", "nat", "-F", "IDSPOOF_QUIC").Run()
	exec.Command("iptables", "-t", "nat", "-X", "IDSPOOF_QUIC").Run()
}

func (t *quicTunnel) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.mode == ModeTransparent {
		t.removeTransparent()
	}

	if t.cmd != nil && t.cmd.Process != nil {
		t.cmd.Process.Kill()
		t.cmd.Wait()
	}

	t.running = false
	return nil
}

func (t *quicTunnel) Status() Status {
	t.mu.Lock()
	defer t.mu.Unlock()

	endpoint := "socks5://127.0.0.1:1080"
	if t.mode == ModeTransparent {
		endpoint = "transparent (iptables REDIRECT)"
	}
	return Status{
		Running:  t.running,
		Protocol: "quic",
		Mode:     t.mode,
		Endpoint: endpoint,
		Details:  "Hysteria2 QUIC tunnel — UDP-based, anti-DPI, high bandwidth",
	}
}
