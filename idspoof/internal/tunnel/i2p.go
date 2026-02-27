package tunnel

import (
	"fmt"
	"os/exec"
	"sync"
	"time"
)

type i2pTunnel struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	mode    Mode
	running bool
}

func (t *i2pTunnel) Name() string { return "I2P (PurpleI2P)" }

func (t *i2pTunnel) Available() bool { return binaryExists("i2pd") }

func (t *i2pTunnel) Start(mode Mode, cfg map[string]string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.mode = mode

	// Start i2pd with default config. It provides:
	// - SOCKS5 proxy on 127.0.0.1:4447
	// - HTTP proxy on 127.0.0.1:4444
	args := []string{"--daemon"}
	if confPath := cfg["config"]; confPath != "" {
		args = append(args, "--conf", confPath)
	}

	t.cmd = exec.Command("i2pd", args...)
	if err := t.cmd.Start(); err != nil {
		return fmt.Errorf("starting i2pd: %w", err)
	}

	// Give i2pd time to start up.
	time.Sleep(3 * time.Second)

	if mode == ModeTransparent {
		if err := t.setupTransparent(); err != nil {
			t.cmd.Process.Kill()
			return fmt.Errorf("iptables setup: %w", err)
		}
	}

	t.running = true
	return nil
}

func (t *i2pTunnel) setupTransparent() error {
	// Route HTTP traffic through i2pd's HTTP outproxy on port 4444.
	rules := [][]string{
		{"-t", "nat", "-N", "IDSPOOF_I2P"},
		{"-t", "nat", "-A", "IDSPOOF_I2P", "-d", "127.0.0.0/8", "-j", "RETURN"},
		{"-t", "nat", "-A", "IDSPOOF_I2P", "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", "4444"},
		{"-t", "nat", "-A", "IDSPOOF_I2P", "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-ports", "4444"},
		{"-t", "nat", "-A", "OUTPUT", "-j", "IDSPOOF_I2P"},
	}
	for _, r := range rules {
		exec.Command("iptables", r...).Run()
	}
	return nil
}

func (t *i2pTunnel) removeTransparent() {
	exec.Command("iptables", "-t", "nat", "-D", "OUTPUT", "-j", "IDSPOOF_I2P").Run()
	exec.Command("iptables", "-t", "nat", "-F", "IDSPOOF_I2P").Run()
	exec.Command("iptables", "-t", "nat", "-X", "IDSPOOF_I2P").Run()
}

func (t *i2pTunnel) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.mode == ModeTransparent {
		t.removeTransparent()
	}

	if t.cmd != nil && t.cmd.Process != nil {
		t.cmd.Process.Kill()
		t.cmd.Wait()
	}

	// Also stop any system i2pd that was running via init.
	exec.Command("systemctl", "stop", "i2pd").Run()

	t.running = false
	return nil
}

func (t *i2pTunnel) Status() Status {
	t.mu.Lock()
	defer t.mu.Unlock()

	endpoint := "socks5://127.0.0.1:4447, http://127.0.0.1:4444"
	if t.mode == ModeTransparent {
		endpoint = "transparent (HTTP/HTTPS via outproxy)"
	}
	return Status{
		Running:  t.running,
		Protocol: "i2p",
		Mode:     t.mode,
		Endpoint: endpoint,
		Details:  "I2P garlic routing — unidirectional tunnels, hidden services",
	}
}
