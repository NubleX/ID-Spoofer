package tunnel

import (
	"fmt"
	"os/exec"
	"sync"
	"time"
)

type shadowsocksTunnel struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	mode    Mode
	running bool
}

func (t *shadowsocksTunnel) Name() string { return "Shadowsocks" }

func (t *shadowsocksTunnel) Available() bool {
	return binaryExists("sslocal") || binaryExists("ss-local")
}

func (t *shadowsocksTunnel) binary() string {
	if binaryExists("sslocal") {
		return "sslocal"
	}
	return "ss-local"
}

func (t *shadowsocksTunnel) Start(mode Mode, cfg map[string]string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	confPath := cfg["config"]
	if confPath == "" {
		return fmt.Errorf("Shadowsocks requires --tunnel-config pointing to a server config JSON")
	}

	t.mode = mode
	bin := t.binary()

	args := []string{"-c", confPath}
	if mode == ModeTransparent {
		// Use redir mode for transparent proxying.
		args = append(args, "--protocol", "redir", "-b", "127.0.0.1:1081")
	} else {
		// SOCKS5 mode.
		args = append(args, "-b", "127.0.0.1:1080")
	}

	t.cmd = exec.Command(bin, args...)
	if err := t.cmd.Start(); err != nil {
		return fmt.Errorf("starting %s: %w", bin, err)
	}

	time.Sleep(1 * time.Second)

	if mode == ModeTransparent {
		if err := t.setupTransparent(); err != nil {
			t.cmd.Process.Kill()
			return fmt.Errorf("iptables setup: %w", err)
		}
	}

	t.running = true
	return nil
}

func (t *shadowsocksTunnel) setupTransparent() error {
	rules := [][]string{
		{"-t", "nat", "-N", "IDSPOOF_SS"},
		{"-t", "nat", "-A", "IDSPOOF_SS", "-d", "127.0.0.0/8", "-j", "RETURN"},
		{"-t", "nat", "-A", "IDSPOOF_SS", "-p", "tcp", "-j", "REDIRECT", "--to-ports", "1081"},
		{"-t", "nat", "-A", "OUTPUT", "-j", "IDSPOOF_SS"},
	}
	for _, r := range rules {
		exec.Command("iptables", r...).Run()
	}
	return nil
}

func (t *shadowsocksTunnel) removeTransparent() {
	exec.Command("iptables", "-t", "nat", "-D", "OUTPUT", "-j", "IDSPOOF_SS").Run()
	exec.Command("iptables", "-t", "nat", "-F", "IDSPOOF_SS").Run()
	exec.Command("iptables", "-t", "nat", "-X", "IDSPOOF_SS").Run()
}

func (t *shadowsocksTunnel) Stop() error {
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

func (t *shadowsocksTunnel) Status() Status {
	t.mu.Lock()
	defer t.mu.Unlock()

	endpoint := "socks5://127.0.0.1:1080"
	if t.mode == ModeTransparent {
		endpoint = "transparent (iptables REDIRECT :1081)"
	}
	return Status{
		Running:  t.running,
		Protocol: "shadowsocks",
		Mode:     t.mode,
		Endpoint: endpoint,
		Details:  "Shadowsocks AEAD proxy — censorship evasion, looks like HTTPS",
	}
}
