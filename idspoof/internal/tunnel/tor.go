package tunnel

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type torTunnel struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	mode    Mode
	dataDir string
}

func (t *torTunnel) Name() string { return "Tor" }

func (t *torTunnel) Available() bool { return binaryExists("tor") }

func (t *torTunnel) Start(mode Mode, cfg map[string]string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.mode = mode
	t.dataDir, _ = os.MkdirTemp("", "idspoof-tor-*")

	// Build torrc.
	torrc := filepath.Join(t.dataDir, "torrc")
	socksPort := "9050"
	transPort := "9040"
	dnsPort := "5353"

	content := fmt.Sprintf(`SocksPort %s
Log notice file %s/tor.log
DataDirectory %s/data
`, socksPort, t.dataDir, t.dataDir)

	if mode == ModeTransparent {
		content += fmt.Sprintf(`TransPort %s
DNSPort %s
AutomapHostsOnResolve 1
`, transPort, dnsPort)
	}

	if err := os.WriteFile(torrc, []byte(content), 0o600); err != nil {
		return fmt.Errorf("writing torrc: %w", err)
	}
	os.MkdirAll(filepath.Join(t.dataDir, "data"), 0o700)

	// Start tor.
	t.cmd = exec.Command("tor", "-f", torrc)
	t.cmd.Stdout = nil
	t.cmd.Stderr = nil
	if err := t.cmd.Start(); err != nil {
		return fmt.Errorf("starting tor: %w", err)
	}

	// Wait for Tor to bootstrap by polling the SOCKS port.
	// Tor typically takes 15-60 seconds to build a circuit.
	if err := waitForPort("127.0.0.1:"+socksPort, 90*time.Second); err != nil {
		t.cmd.Process.Kill()
		return fmt.Errorf("tor did not become ready within 90s: %w", err)
	}

	// Set up iptables for transparent mode.
	if mode == ModeTransparent {
		if err := t.setupTransparent(transPort, dnsPort); err != nil {
			t.cmd.Process.Kill()
			return fmt.Errorf("iptables setup: %w", err)
		}
	}

	return nil
}

func (t *torTunnel) setupTransparent(transPort, dnsPort string) error {
	rules := [][]string{
		{"-t", "nat", "-N", "IDSPOOF_TOR"},
		// Don't redirect local traffic.
		{"-t", "nat", "-A", "IDSPOOF_TOR", "-d", "127.0.0.0/8", "-j", "RETURN"},
		// Redirect DNS to Tor's DNS port.
		{"-t", "nat", "-A", "IDSPOOF_TOR", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", dnsPort},
		// Redirect TCP to Tor's TransPort.
		{"-t", "nat", "-A", "IDSPOOF_TOR", "-p", "tcp", "-j", "REDIRECT", "--to-ports", transPort},
		// Jump from OUTPUT.
		{"-t", "nat", "-A", "OUTPUT", "-j", "IDSPOOF_TOR"},
	}
	for _, r := range rules {
		exec.Command("iptables", r...).Run()
	}

	// Add per-user RETURN rules to prevent tor's own traffic from looping.
	// The tor daemon user varies by distro: debian-tor (Debian/Ubuntu),
	// tor (Arch/Fedora/Alpine), _tor (some BSD-derived distros).
	for _, u := range torUsers() {
		exec.Command("iptables", "-t", "nat", "-I", "IDSPOOF_TOR", "1",
			"-m", "owner", "--uid-owner", u, "-j", "RETURN").Run()
	}

	return nil
}

// torUsers returns all tor daemon usernames found in /etc/passwd.
// Tor packages use different usernames depending on the distribution.
func torUsers() []string {
	candidates := []string{"debian-tor", "tor", "_tor"}
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return candidates // fall back to trying all known names
	}
	defer f.Close()

	var found []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		for _, u := range candidates {
			if strings.HasPrefix(line, u+":") {
				found = append(found, u)
				break
			}
		}
	}
	if len(found) == 0 {
		return candidates
	}
	return found
}

func (t *torTunnel) removeTransparent() {
	exec.Command("iptables", "-t", "nat", "-D", "OUTPUT", "-j", "IDSPOOF_TOR").Run()
	exec.Command("iptables", "-t", "nat", "-F", "IDSPOOF_TOR").Run()
	exec.Command("iptables", "-t", "nat", "-X", "IDSPOOF_TOR").Run()
}

func (t *torTunnel) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.mode == ModeTransparent {
		t.removeTransparent()
	}

	if t.cmd != nil && t.cmd.Process != nil {
		t.cmd.Process.Kill()
		t.cmd.Wait()
	}

	if t.dataDir != "" {
		os.RemoveAll(t.dataDir)
	}

	return nil
}

func (t *torTunnel) Status() Status {
	t.mu.Lock()
	defer t.mu.Unlock()

	running := t.cmd != nil && t.cmd.Process != nil
	endpoint := "socks5://127.0.0.1:9050"
	if t.mode == ModeTransparent {
		endpoint = "transparent (iptables REDIRECT)"
	}
	return Status{
		Running:  running,
		Protocol: "tor",
		Mode:     t.mode,
		Endpoint: endpoint,
		Details:  "Tor anonymity network — 3-hop onion routing",
	}
}
