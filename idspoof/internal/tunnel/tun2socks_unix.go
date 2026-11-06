//go:build unix

package tunnel

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

func (t *tun2socksTunnel) Start(mode Mode, cfg map[string]string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	confPath := cfg["config"]
	if confPath == "" {
		return fmt.Errorf("tun2socks requires --tunnel-config pointing to a YAML file (proxy, device, mtu, fwmark, tun-post-up, ...)")
	}

	// Validate up front so a bad config fails apply immediately instead of
	// a silently dead helper process.
	if _, err := ParseTun2socksConfig(confPath); err != nil {
		return fmt.Errorf("tun2socks: %w", err)
	}

	if running, _ := tun2socksAlive(); running {
		return fmt.Errorf("tun2socks: already running (stop it first)")
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("tun2socks: locating idspoof binary: %w", err)
	}

	logFile, err := os.OpenFile(tun2socksLogfile(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("tun2socks: opening log file: %w", err)
	}
	defer logFile.Close()

	cmd := exec.Command(exePath, "__tun2socks-run", confPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("tun2socks: starting helper: %w", err)
	}
	// Detach: don't wait on the child, and don't leave a zombie around —
	// reap it in the background whenever it eventually exits.
	go cmd.Wait()

	if err := os.WriteFile(tun2socksPidfile(), []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil {
		cmd.Process.Signal(syscall.SIGTERM)
		return fmt.Errorf("tun2socks: writing pidfile: %w", err)
	}

	// Give the helper a moment to either come up or die on a bad config
	// (e.g. device already in use, proxy unreachable at startup).
	time.Sleep(500 * time.Millisecond)
	if running, _ := tun2socksAlive(); !running {
		os.Remove(tun2socksPidfile())
		return fmt.Errorf("tun2socks: helper exited immediately — see %s", tun2socksLogfile())
	}

	return nil
}

func (t *tun2socksTunnel) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	pid, err := tun2socksReadPid()
	if err != nil {
		// Nothing to stop.
		return nil
	}

	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil && err != syscall.ESRCH {
		return fmt.Errorf("tun2socks: stopping helper (pid %d): %w", pid, err)
	}

	for i := 0; i < 20; i++ {
		if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	os.Remove(tun2socksPidfile())
	return nil
}

func (t *tun2socksTunnel) Status() Status {
	running, pid := tun2socksAlive()
	if !running {
		return Status{Running: false, Protocol: "tun2socks"}
	}
	return Status{
		Running:  true,
		Protocol: "tun2socks",
		Mode:     ModeTransparent,
		Endpoint: fmt.Sprintf("pid %d", pid),
		Details:  fmt.Sprintf("embedded tun2socks engine running as detached helper (pid %d) — log: %s", pid, tun2socksLogfile()),
	}
}

// tun2socksAlive reports whether the pidfile points at a live process.
// Signal 0 only checks existence/permission, it doesn't actually signal.
func tun2socksAlive() (bool, int) {
	pid, err := tun2socksReadPid()
	if err != nil {
		return false, 0
	}
	if err := syscall.Kill(pid, 0); err != nil {
		return false, 0
	}
	return true, pid
}
