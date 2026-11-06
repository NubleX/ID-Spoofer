package tunnel

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/NubleX/ID-Spoofer/idspoof/internal/config"
	"github.com/xjasonlyu/tun2socks/v2/engine"
	"gopkg.in/yaml.v3"
)

// tun2socksTunnel embeds the tun2socks Go engine instead of shelling out to
// an external `tun2socks` binary. The engine's own device layer already
// abstracts the TUN driver per OS (tun0 on Linux, utun on macOS, wintun on
// Windows), so this integration needs no per-platform build tags for engine
// configuration — unlike internal/netident, which talks to raw kernel
// interfaces directly.
//
// It bridges a TUN device to a SOCKS5/HTTP/Shadowsocks/SSH proxy, so tools
// that need raw sockets (nmap -O, custom frame crafting) get packets through
// a proxy without the kernel's normal socket-layer restrictions getting in
// the way — see GitHub issues #28 and #30.
//
// Unlike wireguard (kernel-resident after wg-quick exits) or tor/shadowsocks
// (orphaned child process), the engine's TUN<->proxy bridge runs as
// goroutines that die the moment this process exits. So Start re-execs the
// idspoof binary as a detached helper (`idspoof __tun2socks-run`), the same
// way the other tunnels outlive a one-shot `idspoof apply` invocation — and
// tracks it with a pidfile so Stop/Status work from a separate later
// invocation (e.g. `idspoof restore`), not just within the same process.
// Process detachment and signalling are OS-specific: see
// tun2socks_unix.go / tun2socks_windows.go.
type tun2socksTunnel struct {
	mu sync.Mutex
}

func (t *tun2socksTunnel) Name() string { return "tun2socks" }

// Available is always true: tun2socks is compiled into this binary, not an
// external dependency that has to exist in PATH.
func (t *tun2socksTunnel) Available() bool { return true }

func tun2socksPidfile() string {
	return filepath.Join(config.DefaultStateDir, "tun2socks.pid")
}

func tun2socksLogfile() string {
	return filepath.Join(config.DefaultStateDir, "tun2socks.log")
}

// LogTail returns up to n trailing lines of the named tunnel's log file, or
// nil if that tunnel writes none or the file cannot be read. Only the last
// 64 KiB are read so a long-lived log stays cheap.
func LogTail(proto string, n int) []string {
	if proto != "tun2socks" || n <= 0 {
		return nil
	}
	f, err := os.Open(tun2socksLogfile())
	if err != nil {
		return nil
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil
	}
	const window = 64 << 10
	off := int64(0)
	if fi.Size() > window {
		off = fi.Size() - window
	}
	buf := make([]byte, fi.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && len(buf) > 0 {
		return nil
	}
	lines := strings.Split(strings.TrimRight(string(buf), "\n"), "\n")
	if off > 0 && len(lines) > 0 {
		lines = lines[1:] // first line is likely cut mid-way
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}

// ParseTun2socksConfig loads a YAML file into an engine.Key, applying the
// same defaults the CLI's --tunnel-config flag documents. Exported so the
// hidden `__tun2socks-run` helper command parses the file identically to
// how Start validates it.
func ParseTun2socksConfig(path string) (*engine.Key, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	key := &engine.Key{
		MTU:      1500,
		Device:   "tun2socks0",
		LogLevel: "warning",
	}
	if err := yaml.Unmarshal(raw, key); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	if key.Proxy == "" {
		return nil, fmt.Errorf("config %s is missing required key 'proxy'", path)
	}
	return key, nil
}

func tun2socksReadPid() (int, error) {
	raw, err := os.ReadFile(tun2socksPidfile())
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return 0, fmt.Errorf("corrupt pidfile: %w", err)
	}
	return pid, nil
}
