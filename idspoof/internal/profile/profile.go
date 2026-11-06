// Package profile stores named tunnel profiles (protocol, mode and a rendered
// config file) so the TUI can create, pick and test them without the user
// editing files by hand.
//
// Everything here runs as root and its output is later executed by tunnel
// engines, so every value that reaches a shell command or a config file is
// validated against a strict allow-list first.
package profile

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/NubleX/ID-Spoofer/idspoof/internal/tunnel"
)

// MaxBody caps a pasted or generated config file.
const MaxBody = 64 << 10

var (
	nameRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,47}$`)
	deviceRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,14}$`)
	userRe   = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	markRe   = regexp.MustCompile(`^0x[0-9a-fA-F]{1,7}$`)
)

// Profile is one saved tunnel setup.
type Profile struct {
	Name   string `yaml:"name"`
	Tunnel string `yaml:"tunnel"` // key in tunnel.Registry
	Mode   string `yaml:"mode"`   // "transparent" or "socks"
	// ConfigPath is the absolute path of the rendered config file. It is
	// derived by the store and never read from disk.
	ConfigPath string `yaml:"-"`
}

// Store keeps profiles as files in one directory (mode 0700).
type Store struct{ dir string }

// NewStore creates the directory if needed.
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating profile dir: %w", err)
	}
	return &Store{dir: dir}, nil
}

// NeedsConfig reports whether a tunnel cannot start without a config file.
func NeedsConfig(tunnelName string) bool { return tunnelName != "tor" && tunnelName != "i2p" }

// ValidName reports whether s is an acceptable profile name.
func ValidName(s string) bool { return nameRe.MatchString(s) }

func ext(tunnelName string) string {
	switch tunnelName {
	case "wireguard", "lwo", "tor-over-vpn", "vpn-over-tor":
		return "conf"
	case "shadowsocks":
		return "json"
	default:
		return "yaml"
	}
}

func (s *Store) metaPath(name string) string { return filepath.Join(s.dir, name+".profile.yaml") }
func (s *Store) bodyPath(name, tun string) string {
	return filepath.Join(s.dir, name+"."+ext(tun))
}

// List returns all profiles sorted by name. Entries whose config file is
// missing or whose metadata is invalid are skipped.
func (s *Store) List() ([]Profile, error) {
	metas, err := filepath.Glob(filepath.Join(s.dir, "*.profile.yaml"))
	if err != nil {
		return nil, err
	}
	var out []Profile
	for _, m := range metas {
		raw, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		var p Profile
		if yaml.Unmarshal(raw, &p) != nil || !ValidName(p.Name) {
			continue
		}
		if _, ok := tunnel.Registry[p.Tunnel]; !ok {
			continue
		}
		p.ConfigPath = s.bodyPath(p.Name, p.Tunnel)
		if _, err := os.Stat(p.ConfigPath); err != nil {
			continue
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Save validates and writes a profile and its config body.
func (s *Store) Save(p Profile, body string) (Profile, error) {
	if !ValidName(p.Name) {
		return Profile{}, fmt.Errorf("name must be 1-48 chars of a-z 0-9 . _ - and start with a letter or digit")
	}
	if _, ok := tunnel.Registry[p.Tunnel]; !ok {
		return Profile{}, fmt.Errorf("unknown tunnel %q", p.Tunnel)
	}
	switch p.Mode {
	case "":
		p.Mode = string(tunnel.ModeTransparent)
	case string(tunnel.ModeTransparent), string(tunnel.ModeSocks):
	default:
		return Profile{}, fmt.Errorf("mode must be transparent or socks")
	}
	if err := ValidateBody(p.Tunnel, body); err != nil {
		return Profile{}, err
	}

	meta, err := yaml.Marshal(p)
	if err != nil {
		return Profile{}, err
	}
	p.ConfigPath = s.bodyPath(p.Name, p.Tunnel)
	if err := writeAtomic(p.ConfigPath, []byte(body)); err != nil {
		return Profile{}, err
	}
	if err := writeAtomic(s.metaPath(p.Name), meta); err != nil {
		return Profile{}, err
	}
	return p, nil
}

// Delete removes a profile and its config file.
func (s *Store) Delete(name string) error {
	if !ValidName(name) {
		return fmt.Errorf("invalid profile name")
	}
	raw, err := os.ReadFile(s.metaPath(name))
	if err != nil {
		return err
	}
	var p Profile
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return err
	}
	os.Remove(s.bodyPath(name, p.Tunnel))
	return os.Remove(s.metaPath(name))
}

// SetMode changes the saved routing mode of an existing profile.
func (s *Store) SetMode(name, mode string) error {
	if !ValidName(name) {
		return fmt.Errorf("invalid profile name")
	}
	if mode != string(tunnel.ModeTransparent) && mode != string(tunnel.ModeSocks) {
		return fmt.Errorf("mode must be transparent or socks")
	}
	raw, err := os.ReadFile(s.metaPath(name))
	if err != nil {
		return err
	}
	var p Profile
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return err
	}
	p.Mode = mode
	meta, err := yaml.Marshal(p)
	if err != nil {
		return err
	}
	return writeAtomic(s.metaPath(name), meta)
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ValidateBody sanity-checks a config body for the given tunnel. It cannot
// prove the config works, only that it is the right shape and size.
func ValidateBody(tunnelName, body string) error {
	if strings.TrimSpace(body) == "" {
		return fmt.Errorf("config is empty")
	}
	if len(body) > MaxBody {
		return fmt.Errorf("config larger than %d KiB", MaxBody>>10)
	}
	if strings.ContainsRune(body, 0) {
		return fmt.Errorf("config contains a NUL byte")
	}
	switch ext(tunnelName) {
	case "conf":
		if !strings.Contains(body, "[Interface]") {
			return fmt.Errorf("WireGuard config needs an [Interface] section")
		}
	case "json":
		if !json.Valid([]byte(body)) {
			return fmt.Errorf("config is not valid JSON")
		}
	default:
		var m map[string]any
		if err := yaml.Unmarshal([]byte(body), &m); err != nil {
			return fmt.Errorf("config is not valid YAML: %w", err)
		}
		if tunnelName == "tun2socks" {
			if p, _ := m["proxy"].(string); strings.TrimSpace(p) == "" {
				return fmt.Errorf("tun2socks config needs a 'proxy' key")
			}
		}
	}
	return nil
}

// Tun2socksForm holds the fields of the TUI's tun2socks form.
type Tun2socksForm struct {
	Proxy     string // socks5://host:port, http://..., ss://..., ...
	Device    string // default tun2socks0
	MTU       int    // default 1500
	Mark      string // engine's own fwmark, hex, default 0x2323
	PivotUser string // optional: route this user's traffic into the TUN
}

// RenderTun2socks validates the form and returns the YAML config. Every
// value interpolated into the post-up shell command is validated first
// because the command runs as root.
func RenderTun2socks(f Tun2socksForm) (string, error) {
	f.Proxy = strings.TrimSpace(f.Proxy)
	u, err := url.Parse(f.Proxy)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("proxy must look like socks5://127.0.0.1:1080")
	}
	switch u.Scheme {
	case "socks5", "socks4", "http", "ss", "relay":
	default:
		return "", fmt.Errorf("proxy scheme must be socks5, socks4, http, ss or relay")
	}
	if strings.ContainsAny(f.Proxy, " \t\r\n\x00") {
		return "", fmt.Errorf("proxy must not contain whitespace")
	}
	if f.Device == "" {
		f.Device = "tun2socks0"
	}
	if !deviceRe.MatchString(f.Device) {
		return "", fmt.Errorf("device must be 1-15 chars: letters, digits, _ -, starting with a letter")
	}
	if f.MTU == 0 {
		f.MTU = 1500
	}
	if f.MTU < 576 || f.MTU > 9000 {
		return "", fmt.Errorf("MTU must be between 576 and 9000")
	}
	if f.Mark == "" {
		f.Mark = "0x2323"
	}
	if !markRe.MatchString(f.Mark) {
		return "", fmt.Errorf("mark must be hex like 0x2323 (up to 7 digits)")
	}
	mark, _ := strconv.ParseUint(f.Mark[2:], 16, 32)

	postUp := fmt.Sprintf("ip addr add 198.18.0.1/15 dev %s && ip link set %s up", f.Device, f.Device)
	if f.PivotUser != "" {
		if !userRe.MatchString(f.PivotUser) {
			return "", fmt.Errorf("pivot user must be a plain unix user name")
		}
		pm := fmt.Sprintf("0x%x", mark+1)
		postUp += fmt.Sprintf(
			" && ip route add default dev %s table 100"+
				" && iptables -t mangle -A OUTPUT -m owner --uid-owner %s -j MARK --set-mark %s"+
				" && ip rule add fwmark %s table 100",
			f.Device, f.PivotUser, pm, pm)
	}

	out := struct {
		Proxy    string `yaml:"proxy"`
		Device   string `yaml:"device"`
		MTU      int    `yaml:"mtu"`
		Mark     int    `yaml:"fwmark"`
		PostUp   string `yaml:"tun-post-up"`
		LogLevel string `yaml:"loglevel"`
	}{f.Proxy, f.Device, f.MTU, int(mark), "sh -c '" + postUp + "'", "info"}

	raw, err := yaml.Marshal(out)
	if err != nil {
		return "", err
	}
	return "# generated by the idspoof TUI\n" + string(raw), nil
}
