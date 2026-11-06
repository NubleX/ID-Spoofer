// Package boot reads and writes the boot profile: what the idspoof daemon
// applies when the machine starts, before the network comes up.
package boot

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/NubleX/ID-Spoofer/idspoof/internal/profile"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/tunnel"
)

// DefaultPath is where the boot profile lives.
const DefaultPath = "/etc/idspoof/boot.yaml"

// Config is the boot profile. The zero value does nothing.
type Config struct {
	MAC     bool   `yaml:"mac"`
	Persona string `yaml:"persona"` // windows, macos, ios, linux, android, or "" for none
	SysInfo bool   `yaml:"sysinfo"`
	Tunnel  string `yaml:"tunnel"`  // key in tunnel.Registry, or ""
	Profile string `yaml:"profile"` // saved tunnel profile name
	Mode    string `yaml:"mode"`    // transparent or socks
}

var personas = map[string]bool{"windows": true, "macos": true, "ios": true, "linux": true, "android": true}

// Enabled reports whether the profile asks for anything.
func (c Config) Enabled() bool {
	return c.MAC || c.Persona != "" || c.SysInfo || c.Tunnel != ""
}

// Validate checks every field so a hand-edited file cannot start something
// the TUI would not have offered.
func (c Config) Validate() error {
	if c.Persona != "" && !personas[c.Persona] {
		return fmt.Errorf("persona %q is not one of windows, macos, ios, linux, android", c.Persona)
	}
	switch c.Mode {
	case "", string(tunnel.ModeTransparent), string(tunnel.ModeSocks):
	default:
		return fmt.Errorf("mode must be transparent or socks")
	}
	if c.Tunnel == "" {
		if c.Profile != "" {
			return fmt.Errorf("profile %q is set but no tunnel is chosen", c.Profile)
		}
		return nil
	}
	if _, ok := tunnel.Registry[c.Tunnel]; !ok {
		return fmt.Errorf("unknown tunnel %q", c.Tunnel)
	}
	if profile.NeedsConfig(c.Tunnel) && c.Profile == "" {
		return fmt.Errorf("tunnel %s needs a saved profile", c.Tunnel)
	}
	if c.Profile != "" && !profile.ValidName(c.Profile) {
		return fmt.Errorf("invalid profile name %q", c.Profile)
	}
	return nil
}

// Summary is a one-line description for the TUI.
func (c Config) Summary() string {
	if !c.Enabled() {
		return "nothing (daemon idles)"
	}
	var p []string
	if c.MAC {
		p = append(p, "MAC")
	}
	if c.Persona != "" {
		p = append(p, c.Persona+" persona")
	}
	if c.SysInfo {
		p = append(p, "sysinfo")
	}
	if c.Tunnel != "" {
		t := c.Tunnel
		if c.Profile != "" {
			t += " (" + c.Profile + ")"
		}
		p = append(p, t)
	}
	return strings.Join(p, " + ")
}

// Load reads and validates the file. A missing file is an empty config.
func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Config{}, nil
	}
	if err != nil {
		return Config{}, err
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && err.Error() != "EOF" {
		return Config{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Save validates and writes the file atomically with mode 0600.
func Save(path string, c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	raw, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append([]byte("# written by the idspoof TUI\n"), raw...), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Clear removes the boot profile.
func Clear(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
