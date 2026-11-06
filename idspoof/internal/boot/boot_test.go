package boot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "etc", "boot.yaml")
	want := Config{MAC: true, Persona: "linux", Tunnel: "tun2socks", Profile: "lab", Mode: "transparent"}
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode: %v %v", fi, err)
	}
	got, err := Load(path)
	if err != nil || got != want {
		t.Fatalf("Load = %+v, %v; want %+v", got, err, want)
	}
	if err := Clear(path); err != nil {
		t.Fatal(err)
	}
	if got, err := Load(path); err != nil || got.Enabled() {
		t.Errorf("after Clear: %+v, %v", got, err)
	}
	if err := Clear(path); err != nil {
		t.Errorf("Clear of a missing file should succeed: %v", err)
	}
}

func TestMissingAndEmptyFileDoNothing(t *testing.T) {
	dir := t.TempDir()
	if c, err := Load(filepath.Join(dir, "none.yaml")); err != nil || c.Enabled() {
		t.Errorf("missing file: %+v, %v", c, err)
	}
	empty := filepath.Join(dir, "empty.yaml")
	os.WriteFile(empty, []byte("# nothing\n"), 0o600)
	if c, err := Load(empty); err != nil || c.Enabled() {
		t.Errorf("empty file: %+v, %v", c, err)
	}
}

func TestValidateRejects(t *testing.T) {
	bad := []Config{
		{Persona: "beos"},
		{Mode: "weird"},
		{Tunnel: "nope"},
		{Tunnel: "tun2socks"}, // needs a profile
		{Tunnel: "tun2socks", Profile: "../etc/passwd"}, // path traversal
		{Profile: "lab"}, // profile without tunnel
	}
	for i, c := range bad {
		if c.Validate() == nil {
			t.Errorf("case %d accepted: %+v", i, c)
		}
	}
	for _, c := range []Config{{}, {MAC: true}, {Tunnel: "tor"}, {Tunnel: "tun2socks", Profile: "lab"}} {
		if err := c.Validate(); err != nil {
			t.Errorf("%+v rejected: %v", c, err)
		}
	}
}

func TestLoadRejectsUnknownKeysAndBadValues(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"unknown key": "mac: true\nrun_as: root\n",
		"bad persona": "persona: beos\n",
		"not yaml":    "mac: [unclosed\n",
	} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".yaml")
		os.WriteFile(p, []byte(body), 0o600)
		if _, err := Load(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSummary(t *testing.T) {
	if s := (Config{}).Summary(); !strings.Contains(s, "nothing") {
		t.Errorf("empty summary = %q", s)
	}
	s := Config{MAC: true, Persona: "linux", Tunnel: "tun2socks", Profile: "lab"}.Summary()
	for _, w := range []string{"MAC", "linux persona", "tun2socks (lab)"} {
		if !strings.Contains(s, w) {
			t.Errorf("summary %q missing %q", s, w)
		}
	}
}
