package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRenderTun2socksDefaults(t *testing.T) {
	out, err := RenderTun2socks(Tun2socksForm{Proxy: "socks5://127.0.0.1:10880"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := yaml.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("output is not valid YAML: %v", err)
	}
	if m["proxy"] != "socks5://127.0.0.1:10880" || m["device"] != "tun2socks0" || m["mtu"] != 1500 {
		t.Errorf("unexpected defaults: %v", m)
	}
	if m["fwmark"] != 0x2323 {
		t.Errorf("fwmark = %v; want %d", m["fwmark"], 0x2323)
	}
	if up, _ := m["tun-post-up"].(string); !strings.HasPrefix(up, "sh -c '") || strings.Contains(up, "iptables") {
		t.Errorf("post-up without pivot should only address the device: %q", up)
	}
}

func TestRenderTun2socksPivot(t *testing.T) {
	out, err := RenderTun2socks(Tun2socksForm{Proxy: "socks5://127.0.0.1:1", PivotUser: "pivot"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--uid-owner pivot", "--set-mark 0x2324", "ip rule add fwmark 0x2324 table 100"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestRenderTun2socksRejectsInjection(t *testing.T) {
	bad := []Tun2socksForm{
		{Proxy: "socks5://127.0.0.1:1", Device: "tun0; reboot"},
		{Proxy: "socks5://127.0.0.1:1", Device: "tun0' && id #"},
		{Proxy: "socks5://127.0.0.1:1", PivotUser: "x; rm -rf /"},
		{Proxy: "socks5://127.0.0.1:1", PivotUser: "a b"},
		{Proxy: "socks5://127.0.0.1:1", Mark: "0x2323; id"},
		{Proxy: "socks5://127.0.0.1:1", Mark: "9"},
		{Proxy: "file:///etc/passwd"},
		{Proxy: "socks5://"},
		{Proxy: "socks5://host:1 --evil"},
		{Proxy: "socks5://127.0.0.1:1", MTU: 100},
	}
	for i, f := range bad {
		if _, err := RenderTun2socks(f); err == nil {
			t.Errorf("case %d accepted: %+v", i, f)
		}
	}
}

func TestStoreRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "profiles")
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := RenderTun2socks(Tun2socksForm{Proxy: "socks5://127.0.0.1:1"})
	p, err := s.Save(Profile{Name: "lab", Tunnel: "tun2socks"}, body)
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode != "transparent" || p.ConfigPath == "" {
		t.Errorf("defaults not applied: %+v", p)
	}
	if fi, err := os.Stat(p.ConfigPath); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("config file mode: %v %v", fi, err)
	}
	list, err := s.List()
	if err != nil || len(list) != 1 || list[0].Name != "lab" || list[0].ConfigPath != p.ConfigPath {
		t.Fatalf("List() = %+v, %v", list, err)
	}
	if err := s.Delete("lab"); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.List(); len(list) != 0 {
		t.Errorf("profile still listed after delete: %+v", list)
	}
}

func TestSaveRejectsBadInput(t *testing.T) {
	s, _ := NewStore(t.TempDir())
	cases := []struct {
		name string
		p    Profile
		body string
	}{
		{"path traversal name", Profile{Name: "../evil", Tunnel: "tun2socks"}, "proxy: socks5://x:1"},
		{"upper-case name", Profile{Name: "Lab", Tunnel: "tun2socks"}, "proxy: socks5://x:1"},
		{"unknown tunnel", Profile{Name: "a", Tunnel: "nope"}, "x"},
		{"bad mode", Profile{Name: "a", Tunnel: "tun2socks", Mode: "weird"}, "proxy: socks5://x:1"},
		{"empty body", Profile{Name: "a", Tunnel: "tun2socks"}, "  \n"},
		{"tun2socks without proxy", Profile{Name: "a", Tunnel: "tun2socks"}, "device: tun0"},
		{"wireguard without interface", Profile{Name: "a", Tunnel: "wireguard"}, "[Peer]\nPublicKey=x"},
		{"shadowsocks bad json", Profile{Name: "a", Tunnel: "shadowsocks"}, "{not json"},
		{"NUL byte", Profile{Name: "a", Tunnel: "quic"}, "a: b\x00"},
		{"too large", Profile{Name: "a", Tunnel: "quic"}, strings.Repeat("a: b\n", MaxBody)},
	}
	for _, c := range cases {
		if _, err := s.Save(c.p, c.body); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
	if list, _ := s.List(); len(list) != 0 {
		t.Errorf("rejected input left profiles behind: %+v", list)
	}
}
