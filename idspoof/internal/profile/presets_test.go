package profile

import (
	"encoding/base64"
	"strings"
	"testing"
)

var testKey = base64.StdEncoding.EncodeToString(make([]byte, 32))

// sampleValues returns plausible answers for every field of a preset.
func sampleValues(p Preset) map[string]string {
	v := map[string]string{}
	for _, f := range p.Fields {
		switch f.Key {
		case "password", "auth":
			v[f.Key] = "s3cret"
		case "host", "server":
			v[f.Key] = "example.org"
		case "privkey", "pubkey":
			v[f.Key] = testKey
		case "endpoint":
			v[f.Key] = "192.0.2.1:51820"
		}
	}
	if p.ID == "hy2-client" {
		v["server"] = "example.org:443"
	}
	return v
}

func TestEveryPresetRendersAndValidates(t *testing.T) {
	for _, p := range allPresets() {
		body, err := p.Render(sampleValues(p))
		if err != nil {
			t.Errorf("%s: %v", p.ID, err)
			continue
		}
		for _, tun := range p.Tunnels {
			if err := ValidateBody(tun, body); err != nil {
				t.Errorf("%s as %s: rendered config rejected: %v\n%s", p.ID, tun, err, body)
			}
		}
	}
}

func TestPresetsForCoversTunnels(t *testing.T) {
	for _, tun := range []string{"tun2socks", "wireguard", "lwo", "shadowsocks", "quic", "tor-over-vpn", "vpn-over-tor"} {
		if len(PresetsFor(tun)) == 0 {
			t.Errorf("no preset for %s", tun)
		}
	}
	for _, tun := range []string{"tor", "i2p"} {
		if len(PresetsFor(tun)) != 0 {
			t.Errorf("%s needs no config but has presets", tun)
		}
	}
	if n := len(PresetsFor("tun2socks")); n < 6 {
		t.Errorf("tun2socks has %d presets; want a range", n)
	}
}

func TestNoPresetFieldAcceptsNewlineInjection(t *testing.T) {
	for _, p := range allPresets() {
		for _, f := range p.Fields {
			v := sampleValues(p)
			v[f.Key] = "x\nPostUp = reboot"
			if _, err := p.Render(v); err == nil {
				t.Errorf("%s: field %s accepted a newline", p.ID, f.Key)
			}
		}
	}
}

func TestWireGuardPresetRejectsBadInput(t *testing.T) {
	var wg Preset
	for _, p := range allPresets() {
		if p.ID == "wg-client" {
			wg = p
		}
	}
	base := sampleValues(wg)
	base["address"] = "10.0.0.2/32"
	bad := map[string]string{
		"privkey":   "not-a-key",
		"pubkey":    testKey[:20],
		"address":   "10.0.0.2",
		"allowed":   "everything",
		"dns":       "dns.example",
		"endpoint":  "no-port",
		"keepalive": "9999",
	}
	for k, val := range bad {
		v := map[string]string{}
		for kk, vv := range base {
			v[kk] = vv
		}
		v[k] = val
		if _, err := wg.Render(v); err == nil {
			t.Errorf("%s=%q accepted", k, val)
		}
	}
	body, err := wg.Render(base)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, "PostUp") || !strings.Contains(body, "PersistentKeepalive = 25") {
		t.Errorf("unexpected body:\n%s", body)
	}
}

func TestShadowsocksPresetRejectsUnknownCipher(t *testing.T) {
	for _, id := range []string{"ss-local", "t2s-ss"} {
		for _, p := range allPresets() {
			if p.ID != id {
				continue
			}
			v := sampleValues(p)
			v["method"] = "rot13"
			if _, err := p.Render(v); err == nil {
				t.Errorf("%s accepted an unknown cipher", id)
			}
		}
	}
}

func TestRequiredFieldMissing(t *testing.T) {
	for _, p := range allPresets() {
		for _, f := range p.Fields {
			if f.Optional || f.Default != "" {
				continue
			}
			v := sampleValues(p)
			delete(v, f.Key)
			if _, err := p.Render(v); err == nil {
				t.Errorf("%s: missing %s accepted", p.ID, f.Key)
			}
		}
	}
}
