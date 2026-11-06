package netrecon

import (
	"encoding/json"
	"testing"
)

func TestParseSSLine(t *testing.T) {
	cases := []struct {
		name, line, proto string
		wantProto         string
		wantAddr          string
		wantPID           int
		wantProc          string
	}{
		{
			name:      "tcp single-type, no Netid column",
			line:      `LISTEN 0 4096 127.0.0.1:631 0.0.0.0:* users:(("cupsd",pid=812,fd=7))`,
			proto:     "tcp",
			wantProto: "tcp", wantAddr: "127.0.0.1:631", wantPID: 812, wantProc: "cupsd",
		},
		{
			name:      "udp single-type, no Netid column",
			line:      `UNCONN 0 0 0.0.0.0:52829 0.0.0.0:* users:(("python3",pid=49212,fd=3))`,
			proto:     "udp",
			wantProto: "udp", wantAddr: "0.0.0.0:52829", wantPID: 49212, wantProc: "python3",
		},
		{
			name:      "with Netid column",
			line:      `tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))`,
			proto:     "tcp",
			wantProto: "tcp", wantAddr: "0.0.0.0:22", wantPID: 1, wantProc: "sshd",
		},
		{
			name:      "ipv6 listener, no process info",
			line:      `LISTEN 0 128 [::]:443 [::]:*`,
			proto:     "tcp",
			wantProto: "tcp6", wantAddr: "[::]:443",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseSSLine(c.line, c.proto)
			if got.Protocol != c.wantProto || got.Address != c.wantAddr ||
				got.PID != c.wantPID || got.Process != c.wantProc {
				t.Errorf("parseSSLine() = %+v; want proto=%s addr=%s pid=%d proc=%s",
					got, c.wantProto, c.wantAddr, c.wantPID, c.wantProc)
			}
		})
	}
}

func TestIPRuleCatchAll(t *testing.T) {
	// Real `ip -j rule show` output on a Mullvad host: the negation flag is
	// printed as "not":null.
	const sample = `[{"priority":0,"src":"all","table":"local"},
{"priority":32764,"src":"all","table":"main","suppress_prefixlen":0},
{"priority":32765,"not":null,"src":"all","fwmark":"0x6d6f6c65","table":"1836018789"},
{"priority":32766,"src":"all","table":"main"},
{"priority":32767,"src":"all","table":"default"},
{"priority":100,"src":"all","fwmark":"0x2324","table":"100"},
{"priority":200,"src":"all","table":"777"}]`
	var rules []ipRule
	if err := json.Unmarshal([]byte(sample), &rules); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"local": false, "main": false, "default": false,
		"1836018789": true,  // inverted fwmark: VPN default
		"100":        false, // mark-only pivot rule
		"777":        true,  // unconditional rule ahead of main
	}
	for _, r := range rules {
		if got := r.catchAll(); got != want[r.Table] {
			t.Errorf("table %s: catchAll() = %v; want %v", r.Table, got, want[r.Table])
		}
	}
}
