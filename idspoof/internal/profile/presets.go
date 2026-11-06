package profile

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Field is one input of a preset form.
type Field struct {
	Key     string
	Label   string
	Default string
	Secret  bool // masked in the TUI
	// Gen names a generator the TUI can run for this field: "wgkey",
	// "sskey" or "password".
	Gen      string
	Optional bool
}

// Preset is a ready-made profile template: the TUI shows its fields as a
// form and Render turns the answers into a validated config body.
type Preset struct {
	ID      string
	Title   string
	Desc    string
	Tunnels []string // tunnels this preset can be saved for
	Fields  []Field
	Render  func(vals map[string]string) (string, error)
}

var hostRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

var ssMethods = map[string]bool{
	"chacha20-ietf-poly1305":        true,
	"aes-128-gcm":                   true,
	"aes-256-gcm":                   true,
	"2022-blake3-aes-128-gcm":       true,
	"2022-blake3-aes-256-gcm":       true,
	"2022-blake3-chacha20-poly1305": true,
}

// PresetsFor returns the presets that can be saved for a tunnel, in menu order.
func PresetsFor(tunnelName string) []Preset {
	var out []Preset
	for _, p := range allPresets() {
		for _, t := range p.Tunnels {
			if t == tunnelName {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

// checkValues rejects missing required fields and any value that could break
// out of its line in a config file (newline injection, e.g. a PostUp= line
// in a WireGuard config that wg-quick would run as root).
func checkValues(fields []Field, vals map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(fields))
	for _, f := range fields {
		v := strings.TrimSpace(vals[f.Key])
		if strings.ContainsAny(v, "\r\n\x00") {
			return nil, fmt.Errorf("%s must be a single line", f.Label)
		}
		if v == "" {
			v = f.Default
		}
		if v == "" && !f.Optional {
			return nil, fmt.Errorf("%s is required", f.Label)
		}
		out[f.Key] = v
	}
	return out, nil
}

func validHostPort(hp string) (string, int, error) {
	host, ps, err := net.SplitHostPort(hp)
	if err != nil {
		return "", 0, fmt.Errorf("%q must look like host:port", hp)
	}
	port, err := strconv.Atoi(ps)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("port in %q must be 1-65535", hp)
	}
	if net.ParseIP(host) == nil && !hostRe.MatchString(host) {
		return "", 0, fmt.Errorf("host in %q is not valid", hp)
	}
	return host, port, nil
}

func t2sAdvanced() []Field {
	return []Field{
		{Key: "device", Label: "TUN device", Default: "tun2socks0"},
		{Key: "mtu", Label: "MTU", Default: "1500"},
		{Key: "mark", Label: "Fwmark (hex)", Default: "0x2323"},
		{Key: "pivot", Label: "Pivot user (optional)", Optional: true},
	}
}

func t2sPreset(id, title, desc, proxy string) Preset {
	fields := append([]Field{{Key: "proxy", Label: "Proxy URL", Default: proxy}}, t2sAdvanced()...)
	return Preset{
		ID: id, Title: title, Desc: desc, Tunnels: []string{"tun2socks"}, Fields: fields,
		Render: func(v map[string]string) (string, error) { return renderT2S(fields, v) },
	}
}

func renderT2S(fields []Field, vals map[string]string) (string, error) {
	v, err := checkValues(fields, vals)
	if err != nil {
		return "", err
	}
	mtu, err := strconv.Atoi(v["mtu"])
	if err != nil {
		return "", fmt.Errorf("MTU must be a number")
	}
	return RenderTun2socks(Tun2socksForm{
		Proxy: v["proxy"], Device: v["device"], MTU: mtu, Mark: v["mark"], PivotUser: v["pivot"],
	})
}

func allPresets() []Preset {
	var ps []Preset

	ps = append(ps,
		t2sPreset("t2s-socks", "SOCKS5 proxy (custom)",
			"Any SOCKS5 server you run or reach.", "socks5://127.0.0.1:1080"),
		t2sPreset("t2s-mullvad", "Mullvad SOCKS5 (inside the tunnel)",
			"Mullvad's proxy at 10.64.0.1:1080, reachable only while connected.", "socks5://10.64.0.1:1080"),
		t2sPreset("t2s-tor", "Tor SOCKS",
			"The local Tor client (needs tor running).", "socks5://127.0.0.1:9050"),
		t2sPreset("t2s-ssh", "SSH dynamic forward",
			"After: ssh -D 10880 -N user@host", "socks5://127.0.0.1:10880"),
		t2sPreset("t2s-i2p", "I2P SOCKS",
			"The local i2pd SOCKS proxy (needs i2pd running).", "socks5://127.0.0.1:4447"),
		t2sPreset("t2s-http", "HTTP proxy",
			"A plain HTTP CONNECT proxy.", "http://127.0.0.1:8080"),
	)

	ssFields := []Field{
		{Key: "method", Label: "Cipher", Default: "chacha20-ietf-poly1305"},
		{Key: "password", Label: "Password", Secret: true, Gen: "sskey"},
		{Key: "host", Label: "Server host"},
		{Key: "port", Label: "Server port", Default: "8388"},
	}
	ps = append(ps, Preset{
		ID: "t2s-ss", Title: "Shadowsocks server (ss:// URL)",
		Desc:    "tun2socks speaks Shadowsocks itself, no sslocal needed.",
		Tunnels: []string{"tun2socks"},
		Fields:  append(append([]Field{}, ssFields...), t2sAdvanced()...),
		Render: func(vals map[string]string) (string, error) {
			all := append(append([]Field{}, ssFields...), t2sAdvanced()...)
			v, err := checkValues(all, vals)
			if err != nil {
				return "", err
			}
			if !ssMethods[v["method"]] {
				return "", fmt.Errorf("unsupported cipher %q", v["method"])
			}
			port, err := strconv.Atoi(v["port"])
			if err != nil || port < 1 || port > 65535 {
				return "", fmt.Errorf("server port must be 1-65535")
			}
			if net.ParseIP(v["host"]) == nil && !hostRe.MatchString(v["host"]) {
				return "", fmt.Errorf("server host is not valid")
			}
			u := url.URL{Scheme: "ss", User: url.UserPassword(v["method"], v["password"]),
				Host: net.JoinHostPort(v["host"], v["port"])}
			vals2 := map[string]string{"proxy": u.String(), "device": v["device"], "mtu": v["mtu"], "mark": v["mark"], "pivot": v["pivot"]}
			return renderT2S(append([]Field{{Key: "proxy", Label: "Proxy URL"}}, t2sAdvanced()...), vals2)
		},
	})

	wgFields := []Field{
		{Key: "address", Label: "Interface address", Default: "10.0.0.2/32"},
		{Key: "privkey", Label: "Private key", Secret: true, Gen: "wgkey"},
		{Key: "dns", Label: "DNS (optional)", Optional: true},
		{Key: "pubkey", Label: "Peer public key"},
		{Key: "endpoint", Label: "Peer endpoint host:port"},
		{Key: "allowed", Label: "Allowed IPs", Default: "0.0.0.0/0, ::/0"},
		{Key: "keepalive", Label: "Keepalive seconds", Default: "25"},
	}
	ps = append(ps, Preset{
		ID: "wg-client", Title: "WireGuard client",
		Desc:    "Standard wg-quick config, generated from the fields.",
		Tunnels: []string{"wireguard", "lwo", "tor-over-vpn", "vpn-over-tor"},
		Fields:  wgFields,
		Render:  renderWG(wgFields),
	})

	sslFields := []Field{
		{Key: "server", Label: "Server host"},
		{Key: "port", Label: "Server port", Default: "8388"},
		{Key: "password", Label: "Password", Secret: true, Gen: "sskey"},
		{Key: "method", Label: "Cipher", Default: "chacha20-ietf-poly1305"},
		{Key: "lport", Label: "Local SOCKS port", Default: "1080"},
	}
	ps = append(ps, Preset{
		ID: "ss-local", Title: "Shadowsocks local client (sslocal)",
		Desc:    "JSON config for sslocal, listening on 127.0.0.1.",
		Tunnels: []string{"shadowsocks"},
		Fields:  sslFields,
		Render: func(vals map[string]string) (string, error) {
			v, err := checkValues(sslFields, vals)
			if err != nil {
				return "", err
			}
			if !ssMethods[v["method"]] {
				return "", fmt.Errorf("unsupported cipher %q", v["method"])
			}
			if net.ParseIP(v["server"]) == nil && !hostRe.MatchString(v["server"]) {
				return "", fmt.Errorf("server host is not valid")
			}
			port, e1 := strconv.Atoi(v["port"])
			lport, e2 := strconv.Atoi(v["lport"])
			if e1 != nil || e2 != nil || port < 1 || port > 65535 || lport < 1 || lport > 65535 {
				return "", fmt.Errorf("ports must be 1-65535")
			}
			raw, err := json.MarshalIndent(map[string]any{
				"server": v["server"], "server_port": port, "password": v["password"],
				"method": v["method"], "local_address": "127.0.0.1", "local_port": lport,
			}, "", "  ")
			return string(raw) + "\n", err
		},
	})

	hyFields := []Field{
		{Key: "server", Label: "Server host:port"},
		{Key: "auth", Label: "Auth password", Secret: true, Gen: "password"},
		{Key: "sni", Label: "TLS SNI (optional)", Optional: true},
		{Key: "listen", Label: "Local SOCKS listen", Default: "127.0.0.1:1080"},
	}
	ps = append(ps, Preset{
		ID: "hy2-client", Title: "Hysteria2 client",
		Desc:    "QUIC-based tunnel with a local SOCKS5 listener.",
		Tunnels: []string{"quic"},
		Fields:  hyFields,
		Render: func(vals map[string]string) (string, error) {
			v, err := checkValues(hyFields, vals)
			if err != nil {
				return "", err
			}
			if _, _, err := validHostPort(v["server"]); err != nil {
				return "", err
			}
			if _, _, err := validHostPort(v["listen"]); err != nil {
				return "", err
			}
			cfg := map[string]any{
				"server": v["server"], "auth": v["auth"],
				"socks5": map[string]string{"listen": v["listen"]},
			}
			if v["sni"] != "" {
				if !hostRe.MatchString(v["sni"]) {
					return "", fmt.Errorf("SNI is not a valid host name")
				}
				cfg["tls"] = map[string]string{"sni": v["sni"]}
			}
			raw, err := yaml.Marshal(cfg)
			return string(raw), err
		},
	})
	return ps
}

func renderWG(fields []Field) func(map[string]string) (string, error) {
	return func(vals map[string]string) (string, error) {
		v, err := checkValues(fields, vals)
		if err != nil {
			return "", err
		}
		for _, k := range []string{"privkey", "pubkey"} {
			raw, err := base64.StdEncoding.DecodeString(v[k])
			if err != nil || len(raw) != 32 {
				return "", fmt.Errorf("%s must be a 44-character base64 WireGuard key", map[string]string{"privkey": "private key", "pubkey": "peer public key"}[k])
			}
		}
		for _, c := range strings.Split(v["address"], ",") {
			if _, _, err := net.ParseCIDR(strings.TrimSpace(c)); err != nil {
				return "", fmt.Errorf("interface address %q must be CIDR like 10.0.0.2/32", strings.TrimSpace(c))
			}
		}
		for _, c := range strings.Split(v["allowed"], ",") {
			if _, _, err := net.ParseCIDR(strings.TrimSpace(c)); err != nil {
				return "", fmt.Errorf("allowed IP %q must be CIDR like 0.0.0.0/0", strings.TrimSpace(c))
			}
		}
		if v["dns"] != "" {
			for _, d := range strings.Split(v["dns"], ",") {
				if net.ParseIP(strings.TrimSpace(d)) == nil {
					return "", fmt.Errorf("DNS %q must be an IP address", strings.TrimSpace(d))
				}
			}
		}
		if _, _, err := validHostPort(v["endpoint"]); err != nil {
			return "", err
		}
		ka, err := strconv.Atoi(v["keepalive"])
		if err != nil || ka < 0 || ka > 600 {
			return "", fmt.Errorf("keepalive must be 0-600 seconds")
		}

		var b strings.Builder
		b.WriteString("# generated by the idspoof TUI\n[Interface]\n")
		fmt.Fprintf(&b, "PrivateKey = %s\nAddress = %s\n", v["privkey"], v["address"])
		if v["dns"] != "" {
			fmt.Fprintf(&b, "DNS = %s\n", v["dns"])
		}
		fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\n", v["pubkey"], v["endpoint"], v["allowed"])
		if ka > 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", ka)
		}
		return b.String(), nil
	}
}
