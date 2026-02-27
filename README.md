<div align="center">
  <img src="assets/images/logo.png" alt="ID-Spoofer Logo" width="400"/>

# ID-Spoofer v2.0

![License](https://img.shields.io/badge/license-GPL%20v3-blue.svg)
![Version](https://img.shields.io/badge/version-2.0.0-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)
![Language](https://img.shields.io/badge/language-Go-00ADD8.svg)
![Status](https://img.shields.io/badge/status-active-brightgreen.svg)

</div>

A cross-platform identity spoofing toolkit for penetration testing and security assessments. Written in Go, ID-Spoofer randomizes MAC addresses and projects a convincing Windows network persona at the wire level — without touching the system hostname or breaking internal configuration.

## Screenshots

<div align="center">

**Applying Windows Network Persona**
<img src="assets/images/screenshot2_persona.png" alt="Applying Windows network persona — DHCP hostname, TTL=128, MSS=1460, NFQUEUE active" width="800"/>

*DHCP hostname injected, TTL set to 128, MSS=1460, NFQUEUE rewriting IP ID + TCP options. System hostname unchanged.*

---

**Status — Persona Active**
<img src="assets/images/screenshot3_rewrite.png" alt="Status view showing IDSPOOF_WINEMU iptables chain and active NFQUEUE rewriter" width="800"/>

*`idspoof status` after apply: IDSPOOF_WINEMU chain dumped, NFQUEUE rewriter confirmed active on queue 42.*

---

**Status — Clean State**
<img src="assets/images/screenshot1_status.png" alt="Status view before apply — no iptables rules, NFQUEUE not active" width="800"/>

*Before apply: sysctl already at Windows values (TTL=128, timestamps=0) but no iptables rules and NFQUEUE not running.*

</div>

## How it works

The key design principle: **your system hostname is never modified**. Instead, ID-Spoofer manipulates the network stack so that passive observers (p0f, Nmap, Wireshark) see a Windows 10/11 machine.

### Network persona layers

When you run `idspoof apply`, five layers activate simultaneously:

| Layer | What changes | Effect |
|-------|-------------|--------|
| **sysctl** | TTL=128, tcp_timestamps=0, tcp_sack=1, tcp_ecn=0, window buffers | Kernel-level Windows TCP/IP parameters |
| **iptables** | `IDSPOOF_WINEMU` mangle chain | Forces TTL=128 on outgoing packets, clamps MSS=1460 on SYN |
| **NFQUEUE** (queue 42) | Intercepts outgoing SYN packets | Rewrites IP ID (Linux=0 → incrementing, Windows style) and reorders TCP options to Windows layout |
| **DHCP** | Option 12 (hostname) + Option 60 (`MSFT 5.0` vendor class) | Router and DHCP server see a Windows machine with a fake hostname |
| **mDNS** | Stops Avahi daemon | Suppresses real hostname broadcast on the local network |

The TCP options rewrite matches the exact Windows 10/11 SYN signature: `MSS, NOP, WScale, NOP, NOP, SACKPermitted` — defeating p0f fingerprinting. The NFQUEUE rewriter is pure Go with no CGo and no external C libraries.

**p0f signature after apply:** `*:128:0:*:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0`

## Requirements

- Linux (Phases 4–5 will add macOS and Windows support)
- Root privileges
- `macchanger` — for MAC address changes
- `iproute2` — interface management
- `iptables` — packet mangling rules
- NetworkManager or dhclient — DHCP hostname injection
- Optional: `avahi-daemon` (stopped during persona apply)

## Installation

### From binary (recommended)

```bash
# Download the latest release for your platform
curl -sL https://github.com/NubleX/id-spoofer/releases/latest/download/idspoof_linux_amd64 -o idspoof
chmod +x idspoof
sudo mv idspoof /usr/local/bin/
```

### Build from source

```bash
git clone https://github.com/NubleX/id-spoofer.git
cd id-spoofer/idspoof
make build
sudo cp bin/idspoof /usr/local/bin/
```

Go 1.22+ required. If Go is not installed:

```bash
curl -sL https://go.dev/dl/go1.22.4.linux-amd64.tar.gz | tar -xz -C ~/.go --strip-components=1
export PATH="$HOME/.go/bin:$PATH"
```

## Usage

All commands require root.

```bash
# Full identity spoof: MAC + Windows network persona + sysinfo
sudo idspoof apply

# MAC addresses only
sudo idspoof apply --mac-only

# Windows network persona only (TCP/IP + DHCP + NFQUEUE)
sudo idspoof apply --netident-only

# Preview changes without applying
sudo idspoof apply --dry-run

# Show current state vs saved originals
sudo idspoof status

# Roll back everything
sudo idspoof restore

# Roll back only MAC addresses
sudo idspoof restore --mac

# Roll back only network persona
sudo idspoof restore --netident

# Interactive TUI menu
sudo idspoof menu

# Version info
idspoof version
```

### Global flags

```
--quiet        Suppress output, skip confirmations
--debug        Verbose logging
--log FILE     Log to file
--state-dir    State directory (default: /var/log/idspoof)
```

### Verifying the persona

Use tcpdump or Wireshark to capture a SYN packet and inspect:
- IP TTL should be 128
- IP ID should be non-zero and incrementing (not 0)
- TCP options order: MSS → NOP → WScale → NOP → NOP → SACKPermitted
- TCP window: 65535, scale factor 8

```bash
sudo tcpdump -i any -nn 'tcp[tcpflags] & tcp-syn != 0' -X
```

## State management

State is stored in `/var/log/idspoof/state.env` — an atomic key=value file backward-compatible with the v1 Bash format. Keys include `ORIG_MACS`, `ORIG_TTL`, `ORIG_TCP_TIMESTAMPS`, and related sysctl originals. `restore` uses these to fully roll back.

## Architecture

The Go rewrite (`idspoof/`) replaces the original Bash scripts with a structured, cross-platform binary:

```
cmd/idspoof/          CLI commands (cobra): apply, restore, status, menu, version
internal/
  mac/                MAC generation and Linux interface manipulation
  netident/           Windows network persona: sysctl, iptables, NFQUEUE, DHCP, mDNS
  spoofer/            Orchestrator: runs selected operations, collects results
  state/              Atomic key=value state file (bash v1 compatible)
  platform/           Platform abstraction + privilege checks
  ui/                 Banner, colors, confirm prompt, progress
  sysinfo/            Fake hardware profile generation (display-only)
legacy/               Original Bash scripts preserved for reference
```

The original Bash toolkit is preserved in `legacy/` and in the `master` branch history.

## Roadmap

- [x] Phase 1–2: Go core + Linux MAC/netident/sysinfo
- [x] Phase 3: CLI commands (apply, restore, status, menu)
- [ ] Phase 4: macOS (ifconfig, scutil, sysctl net.inet.ip.ttl)
- [ ] Phase 5: Windows (registry MAC, WMI hostname, Tcpip\Parameters)
- [ ] Phase 6: GitHub Actions CI + goreleaser multi-platform releases

## Acknowledgements

Thanks to the teams whose open-source work makes this possible:

- **[Charm](https://github.com/charmbracelet)** — [Bubble Tea](https://github.com/charmbracelet/bubbletea) and [Lip Gloss](https://github.com/charmbracelet/lipgloss) power the interactive TUI. Genuinely excellent libraries.
- **[spf13/cobra](https://github.com/spf13/cobra)** — the CLI framework behind every subcommand.

## Legal disclaimer

For penetration testing on systems you own or have explicit written permission to test, security research, and authorized red team assessments only. Users are responsible for compliance with applicable laws.

---

Visit https://www.idarti.com
