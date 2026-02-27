# Changelog

All notable changes to the ID-Spoofer project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.2] - 2026-02-27

### Added

- **Multi-OS network personas** — Windows 10/11, macOS (Sonoma+), Linux (Ubuntu/Arch/Fedora), iOS 17+
  - `--persona windows|macos|linux|ios` CLI flag; persona radio selector in TUI
  - Each persona projects the correct TTL, TCP timestamps, TCP options order, DHCP hostname style, and mDNS behaviour
  - Linux persona: TTL=64, timestamps=1, TCP options in kernel order (`MSS,SACK,TS,NOP,WScale`), WScale=7, distro-style DHCP hostnames
  - macOS persona: TTL=64, timestamps=1, TCP options `MSS,NOP,WS,NOP,NOP,TS,SOK`, no DHCP vendor class, Avahi left running
  - iOS persona: same as macOS with WScale=16
- **Protocol encapsulation** — 8 tunnel protocols managed via `--tunnel` flag or TUI
  - `tor` — onion routing, transparent or SOCKS5 mode; torrc generated on the fly; bootstrap polling
  - `wireguard` — wg-quick wrapper, transparent routing via WireGuard interface
  - `lwo` — WireGuard with Lightweight Obfuscation (ObfuscateKey config option, Mullvad-compatible)
  - `i2p` — i2pd garlic routing, SOCKS5 :4447 / HTTP :4444 / transparent via outproxy
  - `shadowsocks` — sslocal/ss-local AEAD proxy, redir mode or SOCKS5 :1080
  - `quic` — Hysteria2 UDP tunnel, transparent tproxy or SOCKS5 :1080
  - `tor-over-vpn` — WireGuard up first, Tor routed through VPN
  - `vpn-over-tor` — Tor up first (SOCKS), WireGuard routed through Tor
  - `--tunnel-mode transparent|socks`, `--tunnel-config PATH`
- **Granular apply flags** — `--mac`, `--netident`, `--sysinfo` (combinable); no-flag default runs all three
- **TUI sections** — Network Persona radio group + Traffic Encapsulation radio group with per-item descriptions
- **Tor distro portability** — auto-detects tor daemon user (`debian-tor` / `tor` / `_tor`) from `/etc/passwd` to prevent routing loops on non-Debian systems; polls SOCKS port for bootstrap readiness (up to 90s) instead of blind sleep

### Changed

- iptables chain renamed `IDSPOOF_WINEMU` → `IDSPOOF_NETEMU` (generic, backward-compat cleanup on restore)
- DHCP dropin renamed `90-idspoof-windows.conf` → `90-idspoof-persona.conf`; vendor class (Option 60) only injected for Windows persona
- Avahi suppression is now conditional: stopped for Windows, left running for macOS/Linux/iOS
- `apply --mac-only` / `--netident-only` replaced with composable `--mac`, `--netident`, `--sysinfo` flags matching `restore` syntax
- NFQUEUE rewriter now persona-aware via `activePersona atomic.Value`; wscale extracted from persona (7/8/16) rather than hardcoded

---

## [2.0.0] - 2026-02-27

### Changed

- **Full Go rewrite** — replaced ~890-line Bash toolkit with a structured Go binary (`github.com/NubleX/idspoof`)
- **System hostname never modified** — Windows identity is now projected at the wire level only; internal hostname and config files are untouched
- **Network persona layer** replaces naive hostname/fingerprint spoofing:
  - sysctl tuning: TTL=128, tcp_timestamps=0, tcp_sack=1, tcp_ecn=0, window buffers for wscale=8
  - iptables `IDSPOOF_WINEMU` mangle chain: TTL-set + MSS=1460 clamp on SYN packets
  - NFQUEUE (queue 42): pure-Go packet rewriter — rewrites IP ID (0→incrementing) and TCP options to Windows order (`MSS,NOP,WScale,NOP,NOP,SACKPermitted`)
  - DHCP Option 12 (hostname) + Option 60 (`MSFT 5.0` vendor class) via NetworkManager dropin or dhclient.conf
  - mDNS: Avahi daemon stopped to suppress real hostname broadcast
- **Cross-platform architecture** — Go build tags (`//go:build linux`) with macOS and Windows stubs ready for Phase 4–5
- **Cobra CLI** with subcommands: `apply`, `restore`, `status`, `menu`, `version`
- **Atomic state file** at `/var/log/idspoof/state.env` — backward-compatible with Bash v1 format
- Legacy Bash scripts preserved in `idspoof/legacy/` for reference

### Added

- `idspoof apply --netident-only` — apply Windows network persona without touching MACs
- `idspoof apply --dry-run` — preview changes without applying
- `idspoof restore --netident` — roll back only network persona
- `--debug` and `--log FILE` global flags
- Screenshots in `assets/images/`

### Removed

- `emergency-uninstall.sh` — superseded by `idspoof restore`
- `CODE_REVIEW.md` — all issues resolved by the Go rewrite
- GUI/zenity support — CLI-only in v2 (TUI menu via `idspoof menu`)

---

## [1.0.0] - 2025-06-06

### Added

- **Initial stable release** of ID-Spoofer
- **Complete MAC address spoofing** functionality with support for all network interfaces
- **Hostname randomization** with Windows-like naming patterns
- **OS fingerprint obfuscation** by modifying TCP/IP stack parameters
- **GUI support** with zenity integration for user-friendly operation
- **Desktop notifications** using libnotify for status updates
- **Interactive menu system** (`idspoof-menu.sh`) for easy operation
- **Comprehensive logging** capabilities with timestamps
- **Quiet mode** for automated/scripted operations
- **Progress indicators** for long-running operations
- **Modular operation modes** (full, MAC-only, hostname-only)
- **Enhanced command-line interface** with multiple options
- **Desktop integration** with application menu entries
- **Smart installer** with multi-distribution support
- **Uninstaller utility** for clean removal
- **Systemd service** for MAC address restoration (optional)
- **System information spoofing** with realistic hardware profiles
- **Multi-distribution support** (Ubuntu, Debian, Kali, Fedora, RHEL, Arch, openSUSE)

### Technical Improvements

- **Enhanced error handling** with proper exit codes and error messages
- **Automatic cleanup** of temporary files using trap handlers
- **Dependency verification** before execution
- **Temporary directory management** for secure file operations
- **Modular code structure** with separate functions for each operation
- **Input validation** for command-line arguments
- **Smart interface detection** using modern ip commands
- **Original settings backup** for potential restoration
- **Privilege checking** with informative error messages
- **Comprehensive help system** with examples and usage information

### Security Features

- **Locally administered MAC addresses** to avoid vendor conflicts
- **Root privilege verification** for security operations
- **Windows-like TCP/IP fingerprinting** to evade detection
- **Safe interface management** with proper up/down sequencing
- **Audit logging** for security compliance
- **Non-destructive operations** with backup capabilities

### User Experience

- **Modern CLI interface** with colored output and progress bars
- **Interactive confirmations** with clear explanations
- **GUI mode** with dialog boxes and notifications
- **Desktop integration** for easy access
- **Menu-driven interface** for beginners
- **Comprehensive documentation** with examples
- **Version information** and help commands
- **Multiple execution modes** for different use cases

### Installation & Distribution

- **Smart installer script** with distribution detection
- **Automatic dependency installation** for major Linux distributions
- **Clean uninstaller** with complete removal
- **Symbolic link creation** for easy command access
- **Desktop file installation** with application menu integration
- **Multi-distribution packaging** support
- **Proper file permissions** and directory structure

### Documentation

- **Comprehensive README** with badges, features, and usage examples
- **Project logo** in SVG format
- **Detailed installation instructions** for multiple distributions
- **Use case documentation** with legal disclaimers
- **Troubleshooting guide** for common issues
- **Command examples** and technical details
- **License information** (GPL v3.0)
- **Version badges** and project metadata

### Known Issues

- ⚠️ Network connectivity may be temporarily disrupted during MAC address changes
- ⚠️ Some network managers may interfere with MAC address spoofing
- ⚠️ GUI components require X11/Wayland display server
- ⚠️ Some enterprise networks may detect spoofed identifiers

### Dependencies

- **Required**: macchanger, net-tools, iproute2, bash
- **Optional**: zenity (GUI), libnotify-bin (notifications)
- **System**: Linux kernel 3.0+, systemd (optional)

---

## Release Notes

### Version 1.0.0 Highlights

This is the first stable release of ID-Spoofer, representing a complete rewrite and enhancement of the original concept. The tool now provides enterprise-grade functionality with comprehensive error handling, multi-distribution support, and both CLI and GUI interfaces.

Key achievements in this release:

- **Production Ready**: Extensive testing and error handling
- **User Friendly**: Both technical and non-technical user support
- **Secure**: Proper privilege handling and safe operations
- **Portable**: Support for major Linux distributions
- **Maintainable**: Clean, documented, and modular code structure

### Upgrade Path

This is the initial release, so no upgrade path is necessary. Future versions will include migration scripts if needed.

### Breaking Changes

N/A - Initial release

### Deprecations

N/A - Initial release

---

**For support, bug reports, or feature requests, please visit our [GitHub repository](https://github.com/nublex/id-spoofer).**
