# Packaging

## What ships

| File | Installed to | Purpose |
|---|---|---|
| `systemd/idspoof.service` | `/usr/lib/systemd/system/` (deb/rpm), `/etc/systemd/system/` (install.sh) | Boot daemon, ordered before `network-pre.target` |
| `idspoof.desktop` | `<prefix>/share/applications/` | Application menu entry (opens the TUI in a terminal via sudo) |
| `icons/idspoof-{48,256}.png` | `<prefix>/share/icons/hicolor/*/apps/idspoof.png` | Menu icon |
| `install.sh` | tarball root | Installer / uninstaller for non-deb systems |
| `scripts/postinstall.sh`, `scripts/preremove.sh` | package scripts | Enable the unit on install, stop it on removal |
| `tun2socks.example.yaml`, `networkmanager/99-mullvad-ufw` | `share/doc/idspoof/examples/` | Examples |

Releases are built by GoReleaser from a `v*` tag (`.goreleaser.yaml`): tarballs
and zips, a `.deb` and an `.rpm`, and `checksums.txt`. Try it without
publishing: `make snapshot` (needs goreleaser), output in `dist/`.

## The boot daemon

The unit is `Type=notify` and runs `idspoof daemon`. It sends `READY=1` once the
boot profile's identity (MAC, persona) is applied, which releases
`network-pre.target`, so NetworkManager's first DHCP request already carries the
spoofed identity. The tunnel starts afterwards and is restarted if it dies.

- Boot profile: `/etc/idspoof/boot.yaml`, written from the TUI (`B`).
  Fields: `mac`, `persona`, `sysinfo`, `tunnel`, `profile`, `mode`.
- Tunnel profiles live in `<state-dir>/profiles` (default `/var/log/idspoof/profiles`).
- Logs: `journalctl -u idspoof`.
- Recovery: add `idspoof.disable=1` to the kernel command line; the daemon then
  idles and applies nothing.
- `systemctl stop idspoof` restores the original MAC and persona and stops the tunnel.

## Mullvad + `ufw default deny outgoing`

If you run `sudo ufw default deny outgoing` for a real outbound allowlist,
a fixed `ufw allow out port X` rule for your VPN goes stale the moment you
switch server/location/bridge mode, since the peer port changes with it —
and a stale rule means the next reconnect has nothing to match, silently
locking outbound traffic down entirely until you notice.
`packaging/networkmanager/99-mullvad-ufw` is a NetworkManager dispatcher
script that reads the live WireGuard peer from `wg show` on every
connect/reconnect and replaces a single tagged ufw rule to match — so the
allowlist tracks whatever you're actually connected to instead of one port
frozen at install time.

Install this *before* you flip `ufw default deny outgoing`, not after —
test a reconnect/server switch while outgoing is still `allow` so a bug in
the script doesn't lock you out the same way a stale manual rule does:

```bash
sudo install -m 755 -o root -g root \
  packaging/networkmanager/99-mullvad-ufw \
  /etc/NetworkManager/dispatcher.d/99-mullvad-ufw
```

NetworkManager runs everything under `dispatcher.d/` as root automatically
on connection up/down — nothing else to enable. It only ever adds/removes
the one rule it tags with `# mullvad-dynamic`; it won't touch anything else
in your ruleset.

If you ever get locked out again: `sudo ufw default allow outgoing`
restores outbound immediately.
