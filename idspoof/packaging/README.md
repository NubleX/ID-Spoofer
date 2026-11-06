# Packaging

## tun2socks persistence (systemd)

`idspoof` embeds the [tun2socks](https://github.com/xjasonlyu/tun2socks) Go
engine directly (`internal/tunnel/tun2socks.go`) instead of shelling out to a
separate `tun2socks` binary. It solves the same problem as manually running
`setcap cap_net_admin+ep $(which tun2socks)` and `tun2socks -device tun0
-proxy socks5://...` by hand — but as a supervised tunnel that survives
reboot, with a clean `restore` path instead of an orphaned process nobody is
tracking.

Install:

```bash
sudo mkdir -p /etc/idspoof
sudo cp packaging/tun2socks.example.yaml /etc/idspoof/tun2socks.yaml
# edit /etc/idspoof/tun2socks.yaml: set `proxy` to your actual SOCKS/HTTP
# proxy, review the fwmark and tun-post-up routing before enabling

sudo cp packaging/systemd/idspoof-tun2socks.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now idspoof-tun2socks.service
```

Check it:

```bash
sudo idspoof status
sudo journalctl -u idspoof-tun2socks -f
cat /var/log/idspoof/tun2socks.log
```

Stop and remove the tunnel (and whatever else `apply` touched — see the
comment in the unit file if you only want the tunnel):

```bash
sudo systemctl disable --now idspoof-tun2socks.service
```

Review `tun-post-up` in the config before enabling on a box with existing
routing (Mullvad, other VPNs) — it runs arbitrary shell as root right after
the TUN device comes up.

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
