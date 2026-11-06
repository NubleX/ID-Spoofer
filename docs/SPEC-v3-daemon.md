# ID-Spoofer v3 spec: idspoofd, transport fabric, virtual NICs, TUI control

Status: approved draft. Target: next major line after 2.0.8. Nothing here is implemented.

## Context

ID-Spoofer today is a one-shot root CLI plus Bubble Tea TUI (`idspoof/cmd/idspoof/`). It spoofs MAC, hostname, TCP/IP persona (NFQUEUE) and sysinfo, and wraps tunnels (tor, wireguard, lwo, i2p, shadowsocks, quic, combos) by shelling out to system binaries (`idspoof/internal/tunnel/`). The uncommitted tun2socks work in the main checkout (`internal/tunnel/tun2socks*.go`, `packaging/`, `tun2socks_engine.go`) re-execs a detached helper with a pidfile because there is no resident process.

Goal: a resident, supervised, OS-agnostic control plane that starts at boot as root, is controlled by the unprivileged user (TUI first), and treats every network path (VPN, proxy, mesh, dVPN, onion, I2P) as a pluggable transport that can be chained, selected, or policy-routed.

Prerequisite: the tun2socks work is uncommitted on `dev.2.0.6` in `/home/muscle/projects/ID-Spoofer`, not in this worktree. It must be committed (after the e2e steps pass) before phase 1 starts. This spec assumes it lands as-is.

## Answers to the questions asked

### Consuming AntiGoblin

Recommendation: do not consume it as a dependency. Borrow ideas only.
- Facts read by the scout: it is a router-hosted web panel for Keenetic routers on Entware (KeeneticOS 3.5+, aarch64/armv7), shell/CGI backend, UI on port 8899, manages xray/sing-box with iptables/ipset, MIT license, 27 stars. No API, no Go package, no library surface found. Primary language not stated on the repo page; source tree not inspected.
- It targets a different platform and layer (a router, not the host). There is nothing to import or link.
- Its install path pipes unpinned `main`-branch scripts into `sh`, and its USB installer bundles Entware and a prebuilt sing-box. That conflicts with this project's supply-chain stance.
- Worth borrowing: (1) subscription-URL ingestion (vless/ss/trojan/hysteria links) into profiles, (2) domain and geo list routing via ipset/nft sets with SHA-256 verified list updates, (3) supervised sing-box/xray children driven by generated config, (4) root-only state file.
- Interop option, not a dependency: use the same subscription link formats so one profile list serves both a Keenetic router and ID-Spoofer.
- Note: it is a censorship-circumvention router tool, not a host defense stack. The "defensive stack" here is ID-Spoofer plus the kill-switch and policy engine below.

### TUN, TAP and songgao/water

Recommendation: do not add `songgao/water`. Reasons (scout-confirmed unless marked):
- BSD-3-Clause, last commit 17 Mar 2020, 21 open issues, effectively unmaintained.
- Windows TAP needs the OpenVPN tap-windows6 driver and manual IP setup. macOS TAP is a TODO (tuntaposx). macOS TUN is point-to-point only.
- tun2socks v2.7.0 is already a dependency and already brings `golang.zx2c4.com/wireguard` (tun) and wintun, which cover TUN on Linux, macOS (utun), Windows (wintun), BSD. Adding water duplicates this.
- Not confirmed by the scout, to verify before phase 2: wireguard-go's `tun` package is L3 only (no TAP). If true, TAP must be implemented separately.

Plan: one `datapath` interface. L3 (TUN) uses the wireguard/tun device layer on every OS. L2 (TAP) is a Linux-first feature implemented with a thin `/dev/net/tun` `IFF_TAP` wrapper using `golang.org/x/sys/unix` (already a dependency). Windows TAP is optional, behind a build tag and an explicit driver check. macOS gets TUN only; TAP is documented as unsupported (utun cannot do L2).

Honest limit: TAP only matters for L2 jobs (bridging, ARP/frame crafting, VM networking, honeypot NICs). Almost all transports are L3 or SOCKS and need only TUN.

### Do VPNs become obsolete?

No. A VPN is one transport with one trust model, not a separate category. What changes is the framing:
- A VPN gives a whole-host L3 egress and a single known operator. Mesh and dVPN give many operators or peers and different trust and performance. Tor/I2P give anonymity at high latency. A plain proxy gives per-app egress.
- Running them "in parallel" is not pointless: parallel with policy routing gives per-flow isolation (browser via Tor, updates via direct, nmap via tun2socks to a chosen exit). Running them in series gives layered trust (Tor over VPN, VPN over Tor) at a latency cost.
- Stacking hops does not add anonymity beyond the weakest link, and global correlation attacks are unaffected. The spec must not claim otherwise in docs or UI.
- So the product is a transport fabric with four composition modes, and a VPN is just one node type.

### OS-agnostic approach

Three seams, each with per-OS files (matching the existing `_linux/_darwin/_windows` convention in `internal/*`):
1. Datapath: TUN device creation and addressing (shared via wireguard/tun), routing and DNS (per-OS code), TAP (Linux).
2. Service host: systemd unit (Linux), launchd daemon (macOS), Windows service via SCM (`golang.org/x/sys/windows/svc`).
3. IPC: Unix domain socket (Linux, macOS), named pipe with ACL (Windows). Same API on top.

Routing and firewall enforcement differ per OS and are the real portability cost: nftables/iptables + `ip rule` fwmark (Linux), pf (macOS), WFP (Windows). Phase 1 is Linux-complete. macOS and Windows get the daemon, IPC and TUN/SOCKS transports first; kill-switch and policy routing on those OSes are later phases and explicitly marked as such in the UI.

## Goals and non-goals

Goals
- G1: resident root daemon `idspoofd`, started at boot, restarts failed transports, owns all privileged state.
- G2: unprivileged control via local IPC; the TUI is a client. The CLI becomes a client too, with a direct-mode fallback when no daemon is running.
- G3: transports as plugins behind one interface; existing wrappers keep working unchanged.
- G4: composition: chain, selector/failover, policy-route (per app/user/destination), split.
- G5: virtual NIC management (create, address, route, destroy) for TUN, and TAP on Linux.
- G6: listener management: local SOCKS5/HTTP inbound listeners per profile, with a live view of what listens where and what egresses through what.
- G7: kill-switch and leak guard with documented coexistence with Mullvad.
- G8: spoofing ops (MAC, hostname, persona, sysinfo) exposed through the same API, with the existing state/restore guarantees.

Non-goals
- No web UI or Wails desktop app in this line (decided: TUI only). The API is kept stable so a UI can be added later without changes to the daemon.
- No embedded multi-protocol engine in phase 1 (see sing-box decision).
- No claim of anonymity guarantees, no traffic-correlation resistance claims.
- No packaging of third-party prebuilt binaries.

## Architecture

```
 idspoof TUI / CLI (user)         future UI (not in scope)
          |  JSON over HTTP on unix socket / named pipe
          v
 +------------------ idspoofd (root, systemd) ------------------+
 | API + authz (SO_PEERCRED, group idspoof)   event stream (SSE)|
 | Reconciler: desired state (config) vs actual state          |
 | Supervisor: start/stop/health/restart, backoff              |
 | Composer: chain | selector | policy | split                  |
 | Policy/firewall: nft+ip rule (linux), pf, WFP (later)       |
 | Datapath: TUN (wg/tun), TAP (linux), routes, DNS            |
 | Spoofing ops: mac, hostname, netident, sysinfo (existing)   |
 +-------------------------------------------------------------+
        |            |             |              |
   transports: tun2socks, tor, i2p, wireguard, lwo, shadowsocks,
               quic, (later) sing-box profiles, mesh, dVPN
```

### Transport interface (extends today's `tunnel.Tunnel`)

Today: `Name, Available, Start(mode, cfg map[string]string), Stop, Status` and a `Manager` that holds exactly one active tunnel. Change:
- `Manager` becomes a registry of named instances (many concurrent), keyed by instance ID, each with its own state machine: `stopped, starting, up, degraded, stopping, failed`.
- Each transport declares its shape: `Kind` (`socks-out`, `tun-out`, `l2`), `Ingress` (SOCKS port, or TUN name), `Egress` description, and capabilities (`supportsChain`, `needsRoot`, `osSupport`).
- Typed config per transport replaces `map[string]string`; the old map is kept as a compatibility shim so `apply --tunnel` keeps working.
- Keep `Registry` and `Get` in `internal/tunnel/tunnel.go`; add instance management in `manager.go`.

### Composition

- chain: A -> B -> C. Valid when each hop's egress is the next hop's ingress (SOCKS or TUN). `combo.go` (tor-over-vpn, vpn-over-tor) becomes two instances of the generic chain, not special code.
- selector: ordered list with health probe and failover; optional load balancing later.
- policy: match on uid/gid, cgroup, process, destination CIDR/domain-set, then route to an instance. Linux: `fwmark` + `ip rule` + nft sets. This is the AntiGoblin idea, applied to the host.
- split: direct vs tunnel by destination set.

### Virtual NICs

- `datapath.NIC{Name, Kind(TUN|TAP), MTU, Addrs, Routes, Owner}`; daemon records ownership so teardown never touches a NIC it did not create.
- Orphan reaper at daemon start: remove NICs, routes, nft rules and `ip rule`s tagged with the idspoof marker comment, to recover from a crash (this is the failure mode behind earlier lockouts).

### Kill-switch and Mullvad coexistence

- Daemon installs its own nft table `inet idspoof` (never edits ufw or Mullvad tables). Rules are tagged and removable as a unit.
- Kill-switch is opt-in per profile, default off, and requires an explicit allowlist for the control path (loopback, the daemon socket, DHCP, the transport's own upstream endpoints). A dry-run mode prints the ruleset first.
- Safety rail from past lockouts: a "dead-man" timer. Any firewall change that can cut egress is rolled back after N seconds unless the client confirms. Default N = 30.
- Mullvad: it owns its own firewall and routes. The earlier test showed its local SOCKS5 already occupies port 1080, so default proxy ports start at 11080 and are configurable. A dedicated phase 1 test documents what coexists (exit proxy beside the Mullvad tunnel) and what does not.

### Daemon, API, security

- Unit: `idspoofd.service`, `Type=notify`, `ProtectSystem`, `NoNewPrivileges`, `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_ADMIN` (trim after testing), `RuntimeDirectory=idspoof`.
- Socket `/run/idspoof/idspoof.sock`, mode 0660, group `idspoof`. Peer credentials checked per call; read-only calls allowed for the group, mutating calls need group membership plus a per-action allowlist. No TCP listener by default.
- API (JSON, versioned `/v1`): `GET /state`, `GET /events` (SSE), `POST /transports`, `POST /transports/{id}/start|stop`, `POST /profiles`, `POST /compose`, `POST /spoof/{mac|hostname|netident|sysinfo}`, `POST /restore`, `GET /listeners`, `GET /nics`, `POST /killswitch`.
- Config: `/etc/idspoof/config.yaml` (desired state, root-owned 0640 group-readable secrets excluded), secrets in `/etc/idspoof/secrets/` 0600 root. State in the existing `config.DefaultStateDir` (`/var/log/idspoof`), reusing `internal/state`.
- Daemon replaces the detached `__tun2socks-run` helper and pidfile: tun2socks runs as a supervised child (or in-process goroutine) owned by the daemon.
- Windows: named pipe `\\.\pipe\idspoof` with a DACL for the local Users group and Administrators. macOS: launchd plist, socket in `/var/run/idspoof/`.

### TUI changes

Reuse the existing panes (`tui_dashboard.go`, `tui_identity.go`, `tui_tunnel.go`, `tui_traffic.go`, `tui_status.go`). Change data sources from direct calls to the API client, and add:
- Transports pane: instances, state, health, latency, start/stop, edit.
- Compose pane: build chains and selectors, preview the resulting path as `app -> A -> B -> internet`.
- NICs and listeners pane: TUN/TAP devices, local listeners, owner, MTU, bytes in/out.
- Policy pane: rules, target instance, hit counters.
- Kill-switch toggle with dead-man confirmation.
- Header shows daemon connection state; if the daemon is down, the TUI offers direct mode (current behavior).

### sing-box decision (universal protocol engine)

To cover "all the world's VPNs" without writing each protocol, one engine speaking many protocols is the practical route. sing-box (and xray) cover VLESS/Reality, Trojan, Hysteria2, TUIC, Shadowsocks, WireGuard, SOCKS and have their own TUN inbound. AntiGoblin validates this approach.
- Phase 1-3: do not embed. Add `singbox` as a supervised external binary transport driven by generated config. Rationale: embedding pulls a large dependency tree and build tags into every OS build; the project builds with `CGO_ENABLED=0` across 5 targets today.
- Phase 4+: evaluate embedding as a library once the transport interface has settled.
- License check required before shipping any integration: sing-box is GPL-based with additional terms as I recall; this is unverified here and must be read from its LICENSE file first. ID-Spoofer is GPLv3+.
- Mesh/dVPN/other (WireGuard-based meshes, Nym, Lokinet, Yggdrasil, cjdns, Hysteria, "purplei2p" i2pd): each is a transport plugin that wraps its own binary, same as `i2p.go` and `tor.go` do now. Each needs its own license and security review; none are verified in this spec.

## Phases

Phase 0 - baseline (before any new code)
- Commit the tun2socks work, run the e2e steps 1-6 against the 11080 test proxy, tag 2.0.8.
- Exit: tun2socks e2e passes on Linux; CHANGELOG and README match.

Phase 1 - daemon core (Linux)
- `internal/daemon` (server, reconciler, supervisor, event bus), `internal/ipc` (unix socket, peer-cred auth), `cmd/idspoofd`, systemd unit in `packaging/systemd/`.
- `Manager` refactor to many instances; wrap all existing transports unchanged; orphan reaper.
- CLI as client with direct fallback; `idspoof apply` unchanged for users.
- Exit: reboot test shows daemon up, tun2socks instance restarts after `kill -9`, `restore` leaves no NICs/rules/routes; unit tests for state machine and reaper.

Phase 2 - NICs and listeners
- `internal/datapath` (TUN via wg/tun, Linux TAP), NIC ownership and listing, listener inventory (reuse `internal/netrecon`).
- Exit: create/destroy TUN and TAP, ownership respected, no leaks on crash.

Phase 3 - composition, policy, kill-switch (Linux)
- Chain, selector, policy routing (fwmark + nft sets), dead-man firewall rollback, Mullvad coexistence tests.
- Exit: documented matrix of what coexists with Mullvad; leak test passes (no DNS or IPv6 leak with kill-switch on).

Phase 4 - TUI over API
- New panes and API client; direct-mode fallback.
- Exit: every action available in the TUI is an API call; TUI works with daemon stopped.

Phase 5 - transport expansion
- sing-box supervised transport, subscription import, geo/domain set updates with SHA-256 check, then mesh/dVPN plugins one at a time after license and security review.

Phase 6 - macOS and Windows
- launchd and SCM hosts, named-pipe IPC, TUN/SOCKS transports first; pf and WFP kill-switch and policy later.

## Reuse map (existing code to build on)

- `internal/tunnel/tunnel.go` Registry/Get/AvailableProtocols, `waitForPort`; `combo.go` chain logic to generalize.
- `internal/tunnel/tun2socks*.go` (uncommitted): config parsing (`ParseTun2socksConfig`), pidfile logic to be absorbed by the supervisor.
- `internal/state` for persisted originals and restore; `internal/platform/privilege_*.go` for root checks; `internal/netrecon` for interface/route/listener discovery; `internal/netident/iptables_linux.go` as the model for tagged, removable rules.
- `internal/spoofer` (`Options`, `Result`, `Op*`) becomes the payload of `POST /spoof/*`.
- `cmd/idspoof/tui*.go` panes reused; `root.go` gains the client/direct switch.

## Risks

- Lockout from firewall changes (happened before). Mitigation: nft table isolation, dead-man rollback, orphan reaper, dry-run default for kill-switch.
- Root daemon is a high-value target. Mitigation: unix socket only, peer-cred authz, minimal capabilities, no network listener, audit log of every mutating call.
- Scope: this is a large rewrite of the control plane. Mitigation: phases ship independently; phase 1 changes no user-visible CLI behavior.
- Mullvad kill-switch and our nft rules may conflict. Mitigation: phase 3 matrix before enabling by default.
- Cross-OS promises. Mitigation: per-OS feature matrix in README; unsupported features hidden in the TUI, not stubbed.
- Third-party transports bring licenses and unreviewed code. Mitigation: per-plugin review gate; no bundled binaries.

## Verification

- Unit: state machine, reaper (fake NIC/rule backends), chain validity, policy compiler (golden nft output), IPC authz (peer-cred stubs). Use `go test ./...`.
- Integration (Linux, root, in a network namespace or VM, not the daily host): daemon boot, tun2socks instance, `kill -9` recovery, crash then reaper, kill-switch with dead-man rollback, leak test (DNS, IPv6, WebRTC-free curl checks).
- Manual on this host: Mullvad coexistence matrix, exit proxy on 11080 beside Mullvad, TUI against the daemon.
- Release gate per phase: CHANGELOG entry, README feature matrix updated, no stray version strings.

## Open questions

1. "Network listeners": read here as local inbound proxy listeners plus a live inventory of listening sockets. If you meant something else (for example scanning listeners on other hosts), say so.
2. Daemon-down behavior: TUI falls back to direct mode (current behavior). Confirm, or require the daemon.
3. Spec saved at `docs/SPEC-v3-daemon.md` (this file).
4. Scope of "purplei25": read as `PurpleI2P/i2pd` (already wrapped by `i2p.go`). Correct me if you meant another project.

---

# Addendum A: TUI-native control on a sing-box data plane

Added after the first real TUI run. Requirement from the owner: everything is done inside the TUI, no CLI and no hand-edited config files.

## A1. What the TUI cannot do today (code read, `cmd/idspoof/tui*.go`)

- Tunnel apply passes no config path or mode, so tun2socks, WireGuard, Shadowsocks and QUIC fail with "requires --tunnel-config".
- Persona is a radio group with no "none", so Apply always changes the TCP/IP persona.
- No dry-run, no per-operation restore, no confirmation before live changes (a MAC change on the Wi-Fi interface drops the link).
- Apply and Restore run synchronously inside `Update`, so the UI freezes during slow tunnel starts.
- No live tunnel status, start/stop, or log view.
- Dashboard accuracy bugs found in the same run: the listening-ports panel showed the peer column instead of the local address (fixed in the worktree with a regression test, `probe_linux_test.go`); "VPN routed: No" while Mullvad was connected, because only the main routing table's default route is inspected and the Mullvad app routes through fwmark policy rules (not fixed, see A6).

## A2. Novel stack: Identity Profiles compiled to a sing-box config

Two ideas combined.

1. Identity Profile = one bundle of L2 identity (MAC), host identity (hostname, sysinfo), L3/L4 persona (netident) and an egress path. Applying a profile sets all of it together and restore reverts all of it. This replaces "pick tunnel, pick persona" with one object the user names, edits and switches in the TUI.
2. The egress path is a graph of nodes edited in the TUI and compiled to a sing-box JSON config. sing-box is the data plane for every protocol it supports; idspoof stays the identity and control plane. The user never sees JSON.

```
 TUI forms / paste-import  ->  Profile (YAML, root 0600)  ->  compiler  ->  sing-box JSON
                                                                 |             |
                                                    sing-box check (gate)   supervised child
                                                                 |
                                                       idspoof identity ops (existing code)
```

Input methods inside the TUI, so no file editing:
- Form per node type (proxy URL, server, port, keys, MTU) with inline validation.
- Paste box: accepts `vless://`, `ss://`, `trojan://`, `hy2://`, `tuic://`, a wg-quick `.conf`, or a sing-box JSON block, and turns it into a node.
- Subscription URL import (AntiGoblin idea), fetched through a chosen node, never directly, and stored as nodes.
- Presets for the existing wrappers (tor, i2p, wg-quick, tun2socks pivot) so they appear as nodes too.

Compiler rules:
- Node kinds map to sing-box outbounds or endpoints (WireGuard is an endpoint in current docs, "since 1.11.0"). Chain, selector and failover map to detour, selector and urltest, to be confirmed against the config reference when the compiler is written.
- A TUN inbound with `auto_route` replaces the hand-written `tun-post-up` shell lines. Per-user routing uses `include_uid` and friends (documented for the TUN inbound on Linux). The nmap-pivot case becomes a rule "uid pivot -> node X".
- The compiled config must pass `sing-box check` before a start is allowed. If the check fails the TUI shows the error against the form field, nothing is started.
- Tunnels that sing-box cannot express (Tor, I2P) stay wrapped binaries and are exposed to the graph as SOCKS nodes, as today.

tun2socks stays in the tree until the sing-box TUN path reaches parity in a sandbox test, then becomes one preset instead of a separate engine.

## A3. Where Entware and the Keenetic repos fit (scout findings, partly verified)

Read: Entware is a public package repo for embedded devices with opkg feeds (an `aarch64-k3.10` feed listing was confirmed). `keenetic/wireguard` is a GPL-2.0 kernelspace WireGuard tree, `keenetic/keenetic-sdk` is a GPL-2.0 Buildroot-based KeeneticOS build system, `keenetic/kernel-49` is a Linux 4.9 fork for MediaTek. Not confirmed: Entware's architecture list, whether sing-box, wireguard-tools, tor, i2pd or shadowsocks are in each feed, commit dates for any of the four.

Use: a headless node mode, not a dependency.
- Build the daemon for linux/mipsle, arm and arm64 with `CGO_ENABLED=0`, package as an `.ipk` installed under `/opt`, started by an Entware init script. A router running it becomes a managed egress node.
- The workstation TUI manages nodes over SSH-forwarded unix sockets. Profiles can name a node as an egress hop.
- `kernel-49` and `keenetic-sdk` are not needed unless custom firmware images are in scope. Kernel WireGuard on those routers is already provided by the vendor firmware.
- Same-subscription-format interop with AntiGoblin falls out of the paste/subscription importer for free.

## A4. Slice 1 (approved): apply and restore parity in the TUI

- Identity tab: persona gains "None"; MAC, hostname, sysinfo and persona are independent toggles; dry-run preview pane that shows the plan before any live change; confirmation dialog listing every interface that will change.
- Tunnel tab: per-tunnel config via forms and the paste box (A2); transparent or socks mode selector; saved profiles list; "Test config" runs the validation gate without starting.
- Non-blocking apply: operations run as `tea.Cmd`s that stream results to a progress panel; the UI stays responsive and the user can cancel.
- Live tunnel panel: state, pid, endpoint, last log lines, start/stop.
- Restore scoped per operation (MAC only, persona only, tunnel only, all).
- Result log pane with full error text, not one truncated line.
- Dead-man guard for anything that can cut connectivity: auto-revert after N seconds unless confirmed (from the main spec's safety rail), default on for interface-level changes.

Exit criteria: every step of the manual test in the main spec's verification section can be done without leaving the TUI; a sandboxed tmux test script drives the same flow and passes.

## A5. Open items to verify before coding the compiler

- sing-box exact license text and name-use exception wording (only secondary sources read so far).
- Whether embedding as a Go library is practical (package path, build tags, binary size) versus a supervised external binary; default stays external.
- `sing-box check` and `format` command flags, outbound type list, and routing-mark options on the route-rule page (scout hit 404s).
- Entware package availability per target architecture.

## A6. Known TUI and probe defects to fix in slice 1

- VPN-routed detection must consult policy routing (`ip rule`, per-table default routes) and the live WireGuard device, not only the main table.
- Dashboard interface and port tables need a truncation-safe layout below 100 columns.
- The tunnel pane text "Binary found in PATH" is wrong for tun2socks (embedded).
