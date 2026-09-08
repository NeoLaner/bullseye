# bullseye — build plan

A customizable VPN kill switch for Linux. nftables does the enforcing, a TUI does
the driving. Arch first.

Status: stages 1-3, 5 and 6 built 2026-09-08 — it installs, runs, arms at boot and
sits in the bar. Stage 4 (drop detail) and 7 (packaging, polkit) are what is left
before v0.1 is finished.

## The idea in one paragraph

The output chain is `policy drop`. Everything else is **a list of holes**. That is
the whole program. Every VPN — WireGuard, OpenVPN, xray/v2ray, Tailscale, or a
commercial client wrapping one of them — reduces to "a tunnel interface, plus a
way out to its own server". The only thing that differs per VPN is how you
discover that second part, which keeps the generality problem small.

## The four holes

| # | Hole | What it is |
|---|------|------------|
| 1 | **Tunnel** | `oifname "wg0"` — traffic going *into* the VPN. Always on. |
| 2 | **Upstream** | How the VPN process reaches its own server. Miss it and you strangle the tunnel you are protecting. |
| 3 | **Bypass** | The user's allowlist: a single IP, a CIDR, a domain, or an app. The first three name a destination, the fourth a sender (`meta skgid`, ADR-0005). Leaves with the real IP — that is the point and the cost. |
| 4 | **Local** | LAN, loopback, DHCP, link-local, multicast. Safe: none of it routes to the internet. |

## Upstream discovery

Verified on nftables v1.1.6.

| Strategy | Mechanism | Covers | Catch |
|---|---|---|---|
| **cgroup** | `socket cgroupv2 level <depth> "system.slice/<unit>"` | systemd-managed VPNs with a *long-running* process | the cgroup must exist **and hold a process**; `level` is the path depth, and a wrong one matches nothing without erroring |
| **live sockets** | the process holding the tunnel's fd (`/proc/*/fdinfo` `iff:`), then its peers from `ss` | any userspace VPN, session-launched included | a snapshot; goes stale when the server changes |
| **wg show** | `wg show <if> endpoints` | kernel WireGuard, which the two above cannot see at all | follows a roaming peer, unlike a config file |
| **config parse** | wg `Endpoint`, ovpn `remote`, xray JSON `outbounds[]` | before the VPN has started, i.e. at boot | one small parser per format |
| **fwmark** | `meta mark & 0x00ff0000 == 0x00080000` | Tailscale, and anything that marks its own egress | only when the VPN chooses to mark |

Order of preference: **cgroup → live sockets → config parse**, and a strategy
only counts as succeeding when it can produce a match — an existing but empty
cgroup is a failure, not a success (ADR-0003).

cgroup is the prize where it applies: it allows *the process*, not an address, so
the server can change and nothing breaks.

It does not apply to kernel-mode WireGuard, and that is not an edge case —
`wg-quick@.service` is `Type=oneshot`, so systemd releases its cgroup the moment
`wg-quick up` returns, and the encapsulated packets come from the kernel with no
owning process for a cgroup or an `ss` row to name. Strategies 1 and 2 both miss
it. [ADR-0003](knowledge/decisions/adr/ADR-0003-upstream-discovery-corrections.md)
is what stage 2 builds against: a strategy counts as succeeding only when it can
actually match, which fixes WireGuard without special-casing it.

The deadlock to design around: at boot, lockdown blocks everything, so the VPN
cannot dial, so its socket never appears, so its endpoint is never learned. Config
parse is what breaks that cycle — which is why it survives as a strategy even
though it is the ugliest one. Until it resolves, the box stays closed.

For a VPN launched from a session script rather than a unit (no useful cgroup of
its own), the fix is a setup note, not code: run it under
`systemd-run --user --scope` and it gets one.

## Layout

```
src/
  main.rs      dispatch: tui | arm | disarm | status | discover | allow | deny | pin | run | config
  nft.rs       the ONLY place that shells out to nft. -j to read, -f to write, sudo behind one fn
  rules.rs     config + discovered upstream -> ruleset
  discover.rs  cgroup / ss / wg+ovpn+xray -> upstream holes; tunnel interface detection
  config.rs    TOML load/save; owns the bypass list and the pin
  tui.rs       one screen
  drops.rs     journald tail -> Drop { ts, daddr, dport, proto }          (not built)
  daemon.rs    arm at boot; re-arm when the VPN moves server; publish state
  tray.rs      StatusNotifierItem: the state in the bar, one click to change it
packaging/
  bullseye.service       system unit, root — the daemon
  bullseye-tray.service  user unit — the tray, on the user's session bus
```

## Config

```toml
# ~/.config/bullseye/config.toml
[vpn]
interface = "xray_tun"                                # auto-detected when omitted
cgroup    = "system.slice/xray.service"               # a unit whose process stays up
config    = "/opt/v2rayn-bin/binConfigs/config.json"   # fallback, used at boot
pin       = "5.6.7.8"                           # the VPN may reach this and nothing else

[bypass]
allow = ["192.168.1.50", "203.0.113.0/24", "registry.npmjs.org"]
apps  = ["firefox"]                                   # launcher list for `run` and the TUI
group = "bullseye-bypass"                             # no group on the box, no hole

[local]
lan = true
tailscale = true
```

`BULLSEYE_CONFIG` overrides the path, which is how the lockout tests run against a
config that is not the developer's own.

## Build stages

1. **done** — `nft.rs` + `rules.rs` + `arm` / `disarm` / `status`. Parity with the
   shell version it replaces, but generic. Holes come from flags until stage 3
   adds the config file.
2. **done** — `discover.rs`: tunnel detection by device type, cgroup with a
   liveness check and a derived `level`, live sockets, `wg show`, wg/ovpn/xray
   parsers. Built to
   [ADR-0003](knowledge/decisions/adr/ADR-0003-upstream-discovery-corrections.md);
   which derived cgroups are trusted is
   [ADR-0004](knowledge/decisions/adr/ADR-0004-derived-cgroup-trust.md).
3. **done** — `config.rs` + `allow` / `deny` / `pin` / `run`. IP, CIDR, domain and
   app. The config is now the normal source; the stage-2 flags override it for one
   arming and are never written back. `--upstream` became `--pin`, which is the
   same hole named for what the user is actually doing with it.
4. `drops.rs` — rate-limited `log prefix` rule, read back out of journald. The
   chain's counter already answers "is it blocking anything", which is the half the
   TUI needed; this is the half that says *what*, so `a` on a drop can allowlist it.
5. **done** — `tui.rs` — one screen: status header, bypass pane, one-line prompt.
   The drops pane arrives with stage 4.
6. **done** — `daemon.rs` + `tray.rs` + two systemd units. The table is the state
   and the daemon only maintains one that is already loaded; the tray reads what
   the daemon publishes to `/run/bullseye/state` rather than paying a `sudo` call
   (and two journal lines) per refresh.
   [ADR-0006](knowledge/decisions/adr/ADR-0006-daemon-and-tray.md) is why both.
7. PKGBUILD, polkit policy.

## Lockout guards — required from stage 1

A bug here takes the machine offline with no obvious cause, so none of this is
optional and none of it gets simplified away:

- refuse to arm when the upstream set would be empty, unless `--lockdown` says so
  on purpose — lockdown is a defined state, not an accident, and the daemon needs it
- `--dry-run` renders the ruleset and validates it with `nft -c -f`, applying nothing
  (still needs root: nft cannot initialise its cache unprivileged, even to check)
- `arm --timeout <secs>` auto-disarms unless confirmed — the standard "do not lock
  yourself out of the firewall" pattern. The revert is a transient systemd timer,
  never a thread: it has to fire when the terminal or the SSH session dies, which
  is the case it exists for
- the Tailscale hole defaults to on, so there is always a way back in — both of
  it: `oifname "tailscale0"` *and* the fwmark rule that keeps tailscaled's own
  control plane reachable. Either alone is not a way back in
- the escape hatch stays at the top of the README:
  `sudo nft destroy table inet bullseye`

## Deliberately not in v0.1

iptables backend · non-Arch packaging · GUI · IPv6 beyond block-or-allow-wholesale.

The tray was on this list — "a Waybar/SNI module already covers this" — until it
turned out that the module doing the covering was the shell script bullseye
replaces. It is stage 6 now, as a StatusNotifierItem rather than a module for one
bar: the same binary shows up in Waybar, KDE and GNOME with no per-bar config.

## Dependencies

`ratatui`, `serde_json`, `toml`, `ksni`. No netlink crate — shell out to `nft` and
parse its JSON. "No tokio, no async" held until stage 6: a StatusNotifierItem is a
D-Bus service and there is no shelling out to one, so `ksni` brings zbus and a
current-thread tokio runtime with it. bullseye's own code stays synchronous —
`ksni`'s `blocking` API is the whole of the surface it uses.

Declared per stage, not up front — stage 1 shipped needing none of them, and
`serde` was never needed on its own: the config is parsed as a `toml::Table` and
written by hand, so the file keeps its comments.
