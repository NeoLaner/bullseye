# bullseye — build plan

A customizable VPN kill switch for Linux. nftables does the enforcing, a TUI does
the driving. Arch first.

Status: plan approved 2026-09-07, no implementation started.

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
| 3 | **Bypass** | The user's allowlist: a single IP, a CIDR, or a domain. Leaves with the real IP — that is the point and the cost. |
| 4 | **Local** | LAN, loopback, DHCP, link-local, multicast. Safe: none of it routes to the internet. |

## Upstream discovery

Verified on nftables v1.1.6.

| Strategy | Mechanism | Covers | Catch |
|---|---|---|---|
| **cgroup** | `socket cgroupv2 level 2 "system.slice/wg-quick@wg0.service"` | any systemd-managed VPN | the cgroup path must already exist when the rule loads |
| **live sockets** | `ss -tunp` → the VPN process's non-tunnel destinations | everything, including session-launched daemons | a snapshot; goes stale when the server changes |
| **config parse** | wg `Endpoint`, ovpn `remote`, xray JSON `outbounds[]` | before the VPN has started, i.e. at boot | one small parser per format |

Order of preference: **cgroup → live sockets → config parse.**

cgroup is the prize: it allows *the process*, not an address, so the server can
change and nothing breaks. systemd creates the cgroup when the unit starts and
before it dials, so there is no ordering problem.

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
  main.rs      dispatch: tui | arm | disarm | status | allow | deny | daemon
  nft.rs       the ONLY place that shells out to nft. -j to read, -f to write, sudo behind one fn
  rules.rs     config + discovered upstream -> ruleset
  discover.rs  cgroup / ss / wg+ovpn+xray -> upstream holes; tunnel interface detection
  config.rs    TOML load/save; owns the bypass list
  drops.rs     journald tail -> Drop { ts, daddr, dport, proto }
  tui.rs       one screen
  daemon.rs    arm at boot, watch for the VPN, add the upstream hole when it appears
```

## Config

```toml
# ~/.config/bullseye/config.toml
[vpn]
interface = "xray_tun"                                # auto-detected when omitted
cgroup    = "system.slice/wg-quick@wg0.service"        # preferred when systemd-managed
config    = "/opt/v2rayn-bin/binConfigs/config.json"   # fallback, used at boot

[bypass]
allow = ["192.168.1.50", "203.0.113.0/24", "registry.npmjs.org"]

[local]
lan = true
tailscale = true
```

## Build stages

1. `nft.rs` + `rules.rs` + `arm` / `disarm` / `status`. Parity with the shell
   version it replaces, but generic. Testable on day one.
2. `discover.rs` — cgroup, `ss`, wg/ovpn/xray parsers. Where "any VPN" becomes real.
3. `config.rs` + `allow` / `deny`. Single IP, CIDR, domain.
4. `drops.rs` — rate-limited `log prefix` rule, read back out of journald.
5. `tui.rs` — one screen: status header, bypass pane, live-drops pane. `a` on a
   drop allowlists it. This interaction is the only reason a TUI beats `nft -j list`.
6. `daemon.rs` + systemd unit — boot arming.
7. PKGBUILD, README, polkit policy.

## Lockout guards — required from stage 1

A bug here takes the machine offline with no obvious cause, so none of this is
optional and none of it gets simplified away:

- refuse to arm when the upstream set would be empty
- `--dry-run` renders the ruleset and validates it with `nft -c -f`, applying nothing
- `arm --timeout <secs>` auto-disarms unless confirmed — the standard "do not lock
  yourself out of the firewall" pattern
- the Tailscale hole defaults to on, so there is always a way back in
- the escape hatch stays at the top of the README:
  `sudo nft destroy table inet bullseye`

## Deliberately not in v0.1

Tray icon (a Waybar/SNI module already covers this) · iptables backend · non-Arch
packaging · GUI · IPv6 beyond block-or-allow-wholesale.

## Dependencies

`ratatui`, `serde`, `serde_json`, `toml`. No tokio, no async, no netlink crate —
shell out to `nft` and parse its JSON. Declared per stage, not up front.
