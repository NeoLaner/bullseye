# bullseye

A customizable VPN kill switch for Linux. nftables does the enforcing, a TUI does
the driving. Works with any VPN — WireGuard, OpenVPN, xray/v2ray, Tailscale, or a
commercial client wrapping one of them.

> **Status: planning.** The design is settled and written down; no implementation
> yet. See [PLAN.md](PLAN.md).

## Escape hatch

If a kill switch ever locks you out of your own machine, this works with bullseye
stopped, broken or uninstalled:

```sh
sudo nft destroy table inet bullseye
```

## The idea

The output chain is `policy drop`. Everything else is a list of holes:

| Hole | What it is |
|---|---|
| **Tunnel** | traffic going into the VPN interface |
| **Upstream** | how the VPN process reaches its own server |
| **Bypass** | your allowlist — a single IP, a CIDR, or a domain |
| **Local** | LAN, loopback, DHCP, multicast — none of it reaches the internet |

Every VPN reduces to a tunnel interface plus an upstream. The only per-VPN
difference is how the upstream is discovered, which is why supporting a new VPN
is a function rather than a plugin.

## Planned interface

```sh
bullseye                          # TUI
bullseye arm [--dry-run] [--timeout 60]
bullseye disarm
bullseye status
bullseye allow 192.168.1.50       # a single IP
bullseye allow 203.0.113.0/24     # a CIDR
bullseye allow registry.npmjs.org # a domain
bullseye deny  <entry>
bullseye daemon                   # arm at boot, add the upstream when the VPN appears
```

## Documentation

- [PLAN.md](PLAN.md) — build stages and scope
- [knowledge/](knowledge/) — the source of truth for behaviour and decisions
  - [principles](knowledge/constitution/principles.md) — the non-negotiables
  - [glossary](knowledge/constitution/glossary.md) — the domain model
  - [ADR-0001](knowledge/decisions/adr/ADR-0001-nftables-output-drop.md) — why nftables
  - [ADR-0002](knowledge/decisions/adr/ADR-0002-upstream-discovery.md) — how any VPN is supported

## Requirements

Linux with nftables (Arch first). `nft`, `ss`, `iproute2`, systemd.

## License

MIT
