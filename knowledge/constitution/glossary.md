---
id: PRD-BULLSEYE-002
type: product
title: bullseye glossary
status: active
owner: neolaner
created_at: 2026-09-07
last_verified_at: 2026-09-08
effective_from: 0.1.0
supersedes: null
superseded_by: null
related: [PRD-BULLSEYE-001, ADR-0001, ADR-0002, ADR-0003, ADR-0004, ADR-0005]
code_refs: [src/rules.rs, src/discover.rs, src/config.rs]
test_refs: [src/rules.rs, src/config.rs]
tags: [constitution, glossary, domain-model]
---

# bullseye glossary

The domain model. These four hole types are what makes "works with any VPN" a
small problem instead of a large one, so the words are used exactly.

## Hole

A single `accept` rule in an otherwise `policy drop` chain. bullseye's entire job
is deciding which holes exist. There are exactly four kinds.

### Tunnel hole

`oifname "<tunnel>"` — traffic entering the VPN interface. Always present; without
it the kill switch blocks the tunnel and nothing works. Safe by construction:
whatever leaves this way is encrypted and exits at the VPN's address.

### Upstream hole

How the VPN process itself reaches its server. It must escape the tunnel — a VPN
cannot route its own transport through itself — so it is the one hole that
carries the user's real address by necessity rather than by choice. Getting it
wrong strangles the tunnel bullseye exists to protect. Discovery is
[ADR-0003](../decisions/adr/ADR-0003-upstream-discovery-corrections.md), which
supersedes [ADR-0002](../decisions/adr/ADR-0002-upstream-discovery.md).

Tailscale is a VPN like any other and therefore has both holes, not one: a
tunnel hole `oifname "tailscale0"` for tailnet traffic, and an upstream hole for
tailscaled's own control-plane, DERP and STUN egress, which leaves on the
physical link. That upstream is found by fwmark —
`meta mark & 0x00ff0000 == 0x00080000` — not by the three strategies above.
Both are needed: with only the tunnel hole the tailnet dies, and principle 3's
way back into a locked-out box dies with it.

### Bypass hole

Something the user has deliberately excluded from the tunnel. Every bypass leaks
the real address on purpose, which is why the interface never calls one anything
softer than a hole.

Three of the four kinds name a **destination**: a **single IP address**, a **CIDR
range**, or a **domain**. Domains are resolved to addresses when the ruleset is
built, because nftables sets hold addresses and not names — so a bypass covers
the addresses a name had at arm time, and a rotating CDN outgrows it.

The fourth names a **sender**: an **app bypass**, matched as
`meta skgid <gid>` against a dedicated unix group. `bullseye run <command>`
starts a command with that group as its primary group, and only a fresh process
is affected — an already-running program keeps the group it started with, and one
that hands work to a running daemon leaves through that daemon's group instead.
No group on the machine means no hole at all.
[ADR-0005](../decisions/adr/ADR-0005-app-bypass-by-group.md) is why it is a group
rather than a cgroup or a uid.

A bypass is a hole in the *filter*, not a route: it says the packet may leave. On
a VPN that owns the default route the packet still enters the tunnel, and the
destination has to be excluded in the VPN's own routing too.

### Local hole

RFC1918 ranges, CGNAT space, loopback, link-local, DHCP broadcast and multicast.
Safe to allow unconditionally because none of it routes to the internet, so none
of it can expose a public identity.

## Pin

The upstream, fixed by the user to one address instead of discovered. Pinning is a
promise about where the traffic goes: the VPN may reach that server and no other,
so a VPN that reconnects somewhere else finds its own transport blocked and the
tunnel does not come back up. That is the intended outcome, not a failure — the
alternative is a hole that quietly follows the VPN to a server the user never
approved.

The gap between a pin and what the VPN is actually doing is a **mismatch**, and
it is reported wherever state is shown, because "nothing works" is otherwise
indistinguishable from a broken kill switch.

## Armed / disarmed

**Armed** means `table inet bullseye` exists and its output chain has
`policy drop`. **Disarmed** means the table does not exist. There is no third
state; the table is created and destroyed whole.

## Lockdown

Armed with no upstream hole yet — every egress path closed, including the VPN's
own. The deliberate boot state, held until the upstream is discovered. Correct,
not a failure.

## Drop

A packet the kill switch refused. Surfaced through a rate-limited nftables `log`
rule read back from journald. A drop is the primary signal for the user: it names
a destination that wanted out and did not get there, which is either the kill
switch working or a bypass waiting to be added.

## Tunnel interface

The link the VPN creates — `wg0`, `tun0`, `xray_tun`, `tailscale0`. Detected from
interface type rather than name, since the name is a per-VPN convention.
