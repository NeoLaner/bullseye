---
id: PRD-BULLSEYE-002
type: product
title: bullseye glossary
status: active
owner: neolaner
created_at: 2026-09-07
last_verified_at: 2026-09-07
effective_from: 0.1.0
supersedes: null
superseded_by: null
related: [PRD-BULLSEYE-001, ADR-0001, ADR-0002]
code_refs: []
test_refs: []
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
[ADR-0002](../decisions/adr/ADR-0002-upstream-discovery.md).

### Bypass hole

A destination the user has deliberately excluded from the tunnel: a **single IP
address**, a **CIDR range**, or a **domain**. Domains are resolved to addresses
when the ruleset is built, because nftables sets hold addresses and not names —
so a bypass covers the addresses a name had at arm time, and a rotating CDN
outgrows it. Every bypass leaks the real address to that destination on purpose.

### Local hole

RFC1918 ranges, CGNAT space, loopback, link-local, DHCP broadcast and multicast.
Safe to allow unconditionally because none of it routes to the internet, so none
of it can expose a public identity.

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
