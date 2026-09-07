---
id: ADR-0001
type: adr
title: Enforce with a dedicated nftables output chain at policy drop
status: active
owner: neolaner
created_at: 2026-09-07
last_verified_at: 2026-09-07
effective_from: 0.1.0
supersedes: null
superseded_by: null
related: [PRD-BULLSEYE-001, PRD-BULLSEYE-002, ADR-0002]
code_refs: []
test_refs: []
tags: [nftables, enforcement, architecture]
---

# [ADR-0001] Enforce with a dedicated nftables output chain at policy drop

Status: accepted
Date: 2026-09-07
Owner: neolaner
Supersedes: —

## Context and problem

A kill switch must guarantee that no packet leaves the machine outside the VPN.
Three mechanisms could plausibly deliver that: the routing table, a userspace
supervisor that watches the tunnel, or a firewall.

Routing was tried first in the shell implementation this project replaces. A TUN
VPN only *shadows* the real default route — `default dev xray_tun metric 1`
sitting on top of `default via 192.168.1.1 metric 100`. Kill the VPN process and
the metric-100 route takes over instantly. Routing expresses preference; it
cannot express prohibition.

A userspace supervisor is worse: it is a race by construction. Between the tunnel
dropping and the supervisor noticing, packets leave. Polling an HTTP endpoint to
detect the leak can only ever report a leak that already happened.

## Options considered

1. Routing table manipulation — delete the physical default route while connected.
2. A userspace watchdog that reacts to tunnel state.
3. An nftables output chain with `policy drop`, in its own table.
4. The same, but written into an existing table such as `ip filter`.

## Decision

Option 3. All rules live in `table inet bullseye`, with one `output` hook chain at
`policy drop` and an `accept` rule per hole. Arming loads the table; disarming
destroys it.

## Rationale

The kernel drops a leaking packet before it exists — no round trip, no polling
interval, no race window. Because a drop in *any* nftables table wins, bullseye
never needs to read or edit another table, which is why option 4 is rejected:
writing into `ip filter` would put bullseye in the same table as Docker's and
Tailscale's rules, where an ordering mistake breaks somebody else's networking
and disarming stops being a single clean operation.

Enforcement also outlives the program. Once the table is loaded the kill switch
holds whether or not bullseye is running, which satisfies principle 2.

Deliberately absent: a `ct state established accept` rule. Connections opened
directly over the physical interface before arming would otherwise keep leaking
through it. Tunnelled traffic already matches on `oifname`, so the rule would buy
nothing but a hole.

## Benefits

- No race window between a tunnel dying and enforcement applying.
- Disarm is one `nft destroy table`, usable with bullseye uninstalled — this is
  the escape hatch principle 3 requires.
- Other firewall users are untouched, so bullseye can be installed and removed
  without auditing the rest of the system's rules.
- `nft -j` returns structured JSON (verified on v1.1.6), so reading live state
  needs no text parsing.

## Costs and consequences

- nftables only. Systems on legacy iptables are unsupported in v0.1; Arch has
  shipped nftables as default for years, so this is acceptable for an Arch-first
  release.
- Loading rules needs root. v0.1 shells out to `sudo nft` behind a single
  function so the eventual move to polkit or a privileged helper is one change in
  one place.
- The chain is IPv4-first. IPv6 is handled wholesale — link-local and ULA
  accepted, everything else dropped — rather than with per-hole IPv6 support.

## Revisit conditions

- A target distribution ships without nftables.
- IPv6 bypass entries are requested, which needs per-hole address-family handling.
- Shelling out to `nft` becomes a measurable cost, making a netlink crate worth
  the dependency.

## Relations to Feature/Rule/Contract

Implements principles 2 and 4 of [PRD-BULLSEYE-001](../../constitution/principles.md).
Hole vocabulary is defined in [PRD-BULLSEYE-002](../../constitution/glossary.md).
The upstream hole's discovery is [ADR-0002](ADR-0002-upstream-discovery.md).
