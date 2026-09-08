---
id: ADR-0002
type: adr
title: Discover the VPN upstream by cgroup, then live sockets, then config parse
status: superseded
owner: neolaner
created_at: 2026-09-07
last_verified_at: 2026-09-07
effective_from: 0.1.0
supersedes: null
superseded_by: ADR-0003
related: [PRD-BULLSEYE-001, PRD-BULLSEYE-002, ADR-0001, ADR-0003]
code_refs: []
test_refs: []
tags: [nftables, cgroup, vpn-support, architecture]
---

# [ADR-0002] Discover the VPN upstream by cgroup, then live sockets, then config parse

Status: superseded
Date: 2026-09-07
Owner: neolaner
Supersedes: —
Superseded by: [ADR-0003](ADR-0003-upstream-discovery-corrections.md)

> **History only — do not implement from this document.** Three of the specifics
> below were disproved against a live system: the cgroup example cannot load, the
> `level` is not a constant, and Tailscale needs an upstream hole of its own. The
> shape of the decision — three strategies, first success wins, no plugin system —
> survives in ADR-0003. The text below is left exactly as it was accepted.

## Context and problem

The upstream hole — how the VPN process reaches its own server — is the only part
of the ruleset that differs between VPNs, and the only one that cannot be derived
from the interface alone. Get it wrong in the permissive direction and traffic
leaks; get it wrong in the restrictive direction and the kill switch strangles
the tunnel it exists to protect, taking the machine offline with no obvious cause.

The goal of supporting "any VPN" lives entirely in this decision. Everything else
in the ruleset is identical across WireGuard, OpenVPN, xray/v2ray and Tailscale.

## Options considered

All three were tested against a live system on nftables v1.1.6.

1. **cgroup match** — `socket cgroupv2 level 2 "system.slice/wg-quick@wg0.service"`.
   Syntax accepted. The path must already exist when the rule loads: the same rule
   naming a stopped unit fails with `cgroupv2 path fails: No such file or
   directory`, so this cannot be written speculatively.
2. **Live socket inspection** — `ss -tunp`, taking the destinations of the VPN
   process's sockets that are not on the tunnel interface. Confirmed working
   against a session-launched xray, which reported its true upstream
   (`4.3.2.1:443`) with no knowledge of xray's config format.
3. **Config parsing** — WireGuard `Endpoint`, OpenVPN `remote`, xray
   `outbounds[].settings`. Exact, available before the VPN starts, and needs one
   parser per format.
4. **`meta skuid`** — match the VPN's user id. Rejected: on a desktop the VPN and
   everything else run as the same user, so it allows the entire session out.

## Decision

Try all three, in order: **cgroup → live sockets → config parse**, first success
wins. Not a plugin system, not a trait with one implementation — one function
with three strategies, per principle 6.

## Rationale

cgroup is preferred because it allows *the process*, not an address. The VPN can
change server, rotate endpoints or reconnect anywhere and the rule stays correct,
which removes the staleness that both other strategies carry. systemd creates the
unit's cgroup before the process dials, so it exists in time.

Live sockets is the universal fallback because it asks the kernel what the VPN is
actually talking to rather than what a config file says it might. It needs no
per-VPN knowledge at all, which is what makes an unknown VPN work on day one.

Config parsing survives, despite being the ugliest option, because it is the only
one that answers before the VPN has started. That matters for exactly one case,
below.

**The boot deadlock.** At boot the ruleset is armed in lockdown, so the VPN cannot
dial, so no socket appears, so the upstream is never learned, so lockdown never
lifts. cgroup breaks the cycle for systemd-managed VPNs and config parse breaks
it for the rest. Until one of them resolves, the box stays closed — correct
behaviour under principle 1, not a failure.

**Session-launched VPNs.** A VPN started from a session script inherits the
session's cgroup, shared with every other user process, so cgroup matching is
useless for it. The remedy is a setup instruction rather than code: run it under
`systemd-run --user --scope` and it gets a cgroup of its own.

## Benefits

- An unrecognised VPN works with no code changes, via strategy 2.
- Systemd-managed VPNs survive a server change with no re-arm, via strategy 1.
- Adding VPN support is a function, not an extension point.

## Costs and consequences

- Three code paths for one answer, each needing its own test.
- Strategies 2 and 3 produce address snapshots that go stale when the server
  changes; the daemon re-checks and adds addresses to the set while armed, which
  is a single atomic `nft add element`.
- Config parsers track upstream file formats and will occasionally break.
- The `ss` strategy needs the VPN running, so first-arm ordering matters for
  anything not under systemd.

## Revisit conditions

- cgroup v2 matching becomes universally available for user-session processes,
  making strategies 2 and 3 removable.
- A VPN appears that fits none of the three.
- Snapshot staleness proves to bite in practice more than the daemon's re-check
  handles.

## Relations to Feature/Rule/Contract

Fills the upstream hole defined in [PRD-BULLSEYE-002](../../constitution/glossary.md).
Enforcement mechanism is [ADR-0001](ADR-0001-nftables-output-drop.md).
Implements principles 1 and 6 of [PRD-BULLSEYE-001](../../constitution/principles.md).
