---
id: ADR-0003
type: adr
title: Correct upstream discovery for kernel-mode tunnels, cgroup depth and Tailscale
status: active
owner: neolaner
created_at: 2026-09-07
last_verified_at: 2026-09-07
effective_from: 0.1.0
supersedes: ADR-0002
superseded_by: null
related: [PRD-BULLSEYE-001, PRD-BULLSEYE-002, ADR-0001, ADR-0002, ADR-0004]
code_refs: [src/rules.rs, src/discover.rs]
test_refs: [src/rules.rs, tests/lockout_guards.rs]
tags: [nftables, cgroup, wireguard, tailscale, vpn-support, architecture]
---

# [ADR-0003] Correct upstream discovery for kernel-mode tunnels, cgroup depth and Tailscale

Status: accepted
Date: 2026-09-07
Owner: neolaner
Supersedes: [ADR-0002](ADR-0002-upstream-discovery.md)

All four corrections are built. Stage 1 shipped the fwmark mechanism and
Tailscale's second hole (`src/rules.rs`); stage 2 shipped the cgroup liveness
check, the derived `level`, and the `wg show` source (`src/discover.rs`). Where a
derived cgroup path is trusted is [ADR-0004](ADR-0004-derived-cgroup-trust.md).

## Context and problem

ADR-0002 was re-checked against a live Arch system before stage 2 was written.
Its shape survives — three strategies, first success wins, no plugin system — but
three of its specifics are wrong, and one of them fails silently in the direction
that takes a machine offline.

All findings below are measurements on this host, not reasoning:
nftables v1.1.6, systemd 261, iproute2 7.2.0, wireguard-tools 1.0.20260223.

### Finding 1 — the cgroup example cannot load, and cannot ever match

`wg-quick@.service` is `Type=oneshot` with `RemainAfterExit=yes`. Every active
unit of that shape on this host has **no cgroup directory**: systemd releases the
cgroup when the process exits, and `wg-quick up` exits as soon as the link is
configured. `nft` resolves the path in userspace and refuses to load:

```
Error: cgroupv2 path fails: No such file or directory
  socket cgroupv2 level 2 "system.slice/wg-quick@wg0.service"
```

That exact rule is ADR-0002's headline example, PLAN.md's table entry and
PLAN.md's config sample.

The deeper problem outlives the example. Kernel-mode WireGuard encapsulates and
sends from the kernel, so its packets are attributable to no userspace process.
No cgroup rule can match them, and `ss -tunp` reports no owning process either —
its UDP socket is unconnected, so it carries no peer address to read. **Both**
strategy 1 and strategy 2 fail for the VPN the ADR chose as its example, leaving
only strategy 3, which ADR-0002 ranks last.

### Finding 2 — `level` is a function of the path, and a wrong one is silent

`level` must equal the depth of the path being matched. nft accepts a mismatched
level without complaint — `level 1` against a two-segment path parses, loads, and
then matches nothing. A hardcoded level produces a kill switch that strangles the
VPN with no error anywhere.

ADR-0002's own remedy for session-launched VPNs makes this concrete:
`systemd-run --user --scope` yields
`user.slice/user-1000.slice/user@1000.service/app.slice/<name>.scope`, which is
level **5**, not the level 2 the config sample hardcodes.

### Finding 3 — Tailscale is a VPN with two holes, and only one was documented

`oifname "tailscale0"` carries tailnet traffic. It does not carry tailscaled's own
control-plane, DERP and STUN egress, which leaves on the physical link and is
therefore dropped. The tunnel then dies, and with it the remote access that
principle 3 requires as the way back into a locked-out box.

The shell implementation this project replaces already had the answer, and no
document records it: `meta mark & 0x00ff0000 == 0x00080000 accept`. `ip rule`
confirms the mark — `from all fwmark 0x80000/0xff0000`. Tailscale marks its own
egress, which is a fourth discovery mechanism, exact and stateless.

### Finding 4 — two active documents disagree about arming with no upstream

PLAN.md requires arm to "refuse when the upstream set would be empty".
[PRD-BULLSEYE-002](../../constitution/glossary.md) defines exactly that state as
**Lockdown**, "the deliberate boot state", and ADR-0002 depends on reaching it to
break the boot deadlock. Both cannot hold.

## Options considered

1. Keep ADR-0002's ordering and add WireGuard as a special case inside strategy 3.
2. Reorder to put config parse first for kernel-mode tunnels, detected by tunnel type.
3. Keep the ordering, but make each strategy *prove* it can match before it counts
   as a success, and add the two missing mechanisms.

## Decision

Option 3, as four corrections to ADR-0002:

- **A strategy succeeds only when it can produce a match, not merely a rule.** The
  cgroup strategy requires an existing cgroup path *containing at least one
  process*; an empty cgroup is a failure and falls through. This alone fixes
  WireGuard without special-casing it.
- **`level` is computed from the path**, never configured. `config.cgroup` stays a
  path; the depth is derived from it.
- **`wg show <iface> endpoints` is added as a WireGuard-specific runtime source**,
  ranked with live sockets. It is the only runtime reading that tracks a roaming
  WireGuard peer, and it needs no config file.
- **fwmark is added as a discovery mechanism**, used for Tailscale
  (`0x80000/0xff0000`) and available to any VPN that marks its own egress. The
  Tailscale hole is a tunnel hole *and* an upstream hole, not a local one.

On finding 4: the glossary is the more fundamental document, so lockdown stays.
An interactive `arm` refuses an empty upstream; `--lockdown` and the daemon opt
into it explicitly. Stage 1 already implements this reading.

## Rationale

"A strategy that cannot match is a strategy that failed" replaces a per-VPN
special case with one rule that happens to cover kernel WireGuard, oneshot units,
and any future tunnel with no userspace sender. That keeps principle 6 intact:
still a function with strategies, still no plugin system.

Deriving `level` removes a silent-failure mode entirely rather than documenting a
trap, which principle 3 requires of anything that can take a box offline quietly.

fwmark is exact where a socket snapshot is a guess, and stateless where a cgroup
path is fragile. It is only available when a VPN chooses to mark, which is why it
is an addition and not a replacement.

## Benefits

- Kernel-mode WireGuard works, which it did not under ADR-0002 as written.
- A wrong cgroup level becomes impossible instead of undiagnosable.
- The remote-access escape hatch actually stays up, restoring parity with the
  shell implementation.

## Costs and consequences

- The cgroup strategy gains a liveness check — reading `cgroup.procs` — so it is
  no longer a pure "does the path exist" test.
- One more mechanism (fwmark) and one more runtime source (`wg show`) to test.
- `wg show` needs `wireguard-tools`, which is already a `wg-quick` dependency, so
  it adds no install-time cost for the case that uses it.

## Revisit conditions

- A userspace WireGuard implementation (wireguard-go, boringtun) becomes the
  common case, at which point the cgroup strategy covers it and the `wg show`
  source can be dropped.
- Tailscale changes its egress fwmark.

## Relations to Feature/Rule/Contract

Supersedes [ADR-0002](ADR-0002-upstream-discovery.md). Fills the upstream hole defined
in [PRD-BULLSEYE-002](../../constitution/glossary.md). Enforcement is
[ADR-0001](ADR-0001-nftables-output-drop.md). Implements principles 1, 3 and 6 of
[PRD-BULLSEYE-001](../../constitution/principles.md).
