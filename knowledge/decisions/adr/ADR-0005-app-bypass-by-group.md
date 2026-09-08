---
id: ADR-0005
type: adr
title: An app bypass is a unix group, not a cgroup or a uid
status: accepted
owner: neolaner
created_at: 2026-09-08
last_verified_at: 2026-09-08
effective_from: 0.1.0
supersedes: null
superseded_by: null
related: [PRD-BULLSEYE-001, PRD-BULLSEYE-002, ADR-0002, ADR-0003]
code_refs: [src/rules.rs, src/main.rs, src/discover.rs]
test_refs: [src/rules.rs]
tags: [bypass, cgroup, security]
---

# [ADR-0005] An app bypass is a unix group, not a cgroup or a uid

Status: accepted
Date: 2026-09-08
Owner: neolaner
Supersedes: —

## Context and problem

A bypass hole names a destination. "Let this application out" names a sender
instead, so it needs a different kind of match: something the kernel can attribute
a socket to, that the user can put a process into on purpose, and that no other
process falls into by accident.

The upstream hole already matches a sender by cgroup, so cgroup is the obvious
first answer. It does not survive contact with the problem.

## Options considered

1. **cgroup v2** — `socket cgroupv2 level N "<path>"`, as the upstream hole uses.
2. **uid** — a dedicated user, `meta skuid`, and `ip rule uidrange` for routing.
3. **gid** — a dedicated group, `meta skgid`, and the app launched with it as its
   primary group.

## Decision

A dedicated unix group — `bullseye-bypass` by default — matched with
`meta skgid <gid>`. `bullseye run <command>` launches the command with that group
as its primary group via `sudo -u <user> -g <group>`. The hole exists only when
the group exists on the machine.

## Rationale

cgroup fails on rule loading, not on matching. nft resolves a cgroup path to an
id when the rule is **loaded**, so a rule naming an app's scope will not load
while the app is not running — and an app bypass is for apps that are not running
yet. Keeping a cgroup alive to hold the path open means a permanent placeholder
process, which is a daemon in a project whose whole point is that nothing has to
be running for the kill switch to hold (principle 2).

uid works, and `ip rule uidrange` would make policy routing possible later, but it
costs the user their own session: an app under a different uid loses their home
directory, their X or Wayland authority, and their dbus session. A kill switch
should not make a browser unusable.

gid keeps the uid, the home directory and the supplementary groups — verified:
`sudo -u neo -g docker` reports `gid=docker groups=docker wheel neo` — and
`meta skgid` matches the socket's owning group, which is the primary gid. Verified
against nftables v1.1.6 with a counter-only probe table: five packets from a
process launched that way matched `meta skgid 967`.

## Benefits

- The rule loads whether or not anything is running in the group, so the hole is
  as static as every other rule in the table.
- The app keeps the user's session, so a GUI app actually starts.
- No new daemon, no cgroup lifecycle to manage, no privileged helper beyond the
  sudo bullseye already needs.
- Absent group means absent hole: the default install opens nothing.

## Costs and consequences

- It is one hole for a class of processes, not one hole per app. Anything started
  with `bullseye run` bypasses; the `apps` list in the config is a launcher, not
  an allowlist the kernel enforces.
- Only a **fresh** process is affected. An already-running browser keeps the group
  it started with, and a command that hands work to a running daemon leaves
  through that daemon's group instead.
- It is a filter hole, not a route. On a VPN that owns the default route the
  packet is permitted but still goes into the tunnel; split routing by mark is a
  separate change and is not in v0.1.
- `sudo -g` needs a sudoers policy that permits a target group. The common
  `%wheel ALL=(ALL:ALL) ALL` does; a narrower `(ALL)` form does not.

## Revisit conditions

- If split routing lands, uid becomes cheaper than gid, because `ip rule` can
  select on uidrange and has nothing for gid. Revisit as one decision with it.
- If per-app holes are ever wanted as separate rules, revisit — one group cannot
  express them.

## Relations to Feature/Rule/Contract

Extends the Bypass hole in [glossary](../../constitution/glossary.md).
Constrained by principles 2 and 5 in
[principles](../../constitution/principles.md).
