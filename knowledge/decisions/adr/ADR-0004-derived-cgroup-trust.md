---
id: ADR-0004
type: adr
title: Trust a derived cgroup only under system.slice
status: proposed
owner: neolaner
created_at: 2026-09-08
last_verified_at: 2026-09-08
effective_from: 0.1.0
supersedes: null
superseded_by: null
related: [PRD-BULLSEYE-001, PRD-BULLSEYE-002, ADR-0002, ADR-0003]
code_refs: [src/discover.rs]
test_refs: [tests/lockout_guards.rs]
tags: [cgroup, vpn-support, security]
---

# [ADR-0004] Trust a derived cgroup only under system.slice

Status: proposed — needs the owner's decision.
Date: 2026-09-08
Owner: neolaner
Supersedes: —

## Context and problem

[ADR-0003](ADR-0003-upstream-discovery-corrections.md) makes the cgroup strategy
work by requiring the cgroup to hold a process. It does not say where the cgroup
path comes from when the user has not supplied one.

Stage 2 derives it: the process holding the tunnel's fd is found through
`/proc/<pid>/fdinfo` (a TUN fd reports its interface as `iff:`), and that
process's cgroup is read from `/proc/<pid>/cgroup`. That identifies the VPN with
no per-VPN knowledge at all — no process name, no unit name, no config.

The derived path is not always safe to match on. Measured on this machine, xray
reports `user.slice/user-1000.slice/session-2.scope`: the desktop session's own
cgroup, shared with every other process the user is running. Matching it would
allow the entire session out of the kill switch — the same failure that made
ADR-0002 reject `meta skuid`, arrived at from a different direction.

## Options considered

1. Trust any derived cgroup. Rejected: leaks the whole session, as above.
2. Trust a derived cgroup only under `system.slice/`.
3. Verify that every pid in the cgroup belongs to the tunnel's owning process
   tree, and trust any cgroup that passes.

## Decision

Option 2. A cgroup path bullseye derived itself is used only when it begins
`system.slice/`. Anything else falls through to the next strategy, which answers
with addresses rather than a process. A path the user supplies with `--cgroup` is
honoured wherever it points, subject to ADR-0003's liveness check.

## Rationale

`system.slice/<unit>` is a single system service by construction, so the set of
processes it matches is the service. A user-session path carries no such
guarantee, and the cost of being wrong is a silent, total bypass — the direction
principle 1 says never to err in.

Option 3 is more precise and would cover the `systemd-run --user --scope` case
automatically, but it is a process-tree walk guarding against a case that already
has a one-flag answer. It is the upgrade path, not the starting point.

## Benefits

- Auto-discovery cannot open the session-wide hole that ADR-0002 warned about.
- Falling through costs nothing: the socket strategy answers for exactly these
  VPNs, and was verified doing so.

## Costs and consequences

- A VPN under `systemd-run --user --scope` — the remedy ADR-0002 and ADR-0003
  both recommend for session-launched VPNs — is **not** auto-discovered by
  cgroup. It needs `--cgroup` naming it, or it falls through to live sockets.
  Both ADRs read as though that remedy restores automatic cgroup matching; it
  restores it only when asked for explicitly.
- Discovery needs root: reading another user's `fdinfo` is privileged, and most
  VPNs run as root.

## Revisit conditions

- Session-scoped VPNs become common enough that option 3 pays for itself.
- systemd changes how user scopes are nested.

## Relations to Feature/Rule/Contract

Constrains the cgroup strategy of
[ADR-0003](ADR-0003-upstream-discovery-corrections.md). Implements principle 1 of
[PRD-BULLSEYE-001](../../constitution/principles.md).
