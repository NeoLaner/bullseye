---
id: PRD-BULLSEYE-001
type: product
title: bullseye principles
status: active
owner: neolaner
created_at: 2026-09-07
last_verified_at: 2026-09-07
effective_from: 0.1.0
supersedes: null
superseded_by: null
related: [ADR-0001, ADR-0002, ADR-0003]
code_refs: [src/nft.rs, src/rules.rs, src/main.rs]
test_refs: [tests/lockout_guards.rs]
tags: [constitution, security, networking]
---

# bullseye principles

The non-negotiables. A change that breaks one of these needs a superseding ADR,
not a patch.

## 1. Fail closed

When state is unknown, block. An unconfigured, half-started, crashed or confused
bullseye leaks nothing. Every default sits on the restrictive side, and the cost
of that choice — a box with no internet until the tunnel is understood — is
accepted deliberately.

## 2. The kernel enforces, never the program

Enforcement is an nftables ruleset. bullseye writes rules and then gets out of
the way; it is not in the packet path and does not need to be running for the
kill switch to hold. Anything that polls an HTTP endpoint to detect a leak is a
gauge, not a gate: it can only ever notice a leak that already happened.

## 3. Never lock the user out

A kill switch bug takes a machine offline with no obvious cause, which is worse
than a leak because the user cannot even research the fix. Therefore: a dry run
that applies nothing, an arm timeout that reverts itself, a remote-access hole
that defaults to open, and a documented one-line escape hatch that works with
bullseye uninstalled.

## 4. Own table, only ever additive

All rules live in `table inet bullseye`. A drop in any nftables table wins, so
bullseye never needs to modify anyone else's table and never does. Docker's and
Tailscale's rules are left exactly as found. Disarming is a single table destroy.

## 5. Every allowance is a hole, and is named as one

Traffic leaving outside the tunnel carries the user's real address. The interface
says so plainly rather than presenting bypasses as ordinary configuration, and
the UI shows when holes are open.

## 6. Any VPN, no plugin system

Support comes from reducing every VPN to "a tunnel interface plus an upstream",
not from an extension mechanism. Adding a VPN means teaching the discovery step
one more way to find an upstream — a function, not a plugin.
