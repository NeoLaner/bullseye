---
id: ADR-0006
type: adr
title: The table is the desired state, and the daemon publishes what the tray draws
status: proposed
owner: neolaner
created_at: 2026-09-08
last_verified_at: 2026-09-08
effective_from: 0.1.0
supersedes: null
superseded_by: null
related: [PRD-BULLSEYE-001, PRD-BULLSEYE-002, ADR-0003, ADR-0004]
code_refs: [src/daemon.rs, src/tray.rs, packaging/bullseye.service, packaging/bullseye-tray.service]
test_refs: [src/daemon.rs, src/tray.rs]
tags: [daemon, tray, boot, ui]
---

# [ADR-0006] The table is the desired state, and the daemon publishes what the tray draws

Status: proposed
Date: 2026-09-08
Owner: neolaner
Supersedes: —

## Context and problem

Stage 6 adds two processes that were one program's worth of behaviour before: a
daemon that arms at boot and re-arms when the VPN moves server, and a tray icon
that shows the state and toggles it.

They cannot be the same process. The kill switch needs root, because nftables
does; the tray needs the user's session bus, because that is where a
StatusNotifierItem lives, and root's bus is not it. So there are two, and three
questions follow that the rest of bullseye had not had to answer.

**Who decides whether the box should be armed?** A daemon that re-arms on a timer
and a user who just clicked *disarm* are a fight. Any answer that stores a
*desired* state — a flag file, a unit being started or stopped, a field in an IPC
message — puts a second source of truth next to the one the glossary already
names, and the two can disagree.

**What does the tray read?** `nft list` needs root, so every read from the tray is
a `sudo` call, and sudo writes two journal lines per call. Measured on the
development box: 2 lines a call, which at a five-second refresh is ~34k lines a
day to draw one icon. The shell implementation bullseye replaces hit this and
worked around it with a marker file in `/run` that could desync from the kernel.

**When may the daemon narrow the ruleset?** Discovery can fail — a VPN that is
merely down looks exactly like one that was never there. Re-arming on that answer
seals the VPN away from its own server, and a VPN that cannot dial out can never
be discovered again. The box has no way to fix itself.

## Options considered

1. A desired-state file the daemon and the tray both write, and the daemon
   reconciles the kernel to.
2. `systemctl start`/`stop` on the daemon's unit as the toggle, with polkit for
   the privilege, and `ExecStop=bullseye disarm`.
3. The nftables table itself as the state, with the daemon *maintaining* an armed
   ruleset and never creating one it did not find.

## Decision

**Option 3.** `table inet bullseye` is the state, exactly as the glossary already
says — armed or disarmed, no third. The daemon arms once at startup and thereafter
only replaces a ruleset that is already loaded. A disarmed box stays disarmed
until something arms it, and `systemctl restart bullseye` is one of the things
that can.

Three rules follow, and are the whole of the daemon:

- **It never re-arms a disarmed box.** Disarming is a decision, not a fault.
- **It never narrows to lockdown once it has armed with a real upstream.** Stale
  holes stay open instead: one address the user already approved, against a box
  that cannot dial out to correct itself.
- **It never follows a pin.** A pin is a promise about where the traffic goes, so
  a VPN that reconnected elsewhere is reported as a mismatch and left blocked.
  This falls out of the design rather than being enforced: with a pin the rendered
  ruleset does not change when the server does, so there is nothing to re-arm.

The daemon publishes a state word and the report the CLI prints to
`/run/bullseye/state`, and the tray reads that instead of asking nft. The daemon
runs as root, so writing it costs no `sudo` and no journal line. The file is the
unit's `RuntimeDirectory`, so it is removed when the daemon stops — a tray that
finds no file asks the kernel itself, rarely, and says in its tooltip that nothing
is maintaining the ruleset.

**Neither stopping the daemon nor quitting the tray disarms.** Principle 2 already
says bullseye does not need to be running for the kill switch to hold; a unit with
`ExecStop=bullseye disarm` would make that false, and would leave the machine
unprotected whenever the daemon crashed.

## Rationale

The reconciliation loop in option 1 is the standard shape and the wrong one here.
Every desired-state store is a claim about the world that can be false, and the
failure it produces is the worst one bullseye has: a box whose firewall does not
match what anything says about it. Option 3 has nothing to desync, because it
keeps no opinion — it reads the kernel each tick and the kernel is the answer.

Option 2 was attractive because `systemctl is-active` is free and unprivileged and
polkit already covers the privilege. It fails on the third principle: it makes
"the daemon is not running" and "the kill switch is off" the same state, so a
crash, an OOM kill or a botched upgrade silently unprotects the machine.

## Consequences

- Restarting the daemon re-arms, including a box the user had deliberately
  disarmed. This is deliberate — it is what "arm at boot" means — and it is the
  documented way to arm from outside the UI. It also resets the drop counter, so a
  crash-looping daemon resets it repeatedly.
- The tray falls back to asking nft when no daemon is running, and in that mode it
  can only tell armed from disarmed: distinguishing *armed* from *armed and
  working* means running discovery, which from the tray is more `sudo` than a
  status icon is worth. It says so rather than guessing.
- `ksni` brings zbus and a tokio runtime, which is where PLAN's "no tokio, no
  async" ends. A StatusNotifierItem is a D-Bus service and there is no shelling
  out to one; the alternative was a module for one bar, which is not what "works
  with any desktop" means.
- The tray and the TUI shell out to `sudo` with their streams piped, so a box with
  no NOPASSWD rule for `nft` gets an error rather than an invisible prompt. A
  polkit policy is the fix and is stage 7.
