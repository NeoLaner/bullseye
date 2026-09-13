# bullseye

<img src="packaging/bullseye.svg" width="88" align="right" alt="">

A customizable VPN kill switch for Linux. nftables does the enforcing, a TUI does
the driving. Works with any VPN — WireGuard, OpenVPN, xray/v2ray, Tailscale, or a
commercial client wrapping one of them.

## Escape hatch

If a kill switch ever locks you out of your own machine, this works with bullseye
stopped, broken or uninstalled:

```sh
sudo nft destroy table inet bullseye
```

## Install

Arch, or anything with nftables and systemd.

```sh
cargo build --release
sudo install -Dm755 target/release/bullseye /usr/local/bin/bullseye
sudo ln -sf bullseye /usr/local/bin/be                 # `be` is the short name

# only if you want apps to bypass the kill switch:
sudo groupadd -f bullseye-bypass && sudo gpasswd -a "$USER" bullseye-bypass
```

Then:

```sh
be                    # the TUI
```

The TUI asks sudo for the password once, before it draws — nftables is root-only.
Everything is reversible with the escape hatch above.

## First run

```sh
be discover                       # what it found, changing nothing
be arm --dry-run                  # the exact ruleset, applying nothing
be arm --timeout 60               # arm, and self-revert unless you confirm
```

`--timeout` is the one to use the first time. It schedules a systemd timer that
destroys the table, so a mistake fixes itself even if the terminal dies.

## Always on, and an icon for it

Two units. The daemon arms at boot and keeps the ruleset true as the VPN moves
server; the tray puts that in your bar with one click to change it.

```sh
sudo install -Dm644 packaging/bullseye.service /etc/systemd/system/bullseye.service
sudo mkdir -p /etc/bullseye
sudo ln -sfn ~/.config/bullseye/config.toml /etc/bullseye/config.toml
sudo systemctl enable --now bullseye

install -Dm644 packaging/bullseye-tray.service ~/.config/systemd/user/bullseye-tray.service
systemctl --user enable --now bullseye-tray
```

The tray is a StatusNotifierItem, so it appears in Waybar's `tray` module, in KDE
and GNOME, and in anything else that speaks the spec — no per-bar configuration.
On a compositor that never reaches `graphical-session.target` (a bare Hyprland or
sway, without uwsm) the user unit is enabled but nothing ever pulls it in. Start it
from the compositor instead — through the unit, not the binary, so that a session
which *does* reach that target later cannot leave you with two bullseyes:

```
exec-once = systemctl --user start bullseye-tray
```

If you already gate your tray apps on the StatusNotifierWatcher being up, that
script is the better home for the same line.

The icon is the bullseye itself, in four states:

| Icon | State | |
|---|---|---|
| red target, centre filled | **armed** | the kill switch is holding and the tunnel works |
| red target with sight lines | **armed, and nothing is getting out** | no tunnel is up, or the pin no longer matches the server the VPN is dialling. This is the answer to "why did my internet stop" |
| grey target, centre empty | **off** | nothing is enforced |
| a single grey ring | **cannot tell** | no daemon, and `nft` would not answer either. Never drawn as "off": the ruleset may be holding fine |

No colour carries a state on its own — the sight lines and the missing rings say
the same thing to a bar that renders it monochrome, and to a user who cannot tell
the red from the grey. It is drawn rather than installed, so there is no icon
theme to set up and it looks the same on every desktop. Themed names were tried
first and are why: `security-high`/`-medium`/`-low` are colour-correct on Breeze
and inverted on Adwaita, which ships "high" as a red shield and "low" as a
friendly gold one — backwards for a control whose good state is the locked one —
and the padlock pair that replaced them is a colour icon on Adwaita and monochrome
on Breeze, so the same machine looked like two different programs.

Left click toggles. The menu shows the same lines `be status` prints, and quits.

If you already drive a bar module from the shell kill switch this replaces, the
tray supersedes it — drop `custom/vpn` from `modules-left` once you are happy.

**Quitting the tray does not disarm**, and neither does stopping the daemon: the
ruleset lives in the kernel and holds with bullseye stopped, uninstalled or
crashed (principle 2). The icon going away means the icon went away. `be disarm`
is how you mean it, and `systemctl restart bullseye` is how you arm again.

What the daemon will and will not do:

- It **arms at startup**, in lockdown when nothing is known yet — every egress
  path closed, including the VPN's own, held until the upstream turns up. A `pin`
  or a `[vpn] config` is what breaks that deadlock, because both can be read
  before the VPN has started.
- It **re-arms when the upstream moves**, which is what a snapshot of an address
  needs and a `cgroup` upstream does not.
- It **never narrows to lockdown** once it has armed with a real upstream. A VPN
  that has been down long enough for discovery to lose it would otherwise be
  sealed away from its own server, with no way to dial out and be found again.
- It **never re-arms a box you disarmed**. The table is the state; a disarmed box
  is a decision, not a fault.
- It **never follows a pin's server**. Pinning is a promise about where the
  traffic goes, so a VPN that reconnected elsewhere is reported as a mismatch and
  left blocked, not quietly followed.

## The idea

The output chain is `policy drop`. Everything else is a list of holes:

| Hole | What it is |
|---|---|
| **Tunnel** | traffic going into the VPN interface |
| **Upstream** | how the VPN process reaches its own server |
| **Bypass** | your allowlist — an IP, a CIDR, a domain, a country, or an app |
| **Local** | LAN, loopback, DHCP, multicast — none of it reaches the internet |

Tailscale gets both a tunnel hole and an upstream hole by default, because
tailscaled's own control-plane traffic leaves on the physical link. That is what
keeps a locked-out machine reachable.

Every VPN reduces to a tunnel interface plus an upstream. The only per-VPN
difference is how the upstream is discovered, which is why supporting a new VPN
is a function rather than a plugin.

## Pinning the VPN's server

Give bullseye one address and the VPN may reach that address and no other:

```sh
be pin 5.6.7.8     # or `p` in the TUI, or `--pin` for one arming
be pin off               # back to discovering it at every arm
```

A pin is a promise about where your traffic goes. If the VPN reconnects to a
different server, that server is not in the ruleset, so the tunnel cannot come
back up and **nothing gets out** — which is the point. bullseye says so plainly
rather than leaving you to guess:

```
MISMATCH pinned to 5.6.7.8, but the VPN is talking to 9.8.7.6 — blocked
```

Without a pin the upstream is discovered at every arm, in this order — the first
strategy that can actually produce a match wins, and `discover` names it:

| Strategy | Works for | Staleness |
|---|---|---|
| **cgroup** | systemd-managed VPNs | none — it matches the process |
| **live sockets** | any userspace VPN | a snapshot |
| **wg show** | kernel WireGuard, invisible to both of the above | follows a roaming peer |
| **config parse** | before the VPN has started, i.e. at boot | a snapshot |

## Bypassing the kill switch

Four kinds of bypass. All of them leave the tunnel with your real address — that
is what a bypass is.

```sh
be allow 192.168.1.50           # an address
be allow 203.0.113.0/24         # a range
be allow registry.npmjs.org     # a domain, resolved when the ruleset is built
be allow https://jobinja.ir/    # a URL keeps its host and drops the rest
be allow geoip:ir               # a country, every range it has
be deny  registry.npmjs.org

be run firefox                  # an app: this launch bypasses, nothing else does
```

`run` starts the command with the `bullseye-bypass` group as its primary group,
and the ruleset accepts that group's sockets. It has to be a **fresh** process:
an already-running browser keeps the group it started with, and so does anything
that hands the work to a daemon that is already up. With no such group on the
machine there is no hole at all.

A domain covers whatever it resolved to when you armed. A CDN outgrows that —
`registry.npmjs.org` is a dozen Cloudflare addresses today and different ones
next week — so re-arm, or use the range.

### A whole country

`*.ir` is not something a firewall can match. A ruleset holds addresses and not
names, and there is no way to enumerate a top-level domain — so `be allow "*.ir"`
stores `geoip:ir`, and opens every address range Iran has instead.

That is a different claim than the one you made, and it is worth knowing which
way it differs: it covers Iranian services that are not `.ir` at all, and it
misses a `.ir` name parked on a CDN abroad. For "the local sites should see my
real address, not the VPN's", the country is the answer you actually wanted.

The ranges come from the `geoip.dat` an xray or v2ray install already ships — the
same file the VPN's own routing uses to decide what goes direct, so the two
cannot disagree about where Iran is. The usual install paths are searched; point
`[bypass] geoip` at the file if yours is somewhere else. No database, no hole:
the bypass is skipped and the report says so, rather than the arming failing.

## The TUI

```
be
```

```
space   arm / disarm            a   allow an IP, CIDR, domain or geoip:ir
p       pin the VPN's server    A   add an app to launch
enter   launch the selected app d   remove the selected entry
r       re-run discovery        q   quit
```

The header is the whole state: armed or not, the packets dropped since arming,
the tunnel, the upstream, and whether the pin still matches reality.

Every edit here re-arms an armed box, the way `be allow` and `be deny` do — a
bypass you removed is closed in the kernel and not only in the file. It takes a
second or two, because it re-resolves every domain; the message at the bottom
says so when it is done. The one thing it will not do is re-arm into a state
where nothing gets out at all: if the tunnel has gone away, the edit is saved,
the ruleset is left alone, and the message says which.

The corner of the header is the target itself, which is the state with a face on
it — asleep while nothing is enforced, watching while the ruleset holds, startled
for a moment each time the drop counter moves, and alarmed while a pin no longer
matches the server the VPN is dialling:

```
   .-───-.        .-───-.        .-───-.
  / .═══. \      / .───. \      / .───. \
 | | o o | |    | | x x | |    | | - - | |
 | |  u  | |    | |  o  | |    | |  o  | |
  \ `═══' /      \ `───' /      \ `───' /
   `-───-'        `-───-'        `-───-'   z
    armed          dropping       disarmed
```

It is the only thing on the screen that moves on its own, which is how you notice
a state you were not reading. On a terminal too narrow for it, the report gets the
columns instead.

## Commands

```sh
be                                the TUI
be arm [options]                  load the ruleset
be disarm                         destroy it
be status                         what is loaded, and whether the pin still holds
be discover                       what arm would use, changing nothing
be allow <ip|cidr|domain|geoip:cc>
                                  open a bypass, and re-arm if armed
be deny <entry>                   close one
be pin [<ip>|off]                 fix the VPN's server to one address
be run <command...>               launch something outside the tunnel
be config                         where the config lives, and what is in it
be daemon                         arm at boot, and re-arm when the VPN moves server
be tray                           the state in your bar, and a click to change it
```

`arm` options override the config file for one arming and are never written back:
`--tunnel`, `--pin`, `--cgroup`, `--vpn-config`, `--bypass`, `--lockdown`,
`--no-tailscale`, `--no-local`, `--dry-run`, `--timeout`. See `be --help`.

## Config

`~/.config/bullseye/config.toml`, written by the TUI and by `allow`/`deny`/`pin`,
and safe to edit by hand.

```toml
[vpn]
interface = "xray_tun"     # detected from the device type when absent
cgroup    = "system.slice/xray.service"
config    = "/opt/v2rayn-bin/binConfigs/config.json"
pin       = "5.6.7.8"

[bypass]
allow = ["192.168.1.50", "203.0.113.0/24", "registry.npmjs.org"]
apps  = ["firefox"]
group = "bullseye-bypass"

[local]
lan       = true
tailscale = true
```

## What it does not do yet

- **Split routing.** A bypass is a hole in the *filter*: it says the packet may
  leave. If your VPN owns the default route, the packet still goes into the
  tunnel — exclude the destination in the VPN's own routing too. VPNs that route
  selectively (most xray/v2ray setups) need nothing extra.
- **IPv6 per hole.** Blocked or allowed wholesale (ADR-0001).
- **Drop details.** The counter says how many packets were refused, not which.
- **Privileges.** The TUI and the tray shell out to `sudo`, so a box without a
  NOPASSWD rule for `nft` gets an error rather than a prompt — there is nowhere
  to type a password into a bar icon. A polkit policy is stage 7.

## Documentation

- [PLAN.md](PLAN.md) — build stages and scope
- [knowledge/](knowledge/) — the source of truth for behaviour and decisions
  - [principles](knowledge/constitution/principles.md) — the non-negotiables
  - [glossary](knowledge/constitution/glossary.md) — the domain model
  - [ADR-0001](knowledge/decisions/adr/ADR-0001-nftables-output-drop.md) — why nftables
  - [ADR-0003](knowledge/decisions/adr/ADR-0003-upstream-discovery-corrections.md) — how any VPN is supported
  - [ADR-0004](knowledge/decisions/adr/ADR-0004-derived-cgroup-trust.md) — *proposed*: which discovered cgroups are safe to match
  - [ADR-0005](knowledge/decisions/adr/ADR-0005-app-bypass-by-group.md) — why an app bypass is a group, not a cgroup
  - [ADR-0006](knowledge/decisions/adr/ADR-0006-daemon-and-tray.md) — *proposed*: what the daemon maintains, and where the tray reads it
  - [ADR-0002](knowledge/decisions/adr/ADR-0002-upstream-discovery.md) — *superseded*, kept as history

## Requirements

Linux with nftables (Arch first). `nft`, `ss`, `iproute2`, `sudo`, systemd.

## License

MIT
