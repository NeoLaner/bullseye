mod config;
mod daemon;
mod discover;
mod geoip;
mod nft;
mod rules;
mod tray;
mod tui;

use config::Config;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "\
bullseye — a VPN kill switch. The output chain drops; everything else is a hole.

  bullseye                          the TUI
  bullseye arm [options]            load the ruleset
  bullseye disarm                   destroy it
  bullseye status                   what is loaded, and whether the pin still holds
  bullseye discover                 what arm would use, changing nothing
  bullseye allow <ip|cidr|domain|geoip:cc>
                                    open a bypass, and re-arm if armed
  bullseye deny <entry>             close one
  bullseye pin [<ip>|off]           fix the VPN's server to one address
  bullseye run <command...>         launch something outside the tunnel
  bullseye config                   where the config lives, and what is in it
  bullseye daemon                   arm at boot, and re-arm when the VPN moves server
  bullseye tray                     the state in your bar, and a click to change it

arm options — all optional; the config file supplies the rest, and nothing here is
written back to it:
  --tunnel <iface>       the VPN interface; detected from the device type when omitted
  --pin <ip>             the VPN may reach this address and no other. If its server
                         moves, nothing gets out until you change this
  --cgroup <path>        find the upstream by the VPN's process instead of its
                         address, e.g. system.slice/openvpn@home.service
  --vpn-config <path>    a WireGuard, OpenVPN or xray config to read the server
                         from; the only source that works before the VPN starts
  --bypass <ip|cidr|domain|geoip:cc>  leaves outside the tunnel, with your real
                         address. geoip:ir is every address range Iran has, which is
                         all that a whole-ccTLD bypass can be in a firewall
  --lockdown             arm with no upstream on purpose — nothing gets out
  --no-tailscale         close the remote-access hole; you may lose your way back in
  --no-local             close the LAN, DHCP and multicast hole
  --dry-run              render and validate the ruleset, apply nothing
  --timeout <secs>       auto-disarm unless confirmed at the prompt

If a kill switch ever locks you out, this works with bullseye uninstalled:
  sudo nft destroy table inet bullseye
";

fn main() -> ExitCode {
    match dispatch() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("bullseye: {e}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None => tui::run(),
        Some("arm") => arm_command(&args[1..]),
        Some("disarm") => {
            disarm()?;
            println!("disarmed");
            Ok(())
        }
        Some("status") => status(),
        Some("discover") => discover_command(&args[1..]),
        Some("allow") => allow_command(&args[1..]),
        Some("deny") => deny_command(&args[1..]),
        Some("pin") => pin_command(&args[1..]),
        Some("run") => run_command(&args[1..]),
        Some("config") => config_command(),
        Some("daemon") => daemon::run(),
        Some("tray") => tray::run(),
        Some("-h" | "--help") => {
            print!("{USAGE}");
            Ok(())
        }
        Some(other) => Err(format!("unknown command {other:?}\n\n{USAGE}")),
    }
}

/// What arming would do, before anything is loaded.
///
/// Which strategy answered is reported rather than swallowed: a cgroup match holds
/// when the VPN changes server and an address snapshot does not, so the user needs
/// to know which one they have.
pub struct Plan {
    pub holes: rules::Holes,
    pub report: String,
    /// The pin says the VPN may reach one address. This is what it is reaching
    /// instead — every packet of which the kill switch is dropping.
    pub mismatch: Option<String>,
}

/// Config in, holes out. The one place that decides what a ruleset contains, so
/// the TUI and the CLI cannot drift apart on it.
pub fn plan(config: &Config, lockdown: bool) -> Result<Plan, String> {
    let mut holes = rules::Holes::default();
    holes.local = config.lan;
    holes.tailscale = config.tailscale;
    // Three reports rather than one, so the lines read in the order the user
    // thinks in — the tunnel, then the way out to its server, then the holes they
    // opened themselves — instead of the order the holes happen to be built in.
    let mut tunnels_report = String::new();
    let mut upstream_report = String::new();
    let mut report = String::new();

    for entry in &config.allow {
        report += &open_bypass(&mut holes, entry, config.geoip.as_deref())?;
    }
    // No group, no hole. A bypass that lets a whole class of processes out is worth
    // more than an address, so it exists only once the user has made the group.
    if let Some(gid) = discover::group(&config.group) {
        holes.bypass_gid = Some(gid);
        report += &format!(
            "bypass   group {} ({gid}) — anything started by `bullseye run`\n",
            config.group
        );
    }

    let tunnels = match &config.interface {
        Some(named) => vec![discover::tunnel(named)],
        None => discover::tunnels(),
    };
    let hints = discover::Hints {
        cgroup: config.cgroup.clone(),
        config: config.vpn_config.clone(),
    };
    let mut mismatch = None;

    // A pin is the whole upstream: the VPN may reach that address and no other.
    // Discovery still runs underneath, but only to report whether reality agrees —
    // a VPN that has moved server is one the kill switch is now strangling, and the
    // user has to be told rather than left to wonder why nothing works.
    if let Some(pin) = &config.pin
        && !lockdown
    {
        holes.add_upstream(pin)?;
        upstream_report += &format!("upstream {pin} — pinned\n");
    }

    for tunnel in &tunnels {
        holes.add_tunnel(&tunnel.interface)?;
        let kind = tunnel.kind.map_or("not up yet", discover::Kind::name);
        tunnels_report += &format!("tunnel   {} ({kind})\n", tunnel.interface);

        if lockdown {
            continue;
        }
        // Tailscale's upstream is the fwmark hole, which is already open. Only when
        // it turned up on its own, though: naming it with a cgroup or a vpn config
        // is asking for that instead, and skipping would silently ignore the ask.
        if config.interface.is_none() && holes.tailscale && tunnel.interface == "tailscale0" {
            upstream_report += "upstream tailscale0 — by fwmark, already open\n";
            continue;
        }
        // A tunnel nothing can be found for is reported, not fatal: a machine with
        // several tunnels should still arm for the ones that resolved. Ending up
        // with no upstream at all is what the lockdown guard is for.
        match (discover::upstream(tunnel, &hints), &config.pin) {
            (Ok(discover::Upstream::Process { cgroup }), None) => {
                holes.add_upstream_cgroup(&cgroup)?;
                upstream_report +=
                    &format!("upstream {cgroup} — by cgroup, survives a server change\n");
            }
            (Ok(discover::Upstream::Servers { addresses, .. }), Some(pin)) => {
                if !addresses.contains(pin) {
                    mismatch = Some(addresses.join(", "));
                }
            }
            (Ok(discover::Upstream::Servers { addresses, found_by }), None) => {
                for address in &addresses {
                    holes.add_upstream(address)?;
                }
                upstream_report += &format!(
                    "upstream {} — via {found_by}, a snapshot\n",
                    summarised(&addresses)
                );
            }
            // Pinned, so nothing here changes the ruleset — it only decides whether
            // the pin can be checked at all.
            (Ok(discover::Upstream::Process { .. }), Some(_)) => {
                upstream_report += "         the VPN was found by cgroup, so the pin has no \
                                    address to check against\n";
            }
            (Err(_), Some(_)) => {
                upstream_report += "         nothing running to check the pin against\n";
            }
            (Err(why), None) => upstream_report += &format!("upstream none — {why}\n"),
        }
    }
    if lockdown {
        upstream_report += "upstream none — lockdown, on purpose\n";
    }
    Ok(Plan {
        holes,
        report: tunnels_report + &upstream_report + &report,
        mismatch,
    })
}

/// The two shapes that must never be armed by a keystroke or a click: no tunnel at
/// all, which takes the box off the network outright, and no upstream, which
/// strangles the tunnel bullseye exists to protect.
///
/// The CLI refuses the same two in terms of its own flags, because that is what
/// someone typing `arm` can act on. This is worded for someone who has neither a
/// flag nor a terminal in front of them — and it exists so that the next UI cannot
/// ship having remembered only one of them.
pub fn refuse_lockout(plan: &Plan) -> Result<(), String> {
    if plan.holes.tunnel().is_empty() {
        return Err("No VPN interface found — start the VPN, or set [vpn] interface.".into());
    }
    if plan.holes.is_lockdown() {
        return Err(
            "No upstream: the VPN cannot reach its own server, so arming would \
             strangle the tunnel. Pin it, or set [vpn] cgroup or [vpn] config."
                .into(),
        );
    }
    Ok(())
}

/// A bypass is an address, a CIDR, a domain or a country, and only the last two
/// need work: nftables sets hold addresses, so a name is resolved here and covers
/// whatever it pointed at when the ruleset was built, and a country is read out of
/// the geoip database an xray or v2ray install already ships.
fn open_bypass(
    holes: &mut rules::Holes,
    entry: &str,
    geoip: Option<&Path>,
) -> Result<String, String> {
    if let Some(code) = entry.strip_prefix("geoip:") {
        return open_country(holes, entry, code, geoip);
    }
    if rules::address(entry).is_ok() {
        holes.add_bypass(entry)?;
        return Ok(format!("bypass   {entry}\n"));
    }
    let addresses = discover::resolve(std::slice::from_ref(&entry.to_owned()));
    if addresses.is_empty() {
        // Skipped rather than fatal, and the safe direction: a bypass that does not
        // open stays blocked. Refusing to arm because a CDN was briefly unreachable
        // would leave the machine with no kill switch at all.
        return Ok(format!(
            "bypass   {entry} — no public address right now, skipped\n"
        ));
    }
    for address in &addresses {
        holes.add_bypass(address)?;
    }
    Ok(format!("bypass   {entry} -> {}\n", summarised(&addresses)))
}

/// Every range a country has. Thousands of them, so the report counts rather than
/// lists — and names the file they came from, because which database answered is
/// the difference between a bypass that agrees with the VPN's own routing and one
/// that does not.
///
/// Nothing here is fatal, for the reason a domain that will not resolve is not: a
/// bypass that does not open stays blocked, and a box whose geoip database is
/// missing or whose country code has a typo in it still gets a kill switch.
fn open_country(
    holes: &mut rules::Holes,
    entry: &str,
    code: &str,
    geoip: Option<&Path>,
) -> Result<String, String> {
    let Some(path) = geoip::database(geoip) else {
        return Ok(format!(
            "bypass   {entry} — no geoip.dat found, skipped. Install xray's or \
             v2ray's, or point [bypass] geoip at one\n"
        ));
    };
    let ranges = match geoip::ranges(code, &path) {
        Ok(ranges) => ranges,
        Err(why) => return Ok(format!("bypass   {entry} — {why}, skipped\n")),
    };
    for range in &ranges {
        holes.add_bypass(range)?;
    }
    Ok(format!(
        "bypass   {entry} -> {} ranges from {}\n",
        ranges.len(),
        path.display()
    ))
}

/// A name behind a CDN resolves to a dozen addresses, and a dozen addresses on one
/// line is a wall, not a report. The count is the honest summary: what a bypass
/// covers is whatever the name pointed at when the ruleset was built, and the
/// ruleset itself is one `--dry-run` away.
fn summarised(addresses: &[String]) -> String {
    match addresses.len() {
        0..=3 => addresses.join(", "),
        many => format!("{}, and {} more", addresses[..2].join(", "), many - 2),
    }
}

/// Load the ruleset. The revert timer is scheduled first so a revert exists even if
/// arming dies halfway; destroying a table that was never created is a no-op.
pub fn arm(plan: &Plan, timeout: Option<u32>) -> Result<(), String> {
    let ruleset = plan.holes.ruleset();
    nft::check(&ruleset)?; // never load a ruleset the kernel has not agreed to
    if let Some(seconds) = timeout {
        nft::schedule_revert(seconds)?;
    }
    nft::apply(&ruleset)
}

pub fn disarm() -> Result<(), String> {
    let _ = nft::cancel_revert();
    nft::destroy()
}

pub fn armed() -> bool {
    nft::show().is_ok()
}

fn arm_command(args: &[String]) -> Result<(), String> {
    let mut config = Config::load()?;
    let mut lockdown = false;
    let mut dry_run = false;
    let mut timeout = None;

    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let takes_value = matches!(
            flag,
            "--tunnel" | "--pin" | "--bypass" | "--timeout" | "--cgroup" | "--vpn-config"
        );
        let value = match takes_value {
            true => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| format!("{flag} needs a value"))?;
                // `--tunnel --pin 1.2.3.4` would otherwise open a hole named
                // "--pin", which matches nothing and looks like it worked.
                if value.starts_with("--") {
                    return Err(format!("{flag} needs a value, but got {value:?}"));
                }
                value.as_str()
            }
            false => "",
        };
        i += 1 + takes_value as usize;

        match flag {
            "--tunnel" => config.interface = Some(rules::interface(value)?),
            // Hints, not holes: each still has to pass its own check, or the rule
            // loads and silently matches nothing (ADR-0003).
            "--cgroup" => config.cgroup = Some(rules::cgroup(value)?.0),
            "--vpn-config" => config.vpn_config = Some(PathBuf::from(value)),
            "--pin" => config.pin = Some(rules::address(value)?),
            "--bypass" => config.allow.push(rules::bypass_entry(value)?),
            "--timeout" => {
                timeout = Some(
                    value
                        .parse::<u32>()
                        .map_err(|_| format!("--timeout: {value:?} is not a number of seconds"))?,
                )
            }
            "--lockdown" => lockdown = true,
            "--no-tailscale" => config.tailscale = false,
            "--no-local" => config.lan = false,
            "--dry-run" => dry_run = true,
            _ => return Err(format!("unknown option {flag:?}\n\n{USAGE}")),
        }
    }

    let plan = plan(&config, lockdown)?;
    print!("{}", plan.report);
    if let Some(actual) = &plan.mismatch {
        println!(
            "MISMATCH — pinned to {}, but the VPN is talking to {actual}. That traffic \
             is blocked, so the tunnel will not come up until the pin matches.",
            config.pin.as_deref().unwrap_or("?")
        );
    }

    // Lockdown — armed with no upstream — is the deliberate boot state, so it stays
    // reachable. It is never what someone arming by hand meant, so it is opt-in.
    if !lockdown {
        if plan.holes.tunnel().is_empty() {
            return Err("no VPN interface found, and none named with --tunnel \
                        (--lockdown arms with nothing open)"
                .into());
        }
        if plan.holes.is_lockdown() {
            return Err(
                "refusing to arm with an empty upstream: the VPN could not reach \
                 its own server, and the tunnel this protects would die. Pass \
                 --pin, --cgroup or --vpn-config, or --lockdown if that is what \
                 you meant."
                    .into(),
            );
        }
    }

    let ruleset = plan.holes.ruleset();
    if dry_run {
        nft::check(&ruleset)?;
        print!("{ruleset}");
        return Ok(());
    }
    arm(&plan, timeout)?;
    match lockdown {
        true => println!("armed in lockdown — nothing gets out until an upstream is known"),
        false => println!("armed"),
    }
    match timeout {
        Some(seconds) => confirm(seconds),
        None => Ok(()),
    }
}

fn discover_command(args: &[String]) -> Result<(), String> {
    let mut config = Config::load()?;
    let mut i = 0;
    while i < args.len() {
        let (flag, value) = (args[i].as_str(), args.get(i + 1).map(String::as_str));
        i += 2;
        match (flag, value) {
            ("--tunnel", Some(v)) => config.interface = Some(rules::interface(v)?),
            ("--cgroup", Some(v)) => config.cgroup = Some(rules::cgroup(v)?.0),
            ("--vpn-config", Some(v)) => config.vpn_config = Some(PathBuf::from(v)),
            _ => return Err(format!("discover: unexpected {flag:?}\n\n{USAGE}")),
        }
    }
    let plan = plan(&config, false)?;
    match plan.report.is_empty() {
        true => println!("nothing found: no VPN interface, no bypass, no group"),
        false => print!("{}", plan.report),
    }
    if let Some(actual) = plan.mismatch {
        println!("MISMATCH — the VPN is talking to {actual}, which the pin does not cover");
    }
    Ok(())
}

fn allow_command(args: &[String]) -> Result<(), String> {
    let entry = args.first().ok_or("allow: needs an IP, a CIDR or a domain")?;
    let mut config = Config::load()?;
    let entry = config.allow(entry)?;
    config.save()?;
    println!("allowed {entry} — it leaves outside the tunnel, with your real address");
    reapply(&config)
}

fn deny_command(args: &[String]) -> Result<(), String> {
    let entry = args.first().ok_or("deny: needs an entry to remove")?;
    let mut config = Config::load()?;
    if !config.deny(entry) {
        return Err(format!("{entry:?} is not in the bypass list"));
    }
    config.save()?;
    println!("denied {entry}");
    reapply(&config)
}

fn pin_command(args: &[String]) -> Result<(), String> {
    let mut config = Config::load()?;
    match args.first().map(String::as_str) {
        None => {
            match &config.pin {
                Some(pin) => println!("pinned to {pin}"),
                None => println!("not pinned — the upstream is discovered at every arm"),
            }
            return Ok(());
        }
        Some("off") => {
            config.pin = None;
            println!("unpinned — the upstream is discovered at every arm again");
        }
        Some(address) => {
            config.pin = Some(rules::address(address)?);
            println!("pinned to {address} — the VPN may reach that address and no other");
        }
    }
    config.save()?;
    reapply(&config)
}

/// A bypass or a pin that only takes effect at the next arm is a footgun: the user
/// changed the rules and the machine did not. So a change to an armed box re-arms it.
fn reapply(config: &Config) -> Result<(), String> {
    if !armed() {
        println!("not armed — this takes effect at the next `bullseye arm`");
        return Ok(());
    }
    let plan = plan(config, false)?;
    arm(&plan, None)?;
    print!("{}", plan.report);
    println!("re-armed");
    Ok(())
}

/// Launch something with the bypass group as its primary group, which is what the
/// `meta skgid` hole matches. It has to be a fresh process: an already-running
/// browser keeps the group it started with, and so does anything that hands the
/// work to a daemon that is already up.
fn run_command(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("run: needs a command, e.g. `bullseye run firefox`".into());
    }
    if nft::is_root() {
        return Err("run: use your own user, not sudo — the app should not be root, \
                    and it needs your session's environment"
            .into());
    }
    let config = Config::load()?;
    let group = discover::group(&config.group).ok_or_else(|| {
        format!(
            "run: the group {:?} does not exist, so there is no bypass hole to run in.\n  \
             sudo groupadd -f {0} && sudo gpasswd -a $USER {0}",
            config.group
        )
    })?;
    println!("(gid {group} — outside the tunnel, with your real address)");
    let status = launcher(&config.group, args)
        .status()
        .map_err(|e| format!("run: {e}"))?
        .code();
    match status {
        Some(0) | None => Ok(()),
        Some(code) => Err(format!("run: the command exited {code}")),
    }
}

/// sudo resets the environment, and a GUI app started without one cannot find the
/// display. The variables are handed back as arguments to `env`, which needs no
/// sudoers policy to permit — unlike `--preserve-env`.
pub fn launcher(group: &str, command: &[String]) -> std::process::Command {
    let user = std::env::var("USER").unwrap_or_else(|_| "root".into());
    let mut sudo = std::process::Command::new("sudo");
    sudo.args(["-u", &user, "-g", group, "--", "env"]);
    for name in [
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XAUTHORITY",
        "XDG_RUNTIME_DIR",
        "XDG_SESSION_TYPE",
        "DBUS_SESSION_BUS_ADDRESS",
        "HOME",
        "PATH",
        "LANG",
        "TERM",
    ] {
        if let Ok(value) = std::env::var(name) {
            sudo.arg(format!("{name}={value}"));
        }
    }
    sudo.args(command);
    sudo
}

fn config_command() -> Result<(), String> {
    let path = config::path();
    println!("{}", path.display());
    match std::fs::read_to_string(&path) {
        Ok(text) => print!("\n{text}"),
        Err(_) => println!("\n(no file yet — `bullseye allow`, `bullseye pin` or the TUI writes one)"),
    }
    Ok(())
}

/// Blocking on stdin is the point: if the terminal or the SSH session goes away the
/// read ends without a confirmation, and the timer disarms the box.
fn confirm(seconds: u32) -> Result<(), String> {
    println!("reverting in {seconds}s — press ENTER to keep it armed");
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).unwrap_or(0) == 0 {
        println!("not confirmed — the timer will disarm");
        return Ok(());
    }
    match nft::cancel_revert() {
        Ok(()) => println!("kept"),
        Err(e) => println!(
            "kept, but the revert timer would not stop ({e}) — \
             it will disarm in {seconds}s"
        ),
    }
    Ok(())
}

fn status() -> Result<(), String> {
    let config = Config::load()?;
    match nft::show() {
        Ok(table) => {
            println!("armed");
            if let Some(packets) = nft::blocked() {
                println!("blocked  {packets} packets since arming");
            }
            print!("{table}");
        }
        Err(e) if e.contains("No such file or directory") => {
            println!("disarmed — no table inet bullseye");
        }
        Err(e) => return Err(e),
    }
    if let Some(pin) = &config.pin {
        let plan = plan(&config, false)?;
        match plan.mismatch {
            None => println!("pin      {pin} — matches what the VPN is doing"),
            Some(actual) => println!("pin      {pin} — MISMATCH, the VPN is talking to {actual}"),
        }
    }
    Ok(())
}
