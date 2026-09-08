//! Finding the tunnel, and finding the way out to the VPN's own server.
//!
//! ADR-0003: three strategies in order — cgroup, then runtime, then config parse —
//! first success wins, and a strategy counts as succeeding only when it can produce
//! a match, never merely a rule.

use crate::{nft, rules};
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::path::{Path, PathBuf};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// A link a VPN created. The kind comes from the device type, never the name —
/// `wg0`, `tun0`, `xray_tun` and `tailscale0` are per-VPN conventions (glossary).
pub struct Tunnel {
    pub interface: String,
    pub kind: Option<Kind>,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    /// A kernel module with no userspace sender. Nothing holds a socket for it, so
    /// neither a cgroup match nor `ss` can attribute its packets to a process —
    /// the finding ADR-0003 exists for.
    Wireguard,
    /// A TUN/TAP device, held open by whichever process created it.
    Tun,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Wireguard => "wireguard",
            Kind::Tun => "tun",
        }
    }
}

/// The upstream hole, and how it was found. The distinction matters to the user:
/// one of these survives the VPN changing server and the others do not.
pub enum Upstream {
    /// The VPN's own process, by cgroup. Stays correct when the server changes.
    Process { cgroup: String },
    /// Addresses. A snapshot, which is why the daemon re-checks while armed.
    Servers {
        addresses: Vec<String>,
        found_by: &'static str,
    },
}

/// What the user told us, before anything has been looked up.
#[derive(Default)]
pub struct Hints {
    pub cgroup: Option<String>,
    pub config: Option<PathBuf>,
}

/// Every interface a VPN created.
pub fn tunnels() -> Vec<Tunnel> {
    let Ok(links) = std::fs::read_dir("/sys/class/net") else {
        return Vec::new();
    };
    let mut found: Vec<Tunnel> = links
        .flatten()
        .map(|link| link.file_name().to_string_lossy().into_owned())
        .filter(|interface| rules::interface(interface).is_ok())
        .filter_map(|interface| {
            kind(&interface).map(|kind| Tunnel {
                interface,
                kind: Some(kind),
            })
        })
        .collect();
    found.sort_by(|a, b| a.interface.cmp(&b.interface));
    found
}

/// A tunnel the user named. Its kind is unknown when the interface is not up yet,
/// which is the boot case — there is nothing running to ask, so only config parse
/// can answer.
pub fn tunnel(interface: &str) -> Tunnel {
    Tunnel {
        interface: interface.to_owned(),
        kind: kind(interface),
    }
}

fn kind(interface: &str) -> Option<Kind> {
    let link = Path::new("/sys/class/net").join(interface);
    let wireguard = std::fs::read_to_string(link.join("uevent"))
        .is_ok_and(|uevent| uevent.lines().any(|line| line == "DEVTYPE=wireguard"));
    match (wireguard, link.join("tun_flags").exists()) {
        (true, _) => Some(Kind::Wireguard),
        (_, true) => Some(Kind::Tun),
        _ => None,
    }
}

/// ADR-0003's order, first success wins.
pub fn upstream(tunnel: &Tunnel, hints: &Hints) -> Result<Upstream, String> {
    if let Some(cgroup) = by_cgroup(tunnel, hints.cgroup.as_deref()) {
        return Ok(Upstream::Process { cgroup });
    }
    if let Some((addresses, found_by)) = at_runtime(tunnel) {
        return Ok(Upstream::Servers {
            addresses,
            found_by,
        });
    }
    match &hints.config {
        Some(config) => Ok(Upstream::Servers {
            addresses: from_config(config)?,
            found_by: "config parse",
        }),
        None => Err(format!(
            "no upstream found for {}: no cgroup holding the VPN, nothing running to \
             ask, and no --vpn-config to read. Pass --upstream, --cgroup or \
             --vpn-config, or --lockdown to arm closed on purpose.",
            tunnel.interface
        )),
    }
}

/// Strategy 1 — the VPN's process, by cgroup.
///
/// A derived path is only trusted under `system.slice`. A desktop VPN sits in the
/// session's own scope alongside every other process the user is running, so
/// matching it would let the whole session out — the same reason ADR-0002 rejected
/// `meta skuid`. Verified: xray on this machine reports
/// `user.slice/user-1000.slice/session-2.scope`.
// ponytail: a prefix test, not a proof the cgroup holds only the VPN. If a
// `systemd-run --user --scope` VPN needs to be found without a hint, compare the
// pids in cgroup.procs against the tunnel's owner instead.
fn by_cgroup(tunnel: &Tunnel, hint: Option<&str>) -> Option<String> {
    let path = match hint {
        Some(hint) => hint.to_owned(),
        None => {
            let derived = cgroup_of(owner(&tunnel.interface)?)?;
            derived.starts_with("system.slice/").then_some(derived)?
        }
    };
    populated(&path).then_some(path)
}

/// The kernel's own recursive answer to "does anything actually run in here" — the
/// same subtree nft's `socket cgroupv2 level N` matches. ADR-0003 requires this:
/// `wg-quick@.service` is a oneshot whose cgroup is released the moment it exits,
/// so an existence check alone would accept a rule that can never match.
fn populated(path: &str) -> bool {
    std::fs::read_to_string(format!("{CGROUP_ROOT}/{path}/cgroup.events"))
        .is_ok_and(|events| events.lines().any(|line| line.trim() == "populated 1"))
}

fn cgroup_of(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()?
        .lines()
        .find_map(|line| Some(line.strip_prefix("0::/")?.trim().to_owned()))
        .filter(|path| !path.is_empty())
}

/// The process holding this tunnel open. A TUN/TAP fd reports its interface in
/// fdinfo, which identifies the VPN with no per-VPN knowledge whatsoever — no
/// process name, no unit name, no config.
///
/// Privileged because most VPNs run as root: reading another user's fdinfo needs
/// root, and on this machine xray moved from a user session to root mid-development,
/// which took the unprivileged version from working to useless.
fn owner(interface: &str) -> Option<u32> {
    // A glob needs a shell, and nothing else here does. Safe because the name has
    // already been through `rules::interface`: at most 15 bytes of [A-Za-z0-9_.-],
    // so it cannot carry a shell metacharacter. The tab is a real tab.
    // `head` also settles the exit status: grep returns 2 when any of the files it
    // was handed could not be read, which is routine under /proc and would
    // otherwise throw away a match it had already printed.
    let script = format!("grep -lFx 'iff:\t{interface}' /proc/*/fdinfo/* 2>/dev/null | head -n1");
    let found = nft::run("sh", &["-c", &script], None).ok()?;
    found.lines().next()?.split('/').nth(2)?.parse().ok()
}

/// The gid of a group, or None when it does not exist. Read straight out of
/// `/etc/group`: a hole is only opened for a group that is really there, so
/// "absent" has to be an answer rather than an error.
pub fn group(name: &str) -> Option<u32> {
    std::fs::read_to_string("/etc/group")
        .ok()?
        .lines()
        .find(|line| line.starts_with(&format!("{name}:")))
        .and_then(|line| line.split(':').nth(2))
        .and_then(|gid| gid.parse().ok())
}

/// Strategy 2 — what the VPN is talking to right now.
fn at_runtime(tunnel: &Tunnel) -> Option<(Vec<String>, &'static str)> {
    let found = match tunnel.kind? {
        Kind::Wireguard => (peer_endpoints(&tunnel.interface)?, "wg show"),
        Kind::Tun => (sockets_of(owner(&tunnel.interface)?)?, "live sockets"),
    };
    (!found.0.is_empty()).then_some(found)
}

/// `wg show <iface> endpoints` prints `<pubkey>\t<host:port>` per peer. It is the
/// only runtime source for a kernel WireGuard tunnel, and unlike a config file it
/// follows a peer that roams.
fn peer_endpoints(interface: &str) -> Option<Vec<String>> {
    let out = nft::run("wg", &["show", interface, "endpoints"], None).ok()?;
    Some(public_addresses(out.lines().filter_map(|line| {
        Some(host_of(line.split_once('\t')?.1.trim())?.to_owned())
    })))
}

/// The VPN process's own peers. Only public addresses count: a private or loopback
/// peer is already covered by the local hole, and the upstream is by definition a
/// server out on the internet.
fn sockets_of(pid: u32) -> Option<Vec<String>> {
    let out = nft::run("ss", &["-tunH", "-p"], None).ok()?;
    let owned_by_vpn = format!("pid={pid},");
    Some(public_addresses(
        out.lines()
            .filter(|line| line.contains(&owned_by_vpn))
            .filter_map(|line| Some(host_of(line.split_whitespace().nth(5)?)?.to_owned())),
    ))
}

/// Strategy 3 — the config. The only strategy that answers before the VPN has
/// started, which is what breaks the boot deadlock (ADR-0003).
fn from_config(path: &Path) -> Result<Vec<String>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let hosts = match serde_json::from_str::<serde_json::Value>(&text) {
        Ok(json) => xray_hosts(&json),
        Err(_) => wireguard_or_openvpn_hosts(&text),
    };
    if hosts.is_empty() {
        return Err(format!(
            "{}: no endpoint found — expected a WireGuard `Endpoint =`, an OpenVPN \
             `remote`, or xray `outbounds[].settings`",
            path.display()
        ));
    }
    let addresses = resolve(&hosts);
    if addresses.is_empty() {
        return Err(format!(
            "{}: {hosts:?} did not resolve. At boot this is expected — lockdown \
             blocks DNS, so a config naming a domain cannot be used until something \
             else opens the way.",
            path.display()
        ));
    }
    Ok(addresses)
}

/// Scoped to `outbounds` deliberately: xray puts `address` under `dns.servers` too,
/// and this machine's config has `1.1.1.1` and `223.5.5.5` sitting there. Matching
/// on the key name alone would open holes to the user's DNS resolvers and miss the
/// actual server.
fn xray_hosts(config: &serde_json::Value) -> Vec<String> {
    let mut hosts = Vec::new();
    for outbound in config["outbounds"].as_array().into_iter().flatten() {
        for group in ["vnext", "servers"] {
            for server in outbound["settings"][group].as_array().into_iter().flatten() {
                if let Some(address) = server["address"].as_str() {
                    hosts.push(address.to_owned());
                }
            }
        }
    }
    hosts
}

fn wireguard_or_openvpn_hosts(text: &str) -> Vec<String> {
    let mut hosts = Vec::new();
    for line in text.lines().map(str::trim) {
        // WireGuard: Endpoint = host:port
        if let Some(value) = line.strip_prefix("Endpoint")
            && let Some(endpoint) = value.trim_start().strip_prefix('=')
        {
            hosts.extend(host_of(endpoint.trim()).map(str::to_owned));
        }
        // OpenVPN: remote host [port]
        if let Some(value) = line.strip_prefix("remote ") {
            hosts.extend(value.split_whitespace().next().map(str::to_owned));
        }
    }
    hosts
}

/// A config names a host, which may be a domain, while nftables sets hold
/// addresses. Resolving is therefore part of reading a config — and at boot, under
/// lockdown, it is exactly what cannot work yet. A bypass domain takes the same
/// path for the same reason: a set holds addresses, not names.
pub fn resolve(hosts: &[String]) -> Vec<String> {
    public_addresses(
        hosts
            .iter()
            .flat_map(|host| {
                (host.as_str(), 0u16)
                    .to_socket_addrs()
                    .into_iter()
                    .flatten()
            })
            .filter_map(|socket| match socket.ip() {
                IpAddr::V4(v4) => Some(v4.to_string()),
                IpAddr::V6(_) => None, // IPv6 is handled wholesale in v0.1 (ADR-0001)
            }),
    )
}

/// Strips `:port`, leaving the host. IPv6 falls out here rather than being handled.
fn host_of(endpoint: &str) -> Option<&str> {
    let host = endpoint.rsplit_once(':').map_or(endpoint, |(host, _)| host);
    (!host.is_empty() && host != "(none)").then_some(host)
}

/// Deduplicated, sorted, and public only — every one of these becomes a hole that
/// leaves with the user's real address, so nothing gets in by accident.
fn public_addresses(candidates: impl Iterator<Item = String>) -> Vec<String> {
    let mut addresses: Vec<String> = candidates
        .filter_map(|host| host.parse::<Ipv4Addr>().ok())
        .filter(|ip| is_public(*ip))
        .map(|ip| ip.to_string())
        .collect();
    addresses.sort();
    addresses.dedup();
    addresses
}

fn is_public(ip: Ipv4Addr) -> bool {
    let [first, second, ..] = ip.octets();
    let carrier_grade_nat = first == 100 && (64..128).contains(&second);
    !(carrier_grade_nat
        || ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_documentation())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_xray_config_yields_the_server_and_not_the_dns_resolvers() {
        // Shaped like this machine's real config, resolvers and all.
        let config = serde_json::json!({
            "dns": { "servers": [ { "address": "1.1.1.1" }, { "address": "223.5.5.5" } ] },
            "outbounds": [
                { "protocol": "vless",
                  "settings": { "vnext": [ { "address": "5.6.7.8", "port": 443 } ] } },
                { "protocol": "freedom", "settings": {} }
            ]
        });
        assert_eq!(xray_hosts(&config), ["5.6.7.8"]);
    }

    #[test]
    fn wireguard_and_openvpn_endpoints_are_read_from_their_own_shapes() {
        let wg = "[Peer]\nEndpoint = 203.0.113.9:51820\nAllowedIPs = 0.0.0.0/0\n";
        assert_eq!(wireguard_or_openvpn_hosts(wg), ["203.0.113.9"]);
        let ovpn = "client\ndev tun\nremote vpn.example.com 1194 udp\n";
        assert_eq!(wireguard_or_openvpn_hosts(ovpn), ["vpn.example.com"]);
    }

    #[test]
    fn only_public_addresses_become_holes() {
        let candidates = ["4.3.2.1", "127.0.0.1", "192.168.1.1", "100.100.100.100"];
        assert_eq!(
            public_addresses(candidates.iter().map(|s| s.to_string())),
            ["4.3.2.1"]
        );
        // the tailnet, the LAN and loopback are the local hole's job, not upstream
        assert!(!is_public("100.100.100.100".parse().unwrap()));
        assert!(!is_public("10.0.0.1".parse().unwrap()));
        assert!(is_public("5.6.7.8".parse().unwrap()));
    }

    #[test]
    fn an_endpoint_without_a_peer_is_not_an_address() {
        assert_eq!(host_of("203.0.113.9:51820"), Some("203.0.113.9"));
        assert_eq!(host_of("(none)"), None);
        assert_eq!(host_of(""), None);
    }
}
