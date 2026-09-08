//! Holes -> nftables ruleset text. Nothing here talks to the kernel.
//!
//! The hole vocabulary is knowledge/constitution/glossary.md.

/// Everything the kill switch lets out.
///
/// Four of these are the glossary's hole kinds. `tailscale` is the fifth thing the
/// shell implementation had and no document mentions: `oifname "tailscale0"` alone
/// only carries tailnet traffic, while tailscaled's own control-plane and DERP
/// egress leaves on the physical link. Drop that and the tunnel dies, taking
/// principle 3's way back into the box with it.
pub struct Holes {
    tunnel: Vec<String>,
    upstream: Vec<String>,
    /// Upstreams matched as a process rather than an address, as (path, level).
    /// Worth the second field: an address goes stale when the VPN's server
    /// changes, a cgroup does not.
    upstream_cgroups: Vec<(String, usize)>,
    bypass: Vec<String>,
    /// Sockets owned by this group leave outside the tunnel, whatever they are
    /// talking to. The one hole keyed on *who* is sending rather than on where it
    /// is going, which is what makes a per-app bypass possible at all.
    pub bypass_gid: Option<u32>,
    pub local: bool,
    pub tailscale: bool,
}

impl Default for Holes {
    fn default() -> Self {
        Self {
            tunnel: Vec::new(),
            upstream: Vec::new(),
            upstream_cgroups: Vec::new(),
            bypass: Vec::new(),
            bypass_gid: None,
            local: true,
            tailscale: true, // principle 3: there is always a way back in
        }
    }
}

/// None of it routes to the internet, so none of it can expose a public identity.
/// Loopback is absent on purpose — `oif "lo"` covers it before this rule.
const LOCAL4: &str = "10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 172.16.0.0/12, \
                      192.168.0.0/16, 224.0.0.0/4, 255.255.255.255";
const LOCAL6: &str = "fc00::/7, fe80::/10, ff00::/8";

impl Holes {
    /// The address holes are private and only fill through these, so nothing can
    /// reach a root ruleset without going through the parsers below. Stage 2 adds
    /// three more callers; this is what stops one of them forgetting.
    pub fn add_tunnel(&mut self, name: &str) -> Result<(), String> {
        let name = interface(name)?;
        if !self.tunnel.contains(&name) {
            self.tunnel.push(name);
        }
        Ok(())
    }

    pub fn add_upstream(&mut self, destination: &str) -> Result<(), String> {
        self.upstream.push(address(destination)?);
        Ok(())
    }

    pub fn add_bypass(&mut self, destination: &str) -> Result<(), String> {
        self.bypass.push(address(destination)?);
        Ok(())
    }

    pub fn add_upstream_cgroup(&mut self, path: &str) -> Result<(), String> {
        self.upstream_cgroups.push(cgroup(path)?);
        Ok(())
    }

    /// Armed with no upstream hole of any kind: the glossary's Lockdown. Correct at
    /// boot and never what someone arming by hand meant, so `arm` makes it opt-in.
    pub fn is_lockdown(&self) -> bool {
        self.upstream.is_empty() && self.upstream_cgroups.is_empty()
    }

    pub fn tunnel(&self) -> &[String] {
        &self.tunnel
    }

    /// The whole ruleset as an `nft -f` script. Leads with `destroy` so loading it
    /// is one atomic transaction that replaces the table whole, and is idempotent:
    /// `destroy` on an absent table succeeds where `delete` does not.
    pub fn ruleset(&self) -> String {
        let mut s = String::from("destroy table inet bullseye\ntable inet bullseye {\n");
        s += &nft_set("upstream4", &self.upstream);
        s += &nft_set("bypass4", &self.bypass);
        s += "\tchain output {\n";
        s += "\t\ttype filter hook output priority filter; policy drop;\n";
        s += "\t\toif \"lo\" accept\n";
        for tunnel in &self.tunnel {
            // The tailscale block below already opens it, and a second identical
            // accept is just noise in a ruleset people have to be able to read.
            if self.tailscale && tunnel == "tailscale0" {
                continue;
            }
            s += &format!("\t\toifname \"{tunnel}\" accept\n");
        }
        s += "\t\tip daddr @upstream4 accept\n";
        for (path, level) in &self.upstream_cgroups {
            s += &format!("\t\tsocket cgroupv2 level {level} \"{path}\" accept\n");
        }
        s += "\t\tip daddr @bypass4 accept\n";
        if let Some(gid) = self.bypass_gid {
            s += &format!("\t\tmeta skgid {gid} accept\n");
        }
        if self.tailscale {
            s += "\t\toifname \"tailscale0\" accept\n";
            s += "\t\tmeta mark & 0x00ff0000 == 0x00080000 accept\n";
        }
        if self.local {
            s += &format!("\t\tip daddr {{ {LOCAL4} }} accept\n");
            s += &format!("\t\tip6 daddr {{ {LOCAL6} }} accept\n");
        }
        s += "\t\tcounter comment \"bullseye: egress blocked\"\n";
        s += "\t}\n}\n";
        s
    }
}

/// Named rather than anonymous so the daemon can widen a snapshot with a single
/// atomic `nft add element` instead of re-arming (ADR-0002, costs).
fn nft_set(name: &str, elements: &[String]) -> String {
    let elements = match elements {
        [] => String::new(),
        e => format!(" elements = {{ {} }}", e.join(", ")),
    };
    format!("\tset {name} {{ type ipv4_addr; flags interval;{elements} }}\n")
}

/// Parse an IPv4 address or CIDR, and render it back from the parsed value.
///
/// Everything here is pasted into a script that runs as root, so the output is only
/// ever an address or an address and a prefix length — never the caller's text.
pub fn address(input: &str) -> Result<String, String> {
    let (host, prefix) = input.split_once('/').unwrap_or((input, "32"));
    let ip: std::net::Ipv4Addr = host.parse().map_err(|_| {
        if host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("{input:?}: IPv6 is handled wholesale in v0.1, not per hole (ADR-0001)")
        } else {
            format!("{input:?} is not an IPv4 address or CIDR")
        }
    })?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| format!("{input:?}: prefix length is not a number"))?;
    if prefix > 32 {
        return Err(format!("{input:?}: prefix length must be 0-32"));
    }
    if prefix == 0 {
        return Err(format!(
            "{input:?}: a /0 hole matches every destination, which turns the kill \
             switch off rather than opening a hole in it. Disarm instead."
        ));
    }
    Ok(match input.contains('/') {
        true => format!("{ip}/{prefix}"),
        false => ip.to_string(),
    })
}

/// A bypass entry as the glossary defines one: a single address, a CIDR, or a
/// domain. Which of the three it is only matters at arm time, when the domain has
/// to be resolved and the other two do not.
pub fn bypass_entry(input: &str) -> Result<String, String> {
    address(input).or_else(|why| {
        domain(input).map_err(|_| match input.contains(char::is_numeric) {
            true => why, // looks like a botched address; say so rather than "not a domain"
            false => format!("{input:?} is not an IP address, a CIDR or a domain"),
        })
    })
}

/// A hostname. It never reaches a ruleset — it is resolved to addresses first —
/// but it is written back to the config file, so it is held to the same standard.
pub fn domain(input: &str) -> Result<String, String> {
    let shaped = (1..=253).contains(&input.len())
        && !input.starts_with(['-', '.'])
        && !input.ends_with('-')
        && input.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    match shaped {
        true => Ok(input.to_owned()),
        false => Err(format!("{input:?} is not a domain")),
    }
}

/// A command the TUI can launch and the config can hold. Never handed to a shell —
/// `run` splits it on whitespace and execs it — so the bar is only that it survives
/// a round trip through the config file.
pub fn app(input: &str) -> Result<String, String> {
    let shaped = !input.trim().is_empty()
        && input.len() <= 256
        && input
            .chars()
            .all(|c| !c.is_control() && !"\"\\'`$".contains(c));
    match shaped {
        true => Ok(input.trim().to_owned()),
        false => Err(format!("{input:?} is not a command name")),
    }
}

/// A unix group name, as `groupadd` would accept it.
pub fn group(input: &str) -> Result<String, String> {
    let shaped = (1..=32).contains(&input.len())
        && !input.starts_with('-')
        && input
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b));
    match shaped {
        true => Ok(input.to_owned()),
        false => Err(format!("{input:?} is not a group name")),
    }
}

/// Parse a cgroup v2 path, returning it with the level nftables must compare at.
///
/// The level is the path's depth and is derived here rather than configured: nft
/// accepts a mismatched level without complaint and then matches nothing, which is
/// a kill switch that strangles the VPN with no error anywhere (ADR-0003).
pub fn cgroup(input: &str) -> Result<(String, usize), String> {
    let segments: Vec<&str> = input.split('/').collect();
    let shaped = (1..=15).contains(&segments.len())
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && *segment != "."
                && *segment != ".."
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-.@:+".contains(&b))
        });
    match shaped {
        true => Ok((input.to_owned(), segments.len())),
        false => Err(format!("{input:?} is not a cgroup path")),
    }
}

/// IFNAMSIZ is 16 including the NUL, and nft takes the name as a quoted string —
/// so a name that could close that quote never gets there.
pub fn interface(input: &str) -> Result<String, String> {
    let shaped = !input.is_empty()
        && input.len() < 16
        && input
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b));
    match shaped {
        true => Ok(input.to_owned()),
        false => Err(format!("{input:?} is not an interface name")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_unparsed_reaches_a_root_ruleset() {
        assert!(address("1.2.3.4 } ; chain evil {").is_err());
        assert!(address("registry.npmjs.org").is_err());
        assert!(address("1.2.3.4/33").is_err());
        assert!(address("0.0.0.0/0").is_err()); // the off switch, not a hole
        assert!(address("::1").is_err());
        assert!(interface("wg0\" accept; ").is_err());
        assert!(interface("").is_err());
        assert!(interface("an-interface-name-far-too-long").is_err());
        assert_eq!(address("10.0.0.0/8").unwrap(), "10.0.0.0/8");
        assert_eq!(address("1.2.3.4").unwrap(), "1.2.3.4");
        assert_eq!(interface("xray_tun").unwrap(), "xray_tun");

        let mut holes = Holes::default();
        assert!(holes.add_upstream("1.2.3.4 } ; chain evil {").is_err());
        assert!(holes.add_tunnel("wg0\" accept; ").is_err());
        assert!(holes.is_lockdown() && holes.tunnel().is_empty());
    }

    #[test]
    fn the_default_leaves_a_way_back_in() {
        let mut holes = Holes::default();
        holes.add_tunnel("wg0").unwrap();
        let ruleset = holes.ruleset();
        assert!(ruleset.contains("oifname \"wg0\" accept"));
        assert!(ruleset.contains("oifname \"tailscale0\" accept"));
        // without the fwmark hole tailscaled cannot reach its control plane
        assert!(ruleset.contains("meta mark & 0x00ff0000 == 0x00080000 accept"));
    }

    #[test]
    fn a_tunnel_is_opened_once_however_many_times_it_is_named() {
        let mut holes = Holes::default();
        holes.add_tunnel("wg0").unwrap();
        holes.add_tunnel("wg0").unwrap();
        holes.add_tunnel("tailscale0").unwrap(); // also opened by the tailscale hole
        let ruleset = holes.ruleset();
        assert_eq!(ruleset.matches("oifname \"wg0\" accept").count(), 1);
        assert_eq!(ruleset.matches("oifname \"tailscale0\" accept").count(), 1);

        holes.tailscale = false;
        assert_eq!(
            holes
                .ruleset()
                .matches("oifname \"tailscale0\" accept")
                .count(),
            1
        );
    }

    #[test]
    fn a_cgroup_upstream_carries_the_level_its_path_implies() {
        assert_eq!(
            cgroup("system.slice/tailscaled.service").unwrap(),
            ("system.slice/tailscaled.service".to_owned(), 2)
        );
        // ADR-0002's own remedy for a session VPN: `systemd-run --user --scope`
        assert_eq!(
            cgroup("user.slice/user-1000.slice/user@1000.service/app.slice/vpn.scope")
                .unwrap()
                .1,
            5
        );
        assert!(cgroup("").is_err());
        assert!(cgroup("a//b").is_err());
        assert!(cgroup("../../etc").is_err());
        assert!(cgroup("evil\" accept; socket cgroupv2 level 1 \"").is_err());

        let mut holes = Holes::default();
        assert!(holes.is_lockdown());
        holes
            .add_upstream_cgroup("system.slice/xray.service")
            .unwrap();
        assert!(!holes.is_lockdown());
        assert!(
            holes
                .ruleset()
                .contains("socket cgroupv2 level 2 \"system.slice/xray.service\" accept")
        );
    }

    #[test]
    fn a_bypass_entry_is_an_address_a_cidr_or_a_domain_and_nothing_else() {
        assert_eq!(bypass_entry("1.2.3.4").unwrap(), "1.2.3.4");
        assert_eq!(bypass_entry("10.0.0.0/8").unwrap(), "10.0.0.0/8");
        assert_eq!(bypass_entry("registry.npmjs.org").unwrap(), "registry.npmjs.org");
        assert!(bypass_entry("1.2.3.4 } ; chain evil {").is_err());
        assert!(bypass_entry("0.0.0.0/0").is_err()); // the off switch, not a hole
        assert!(bypass_entry("exa mple.com").is_err());
        assert!(bypass_entry("evil\".com").is_err());
        assert!(app("firefox --private-window").is_ok());
        assert!(app("firefox; rm -rf ~").is_ok()); // never shelled out, so this is a name
        assert!(app("evil\"name").is_err()); // but it does go back into the config file
        assert!(group("bullseye-bypass").is_ok() && group("bad group").is_err());
    }

    #[test]
    fn an_app_group_opens_one_hole_keyed_on_the_sender() {
        let mut holes = Holes::default();
        holes.add_tunnel("wg0").unwrap();
        assert!(!holes.ruleset().contains("skgid"));
        holes.bypass_gid = Some(972);
        assert!(holes.ruleset().contains("meta skgid 972 accept"));
    }

    #[test]
    fn the_table_is_replaced_whole_and_drops_by_default() {
        let ruleset = Holes::default().ruleset();
        assert!(ruleset.starts_with("destroy table inet bullseye\n"));
        assert!(ruleset.contains("policy drop;"));
        assert!(!ruleset.contains("ct state")); // ADR-0001: no established-accept hole
    }

    #[test]
    fn an_empty_set_renders_without_an_elements_clause() {
        assert_eq!(
            nft_set("upstream4", &[]),
            "\tset upstream4 { type ipv4_addr; flags interval; }\n"
        );
        assert_eq!(
            nft_set("bypass4", &["1.2.3.4".into(), "10.0.0.0/8".into()]),
            "\tset bypass4 { type ipv4_addr; flags interval; elements = { 1.2.3.4, 10.0.0.0/8 } }\n"
        );
    }
}
