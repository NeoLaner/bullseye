//! The config file — `~/.config/bullseye/config.toml` — and the only writer of it.
//!
//! Everything here ends up in a ruleset that runs as root, so every value is
//! validated by `rules` on the way in. Nothing reaches the file, or nft, unparsed.

use crate::rules;
use std::path::{Path, PathBuf};

/// Sockets owned by this group leave outside the tunnel. It does not exist until
/// the user creates it, and the hole stays closed until it does — a group that is
/// absent is not an allowance waiting to happen.
pub const BYPASS_GROUP: &str = "bullseye-bypass";

pub struct Config {
    pub interface: Option<String>,
    pub cgroup: Option<String>,
    pub vpn_config: Option<PathBuf>,
    /// The upstream, fixed to one address by the user. The VPN may reach that
    /// server and no other: if it moves, the tunnel dies rather than the hole
    /// quietly following it somewhere the user never approved.
    pub pin: Option<String>,
    pub allow: Vec<String>,
    pub apps: Vec<String>,
    pub group: String,
    pub lan: bool,
    pub tailscale: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interface: None,
            cgroup: None,
            vpn_config: None,
            pin: None,
            allow: Vec::new(),
            apps: Vec::new(),
            group: BYPASS_GROUP.to_owned(),
            lan: true,
            tailscale: true, // principle 3: there is always a way back in
        }
    }
}

impl Config {
    /// A missing file is the default config, not an error — bullseye has to work
    /// on a machine it has never been configured on.
    pub fn load() -> Result<Self, String> {
        let path = path();
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Ok(Self::default());
        };
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    fn parse(text: &str) -> Result<Self, String> {
        let doc: toml::Table = text.parse().map_err(|e| format!("{e}"))?;
        let default = Self::default();
        Ok(Self {
            interface: optional(&doc, "vpn", "interface", rules::interface)?,
            cgroup: optional(&doc, "vpn", "cgroup", |v| rules::cgroup(v).map(|(p, _)| p))?,
            vpn_config: optional(&doc, "vpn", "config", |v| Ok(v.to_owned()))?.map(PathBuf::from),
            pin: optional(&doc, "vpn", "pin", rules::address)?,
            allow: every(&doc, "bypass", "allow", rules::bypass_entry)?,
            apps: every(&doc, "bypass", "apps", rules::app)?,
            group: optional(&doc, "bypass", "group", rules::group)?.unwrap_or(default.group),
            lan: flag(&doc, "local", "lan", default.lan)?,
            tailscale: flag(&doc, "local", "tailscale", default.tailscale)?,
        })
    }

    pub fn allow(&mut self, entry: &str) -> Result<(), String> {
        let entry = rules::bypass_entry(entry)?;
        if !self.allow.contains(&entry) {
            self.allow.push(entry);
        }
        Ok(())
    }

    pub fn deny(&mut self, entry: &str) -> bool {
        let before = self.allow.len() + self.apps.len();
        self.allow.retain(|kept| kept != entry);
        self.apps.retain(|kept| kept != entry);
        before != self.allow.len() + self.apps.len()
    }

    /// Written whole, with the comments, so the file stays hand-editable after the
    /// TUI has touched it. Every value went through `rules`, so plain quoting is
    /// enough: none of them can contain a quote.
    pub fn save(&self) -> Result<(), String> {
        let path = path();
        let directory = path.parent().expect("the config path has a directory");
        std::fs::create_dir_all(directory).map_err(|e| format!("{}: {e}", directory.display()))?;
        std::fs::write(&path, self.render()).map_err(|e| format!("{}: {e}", path.display()))?;
        // Under sudo — which the TUI needs for nft — a fresh file would land owned
        // by root, and the user could no longer edit their own config by hand.
        give_back(directory);
        give_back(&path);
        Ok(())
    }

    fn render(&self) -> String {
        let mut s = String::from(
            "# bullseye — a VPN kill switch. The output chain drops; everything below\n\
             # is a hole in it. Every hole outside the tunnel carries your real address.\n\n\
             [vpn]\n",
        );
        s += &line(
            "interface",
            self.interface.as_deref(),
            "the tunnel; detected from the device type when absent",
        );
        s += &line(
            "cgroup",
            self.cgroup.as_deref(),
            "match the VPN's process, not its address, so the hole survives a server change",
        );
        s += &line(
            "config",
            self.vpn_config.as_ref().and_then(|p| p.to_str()),
            "a WireGuard, OpenVPN or xray config — the only source that works before the VPN starts",
        );
        s += &line(
            "pin",
            self.pin.as_deref(),
            "the VPN may reach this address and no other; if its server moves, nothing gets out",
        );
        s += "\n[bypass]\n\
              # Leaves outside the tunnel, with your real address: an IP, a CIDR or a domain.\n";
        s += &format!("allow = {}\n", strings(&self.allow));
        s += "# Launched by `bullseye run <name>`, and listed in the TUI.\n";
        s += &format!("apps = {}\n", strings(&self.apps));
        s += "# Sockets owned by this group leave outside the tunnel. No group, no hole:\n\
              #   sudo groupadd -f bullseye-bypass && sudo gpasswd -a $USER bullseye-bypass\n";
        s += &format!("group = {}\n", quoted(&self.group));
        s += "\n[local]\n\
              # LAN, DHCP, multicast — none of it routes to the internet.\n";
        s += &format!("lan = {}\n", self.lan);
        s += "# Both tailscale holes: the tunnel, and tailscaled's own control plane.\n\
              # This is the way back into a box you have locked yourself out of.\n";
        s += &format!("tailscale = {}\n", self.tailscale);
        s
    }
}

/// The config belongs to the user even when bullseye is running as root, because
/// the TUI needs root for nft and would otherwise quietly start a second config
/// under `/root`.
pub fn path() -> PathBuf {
    // The override exists so the tests can run against a config that is not the
    // developer's own — a kill switch test that reads whatever happens to be in
    // ~/.config passes or fails by accident.
    match std::env::var("BULLSEYE_CONFIG") {
        Ok(path) => PathBuf::from(path),
        Err(_) => home().join(".config/bullseye/config.toml"),
    }
}

fn home() -> PathBuf {
    if let Ok(user) = std::env::var("SUDO_USER")
        && let Some(home) = passwd_home(&user)
    {
        return home;
    }
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/root"))
}

/// `name:x:uid:gid:gecos:home:shell` — the sixth field. Read rather than shelled
/// out to: this runs before the TUI has a terminal to report a failure on.
fn passwd_home(user: &str) -> Option<PathBuf> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd
        .lines()
        .find(|line| line.starts_with(&format!("{user}:")))
        .and_then(|line| line.split(':').nth(5))
        .map(PathBuf::from)
}

fn give_back(path: &Path) {
    if let (Ok(uid), Ok(gid)) = (env_id("SUDO_UID"), env_id("SUDO_GID")) {
        let _ = std::os::unix::fs::chown(path, Some(uid), Some(gid));
    }
}

fn env_id(name: &str) -> Result<u32, ()> {
    std::env::var(name).map_err(|_| ())?.parse().map_err(|_| ())
}

fn optional(
    doc: &toml::Table,
    section: &str,
    key: &str,
    valid: impl Fn(&str) -> Result<String, String>,
) -> Result<Option<String>, String> {
    match doc.get(section).and_then(|s| s.get(key)) {
        None => Ok(None),
        Some(value) => {
            let text = value
                .as_str()
                .ok_or_else(|| format!("[{section}] {key}: expected a string"))?;
            // An empty value reads as "not set" in a file people edit by hand,
            // and validating it would reject a config the user meant to blank out.
            match text.is_empty() {
                true => Ok(None),
                false => Ok(Some(
                    valid(text).map_err(|e| format!("[{section}] {key}: {e}"))?,
                )),
            }
        }
    }
}

fn every(
    doc: &toml::Table,
    section: &str,
    key: &str,
    valid: impl Fn(&str) -> Result<String, String>,
) -> Result<Vec<String>, String> {
    let Some(value) = doc.get(section).and_then(|s| s.get(key)) else {
        return Ok(Vec::new());
    };
    let entries = value
        .as_array()
        .ok_or_else(|| format!("[{section}] {key}: expected a list"))?;
    entries
        .iter()
        .map(|entry| {
            let text = entry
                .as_str()
                .ok_or_else(|| format!("[{section}] {key}: expected a list of strings"))?;
            valid(text).map_err(|e| format!("[{section}] {key}: {e}"))
        })
        .collect()
}

fn flag(doc: &toml::Table, section: &str, key: &str, default: bool) -> Result<bool, String> {
    match doc.get(section).and_then(|s| s.get(key)) {
        None => Ok(default),
        Some(value) => value
            .as_bool()
            .ok_or_else(|| format!("[{section}] {key}: expected true or false")),
    }
}

fn line(key: &str, value: Option<&str>, why: &str) -> String {
    // An unset key is written commented out rather than dropped, so the file
    // documents what can be set without the user going to find the README.
    match value {
        Some(value) => format!("# {why}\n{key} = {}\n", quoted(value)),
        None => format!("# {why}\n#{key} = \"\"\n"),
    }
}

fn quoted(value: &str) -> String {
    format!("\"{value}\"")
}

fn strings(values: &[String]) -> String {
    match values {
        [] => "[]".to_owned(),
        values => format!(
            "[{}]",
            values
                .iter()
                .map(|v| quoted(v))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_saved_config_reads_back_as_itself() {
        let mut config = Config {
            interface: Some("xray_tun".into()),
            pin: Some("5.6.7.8".into()),
            ..Default::default()
        };
        config.allow("registry.npmjs.org").unwrap();
        config.allow("192.168.1.50").unwrap();
        config.apps.push("firefox".into());
        config.lan = false;

        let read = Config::parse(&config.render()).unwrap();
        assert_eq!(read.interface.as_deref(), Some("xray_tun"));
        assert_eq!(read.pin.as_deref(), Some("5.6.7.8"));
        assert_eq!(read.allow, ["registry.npmjs.org", "192.168.1.50"]);
        assert_eq!(read.apps, ["firefox"]);
        assert!(!read.lan && read.tailscale);
        assert_eq!(read.group, BYPASS_GROUP);
    }

    #[test]
    fn a_config_that_would_widen_the_ruleset_is_refused_not_ignored() {
        // Fail closed: a config bullseye cannot understand stops it, rather than
        // arming with the half of the file it did parse.
        assert!(Config::parse("[vpn]\npin = \"1.2.3.4 } ; chain evil {\"\n").is_err());
        assert!(Config::parse("[bypass]\nallow = [\"0.0.0.0/0\"]\n").is_err());
        assert!(Config::parse("[vpn]\ninterface = \"wg0\\\" accept; \"\n").is_err());
        assert!(Config::parse("[local]\nlan = \"yes\"\n").is_err());
        assert!(Config::parse("[bypass]\nallow = \"one.example.com\"\n").is_err());
        // A blank value is how someone clears a key by hand.
        assert!(Config::parse("[vpn]\npin = \"\"\n").unwrap().pin.is_none());
    }

    #[test]
    fn denying_removes_an_address_a_domain_or_an_app() {
        let mut config = Config::default();
        config.allow("1.2.3.4").unwrap();
        config.apps.push("firefox".into());
        assert!(config.deny("1.2.3.4") && config.deny("firefox"));
        assert!(!config.deny("1.2.3.4"));
        assert!(config.allow.is_empty() && config.apps.is_empty());
    }
}
