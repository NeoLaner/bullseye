//! Boot arming, and keeping the ruleset true while the VPN's server moves.
//!
//! Principle 2 still holds: the daemon is not in the packet path, and the kill
//! switch does not stop holding when it dies. It does two things — it arms once at
//! startup, so a box is protected before its first packet leaves, and it notices
//! when the ruleset it *would* build now differs from the one it loaded, which is
//! what a VPN reconnecting to a different server looks like from here.
//!
//! The table is the state (glossary: armed or disarmed, no third). A box the user
//! disarmed stays disarmed: the daemon maintains an armed ruleset, it does not
//! overrule a decision to have none. Restarting the unit is therefore also how you
//! arm again from outside the UI.

use crate::config::Config;
use crate::{Plan, nft};
use std::time::Duration;

/// Slow on purpose. A tick reads /proc, asks `ss` and resolves every bypass
/// domain, and the thing it is watching for — the VPN moving server — happens
/// about once an hour. Nothing waits on this tick: the tray redraws from its own
/// click at once, and this only confirms it.
const TICK: Duration = Duration::from_secs(30);

/// What the tray reads instead of asking nft itself. The tray runs as the user, so
/// each of its `nft` calls would be a `sudo` call, and sudo writes two journal
/// lines apiece — 5k lines a day to draw one icon.
///
/// It goes away with the daemon's RuntimeDirectory, which is the point: a tray
/// that finds no file asks the kernel directly rather than showing a stale answer
/// about a kill switch.
pub const STATE_FILE: &str = "/run/bullseye/state";

/// What the tray draws. The glossary has two states, armed and disarmed. This has
/// two more, and both are things the user has to be told rather than left to infer:
/// "armed, and nothing is getting out", which is the answer to "why did my
/// internet stop"; and "cannot tell", which is not the same as "off" and must
/// never be drawn as it — the ruleset may be holding perfectly well.
///
/// The daemon only ever publishes the first three. `Unknown` is what the tray
/// reaches when it has neither a daemon to read nor an nft it is allowed to run.
#[derive(Clone, Copy, PartialEq)]
pub enum State {
    Armed,
    Blocked,
    Disarmed,
    Unknown,
}

/// The state, and the lines underneath that say why it is that.
pub struct Status {
    pub state: State,
    pub detail: String,
    /// When the daemon wrote this. The tray needs it to tell a fresh answer from
    /// one published before its own last click: this clock is slow on purpose, and
    /// an icon that lags a click is an icon that gets clicked again.
    pub published: std::time::SystemTime,
}

impl State {
    fn word(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::Blocked => "blocked",
            Self::Disarmed => "disarmed",
            Self::Unknown => "unknown",
        }
    }

    fn spelt(word: &str) -> Option<Self> {
        match word {
            "armed" => Some(Self::Armed),
            "blocked" => Some(Self::Blocked),
            "disarmed" => Some(Self::Disarmed),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// The last thing the daemon published, or None when no daemon is running.
pub fn status() -> Option<Status> {
    let text = std::fs::read_to_string(STATE_FILE).ok()?;
    let published = std::fs::metadata(STATE_FILE).ok()?.modified().ok()?;
    let (word, detail) = text.split_once('\n')?;
    Some(Status {
        state: State::spelt(word)?,
        detail: detail.to_owned(),
        published,
    })
}

/// What the daemon loaded, which is not what `plan` would build now — that is the
/// whole difference it watches for. The flag is carried separately because a
/// freshly built plan cannot answer whether what is *in the kernel* is a lockdown
/// once the world has moved on underneath it.
#[derive(Default)]
struct Loaded {
    ruleset: Option<String>,
    lockdown: bool,
}

pub fn run() -> Result<(), String> {
    if !nft::is_root() {
        return Err("the daemon loads and destroys an nftables table, which needs root".into());
    }
    // A missing config file is the default config, which is right for a first run
    // by hand and wrong for a daemon: it would arm on discovery alone, quietly
    // ignoring the pin and the bypasses the user wrote. Said once, at startup,
    // because the alternative is a box that is armed differently than its config
    // says with nothing anywhere to explain it.
    let path = crate::config::path();
    if !path.exists() {
        eprintln!(
            "bullseye: {} does not exist, so this is running on defaults — no pin, \
             no bypasses, upstream by discovery alone. The unit points \
             BULLSEYE_CONFIG at /etc/bullseye/config.toml; symlink your own config \
             there.",
            path.display()
        );
    }
    let mut loaded = Loaded::default();
    let mut announced = String::new();
    loop {
        // Never fatal. A daemon that exits because the config was briefly
        // unreadable takes the box's only re-armer with it, and systemd restarting
        // it would re-arm from scratch every time.
        if let Err(why) = tick(&mut loaded, &mut announced) {
            let complaint = format!("bullseye: {why}");
            if complaint != announced {
                eprintln!("{complaint}");
                announced = complaint;
            }
        }
        std::thread::sleep(TICK);
    }
}

fn tick(loaded: &mut Loaded, announced: &mut String) -> Result<(), String> {
    let config = Config::load()?;
    let plan = crate::plan(&config, false)?;
    let ruleset = plan.holes.ruleset();
    // One nft call answers both questions, so the tick costs one process.
    let blocked = nft::blocked();

    let first_run = loaded.ruleset.is_none();
    // Widening is safe, narrowing to a lockdown is not: a VPN that has stopped
    // long enough for discovery to lose it would be sealed away from its own
    // server, and could never dial back out to be discovered again. The stale
    // holes stay open instead — one address the user already approved, against a
    // box with no way to fix itself.
    let usable = !plan.holes.is_lockdown() || loaded.lockdown;
    let changed = loaded.ruleset.as_deref() != Some(ruleset.as_str());

    // Lockdown is right exactly once, at boot, when nothing has ever been known:
    // fail closed until the upstream turns up (principle 1, and PLAN's boot
    // deadlock — a pin or a VPN config is what breaks it).
    if first_run || (changed && usable && blocked.is_some()) {
        crate::arm(&plan, None)?;
        loaded.lockdown = plan.holes.is_lockdown();
        loaded.ruleset = Some(ruleset);
        let said = format!("bullseye: armed\n{}", plan.report);
        if said != *announced {
            print!("{said}");
            *announced = said;
        }
        // A table that was just replaced has a counter at zero; asking nft again
        // for a number we already know would double the tick's cost.
        publish(&plan, Some(0));
        return Ok(());
    }
    publish(&plan, blocked);
    Ok(())
}

/// One word the tray maps to an icon, then the same report the CLI prints.
fn publish(plan: &Plan, blocked: Option<u64>) {
    let (state, detail) = describe(plan, blocked);
    let path = std::path::Path::new(STATE_FILE);
    if let Some(directory) = path.parent() {
        let _ = std::fs::create_dir_all(directory);
    }
    let _ = std::fs::write(path, format!("{}\n{detail}", state.word()));
}

/// Armed is not the same as working, and the gap between them is the thing worth
/// showing: a pin that no longer matches, or a tunnel that never came up, is a box
/// where nothing gets out at all — and "the internet stopped" is otherwise
/// indistinguishable from a broken kill switch (glossary, mismatch).
fn describe(plan: &Plan, blocked: Option<u64>) -> (State, String) {
    let Some(packets) = blocked else {
        return (
            State::Disarmed,
            "Nothing is enforced — every packet leaves as it likes.".into(),
        );
    };
    let mut state = State::Armed;
    let mut detail = String::new();
    if let Some(actual) = &plan.mismatch {
        detail += &format!(
            "MISMATCH — the VPN is talking to {actual}, which the pin does not\n\
                            cover, so its own traffic is being dropped.\n\n"
        );
        state = State::Blocked;
    }
    if plan.holes.tunnel().is_empty() {
        detail += "No tunnel is up, so nothing can leave through one.\n\n";
        state = State::Blocked;
    }
    detail += &plan.report;
    detail += &format!("\n{packets} packets blocked since arming");
    (state, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Built by hand rather than through `plan`, which shells out to `ss` and
    /// reads /proc: what is being tested is how a plan is described, not whether
    /// this machine happens to have a tunnel up.
    fn plan_of(tunnel: Option<&str>, mismatch: Option<&str>) -> Plan {
        let mut holes = crate::rules::Holes::default();
        if let Some(tunnel) = tunnel {
            holes.add_tunnel(tunnel).unwrap();
        }
        Plan {
            holes,
            report: "tunnel   wg0 (wireguard)\n".into(),
            mismatch: mismatch.map(str::to_owned),
        }
    }

    #[test]
    fn a_state_word_survives_the_round_trip_to_the_tray() {
        for state in [
            State::Armed,
            State::Blocked,
            State::Disarmed,
            State::Unknown,
        ] {
            assert!(State::spelt(state.word()) == Some(state));
        }
        // The word is the first line and nothing else, or the tray would map a
        // kill switch's state off a string it did not recognise.
        assert!(State::spelt("armed\n").is_none());
        assert!(State::spelt("").is_none());
    }

    #[test]
    fn armed_is_not_the_same_as_working() {
        // Armed and healthy: a tunnel to leave through, and the pin agrees.
        let (state, detail) = describe(&plan_of(Some("wg0"), None), Some(7));
        assert!(state == State::Armed);
        assert!(detail.contains("7 packets blocked"));
        assert!(
            detail.contains("tunnel   wg0"),
            "the report is kept, not replaced"
        );

        // Armed with no tunnel, and armed against the wrong server, are both
        // "nothing gets out" — the state the user needs named, because it is
        // otherwise indistinguishable from a kill switch that has broken.
        assert!(describe(&plan_of(None, None), Some(0)).0 == State::Blocked);
        let (state, detail) = describe(&plan_of(Some("wg0"), Some("1.2.3.4")), Some(0));
        assert!(state == State::Blocked);
        assert!(detail.contains("MISMATCH") && detail.contains("1.2.3.4"));

        // Disarmed outranks every complaint: there is nothing there to block.
        assert!(describe(&plan_of(None, Some("1.2.3.4")), None).0 == State::Disarmed);
    }
}
