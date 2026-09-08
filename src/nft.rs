//! The only place that shells out. ADR-0001: the kernel enforces, bullseye just
//! loads and destroys one table.

use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

/// Set once by the TUI. Every sudo call it makes has its streams piped, so a
/// password prompt would be invisible and the screen would simply stop responding.
/// `-n` turns that hang into an error the TUI can print.
static NON_INTERACTIVE: AtomicBool = AtomicBool::new(false);

pub fn never_prompt() {
    NON_INTERACTIVE.store(true, Ordering::Relaxed);
}

/// A transient systemd timer, not a thread — the revert has to survive this process
/// being killed and the terminal going away, which is the case the guard exists for.
const REVERT_UNIT: &str = "bullseye-revert";

/// The TUI asks before it draws: a sudo password prompt behind an alternate screen
/// is a hang with no visible cause.
pub fn is_root() -> bool {
    std::fs::metadata("/proc/self")
        .map(|m| m.uid() == 0)
        .unwrap_or(false)
}

/// Every privileged call goes through here, so the move to polkit or a privileged
/// helper is one change in one place (ADR-0001, costs).
fn privileged(program: &str) -> Command {
    if is_root() {
        return Command::new(program);
    }
    let mut sudo = Command::new("sudo");
    if NON_INTERACTIVE.load(Ordering::Relaxed) {
        sudo.arg("-n");
    }
    sudo.arg(program);
    sudo
}

/// Ok is stdout, Err is stderr — callers read the error text, since "table absent"
/// and "nft is broken" arrive on the same exit code.
/// Also used by `discover` for `ss` and `wg`, so this stays the one place bullseye
/// shells out at all.
pub fn run(program: &str, args: &[&str], script: Option<&str>) -> Result<String, String> {
    let mut child = privileged(program)
        .args(args)
        .stdin(if script.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run {program}: {e}"))?;
    if let Some(script) = script {
        child
            .stdin
            .take()
            .expect("stdin was piped")
            .write_all(script.as_bytes())
            .map_err(|e| format!("writing to {program}: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("waiting for {program}: {e}"))?;
    match out.status.success() {
        true => Ok(String::from_utf8_lossy(&out.stdout).into_owned()),
        false => Err(String::from_utf8_lossy(&out.stderr).trim().to_owned()),
    }
}

/// Validate a ruleset without loading it. Needs root anyway: nft cannot initialise
/// its cache unprivileged, even in check mode.
pub fn check(script: &str) -> Result<(), String> {
    run("nft", &["-c", "-f", "-"], Some(script)).map(drop)
}

pub fn apply(script: &str) -> Result<(), String> {
    run("nft", &["-f", "-"], Some(script)).map(drop)
}

pub fn show() -> Result<String, String> {
    run("nft", &["list", "table", "inet", "bullseye"], None)
}

/// The escape hatch, and idempotent — `destroy` on an absent table succeeds.
pub fn destroy() -> Result<(), String> {
    run("nft", &["destroy", "table", "inet", "bullseye"], None).map(drop)
}

/// Packets the kill switch has refused since it was armed, from the counter at the
/// bottom of the chain — and None when it is not armed at all, since the counter
/// only exists inside bullseye's own table. One call answers both questions, which
/// is what lets the TUI poll twice a minute without spawning nft twice each time.
///
/// The cheap half of a drop log: it cannot say what was blocked, but it says that
/// something was, which is the signal a user acts on.
pub fn blocked() -> Option<u64> {
    let json = run("nft", &["-j", "list", "table", "inet", "bullseye"], None).ok()?;
    let listing: serde_json::Value = serde_json::from_str(&json).ok()?;
    listing["nftables"]
        .as_array()?
        .iter()
        .find(|entry| entry["rule"]["comment"] == "bullseye: egress blocked")?["rule"]["expr"]
        .as_array()?
        .iter()
        .find_map(|expr| expr["counter"]["packets"].as_u64())
}

pub fn schedule_revert(seconds: u32) -> Result<(), String> {
    let _ = cancel_revert(); // a leftover timer would collide on the unit name
    run(
        "systemd-run",
        &[
            &format!("--on-active={seconds}"),
            &format!("--unit={REVERT_UNIT}"),
            "--collect",
            "nft",
            "destroy",
            "table",
            "inet",
            "bullseye",
        ],
        None,
    )
    .map(drop)
}

pub fn cancel_revert() -> Result<(), String> {
    run(
        "systemctl",
        &["stop", &format!("{REVERT_UNIT}.timer")],
        None,
    )
    .map(drop)
}
