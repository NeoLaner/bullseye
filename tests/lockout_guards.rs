//! The lockout checklist from .github/pull_request_template.md, run rather than ticked.
//!
//! A kill switch bug takes a machine offline with no obvious cause, so these guards
//! are the part that must not rot. Every one of them fires before bullseye reaches
//! for nft, which is why the whole file runs without root.
//!
//! Interfaces are named `bullseye_gone` on purpose: discovery reads the real
//! machine, so a test naming a plausible interface would pass or fail depending on
//! what the developer happens to have running.

use std::process::{Command, Output};

fn bullseye(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bullseye"))
        .args(args)
        // Never the developer's own config: these guards have to hold on a machine
        // configured any way at all, and a pin or a bypass sitting in ~/.config
        // would quietly change what is being tested.
        .env("BULLSEYE_CONFIG", "/nonexistent/bullseye/config.toml")
        .output()
        .expect("the binary under test was built")
}

/// Asserts the command was refused, and hands back everything it said. Both
/// streams: discovery reports what it found on stdout and the refusal lands on
/// stderr, so a reason can be on either.
fn refused(args: &[&str]) -> String {
    let out = bullseye(args);
    assert!(!out.status.success(), "expected {args:?} to be refused");
    String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
}

#[test]
fn an_upstream_that_cannot_be_found_is_refused_and_names_the_way_out() {
    // Nothing to discover from: the interface is not up, so there is no cgroup
    // holding it and nothing running to ask. Lockdown is a real state, so the
    // refusal has to name the way into it rather than just failing.
    let why = refused(&["arm", "--tunnel", "bullseye_gone"]);
    assert!(why.contains("--lockdown"), "{why}");
    assert!(why.contains("--vpn-config"), "{why}");
}

#[test]
fn a_dead_cgroup_is_not_an_upstream() {
    // ADR-0003: the path must hold a process. A `wg-quick@` oneshot releases its
    // cgroup the moment it exits, so an existence check would accept a rule that
    // can never match and strangle the tunnel silently.
    let why = refused(&[
        "arm",
        "--tunnel",
        "bullseye_gone",
        "--cgroup",
        "system.slice/bullseye-absent.service",
    ]);
    assert!(why.contains("no upstream found"), "{why}");
}

#[test]
fn a_config_naming_nothing_reachable_is_refused() {
    refused(&[
        "arm",
        "--tunnel",
        "bullseye_gone",
        "--vpn-config",
        "/dev/null",
    ]);
}

#[test]
fn a_hole_that_matches_everything_is_refused() {
    for hole in ["--bypass", "--pin"] {
        let why = refused(&["arm", "--tunnel", "bullseye_gone", hole, "0.0.0.0/0"]);
        assert!(why.contains("turns the kill switch off"), "{hole}: {why}");
    }
}

#[test]
fn nothing_unparsed_can_reach_a_root_ruleset() {
    refused(&[
        "arm",
        "--tunnel",
        "wg0",
        "--pin",
        "1.2.3.4 } ; chain evil {",
    ]);
    refused(&["arm", "--tunnel", "wg0\" accept; ", "--pin", "1.2.3.4"]);
    refused(&["arm", "--tunnel", "wg0", "--pin", "registry.npmjs.org"]);
    refused(&["arm", "--tunnel", "wg0", "--bypass", "evil\".com"]);
    refused(&["arm", "--tunnel", "wg0", "--timeout", "soon"]);
    refused(&["arm", "--tunnel", "--pin", "1.2.3.4"]); // a flag is not a value
}

#[test]
fn the_escape_hatch_is_in_the_help_where_a_locked_out_user_will_look() {
    let usage = String::from_utf8_lossy(&bullseye(&["--help"]).stdout).into_owned();
    assert!(usage.contains("nft destroy table inet bullseye"), "{usage}");
}
