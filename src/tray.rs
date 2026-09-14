//! The kill switch in the bar: what it is doing, and one click to change it.
//!
//! A StatusNotifierItem rather than a module for one bar, so the same binary shows
//! up in Waybar, KDE, GNOME's extensions and anything else that speaks the spec.
//! It runs as the user, because the session bus the tray lives on is the user's —
//! and so it reads the daemon's published state rather than asking nft, since
//! every such ask would be a `sudo` call and sudo writes two journal lines each.
//!
//! Quitting it changes nothing. The ruleset is in the kernel and stays there
//! (principle 2); the icon going away means the icon went away.

use crate::daemon::{self, State};
use crate::{config::Config, nft};
use ksni::blocking::{Handle, TrayMethods};
use ksni::menu::StandardItem;
use ksni::{Category, MenuItem, Status, ToolTip};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime};

/// Re-reading a file costs nothing, and nothing here needs to be faster: a click
/// redraws from its own outcome at once, and everything else moves on the daemon's
/// slower clock.
const REFRESH: Duration = Duration::from_secs(5);

/// Only reached when no daemon is running, when this has to ask nft itself. Each
/// ask is a line in the journal, so it asks rarely and says so in the tooltip.
const PROBE: Duration = Duration::from_secs(30);

/// The tray's own handle, so a click can hand slow work to a thread and still
/// redraw when it finishes. It cannot live in the struct: `spawn` consumes the
/// tray and hands the handle back afterwards.
static HANDLE: OnceLock<Handle<Bullseye>> = OnceLock::new();

pub fn run() -> Result<(), String> {
    if nft::is_root() {
        return Err(
            "run the tray as yourself, not with sudo: the tray belongs on your \
                    session bus, and root's is a different one"
                .into(),
        );
    }
    // The TUI's reason, in a place with even less to draw on: this process has no
    // terminal at all, so a sudo password prompt would be a click that silently
    // never finishes.
    nft::never_prompt();

    let mut tray = Bullseye {
        // Never "off" as a starting guess: the first read has not happened yet,
        // and a bar that says the kill switch is off before it has looked is
        // wrong in the direction that matters.
        state: State::Unknown,
        detail: String::new(),
        problem: None,
        working: false,
        probed: None,
        acted: None,
    };
    tray.reread();
    // The tray may well start before the bar does — a session autostart usually
    // does. Without this that is a hard error at spawn; with it, the watcher
    // turning up later is enough.
    let handle = tray
        .assume_sni_available(true)
        .spawn()
        .map_err(|e| format!("no system tray on this session bus: {e}"))?;
    let _ = HANDLE.set(handle.clone());

    while !handle.is_closed() {
        std::thread::sleep(REFRESH);
        let _ = handle.update(Bullseye::reread);
    }
    Ok(())
}

struct Bullseye {
    state: State,
    detail: String,
    /// The last thing that went wrong, kept until the next click rather than
    /// overwritten by the next refresh: an arm that was refused is the one message
    /// the user has to be able to read.
    problem: Option<String>,
    /// Set while a click is still being served. A kill switch that toggles twice
    /// because the second click landed before the first had finished is worse than
    /// one that ignores the second.
    working: bool,
    probed: Option<Instant>,
    /// When this tray last changed the ruleset itself. Until the daemon has
    /// published something newer, its file still describes the box as it was
    /// before the click — and believing it would show the state the user just
    /// changed away from, at the one moment they are looking at the icon.
    acted: Option<SystemTime>,
}

impl Bullseye {
    /// The daemon's answer where there is one, and the kernel's where there is not.
    fn reread(&mut self) {
        if self.working {
            return; // a click is still in flight; it will redraw when it lands
        }
        if let Some(status) = daemon::status()
            && caught_up(status.published, self.acted)
        {
            self.state = status.state;
            self.detail = status.detail;
            self.acted = None;
            self.probed = None;
            return;
        }
        // Either no daemon, or one that has not noticed the click yet. Both mean
        // the kernel is the only thing that can be asked.
        if self.probed.is_some_and(|at| at.elapsed() < PROBE) {
            return;
        }
        self.probed = Some(Instant::now());
        // Coarser than the daemon's answer on purpose: telling armed from disarmed
        // is one nft call, while telling working from merely armed would mean
        // running discovery, and discovery from here is more sudo than a status
        // icon is worth.
        //
        // `show`, not `blocked`, because the two failures have to stay apart. An
        // absent table and an nft this user may not run both come back as "no
        // number", and drawing the second as "off" would be the one lie a kill
        // switch must never tell.
        match nft::show() {
            Ok(_) => {
                self.state = State::Armed;
                self.detail = "The ruleset is loaded.".into();
            }
            Err(why) if why.contains("No such file or directory") => {
                self.state = State::Disarmed;
                self.detail = "Nothing is enforced — every packet leaves as it likes.".into();
            }
            Err(why) => {
                // Not knowing is not "off", and drawing it as "off" would be the
                // one lie a kill switch must never tell: the ruleset may be
                // holding perfectly well right now.
                self.state = State::Unknown;
                self.detail = format!(
                    "nft would not answer, and no daemon is running to have asked \
                     for me, so nothing here knows whether the kill switch is on:\n\n\
                     {why}\n\n\
                     Either enable the bullseye service, or allow this user to run \
                     nft without a password — there is nowhere to type one into a \
                     bar icon."
                );
                return;
            }
        }
        self.detail += "\n\nNo bullseye daemon is running, so nothing re-arms when the \
                        VPN moves to another server, and the packet counter is not \
                        being read.";
    }

    fn toggle(&mut self) {
        if self.working {
            return;
        }
        self.working = true;
        self.problem = None;
        // Anything but a box known to be armed is armed by a click. From
        // Unknown that is the safe direction: arming a box that already is one is
        // an atomic replacement of the same ruleset, while disarming it is not.
        let arming = self.state != State::Armed && self.state != State::Blocked;
        self.detail = match arming {
            true => "Arming…",
            false => "Disarming…",
        }
        .into();
        // Off the bus thread. Arming resolves every bypass domain and asks `ss` who
        // holds the tunnel, which is seconds — and a menu that freezes for seconds
        // is a menu that gets clicked again.
        std::thread::spawn(move || {
            let outcome = match arming {
                true => arm(),
                false => crate::disarm(),
            };
            let Some(handle) = HANDLE.get() else {
                return;
            };
            let _ = handle.update(|tray: &mut Bullseye| {
                tray.working = false;
                tray.probed = None;
                match outcome {
                    // What just happened is known here, and is known sooner than
                    // anything that has to be read back out of the kernel.
                    Ok(()) => {
                        tray.acted = Some(SystemTime::now());
                        tray.state = match arming {
                            true => State::Armed,
                            false => State::Disarmed,
                        };
                        tray.detail = match arming {
                            true => "Armed just now.",
                            false => "Disarmed just now — nothing is enforced.",
                        }
                        .into();
                    }
                    Err(why) => {
                        tray.problem = Some(why);
                        tray.reread();
                    }
                }
            });
        });
    }

    /// Everything the tooltip and the menu say, worst news first.
    fn lines(&self) -> String {
        wrapped(&match &self.problem {
            Some(why) => format!("{why}\n\n{}", self.detail),
            None => self.detail.clone(),
        })
    }
}

/// The tray's arm: build a plan, then refuse the two shapes that would take the
/// box off the network. `refuse_lockout` is shared with the TUI so that a click
/// and a keystroke cannot come to different conclusions.
fn arm() -> Result<(), String> {
    let config = Config::load()?;
    let plan = crate::plan(&config, false)?;
    crate::refuse_lockout(&plan)?;
    crate::arm(&plan, None)
}

impl ksni::Tray for Bullseye {
    fn id(&self) -> String {
        "bullseye".into()
    }

    fn title(&self) -> String {
        "bullseye".into()
    }

    /// Not an application: it is the state of something the kernel is doing, which
    /// carries on whether this is running or not.
    fn category(&self) -> Category {
        Category::SystemServices
    }

    fn status(&self) -> Status {
        match self.state {
            // Armed and nothing getting out is the state worth interrupting for:
            // it is the answer to "why did my internet stop", and a bar that
            // emphasises it saves the user the search.
            State::Blocked | State::Unknown => Status::NeedsAttention,
            _ => Status::Active,
        }
    }

    /// The program's own mark, not a themed name. `icon_name` stays empty on
    /// purpose: the spec says a host prefers the name and falls back to the
    /// pixmap, so anything returned here would hide the bullseye.
    ///
    /// The themed names were tried first and are why this exists. The obvious
    /// ones — `security-high`, `-medium`, `-low` — are correct on Breeze and
    /// inverted on Adwaita, which ships "high" as a red shield and "low" as a
    /// friendly gold one: backwards for a control whose good state is the locked
    /// one. The padlock pair that replaced them is a colour icon on Adwaita and
    /// monochrome on Breeze, so the same box looked like two different programs.
    /// A drawn icon is the same icon everywhere.
    ///
    /// Three sizes because the host picks the nearest and scales; 22 is the usual
    /// bar height and 44 is the same bar on a HiDPI screen.
    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        [22, 32, 44].iter().map(|&px| draw(px, self.state)).collect()
    }

    /// Hosts that honour NeedsAttention draw this one instead, so it has to say
    /// the same thing rather than fall back to a default.
    fn attention_icon_pixmap(&self) -> Vec<ksni::Icon> {
        self.icon_pixmap()
    }

    fn tool_tip(&self) -> ToolTip {
        ToolTip {
            icon_pixmap: self.icon_pixmap(),
            // A refused click outranks the state: it is the one message the user
            // asked for, and the state behind it has not changed anyway.
            title: match self.problem.as_deref().and_then(|why| why.lines().next()) {
                Some(why) => why.to_owned(),
                None => match self.state {
                    State::Armed => "Kill switch: armed",
                    State::Blocked => "Kill switch: armed — nothing is getting out",
                    State::Disarmed => "Kill switch: off",
                    State::Unknown => "Kill switch: cannot tell",
                }
                .into(),
            },
            // Markup, not plain text: a bar renders a subset of HTML here, and an
            // ampersand in a config value would otherwise end the tooltip early.
            description: escaped(&self.lines()),
            ..Default::default()
        }
    }

    /// Left click, which is the whole point of the icon.
    fn activate(&mut self, _x: i32, _y: i32) {
        self.toggle();
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let mut items = vec![
            StandardItem {
                label: match self.state {
                    State::Armed | State::Blocked => "Disarm — stop enforcing anything".into(),
                    _ => "Arm — drop everything that is not a hole".into(),
                },
                icon_name: menu_icon(self.state).into(),
                enabled: !self.working,
                activate: Box::new(|tray: &mut Self| tray.toggle()),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
        ];
        items.extend(
            self.lines()
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|line| {
                    StandardItem {
                        label: labelled(line),
                        enabled: false,
                        ..Default::default()
                    }
                    .into()
                }),
        );
        items.push(MenuItem::Separator);
        items.push(
            StandardItem {
                label: "Quit — the kill switch stays as it is".into(),
                icon_name: "application-exit".into(),
                // Nothing here needs unwinding, and the ruleset is not this
                // process's to hold: leaving at once is what makes the icon vanish
                // the moment it is asked to.
                activate: Box::new(|_| std::process::exit(0)),
                ..Default::default()
            }
            .into(),
        );
        items
    }
}

/// Whether the daemon's report describes the box as it is now, or as it was before
/// this tray last changed it. Equal timestamps count as caught up: the daemon
/// publishes after it acts, so a tie is its answer, not a stale one.
fn caught_up(published: SystemTime, acted: Option<SystemTime>) -> bool {
    acted.is_none_or(|acted| published >= acted)
}

/// A menu label eats single underscores — they mark access keys — and `xray_tun`
/// would arrive as `xraytun`. Doubling one is how the spec says to mean it.
fn labelled(line: &str) -> String {
    line.replace('_', "__")
}

/// A menu row is as wide as its label, and a bar will happily draw one clear
/// across the screen — a refused arm or an nft error arrives as one long sentence.
/// Everything the menu and the tooltip show comes through `lines`, so it is broken
/// here once rather than every message being written pre-broken and each of them
/// guessing at a width.
///
/// Breaks are found in the line itself rather than rebuilt out of its words, so
/// the report's columns — `tunnel   xray_tun (tun)` — keep the spacing that lines
/// them up, and a row that already fits is passed through untouched.
const WIDTH: usize = 72;

fn wrapped(text: &str) -> String {
    let mut rows = Vec::new();
    for line in text.lines() {
        let mut rest = line;
        while rest.chars().count() > WIDTH {
            let limit = rest
                .char_indices()
                .nth(WIDTH)
                .map_or(rest.len(), |(at, _)| at);
            // Nothing to break on — an address list run together, a path — goes out
            // wide. A row cut mid-word is worse than a wide one.
            let Some(at) = rest[..limit].rfind(' ') else {
                break;
            };
            rows.push(rest[..at].trim_end().to_owned());
            rest = rest[at + 1..].trim_start();
        }
        rows.push(rest.to_owned());
    }
    rows.join("\n")
}

/// A tooltip is markup, and the text pasted into it includes config values. They
/// are all validated by `rules`, so none of them can contain either of these
/// today — this is here so that staying true is not a thing to remember.
fn escaped(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;")
}

/// The logo, drawn rather than shipped. A bullseye is concentric circles, so the
/// mark that names the program is arithmetic: no image in the binary, no asset
/// path to find at runtime, no icon theme to install, and the same shape at every
/// size a bar asks for.
///
/// The gaps between the rings are left transparent rather than painted white. A
/// bar can be any colour, and rings separated by the panel behind them read as a
/// bullseye on all of them.
pub(crate) fn draw(px: i32, state: State) -> ksni::Icon {
    /// Fractions of the radius, outermost first, so a state drawn with fewer of
    /// them loses the centre rather than the ring that makes it recognisable.
    static BANDS: [(f32, f32); 3] = [(0.72, 0.98), (0.34, 0.56), (0.0, 0.18)];
    const RED: [u8; 3] = [222, 40, 33];
    const GREY: [u8; 3] = [140, 140, 140];

    // Colour is never the only difference: blocked carries the sight lines and
    // the two unenforced states lose rings, so these are four shapes to a user
    // who cannot tell the red from the grey — or whose bar renders neither.
    let (ink, bands, sights) = match state {
        State::Armed => (RED, 3, false),
        State::Blocked => (RED, 3, true),
        // The same target with nothing in the middle: nothing is being enforced.
        State::Disarmed => (GREY, 2, false),
        // One ring, and no claim about what is inside it.
        State::Unknown => (GREY, 1, false),
    };

    let radius = px as f32 / 2.0;
    let mut data = Vec::with_capacity((px * px * 4) as usize);
    for y in 0..px {
        for x in 0..px {
            // 3x3 supersample. A bar icon is 22 pixels across, and a circle drawn
            // one sample to the pixel at that size is a staircase.
            let mut covered = 0u32;
            for sample in 0..9 {
                let dx = x as f32 + (sample % 3) as f32 / 3.0 + 1.0 / 6.0 - radius;
                let dy = y as f32 + (sample / 3) as f32 / 3.0 + 1.0 / 6.0 - radius;
                let d = dx.hypot(dy) / radius;
                let on_ring = BANDS[..bands].iter().any(|&(from, to)| d >= from && d <= to);
                let on_sights = sights && d <= 1.0 && dx.abs().min(dy.abs()) < radius * 0.05;
                covered += u32::from(on_ring || on_sights);
            }
            // ARGB32 in network byte order, which is what the spec asks for, and
            // not premultiplied — only the anti-aliased edge carries a partial
            // alpha at all, so the two readings differ by a rim of pixels.
            data.extend_from_slice(&[(covered * 255 / 9) as u8, ink[0], ink[1], ink[2]]);
        }
    }
    ksni::Icon {
        width: px,
        height: px,
        data,
    }
}

/// A menu row is drawn from a themed name — the only pixmap a row can carry is a
/// PNG, and encoding one to put a bullseye next to a word is not worth a decoder
/// in the binary. So the padlock stays here, where the drawn mark cannot go.
fn menu_icon(state: State) -> &'static str {
    match state {
        State::Armed | State::Blocked => "changes-prevent",
        _ => "changes-allow",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_the_menu_and_the_tooltip_show_survives_their_own_escaping() {
        // A tunnel name is the common case and the one that breaks silently:
        // an access-key underscore is eaten, not rejected.
        assert_eq!(
            labelled("tunnel   xray_tun (tun)"),
            "tunnel   xray__tun (tun)"
        );
        assert_eq!(escaped("a & b <c>"), "a &amp; b &lt;c>");
        assert_eq!(escaped("5.6.7.8 — pinned"), "5.6.7.8 — pinned");
    }

    #[test]
    fn a_long_line_wraps_without_losing_a_word_or_a_column() {
        let refused = "No upstream: the VPN cannot reach its own server, so arming \
                       would strangle the tunnel. Pin it, or set [vpn] cgroup or \
                       [vpn] config.";
        let broken = wrapped(refused);
        assert!(broken.lines().count() > 1);
        for row in broken.lines() {
            assert!(row.chars().count() <= WIDTH, "{row:?} is still too wide");
        }
        // The same words in the same order: wrapping may not drop or reorder any
        // part of the one message the user has to be able to read.
        assert_eq!(
            broken.split_whitespace().collect::<Vec<_>>(),
            refused.split_whitespace().collect::<Vec<_>>()
        );
        // A row that fits keeps the spacing that aligns the report.
        assert_eq!(wrapped("tunnel   xray__tun (tun)"), "tunnel   xray__tun (tun)");
        // Nothing to break on: wide rather than cut mid-word.
        let unbreakable = "a".repeat(WIDTH + 10);
        assert_eq!(wrapped(&unbreakable), unbreakable);
    }

    #[test]
    fn a_report_older_than_the_click_is_not_believed() {
        // The daemon publishes on a slow clock. Between a click and its next tick
        // its file still says what the box was, and adopting that would show the
        // user the state they just changed away from.
        let click = SystemTime::now();
        let before = click - Duration::from_secs(20);
        let after = click + Duration::from_secs(20);
        assert!(!caught_up(before, Some(click)));
        assert!(caught_up(after, Some(click)));
        // A tie is the daemon's answer: it publishes after it acts.
        assert!(caught_up(click, Some(click)));
        // Nothing has been clicked, so anything it says is news.
        assert!(caught_up(before, None));
    }

    #[test]
    fn worst_news_comes_first_and_is_not_lost_to_a_refresh() {
        let mut tray = Bullseye {
            state: State::Disarmed,
            detail: "0 packets blocked since arming".into(),
            problem: Some("No VPN interface found.".into()),
            working: false,
            probed: None,
            acted: None,
        };
        assert!(tray.lines().starts_with("No VPN interface found."));
        assert!(tray.lines().contains("0 packets blocked"));
        // A click clears it; nothing else does, or the one message the user has to
        // read would be gone before they hovered.
        tray.working = true;
        tray.reread();
        assert!(tray.problem.is_some());
    }
    #[test]
    fn the_mark_is_a_bullseye_at_every_size_a_bar_asks_for() {
        for px in [22, 32, 44] {
            let icon = draw(px, State::Armed);
            assert_eq!(icon.data.len(), (px * px * 4) as usize);
            let alpha_at = |x: i32, y: i32| icon.data[((y * px + x) * 4) as usize];
            assert_eq!(alpha_at(px / 2, px / 2), 255, "{px}: no centre to hit");
            assert_eq!(alpha_at(0, 0), 0, "{px}: a circle does not reach the corner");
        }
        // The states differ by shape and not only by colour: armed has the centre
        // filled, disarmed is the same target with nothing in it.
        let centre = |state| {
            let px = 32;
            draw(px, state).data[((px / 2 * px + px / 2) * 4) as usize]
        };
        assert_eq!(centre(State::Armed), 255);
        assert_eq!(centre(State::Disarmed), 0);
    }
}
