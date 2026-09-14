//! One screen: what is armed, what gets out, and the keys that change either.
//!
//! Principle 5 is the whole layout — every hole is listed as a hole, and the pin
//! sits next to what the VPN is actually doing so a mismatch is visible rather
//! than something the user discovers as "the internet stopped working".

use crate::daemon::State;
use crate::{Plan, config::Config, discover, nft, rules, tray};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, List, ListItem, ListState, Paragraph};
use ratatui::{DefaultTerminal, Frame};
use std::time::Duration;

const KEYS: &str = "space arm/disarm · a allow · A app · d deny · p pin · \
                    enter run · r refresh · q quit";

/// The tray's mark, pixels across. A cell is one pixel wide and two tall, so it
/// takes this many columns and half as many lines. Drawn only on a terminal with
/// room to spare for it.
const MARK: u16 = 16;

pub fn run() -> Result<(), String> {
    // Before the alternate screen, never behind it: a sudo password prompt with
    // nowhere to draw is a hang with no visible cause. The probe is a real `nft`
    // call rather than `sudo -v`, because those two do not follow the same sudoers
    // rules — validation asks for a password on a box where the command itself
    // would not have needed one.
    if !nft::is_root() {
        let primed = std::process::Command::new("sudo")
            .args(["nft", "list", "tables"])
            .stdout(std::process::Stdio::null())
            .status()
            .map_err(|e| format!("cannot run sudo: {e}"))?;
        if !primed.success() {
            return Err("the TUI loads and destroys an nftables table, which needs root".into());
        }
        nft::never_prompt();
    }
    let mut app = App::start()?;
    let mut terminal = ratatui::init();
    let outcome = app.until_quit(&mut terminal);
    ratatui::restore();
    outcome
}

struct App {
    config: Config,
    plan: Plan,
    blocked: Option<u64>,
    selected: usize,
    prompt: Option<Prompt>,
    message: String,
    /// Work waiting for a draw to happen first.
    pending: Option<Job>,
}

/// Work that has to happen after a draw rather than before one. Rebuilding the plan
/// resolves every bypass domain and re-arming shells out to nft, so both take
/// seconds — and a screen that freezes for two of them with the old list still on it
/// is how a keypress that did work reads as one that did nothing.
enum Job {
    Refresh,
    /// The config changed, so the kernel has to be told.
    Reapply,
}

/// The one-line editor at the bottom. A prompt rather than a form: everything the
/// user can change here is a single string.
struct Prompt {
    label: &'static str,
    buffer: String,
    field: Field,
}

enum Field {
    Allow,
    App,
    Pin,
}

/// A row of the bypass pane, which is the only list on the screen.
enum Row {
    Allow(String),
    App(String),
}

impl App {
    fn start() -> Result<Self, String> {
        let config = Config::load()?;
        let plan = crate::plan(&config, false)?;
        Ok(Self {
            config,
            plan,
            blocked: nft::blocked(),
            selected: 0,
            prompt: None,
            message: String::new(),
            pending: None,
        })
    }

    fn until_quit(&mut self, terminal: &mut DefaultTerminal) -> Result<(), String> {
        loop {
            terminal
                .draw(|frame| self.draw(frame))
                .map_err(|e| format!("drawing: {e}"))?;
            // After the draw, so the row that just went and the line saying so are
            // already on the screen while this runs.
            if let Some(job) = self.pending.take() {
                match job {
                    Job::Refresh => {
                        self.refresh();
                    }
                    Job::Reapply => self.reapply(),
                }
                continue;
            }
            // Cheap poll: the counter is the one thing that moves on its own, and
            // seeing it climb is how a user learns the kill switch is working.
            if !event::poll(Duration::from_secs(2)).map_err(|e| format!("input: {e}"))? {
                self.blocked = nft::blocked();
                continue;
            }
            if let Event::Key(key) = event::read().map_err(|e| format!("input: {e}"))? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                    return Ok(());
                }
                match &mut self.prompt {
                    Some(_) => self.typed(key.code),
                    None => {
                        if self.pressed(key.code) {
                            return Ok(());
                        }
                    }
                }
            }
        }
    }

    /// True when the key was quit.
    fn pressed(&mut self, key: KeyCode) -> bool {
        self.message.clear();
        match key {
            KeyCode::Char('q') | KeyCode::Esc => return true,
            KeyCode::Char(' ') => self.toggle(),
            KeyCode::Char('r') => self.pending = Some(Job::Refresh),
            KeyCode::Char('a') => self.ask("allow (IP, CIDR, domain or geoip:ir)", Field::Allow),
            KeyCode::Char('A') => self.ask("app to launch outside the tunnel", Field::App),
            KeyCode::Char('p') => self.ask("pin the VPN's server (empty to unpin)", Field::Pin),
            KeyCode::Char('d') => self.deny(),
            KeyCode::Enter => self.launch(),
            KeyCode::Up | KeyCode::Char('k') => self.selected = self.selected.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected = (self.selected + 1).min(self.rows().len().saturating_sub(1));
            }
            _ => {}
        }
        false
    }

    fn typed(&mut self, key: KeyCode) {
        let Some(prompt) = &mut self.prompt else {
            return;
        };
        match key {
            KeyCode::Esc => self.prompt = None,
            KeyCode::Backspace => {
                prompt.buffer.pop();
            }
            KeyCode::Char(c) => prompt.buffer.push(c),
            KeyCode::Enter => {
                let Some(prompt) = self.prompt.take() else {
                    return;
                };
                let entry = prompt.buffer.trim().to_owned();
                match self.commit(prompt.field, &entry) {
                    // A refused entry changed nothing, and re-resolving every bypass
                    // to discover that is two frozen seconds spent on no news.
                    Err(why) => self.message = why,
                    Ok(said) => {
                        self.message = said;
                        self.pending = Some(Job::Reapply);
                    }
                }
            }
            _ => {}
        }
    }

    fn commit(&mut self, field: Field, entry: &str) -> Result<String, String> {
        match field {
            Field::Allow => {
                let opened = self.config.allow(entry)?;
                self.config.save()?;
                Ok(format!("{opened} leaves outside the tunnel now"))
            }
            Field::App => {
                self.config.apps.push(rules::app(entry)?);
                self.config.save()?;
                Ok(format!("{entry} added — press enter on it to launch it"))
            }
            Field::Pin => {
                self.config.pin = match entry.is_empty() || entry == "off" {
                    true => None,
                    false => Some(rules::address(entry)?),
                };
                self.config.save()?;
                Ok(match &self.config.pin {
                    Some(pin) => format!("pinned to {pin} — the VPN may reach nothing else"),
                    None => "unpinned — the upstream is discovered at every arm".into(),
                })
            }
        }
    }

    fn ask(&mut self, label: &'static str, field: Field) {
        self.prompt = Some(Prompt {
            label,
            buffer: String::new(),
            field,
        });
    }

    fn deny(&mut self) {
        let Some(row) = self.rows().into_iter().nth(self.selected) else {
            return;
        };
        let entry = match row {
            Row::Allow(entry) | Row::App(entry) => entry,
        };
        self.config.deny(&entry);
        self.message = match self.config.save() {
            Ok(()) => format!("{entry} no longer bypasses"),
            Err(why) => why,
        };
        self.selected = self.selected.saturating_sub(1);
        self.pending = Some(Job::Reapply);
    }

    /// A config change the kernel never hears about is a hole the user believes they
    /// closed. The CLI re-arms after every edit and this did not, so a denied bypass
    /// left the list, left the file, and stayed open in the ruleset.
    ///
    /// The daemon's guard comes with it: narrowing a live ruleset into a lockdown
    /// would seal the box away from the VPN it is protecting, so an edit that would
    /// do that is kept out of the kernel and said out loud instead.
    fn reapply(&mut self) {
        if !self.refresh() {
            return; // the message is why, and arming a stale plan would be worse
        }
        if self.blocked.is_none() {
            self.message += " — disarmed, so this takes effect at the next arm";
            return;
        }
        if let Err(why) = crate::refuse_lockout(&self.plan) {
            self.message += &format!(" — the ruleset is unchanged: {why}");
            return;
        }
        self.message = match crate::arm(&self.plan, None) {
            Ok(()) => format!("{} — re-armed", self.message),
            Err(why) => why,
        };
    }

    fn launch(&mut self) {
        let Some(Row::App(command)) = self.rows().into_iter().nth(self.selected) else {
            self.message = "enter launches an app row; a is how you add an address".into();
            return;
        };
        let Some(gid) = discover::group(&self.config.group) else {
            self.message = format!(
                "the group {:?} does not exist yet: sudo groupadd -f {0} && \
                 sudo gpasswd -a $USER {0}",
                self.config.group
            );
            return;
        };
        let words: Vec<String> = command.split_whitespace().map(str::to_owned).collect();
        // Detached, and its output thrown away: this screen owns the terminal, and
        // a child writing to it would scribble over the ruleset the user is reading.
        self.message = match crate::launcher(&self.config.group, &words)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(_) => format!("launched {command} as gid {gid} — outside the tunnel"),
            Err(e) => format!("could not launch {command}: {e}"),
        };
    }

    fn toggle(&mut self) {
        if self.blocked.is_some() {
            self.message = match crate::disarm() {
                Ok(()) => "disarmed — nothing is enforcing anything now".into(),
                Err(why) => why,
            };
            self.pending = Some(Job::Refresh);
            return;
        }
        // The CLI's guards, and for the same reason: arming with no upstream
        // strangles the tunnel, and arming with no tunnel blocks the box outright.
        if let Err(why) = crate::refuse_lockout(&self.plan) {
            self.message = why;
            return;
        }
        self.message = match crate::arm(&self.plan, None) {
            Ok(()) => "armed".into(),
            Err(why) => why,
        };
        self.pending = Some(Job::Refresh);
    }

    /// Re-runs discovery, and answers whether the plan is now the current one. Slow
    /// enough to be a keypress rather than a tick — it reads /proc, asks `ss`, and
    /// resolves every bypass domain.
    fn refresh(&mut self) -> bool {
        self.blocked = nft::blocked();
        match crate::plan(&self.config, false) {
            Ok(plan) => {
                self.plan = plan;
                true
            }
            Err(why) => {
                self.message = why;
                false
            }
        }
    }

    fn rows(&self) -> Vec<Row> {
        let allowed = self.config.allow.iter().cloned().map(Row::Allow);
        let apps = self.config.apps.iter().cloned().map(Row::App);
        allowed.chain(apps).collect()
    }

    fn draw(&mut self, frame: &mut Frame) {
        // Sized from the lines it actually holds, capped so that a machine with
        // several tunnels still shows what bypasses in the pane below. The mark
        // is the one thing here that may be dropped: a narrow terminal spends its
        // columns on the report, and a short one on the bypass pane.
        let header = self.header();
        let mark = match frame.area().width >= 64 {
            true => (MARK + 1, MARK / 2),
            false => (0, 0),
        };
        let areas = Layout::vertical([
            Constraint::Length((header.len().max(mark.1 as usize) as u16 + 2).min(12)),
            Constraint::Min(3),
            Constraint::Length(2),
        ])
        .split(frame.area());

        let block = Block::bordered().title(" bullseye ");
        let inside = Layout::horizontal([Constraint::Min(0), Constraint::Length(mark.0)])
            .split(block.inner(areas[0]));
        frame.render_widget(block, areas[0]);
        frame.render_widget(Paragraph::new(header), inside[0]);
        frame.render_widget(Paragraph::new(self.mark()), inside[1]);

        let rows = self.rows();
        let items: Vec<ListItem> = match rows.is_empty() {
            true => vec![ListItem::new(Line::from(Span::styled(
                "nothing bypasses — everything goes through the tunnel or nowhere",
                Style::default().fg(Color::DarkGray),
            )))],
            false => rows.iter().map(bypass_row).collect(),
        };
        let mut state = ListState::default().with_selected(Some(self.selected));
        frame.render_stateful_widget(
            List::new(items)
                .block(Block::bordered().title(" bypass — leaves with your real address "))
                .highlight_symbol("> ")
                .highlight_style(Style::default().add_modifier(Modifier::BOLD)),
            areas[1],
            &mut state,
        );

        let footer = match &self.prompt {
            Some(prompt) => vec![
                Line::from(vec![
                    Span::styled(
                        format!("{}: ", prompt.label),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::raw(&prompt.buffer),
                    Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
                ]),
                Line::from(Span::styled(
                    "enter to accept · esc to cancel",
                    Style::default().fg(Color::DarkGray),
                )),
            ],
            None => vec![
                Line::from(Span::styled(
                    self.message.as_str(),
                    Style::default().fg(Color::Yellow),
                )),
                Line::from(Span::styled(KEYS, Style::default().fg(Color::DarkGray))),
            ],
        };
        frame.render_widget(Paragraph::new(footer), areas[2]);
    }

    /// The tray's bullseye, in the tray's colours and shapes, so the screen and the
    /// bar are the same program. The header says all of it in words.
    fn mark(&self) -> Vec<Line<'static>> {
        let state = match self.blocked {
            Some(_) if self.config.pin.is_some() && self.plan.mismatch.is_some() => {
                State::Blocked
            }
            Some(_) => State::Armed,
            None => State::Disarmed,
        };
        draw_mark(tray::draw(MARK as i32, state))
    }

    fn header(&self) -> Vec<Line<'_>> {
        let mut lines = vec![Line::from(match self.blocked {
            Some(packets) => vec![
                Span::styled(
                    "ARMED",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("    {packets} packets blocked since arming")),
            ],
            None => vec![
                Span::styled("DISARMED", Style::default().fg(Color::Red)),
                Span::raw("  nothing is enforced — every packet leaves as it likes"),
            ],
        })];
        // Second, never last: it is the line that explains why nothing works, and
        // the header is the part of the screen that gets cut when space runs out.
        if let (Some(pin), Some(actual)) = (&self.config.pin, &self.plan.mismatch) {
            lines.push(Line::from(Span::styled(
                format!("MISMATCH pinned to {pin}, but the VPN is talking to {actual} — blocked"),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )));
        }
        lines.extend(self.plan.report.lines().map(Line::raw));
        lines
    }
}

/// A pixmap as half blocks: each cell is the pixel above and the pixel below it,
/// and a pixel is either ink or the terminal behind it — the tray leaves its gaps
/// transparent for the same reason.
fn draw_mark(icon: ksni::Icon) -> Vec<Line<'static>> {
    let px = icon.width as usize;
    let pixel = |x: usize, y: usize| &icon.data[(y * px + x) * 4..][..4];
    (0..px / 2)
        .map(|row| {
            let cells = (0..px).map(|x| {
                let (top, bottom) = (pixel(x, row * 2), pixel(x, row * 2 + 1));
                let glyph = match (top[0] >= 128, bottom[0] >= 128) {
                    (true, true) => "█",
                    (true, false) => "▀",
                    (false, true) => "▄",
                    (false, false) => " ",
                };
                Span::styled(glyph, Style::default().fg(Color::Rgb(top[1], top[2], top[3])))
            });
            Line::from(std::iter::once(Span::raw(" ")).chain(cells).collect::<Vec<_>>())
        })
        .collect()
}

fn bypass_row(row: &Row) -> ListItem<'_> {
    let (tag, entry, colour) = match row {
        Row::Allow(entry) => ("      ", entry, Color::Yellow),
        Row::App(entry) => ("app   ", entry, Color::Magenta),
    };
    ListItem::new(Line::from(vec![
        Span::styled(tag, Style::default().fg(Color::DarkGray)),
        Span::styled(entry.as_str(), Style::default().fg(colour)),
    ]))
}
