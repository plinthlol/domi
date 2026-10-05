//! The terminal: setup, the event loop, and teardown.
//!
//! This is the only module that touches crossterm's raw mode or the alternate
//! screen. Everything else works on [`AppState`] and is testable without a
//! terminal.
//!
//! The loop itself is deliberately synchronous. Crossterm's event reader is
//! blocking, so the tick that drives the auto-lock countdown runs on a timer
//! rather than by polling a second thread; the alternative would add a channel
//! and a shared state just to wake up once a second.

use std::io::{self, Stdout, Write};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use crate::keys;
use crate::state::{AppState, Status};
use crate::ui;
use crate::vault_store::VaultPaths;

/// How often the auto-lock countdown is re-evaluated while idle.
const TICK: Duration = Duration::from_secs(1);

/// A drawing surface, so tests can drive the loop over a `TestBackend`.
pub type Term = Terminal<CrosstermBackend<Stdout>>;

/// Owns one [`AppState`] and the terminal it draws to.
pub struct App {
    state: AppState,
    terminal: Term,
    /// Copied out of the backend after a copy is queued. The shell writes the
    /// escape sequence itself, because a TUI has no clipboard API of its own.
    pending_clipboard: Option<String>,
}

impl App {
    /// Builds an app over the real terminal and the default vault location.
    pub fn new(paths: VaultPaths) -> Self {
        let state = AppState::with_config_file(paths, crate::config::Config::default_file());
        let terminal = match setup_terminal() {
            Ok(t) => t,
            Err(e) => {
                // A terminal we cannot take over is not a crash; say why on
                // stderr and leave the exit code for the caller.
                eprintln!("{}: cannot start the interface: {e}", crate::bin_name());
                std::process::exit(1);
            }
        };
        App { state, terminal, pending_clipboard: None }
    }

    /// Runs until the user quits, then restores the terminal.
    pub fn run(mut self) {
        let _guard = with_guard();
        self.state.initial_screen();
        self.redraw();

        let mut last = Instant::now();
        loop {
            // `poll` rather than a blocking `read`: a blocking read would only
            // return when the user presses something, so the auto-lock
            // countdown could never fire while they were away — which is
            // exactly when it matters. The tick below needs to run on its own.
            let ready = event::poll(TICK).unwrap_or(false);

            if ready {
                match event::read() {
                    Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => {
                        if let Err(keys::Unbound) = keys::handle(&mut self.state, key) {
                            self.state.notify(Status::info("That key does nothing here"));
                        }
                        self.flush_clipboard();
                        self.redraw();
                        if self.state.should_quit {
                            break;
                        }
                        last = Instant::now();
                        continue;
                    }
                    Ok(Event::Resize(_, _)) => {
                        // Ratatui recomputes the layout on the next draw; the
                        // frame is forced because the diff was computed against
                        // the old size.
                        let _ = self.terminal.autoresize();
                        self.redraw();
                        last = Instant::now();
                        continue;
                    }
                    Ok(_) => {}
                    // A read error means stdin is gone. Exiting through the
                    // normal teardown keeps the terminal usable.
                    Err(_) => break,
                }
            }

            let elapsed = last.elapsed();
            if elapsed >= TICK {
                self.state.tick_idle(elapsed.as_secs() as u64);
                // Redraw every tick, not only when the lock fires: the footer
                // carries a countdown, so skipping the frames would leave it
                // frozen at whatever it read when the user last pressed a key.
                self.flush_clipboard();
                self.redraw();
                last = Instant::now();
            }
        }

        self.shutdown();
    }

    /// Draws the current state.
    fn redraw(&mut self) {
        if self.terminal.draw(|f| ui::draw(f, &self.state)).is_err() {
            // A failed draw means the terminal is gone. Stop rather than spin.
            self.state.should_quit = true;
        }
    }

    /// Writes any queued clipboard payload as an OSC 52 sequence.
    fn flush_clipboard(&mut self) {
        let Some(payload) = self.state.pending_copy.take() else { return };
        let result = crate::clipboard::copy(&payload, |seq| {
            let mut out = io::stdout();
            let _ = out.write_all(seq.as_bytes());
            let _ = out.flush();
        });
        if let Err(msg) = result {
            self.state.notify_error(crate::error::AppError::BadInput(msg));
        } else {
            self.pending_clipboard = None;
        }
    }

    /// Restores the terminal to the state it was in before the app started.
    ///
    /// Also used on the panic path via the guard below, so a crash mid-render
    /// does not leave the user with a raw-mode terminal and no echo.
    fn shutdown(mut self) {
        let _ = restore_terminal(&mut self.terminal);
    }
}

/// Puts the terminal into raw mode on the alternate screen.
fn setup_terminal() -> io::Result<Term> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;
    // Clear on every frame: ratatui diffs against the previous buffer, and a
    // resize or a scroll can leave stale cells behind otherwise.
    terminal.clear()?;
    Ok(terminal)
}

/// Undoes [`setup_terminal`].
fn restore_terminal(terminal: &mut Term) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()
}

/// Restores the terminal when the stack unwinds.
///
/// A panic in a draw closure would otherwise leave the user's shell in raw
/// mode with the alternate screen still up, with no echo and no way back
/// short of killing the process.
pub struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

/// Wraps a run so the guard is armed for the whole session.
pub fn with_guard() -> TerminalGuard {
    TerminalGuard
}
