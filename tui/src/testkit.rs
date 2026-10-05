//! Helpers for asserting on what the app draws.
//!
//! Ratatui renders into a [`Buffer`], so a test can draw a screen into a fixed
//! grid and read the cells back as text. That makes it possible to check a
//! screen's layout without a terminal, which is what iocraft's `Canvas` did
//! before the rewrite.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::Terminal;

use crate::keys;
use crate::state::AppState;
use crate::ui;

/// A drawing surface backed by an in-memory grid.
pub type TestTerm = Terminal<TestBackend>;

/// Builds a state pointed at a throwaway vault and an unused config file.
///
/// The screen is decided from what is on disk, the same way the real app does
/// on startup, so a test sees the screen a user would actually land on.
///
/// The config path is per-process and per-counter so a test run never reads or
/// writes the real `~/.config/domi/config.toml`.
pub fn state() -> AppState {
    state_at(crate::vault_store::testing::TempVault::new().paths())
}

/// Builds a state at a specific vault path, already on its opening screen.
pub fn state_at(paths: crate::vault_store::VaultPaths) -> AppState {
    let file = scratch_path("config");
    let mut state = AppState::with_config_file(paths, file);
    state.initial_screen();
    state
}

use std::sync::atomic::{AtomicU32, Ordering};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A unique path under the temp dir, for tests that need a real file.
pub fn scratch_path(kind: &str) -> std::path::PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("domi-test-{kind}-{}-{n}", std::process::id()))
}

/// A terminal of the given size.
pub fn terminal(width: u16, height: u16) -> TestTerm {
    Terminal::new(TestBackend::new(width, height)).expect("a test backend always fits")
}

/// Renders one frame and returns the resulting buffer.
pub fn render(state: &AppState, width: u16, height: u16) -> Buffer {
    let mut term = terminal(width, height);
    term.draw(|f| ui::draw(f, state)).expect("draw into a test backend cannot fail");
    term.backend().buffer().clone()
}

/// The whole frame as text, one string per line.
pub fn lines(buffer: &Buffer) -> Vec<String> {
    (0..buffer.area.height)
        .map(|y| row_text(buffer, y))
        .collect()
}

/// One row of the buffer as text, with trailing blanks trimmed.
pub fn row_text(buffer: &Buffer, y: u16) -> String {
    let area = buffer.area();
    let text: String = (area.x..area.x + area.width)
        .map(|x| buffer[(x, y)].symbol())
        .collect();
    text.trim_end().to_string()
}

/// Every line that contains `needle`.
///
/// Returns line indexes so a failure can say where it looked, which a bare
/// "not found" does not.
pub fn lines_containing(buffer: &Buffer, needle: &str) -> Vec<String> {
    lines(buffer)
        .into_iter()
        .enumerate()
        .filter(|(_, text)| text.contains(needle))
        .map(|(i, text)| format!("row {i}: {text}"))
        .collect()
}

/// Asserts `needle` appears somewhere on screen, printing the frame if not.
#[track_caller]
pub fn assert_shows(buffer: &Buffer, needle: &str) {
    let hits = lines_containing(buffer, needle);
    assert!(
        !hits.is_empty(),
        "expected {needle:?} on screen, but it was not there.\n--- frame ---\n{}",
        lines(buffer).join("\n")
    );
}

/// Asserts `needle` appears nowhere on screen.
#[track_caller]
pub fn assert_hides(buffer: &Buffer, needle: &str) {
    let hits = lines_containing(buffer, needle);
    assert!(
        hits.is_empty(),
        "expected {needle:?} to be hidden, but found:\n{}",
        hits.join("\n")
    );
}

// ------------------------------------------------------------ key dispatch ---

/// A press of an unmodified character.
pub fn press(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
}

/// A press of a named key.
pub fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

/// A Ctrl-modified press.
pub fn ctrl(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
}

/// Sends one key to the app, ignoring whether anything claimed it.
pub fn send(state: &mut AppState, mut k: KeyEvent) {
    k.kind = KeyEventKind::Press;
    let _ = keys::handle(state, k);
}

/// Sends several keys in order.
pub fn send_all(state: &mut AppState, ks: &[KeyEvent]) {
    for k in ks {
        send(state, *k);
    }
}

/// Sends a string as individual character presses.
pub fn type_text(state: &mut AppState, text: &str) {
    for c in text.chars() {
        send(state, press(c));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rendered_buffer_can_be_read_back_as_text() {
        let state = state();
        let buffer = render(&state, 80, 24);
        let text = lines(&buffer).join("\n");
        assert!(text.contains("vault"), "the setup screen should mention a vault:\n{text}");
    }

    #[test]
    fn assert_shows_reports_the_frame_it_looked_at() {
        // A failing assertion must show the frame, or debugging a layout
        // problem means re-running under a terminal.
        let state = state();
        let buffer = render(&state, 80, 24);
        assert_shows(&buffer, "No vault exists yet");
    }

    #[test]
    fn each_test_state_gets_its_own_config_file() {
        let a = state();
        let b = state();
        assert_ne!(a.config_file, b.config_file);
    }
}
#[cfg(test)]
mod render_tests {
    use super::*;
    use crate::state::{Field, Screen};

    /// An unlocked vault holding one entry, for the list screen.
    fn with_entry() -> (crate::vault_store::testing::TempVault, AppState) {
        let tmp = crate::vault_store::testing::TempVault::new();
        let mut state = state_at(tmp.paths());
        state.kdf = crate::vault_store::test_params();
        state.create_vault("horse", "horse").expect("the vault is created");
        state.begin_new();
        if let Some(form) = state.form.as_mut() {
            form.title = "GitHub".into();
            form.username = "ada".into();
            form.password = "hunter2".into();
            form.url = "https://github.com".into();
        }
        state.save_form().expect("the entry saves");
        (tmp, state)
    }

    #[test]
    fn the_setup_screen_explains_itself() {
        let state = state();
        let buffer = render(&state, 80, 24);
        assert_shows(&buffer, "No vault exists yet");
        assert_shows(&buffer, "Master password");
        assert_shows(&buffer, "esc quit");
    }

    #[test]
    fn the_unlock_screen_names_the_vault() {
        let tmp = crate::vault_store::testing::TempVault::new();
        std::fs::create_dir_all(tmp.path()).unwrap();
        std::fs::write(tmp.path().join("manifest.json"), "{}").unwrap();
        let mut state = state_at(tmp.paths());
        assert_eq!(state.initial_screen(), Screen::Unlock);

        let buffer = render(&state, 80, 24);
        assert_shows(&buffer, "Unlock");
        assert_shows(&buffer, "enter unlock");
    }

    #[test]
    fn a_typed_password_is_drawn_as_dots_and_never_as_text() {
        let mut state = state();
        type_text(&mut state, "swordfish");
        let buffer = render(&state, 80, 24);
        assert_shows(&buffer, "*********");
        assert_hides(&buffer, "swordfish");
    }

    #[test]
    fn the_vault_screen_lists_the_entry() {
        let (_tmp, state) = with_entry();
        let buffer = render(&state, 100, 24);
        assert_shows(&buffer, "GitHub");
        assert_shows(&buffer, "ada");
        assert_shows(&buffer, "Entries (1)");
        assert_shows(&buffer, "Details");
    }

    #[test]
    fn the_detail_pane_masks_the_password_until_reveal_is_asked_for() {
        let (_tmp, mut state) = with_entry();
        state.load_detail();
        let buffer = render(&state, 100, 24);
        assert_hides(&buffer, "hunter2");
        assert_shows(&buffer, "*******");

        state.toggle_reveal();
        let buffer = render(&state, 100, 24);
        assert_shows(&buffer, "hunter2");
    }

    #[test]
    fn the_editor_draws_the_fields_that_fit_and_scrolls_to_the_focused_one() {
        let (_tmp, mut state) = with_entry();
        state.begin_new();
        let buffer = render(&state, 100, 30);
        assert_shows(&buffer, "New entry");
        assert_shows(&buffer, "Title");
        assert_shows(&buffer, "Generator");

        // Tab far enough that the focused field scrolls out of the first page.
        let form = state.form.as_mut().expect("the editor is open");
        form.focused = Field::Tags;
        let buffer = render(&state, 100, 30);
        assert_shows(&buffer, "Tags");
    }

    #[test]
    fn every_editor_field_is_reachable_and_draws_its_label() {
        // Each field gets focused in turn and checked, so a field that is never
        // drawn cannot slip through.
        let (_tmp, mut state) = with_entry();
        state.begin_new();
        for field in Field::ALL {
            state.form.as_mut().expect("the editor is open").focused = field;
            let buffer = render(&state, 100, 30);
            assert_shows(&buffer, field.label());
        }
    }

    #[test]
    fn the_editor_never_draws_a_password_in_the_clear() {
        let (_tmp, mut state) = with_entry();
        state.begin_edit();
        let buffer = render(&state, 100, 30);
        assert_shows(&buffer, "Edit entry");
        assert_hides(&buffer, "hunter2");
    }

    #[test]
    fn the_settings_screen_lists_every_row() {
        let (_tmp, state) = with_entry();
        let mut settings = state;
        settings.screen = Screen::Settings;
        let buffer = render(&settings, 100, 24);
        for row in ["Vault directory", "Key derivation", "Auto-lock", "Master password", "Reset vault"] {
            assert_shows(&buffer, row);
        }
    }

    #[test]
    fn a_confirm_dialog_is_drawn_over_the_list() {
        let (_tmp, mut state) = with_entry();
        state.request_delete_selected();
        let buffer = render(&state, 100, 24);
        assert_shows(&buffer, "Delete entry");
        assert_shows(&buffer, "GitHub");
        assert_shows(&buffer, "cancel");
    }

    #[test]
    fn the_auto_lock_countdown_shows_only_when_the_delay_is_armed() {
        let (_tmp, mut state) = with_entry();
        state.auto_lock_secs = 0;
        let buffer = render(&state, 100, 24);
        assert_hides(&buffer, "locks in");

        state.auto_lock_secs = 300;
        let buffer = render(&state, 100, 24);
        assert_shows(&buffer, "locks in");
    }

    #[test]
    fn an_empty_search_result_explains_itself_rather_than_rendering_nothing() {
        let (_tmp, mut state) = with_entry();
        state.set_query("no such entry".into());
        let buffer = render(&state, 100, 24);
        assert_shows(&buffer, "Nothing matches this search");
    }

    #[test]
    fn a_narrow_terminal_does_not_panic() {
        // Every layout here does arithmetic on the frame size; a width or
        // height of zero is the usual way that arithmetic goes wrong.
        for (w, h) in [(1, 1), (2, 2), (10, 3), (20, 5), (200, 60)] {
            let state = state();
            let _ = render(&state, w, h);
        }
    }

    #[test]
    fn a_narrow_terminal_does_not_panic_on_any_screen() {
        // Every screen draws through the same entry point, so one state walked
        // through all five is enough to exercise each layout.
        let mut state = state();
        for screen in [Screen::Setup, Screen::Unlock, Screen::Vault, Screen::Edit, Screen::Settings] {
            state.screen = screen;
            for (w, h) in [(1, 1), (8, 4), (40, 10)] {
                let _ = render(&state, w, h);
            }
        }
    }

    #[test]
    fn sending_a_batch_of_keys_applies_them_in_order() {
        let (_tmp, mut state) = with_entry();
        send_all(&mut state, &[press('/'), press('g'), press('i'), press('t')]);
        assert_eq!(state.query, "git");
    }
}

#[cfg(test)]
mod status_tests {
    use super::*;
    use crate::state::Screen;

    #[test]
    fn the_settings_screen_shows_why_a_change_was_refused() {
        // Without a status line here, a rejected master-password change closed
        // its dialog and left no trace of the reason.
        let mut state = state();
        state.kdf = crate::vault_store::test_params();
        state.create_vault("horse", "horse").unwrap();
        state.screen = Screen::Settings;
        state.notify_error(crate::error::AppError::BadInput("Passwords do not match".into()));

        let buffer = render(&state, 100, 24);
        assert_shows(&buffer, "Passwords do not match");
    }

    #[test]
    fn the_settings_screen_confirms_a_change_that_worked() {
        let mut state = state();
        state.kdf = crate::vault_store::test_params();
        state.create_vault("horse", "horse").unwrap();
        state.screen = Screen::Settings;
        state.notify(crate::state::Status::success("Master password changed"));

        let buffer = render(&state, 100, 24);
        assert_shows(&buffer, "Master password changed");
    }

    #[test]
    fn a_modal_shows_the_error_its_own_submit_raised() {
        let mut state = state();
        state.kdf = crate::vault_store::test_params();
        state.create_vault("horse", "horse").unwrap();
        state.request_reset_vault();
        state.notify_error(crate::error::AppError::Storage("permission denied".into()));

        let buffer = render(&state, 100, 24);
        assert_shows(&buffer, "permission denied");
    }
}
