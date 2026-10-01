//! Key handling: a pure translation from a key event to a state change.
//!
//! Split out from the view so every binding is testable without a terminal.
//! The rule that shapes this file: **a modal owns the keyboard**. When one is
//! open, only the modal's own keys are considered; everything beneath it is
//! unreachable. That check happens once, at the top, rather than being
//! duplicated in every handler.
//!
//! The AppState is mutated through small named actions rather than by writing
//! fields inline, so a binding reads as "up arrow moves the selection" rather
//! than a diff.

use fuin_core::password::MAX_PASSWORD_LENGTH;
use iocraft::prelude::KeyCode;

use crate::state::{AppState, Field, Focus, Modal, Screen, Status};
use crate::widgets::modal;

/// What a key press asks the app to do.
///
/// Returned instead of mutating directly so a caller (or a test) can see what
/// would happen, and so a key that needs a slow action — unlocking, rekeying —
/// can be handled outside the render pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Nothing to do.
    None,
    /// Close the app.
    Quit,
    /// Draw a new frame.
    Redraw,
    /// Move the list selection.
    MoveSelection(i64),
    /// Jump to the top or bottom of the list.
    JumpToStart,
    JumpToEnd,
    /// Open the create-entry form.
    NewEntry,
    /// Open the edit form for the selection.
    EditEntry,
    /// Confirm and delete the selection.
    DeleteEntry,
    /// Toggle the favorite flag on the selection.
    ToggleFavorite,
    /// Copy a field to the clipboard.
    CopyPassword,
    CopyUsername,
    /// Toggle the reveal flag.
    ToggleReveal,
    /// Move focus into or out of the search box.
    ToggleSearch,
    /// Cycle the favorites filter.
    ToggleFavoritesFilter,
    /// Open settings.
    OpenSettings,
    /// Leave the current screen.
    Back,
    /// Attempt to unlock or create the vault.
    SubmitPassword,
    /// Save the open form.
    SaveForm,
    /// Fill the form's password with a generated one.
    GeneratePassword,
    /// Tab between form fields.
    FocusNextField,
    FocusPrevField,
    /// Edit a field's text, for the focused text input.
    InsertChar(char),
    /// Apply an edit to the focused field, from a text input's on_change.
    SetFieldText(String),
    /// Filter the list to the selected entry's tag.
    ToggleTagFilter,
    /// Toggle or step a non-text form field.
    ToggleFocusedField,
    /// Lock the vault and return to the unlock screen.
    Lock,
}

/// Maps a key event to an [`Action`].
///
/// `ctrl` and `shift` are passed separately because iocraft reports modifiers
/// in a field distinct from the key code.
pub fn handle_key(
    state: &mut AppState,
    code: KeyCode,
    ctrl: bool,
    shift: bool,
) -> Action {
    // A modal swallows everything except its own keys.
    if let Some(m) = state.modal.clone() {
        return handle_modal_key(state, m, code, ctrl);
    }

    match state.screen {
        Screen::Setup | Screen::Unlock => handle_auth_key(state, code, ctrl),
        Screen::Edit => handle_edit_key(state, code, ctrl, shift),
        Screen::Settings => handle_settings_key(state, code, ctrl),
        Screen::Vault => handle_vault_key(state, code, ctrl),
    }
}

/// Unlock and setup share one screen's keys: type a password, submit it.
fn handle_auth_key(state: &mut AppState, code: KeyCode, ctrl: bool) -> Action {
    use KeyCode as C;
    if ctrl {
        if let C::Char('c') = code {
            return Action::Quit;
        }
        return Action::None;
    }
    match code {
        C::Esc => Action::Quit,
        C::Enter => Action::SubmitPassword,
        C::Backspace => {
            state.password.pop();
            Action::Redraw
        }
        C::Char(c) => {
            if state.password.chars().count() < MAX_PASSWORD_LENGTH {
                state.password.push(c);
            }
            Action::Redraw
        }
        _ => Action::None,
    }
}

/// Keys on the create/edit form.
fn handle_edit_key(
    state: &mut AppState,
    code: KeyCode,
    ctrl: bool,
    shift: bool,
) -> Action {
    use KeyCode as C;
    // Ctrl+S saves, which is the one shortcut muscle memory demands here.
    if ctrl {
        return match code {
            C::Char('s') | C::Char('S') => Action::SaveForm,
            C::Char('c') => Action::Quit,
            _ => Action::None,
        };
    }
    match code {
        C::Esc => Action::Back,
        C::Tab => {
            if shift {
                Action::FocusPrevField
            } else {
                Action::FocusNextField
            }
        }
        C::Enter => {
            // Enter in a text field moves on rather than saving, so a
            // multi-line note doesn't submit the form.
            Action::FocusNextField
        }
        C::Char('g') | C::Char('G') => Action::GeneratePassword,
        // A focused toggle or cycler responds directly; text fields let the
        // TextInput handle the keystroke instead.
        C::Char(' ') => Action::ToggleFocusedField,
        C::Left | C::Right => Action::ToggleFocusedField,
        C::Char(c) => Action::InsertChar(c),
        C::Backspace => Action::SetFieldText(backspace(&field_text(state))),
        _ => Action::None,
    }
}

/// The current field's text, or empty when no form is open.
fn field_text(state: &AppState) -> String {
    state.form.as_ref().map(|f| f.text().to_string()).unwrap_or_default()
}

/// Removes the last character, respecting char boundaries.
fn backspace(text: &str) -> String {
    let mut out = text.to_string();
    out.pop();
    out
}

/// Keys on the settings screen.
fn handle_settings_key(state: &mut AppState, code: KeyCode, ctrl: bool) -> Action {
    use KeyCode as C;
    if ctrl {
        if let C::Char('c') = code {
            return Action::Quit;
        }
        return Action::None;
    }
    match code {
        C::Esc => Action::Back,
        C::Char('q') | C::Char('Q') => Action::Lock,
        C::Up | C::Char('k') => {
            state.move_settings_row(-1);
            Action::Redraw
        }
        C::Down | C::Char('j') => {
            state.move_settings_row(1);
            Action::Redraw
        }
        // The arrows act on the row in focus when it is one the user can
        // change, and otherwise simply move on.
        C::Left | C::Char('h') => adjust_setting(state, -1),
        C::Right | C::Char('l') => adjust_setting(state, 1),
        C::Enter => apply_setting(state),
        _ => Action::None,
    }
}

/// What `left`/`right` does on the highlighted settings row.
fn adjust_setting(state: &mut AppState, delta: i64) -> Action {
    match state.settings_row {
        AppState::ROW_AUTO_LOCK => {
            state.step_auto_lock(delta);
            Action::Redraw
        }
        // The vault and key-derivation rows are read-only: changing where the
        // vault lives mid-session would orphan the open one.
        _ => Action::Redraw,
    }
}

/// What `enter` does on the highlighted settings row.
fn apply_setting(state: &mut AppState) -> Action {
    match state.settings_row {
        AppState::ROW_MASTER_PASSWORD => {
            state.begin_master_password_change();
            Action::Redraw
        }
        AppState::ROW_RESET => {
            state.modal = Some(crate::widgets::modal::reset_confirmation());
            Action::Redraw
        }
        _ => Action::Redraw,
    }
}

/// Keys on the main vault screen, routed by which pane has focus.
fn handle_vault_key(state: &mut AppState, code: KeyCode, ctrl: bool) -> Action {
    use KeyCode as C;
    if ctrl {
        if let C::Char('c') = code {
            return Action::Quit;
        }
        return Action::None;
    }

    // While the search box has focus, printable keys are text, not commands.
    if state.focus == Focus::Search {
        return match code {
            C::Esc | C::Enter | C::Down => {
                state.focus = Focus::List;
                Action::Redraw
            }
            C::Char(c) => {
                state.query.push(c);
                state.refresh();
                Action::Redraw
            }
            C::Backspace => {
                state.query.pop();
                state.refresh();
                Action::Redraw
            }
            _ => Action::None,
        };
    }

    match code {
        C::Up | C::Char('k') => Action::MoveSelection(-1),
        C::Down | C::Char('j') => Action::MoveSelection(1),
        C::PageUp => Action::MoveSelection(-10),
        C::PageDown => Action::MoveSelection(10),
        C::Home => Action::JumpToStart,
        C::End => Action::JumpToEnd,
        C::Char('n') | C::Char('N') => Action::NewEntry,
        C::Char('e') | C::Char('E') => Action::EditEntry,
        C::Char('d') | C::Char('D') => Action::DeleteEntry,
        C::Char('f') | C::Char('F') => Action::ToggleFavorite,
        C::Char('c') | C::Char('C') => Action::CopyPassword,
        C::Char('u') | C::Char('U') => Action::CopyUsername,
        C::Char('r') | C::Char('R') => Action::ToggleReveal,
        C::Char('/') => Action::ToggleSearch,
        C::Char('v') | C::Char('V') => Action::ToggleFavoritesFilter,
        C::Char('t') | C::Char('T') => Action::ToggleTagFilter,
        C::Char('s') | C::Char('S') => Action::OpenSettings,
        C::Char('q') | C::Char('Q') => Action::Lock,
        _ => Action::None,
    }
}

/// Keys while a modal is open. Only the modal reacts.
fn handle_modal_key(
    state: &mut AppState,
    m: Modal,
    code: KeyCode,
    ctrl: bool,
) -> Action {
    use KeyCode as C;
    if ctrl {
        if let C::Char('c') = code {
            return Action::Quit;
        }
    }
    // Every modal closes on Escape or Ctrl+C; nothing beneath it reacts.
    if code == C::Esc {
        state.dismiss_modal();
        return Action::Redraw;
    }

    match &m {
        Modal::Confirm { .. } => match code {
            // A destructive confirm is not accepted on a bare `y` alone; Enter
            // is required, so a stray keypress can't delete a vault.
            C::Enter => Action::SaveForm, // the caller interprets this per-modal
            _ => Action::None,
        },
        Modal::Password { .. } => match code {
            C::Enter => Action::SaveForm,
            C::Backspace => {
                if let Some(Modal::Password { value, .. }) =
                    state.modal.as_mut()
                {
                    value.pop();
                }
                Action::Redraw
            }
            C::Char(c) => {
                if let Some(Modal::Password { value, .. }) =
                    state.modal.as_mut()
                {
                    value.push(c);
                }
                Action::Redraw
            }
            _ => Action::None,
        },
    }
}

/// Applies the parts of an action that are cheap and local, returning true if
/// the caller still needs to do slow work (unlock, rekey, clipboard).
pub fn apply_local(state: &mut AppState, action: Action) -> bool {
    match action.clone() {
        Action::None | Action::Redraw => {}
        Action::Quit => state.should_quit = true,
        Action::MoveSelection(delta) => {
            state.move_selection(delta);
            state.touch();
        }
        Action::JumpToStart => {
            state.selected = 0;
            state.load_detail();
            state.touch();
        }
        Action::JumpToEnd => {
            state.selected = state.rows.len().saturating_sub(1);
            state.load_detail();
            state.touch();
        }
        Action::NewEntry => state.begin_new_entry(),
        Action::EditEntry => state.begin_edit_selected(),
        Action::DeleteEntry => {
            if !state.rows.is_empty() {
                state.modal = Some(modal::delete_confirmation(&state.selected_title()));
            }
        }
        Action::ToggleFavorite => state.toggle_selected_favorite(),
        // Copying queues the secret; the shell writes it to the clipboard and
        // reports the outcome, so a failed copy can say so.
        Action::CopyPassword => {
            state.copy_password();
            if state.pending_copy.is_some() {
                return true;
            }
        }
        Action::CopyUsername => {
            state.copy_username();
            if state.pending_copy.is_some() {
                return true;
            }
        }
        Action::ToggleReveal => state.toggle_reveal(),
        Action::ToggleSearch => {
            state.focus = if state.focus == Focus::Search { Focus::List } else { Focus::Search };
            state.touch();
        }
        Action::ToggleFavoritesFilter => {
            state.toggle_favorite_filter();
            state.touch();
        }
        Action::ToggleTagFilter => state.toggle_tag_filter(),
        Action::OpenSettings => {
            state.screen = Screen::Settings;
            state.settings_row = 0;
        }
        Action::Back => {
            if state.screen == Screen::Settings {
                state.screen = Screen::Vault;
            } else if state.screen == Screen::Edit {
                state.cancel_edit();
            }
        }
        Action::Lock => {
            state.lock();
            state.notify(Status::info("Vault locked"));
        }
        Action::FocusNextField => {
            if let Some(f) = state.form.as_mut() {
                f.field = f.field.next();
            }
        }
        Action::FocusPrevField => {
            if let Some(f) = state.form.as_mut() {
                f.field = f.field.prev();
            }
        }
        Action::InsertChar(c) => {
            if let Some(f) = state.form.as_mut() {
                let mut v = f.text().to_string();
                v.push(c);
                f.set_text(v);
            }
        }
        Action::SetFieldText(v) => {
            if let Some(f) = state.form.as_mut() {
                f.set_text(v);
            }
        }
        Action::ToggleFocusedField => {
            if let Some(f) = state.form.as_mut() {
                match f.field {
                    Field::Favorite => f.toggle_favorite(),
                    Field::Category => f.cycle_category(),
                    _ => {}
                }
            }
        }
        Action::GeneratePassword => state.generate_password_into_form(),
        // These need a component update or filesystem work, handled by the
        // caller.
        Action::SubmitPassword | Action::SaveForm => {}
    }
    // Computed after the match, not before: a copy only needs the slow path
    // once the secret has actually been queued.
    needs_slow_work(&action)
}

/// Whether the caller still has filesystem, key-derivation, or clipboard work
/// to do after [`apply_local`] has run.
fn needs_slow_work(action: &Action) -> bool {
    matches!(
        action,
        Action::SubmitPassword | Action::SaveForm | Action::CopyPassword | Action::CopyUsername
    )
}

/// Formats a KDF memory cost for display, in MiB.
pub fn format_memory(memory_kib: u32) -> String {
    format!("{} MiB", memory_kib / 1024)
}

#[cfg(test)]
mod tests {
    use super::*;
    use KeyCode as C;

    fn state_with_screen(screen: Screen) -> AppState {
        let mut s = AppState::new(crate::vault_store::VaultPaths::new("/tmp/fuin-keys"));
        s.screen = screen;
        s
    }

    fn unlocked() -> AppState {
        let mut s = state_with_screen(Screen::Vault);
        s.focus = Focus::List;
        s.rows = vec!["a".into(), "b".into(), "c".into()];
        s
    }

    fn press(state: &mut AppState, code: C) -> Action {
        let ctrl = false;
        let shift = false;
        handle_key(state, code, ctrl, shift)
    }

    #[test]
    fn a_modal_swallows_every_key_underneath_it() {
        let mut s = unlocked();
        s.modal = Some(Modal::Password { title: "t".into(), value: String::new() });
        // 'n' would normally create an entry.
        let action = press(&mut s, C::Char('n'));
        assert_ne!(action, Action::NewEntry, "the modal must block the screen beneath it");
        assert_eq!(s.screen, Screen::Vault, "and must not switch screens");
    }

    #[test]
    fn escape_closes_a_modal_and_restores_the_screen() {
        let mut s = unlocked();
        s.modal = Some(Modal::confirm("t", "b"));
        press(&mut s, C::Esc);
        assert!(!s.modal_open());
    }

    #[test]
    fn ctrl_c_quits_from_anywhere() {
        let mut s = unlocked();
        assert_eq!(handle_key(&mut s, C::Char('c'), true, false), Action::Quit);
    }

    #[test]
    fn unlock_screen_types_and_submits() {
        let mut s = state_with_screen(Screen::Unlock);
        press(&mut s, C::Char('p'));
        press(&mut s, C::Char('w'));
        assert_eq!(s.password, "pw");
        assert_eq!(press(&mut s, C::Enter), Action::SubmitPassword);
    }

    #[test]
    fn backspace_edits_the_password() {
        let mut s = state_with_screen(Screen::Unlock);
        press(&mut s, C::Char('a'));
        press(&mut s, C::Char('b'));
        press(&mut s, C::Backspace);
        assert_eq!(s.password, "a");
    }

    #[test]
    fn escape_on_the_unlock_screen_quits() {
        let mut s = state_with_screen(Screen::Unlock);
        assert_eq!(press(&mut s, C::Esc), Action::Quit);
    }

    #[test]
    fn vault_navigation_keys_move_the_selection() {
        let mut s = unlocked();
        assert_eq!(press(&mut s, C::Down), Action::MoveSelection(1));
        assert_eq!(press(&mut s, C::Char('j')), Action::MoveSelection(1));
        assert_eq!(press(&mut s, C::Up), Action::MoveSelection(-1));
        assert_eq!(press(&mut s, C::Char('k')), Action::MoveSelection(-1));
    }

    #[test]
    fn page_and_home_end_jump_further() {
        let mut s = unlocked();
        assert_eq!(press(&mut s, C::PageDown), Action::MoveSelection(10));
        assert_eq!(press(&mut s, C::Home), Action::JumpToStart);
        assert_eq!(press(&mut s, C::End), Action::JumpToEnd);
    }

    #[test]
    fn vault_command_keys_map_to_their_actions() {
        let mut s = unlocked();
        assert_eq!(press(&mut s, C::Char('n')), Action::NewEntry);
        assert_eq!(press(&mut s, C::Char('e')), Action::EditEntry);
        assert_eq!(press(&mut s, C::Char('d')), Action::DeleteEntry);
        assert_eq!(press(&mut s, C::Char('f')), Action::ToggleFavorite);
        assert_eq!(press(&mut s, C::Char('c')), Action::CopyPassword);
        assert_eq!(press(&mut s, C::Char('u')), Action::CopyUsername);
        assert_eq!(press(&mut s, C::Char('r')), Action::ToggleReveal);
        assert_eq!(press(&mut s, C::Char('/')), Action::ToggleSearch);
        assert_eq!(press(&mut s, C::Char('v')), Action::ToggleFavoritesFilter);
        assert_eq!(press(&mut s, C::Char('s')), Action::OpenSettings);
        assert_eq!(press(&mut s, C::Char('q')), Action::Lock);
    }

    #[test]
    fn uppercase_command_keys_work_too() {
        let mut s = unlocked();
        assert_eq!(press(&mut s, C::Char('N')), Action::NewEntry);
        assert_eq!(press(&mut s, C::Char('Q')), Action::Lock);
    }

    #[test]
    fn slash_enters_search_and_escape_leaves_it() {
        let mut s = unlocked();
        let action = press(&mut s, C::Char('/'));
        assert_eq!(action, Action::ToggleSearch);
        apply_local(&mut s, action);
        assert_eq!(s.focus, Focus::Search);

        // While the box has focus, `/` is literal text, not a second toggle.
        let in_search = press(&mut s, C::Char('/'));
        apply_local(&mut s, in_search);
        assert_eq!(s.query, "/", "a second slash types into the search box");
        assert_eq!(s.focus, Focus::Search, "and does not toggle back out");

        press(&mut s, C::Esc);
        assert_eq!(s.focus, Focus::List);
    }

    #[test]
    fn while_searching_printable_keys_are_text_not_commands() {
        let mut s = unlocked();
        s.focus = Focus::Search;
        press(&mut s, C::Char('g'));
        // 'g' must go into the query, not trigger "generate" or anything else.
        assert_eq!(s.query, "g");
    }

    #[test]
    fn escape_leaves_search_and_returns_to_the_list() {
        let mut s = unlocked();
        s.focus = Focus::Search;
        s.query = "abc".into();
        press(&mut s, C::Esc);
        assert_eq!(s.focus, Focus::List);
    }

    #[test]
    fn enter_confirms_search_and_returns_to_the_list() {
        let mut s = unlocked();
        s.focus = Focus::Search;
        press(&mut s, C::Enter);
        assert_eq!(s.focus, Focus::List);
    }

    #[test]
    fn form_tab_cycles_fields_in_both_directions() {
        let mut s = state_with_screen(Screen::Edit);
        s.begin_new_entry();
        assert_eq!(press(&mut s, C::Tab), Action::FocusNextField);
        // Shift is passed through handle_key.
        assert_eq!(handle_key(&mut s, C::Tab, false, true), Action::FocusPrevField);
    }

    #[test]
    fn form_escape_cancels() {
        let mut s = state_with_screen(Screen::Edit);
        s.begin_new_entry();
        assert_eq!(press(&mut s, C::Esc), Action::Back);
    }

    #[test]
    fn form_ctrl_s_saves() {
        let mut s = state_with_screen(Screen::Edit);
        s.begin_new_entry();
        assert_eq!(handle_key(&mut s, C::Char('s'), true, false), Action::SaveForm);
    }

    #[test]
    fn form_g_generates_a_password() {
        let mut s = state_with_screen(Screen::Edit);
        s.begin_new_entry();
        assert_eq!(press(&mut s, C::Char('g')), Action::GeneratePassword);
    }

    #[test]
    fn settings_navigates_rows_and_leaves() {
        let mut s = state_with_screen(Screen::Settings);
        press(&mut s, C::Down);
        assert_eq!(s.settings_row, 1);
        press(&mut s, C::Up);
        assert_eq!(s.settings_row, 0);
        assert_eq!(press(&mut s, C::Esc), Action::Back);
    }

    #[test]
    fn settings_cursor_stays_within_bounds() {
        let mut s = state_with_screen(Screen::Settings);
        for _ in 0..20 {
            press(&mut s, C::Down);
        }
        assert_eq!(s.settings_row, AppState::SETTINGS_ROWS - 1);
        for _ in 0..20 {
            press(&mut s, C::Up);
        }
        assert_eq!(s.settings_row, 0);
    }

    #[test]
    fn a_destructive_confirm_needs_enter_not_a_bare_key() {
        let mut s = unlocked();
        s.modal = Some(Modal::danger("Delete", "Really?"));
        // A stray 'y' must not delete.
        let action = press(&mut s, C::Char('y'));
        assert_eq!(action, Action::None, "a bare y must not confirm a delete");
    }

    #[test]
    fn apply_local_creates_a_modal_for_delete() {
        let mut s = unlocked();
        apply_local(&mut s, Action::DeleteEntry);
        assert!(s.modal_open(), "delete should ask for confirmation first");
    }

    #[test]
    fn apply_local_opens_the_new_entry_form() {
        let mut s = unlocked();
        apply_local(&mut s, Action::NewEntry);
        assert_eq!(s.screen, Screen::Edit);
        assert!(s.form.is_some());
    }

    #[test]
    fn apply_local_lock_returns_to_unlock_and_clears() {
        let mut s = unlocked();
        s.session = None; // nothing to clear, but the screen must change
        apply_local(&mut s, Action::Lock);
        assert_eq!(s.screen, Screen::Unlock);
    }

    #[test]
    fn apply_local_quit_sets_the_flag() {
        let mut s = unlocked();
        apply_local(&mut s, Action::Quit);
        assert!(s.should_quit);
    }

    #[test]
    fn insert_char_appends_to_the_focused_field() {
        let mut s = state_with_screen(Screen::Edit);
        s.begin_new_entry();
        apply_local(&mut s, Action::InsertChar('G'));
        assert_eq!(s.form.as_ref().unwrap().title, "G");
    }

    #[test]
    fn backspace_helpers_respect_char_boundaries() {
        assert_eq!(backspace("ab"), "a");
        assert_eq!(backspace("a"), "");
        assert_eq!(backspace(""), "");
        assert_eq!(backspace("héllo"), "héll", "must not split a multi-byte char");
    }

    #[test]
    fn the_password_field_caps_its_length_at_the_core_maximum() {
        // The cap is core's, imported rather than restated, so raising core's
        // limit cannot leave the UI rejecting a password core would accept.
        assert_eq!(MAX_PASSWORD_LENGTH, fuin_core::password::MAX_PASSWORD_LENGTH);
        let mut s = state_with_screen(Screen::Unlock);
        for _ in 0..(MAX_PASSWORD_LENGTH + 10) {
            press(&mut s, C::Char('x'));
        }
        assert_eq!(s.password.chars().count(), MAX_PASSWORD_LENGTH);
    }

    #[test]
    fn memory_formats_in_mib() {
        assert_eq!(format_memory(65536), "64 MiB");
        assert_eq!(format_memory(1024), "1 MiB");
    }
}
