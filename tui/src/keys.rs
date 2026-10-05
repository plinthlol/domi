//! The keymap: crossterm events in, state transitions out.
//!
//! Every key press funnels through [`handle`] so the bindings live in one
//! readable table instead of being scattered across render closures. Three
//! rules keep the map predictable:
//!
//! - A modal, when open, swallows everything except what dismisses it. A
//!   half-typed master password can never fall through to "quit" or "delete".
//! - Every binding calls [`AppState::note_activity`], which is what resets the
//!   auto-lock countdown. A binding that forgets it shows up as a vault locking
//!   itself mid-keystroke.
//! - Plain letters are shortcuts only when no search query is open, so the
//!   vault screen can accept typed text without a modal.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::error::AppError;
use crate::state::{AppState, Field, Focus, Modal, Screen, Status, ROW_KDF, ROW_MASTER_PASSWORD, ROW_RESET, ROW_VAULT};

/// A key press this app has no binding for.
///
/// Returned rather than dropped so the caller can show a short hint and make
/// it clear the key was seen rather than lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unbound;

/// Dispatches one key press against `state`.
///
/// Returns `Err(Unbound)` when nothing in the current context claims the key.
pub fn handle(state: &mut AppState, key: KeyEvent) -> Result<(), Unbound> {
    // Terminals without the kitty keyboard protocol report Press and Release.
    // Acting on Release would double every keystroke and every repeat.
    if key.kind != KeyEventKind::Press {
        return Err(Unbound);
    }

    // Quit works from anywhere, including on top of a dialog, so a user is
    // never trapped by a modal they cannot dismiss.
    if is_ctrl(key, KeyCode::Char('c')) || is_ctrl(key, KeyCode::Char('q')) {
        state.should_quit = true;
        state.note_activity();
        return Ok(());
    }

    if state.modal.is_some() {
        return modal_key(state, key);
    }

    match state.screen {
        Screen::Setup => setup_key(state, key),
        Screen::Unlock => unlock_key(state, key),
        Screen::Vault => vault_key(state, key),
        Screen::Edit => edit_key(state, key),
        Screen::Settings => settings_key(state, key),
    }
}

fn is_ctrl(key: KeyEvent, code: KeyCode) -> bool {
    key.code == code && key.modifiers.contains(KeyModifiers::CONTROL)
}

// ----------------------------------------------------------------- modals ---

/// Keys accepted while a dialog is open.
fn modal_key(state: &mut AppState, key: KeyEvent) -> Result<(), Unbound> {
    let Some(modal) = state.modal.clone() else { return Err(Unbound) };

    if let Modal::Confirm { .. } = modal {
        return match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                // Take the dialog down before running the action, so the action
                // can never be run twice by a key repeat.
                state.dismiss_modal();
                match modal.action() {
                    Some(action) => state.confirm_pending(action),
                    None => state.notify(Status::info("Confirmed")),
                }
                state.note_activity();
                Ok(())
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                state.dismiss_modal();
                state.note_activity();
                Ok(())
            }
            _ => Err(Unbound),
        };
    }

    match key.code {
        KeyCode::Esc => {
            state.dismiss_modal();
            state.note_activity();
            Ok(())
        }
        KeyCode::Tab | KeyCode::BackTab => {
            if let Some(m) = state.modal.as_mut() {
                m.tab_field();
            }
            state.note_activity();
            Ok(())
        }
        KeyCode::Enter => {
            state.dismiss_modal();
            commit_text_modal(state, modal);
            state.note_activity();
            Ok(())
        }
        KeyCode::Backspace => {
            if let Some(m) = state.modal.as_mut() {
                m.pop_char();
            }
            state.note_activity();
            Ok(())
        }
        KeyCode::Char(c) => {
            if let Some(m) = state.modal.as_mut() {
                m.push_char(c);
            }
            state.note_activity();
            Ok(())
        }
        _ => Err(Unbound),
    }
}

/// Applies a text-entry dialog's value.
///
/// Takes the dialog by value so the caller can close it first and so this is
/// callable from a test without synthesising a terminal event.
pub fn commit_text_modal(state: &mut AppState, modal: Modal) {
    match modal {
        Modal::Password { title, value, confirm, .. } => {
            if value.is_empty() {
                state.notify_error(AppError::BadInput("Password cannot be empty".into()));
                return;
            }
            // The outcome is computed first so `state` is borrowed once, not
            // once for the call and again for the argument.
            let outcome = state.change_master_password(&value, &confirm);
            report(state, outcome, &title);
        }
        Modal::Text { value, .. } => {
            if value.trim().is_empty() {
                state.notify_error(AppError::BadInput("Directory cannot be empty".into()));
                return;
            }
            let dir = value.trim().to_string();
            let outcome = state.set_vault_dir(&dir);
            report(state, outcome, "Vault location saved");
        }
        Modal::Confirm { .. } => {}
    }
}

fn report(state: &mut AppState, outcome: Result<(), AppError>, success: &str) {
    match outcome {
        Ok(()) => state.notify(Status::success(success)),
        Err(e) => state.notify_error(e),
    }
}

// ------------------------------------------------------------------ setup ---

fn setup_key(state: &mut AppState, key: KeyEvent) -> Result<(), Unbound> {
    match key.code {
        KeyCode::Esc => {
            state.should_quit = true;
            Ok(())
        }
        KeyCode::Enter => {
            let password = std::mem::take(&mut state.password);
            let confirm = std::mem::take(&mut state.confirm);
            state.setup_field = 0;
            let outcome = state.create_vault(&password, &confirm);
            report(state, outcome, "Vault created");
            state.note_activity();
            Ok(())
        }
        KeyCode::Tab | KeyCode::BackTab => {
            // Two fields, so Tab swaps between them in either direction.
            state.setup_field = 1 - state.setup_field.clamp(0, 1);
            state.note_activity();
            Ok(())
        }
        KeyCode::Backspace => {
            target_field(state).pop();
            state.note_activity();
            Ok(())
        }
        KeyCode::Char(c) => {
            let field = target_field(state);
            if field.chars().count() < crate::state::MAX_PASSWORD_LENGTH {
                field.push(c);
            }
            state.note_activity();
            Ok(())
        }
        _ => Err(Unbound),
    }
}

/// The setup-screen string the next keystroke belongs to.
fn target_field(state: &mut AppState) -> &mut String {
    if state.setup_field == 1 { &mut state.confirm } else { &mut state.password }
}

// ----------------------------------------------------------------- unlock ---

fn unlock_key(state: &mut AppState, key: KeyEvent) -> Result<(), Unbound> {
    match key.code {
        KeyCode::Esc => {
            state.should_quit = true;
            Ok(())
        }
        KeyCode::Enter => {
            let password = std::mem::take(&mut state.password);
            match state.unlock(&password) {
                Ok(()) => state.notify(Status::success("Vault unlocked")),
                Err(e) => {
                    // Put it back so a typo can be corrected in place rather
                    // than retyped from nothing.
                    state.password = password;
                    state.screen_error = Some(e.message());
                    state.notify_error(e);
                }
            }
            state.note_activity();
            Ok(())
        }
        KeyCode::Backspace => {
            state.password.pop();
            state.note_activity();
            Ok(())
        }
        KeyCode::Char(c) => {
            if state.password.chars().count() < crate::state::MAX_PASSWORD_LENGTH {
                state.password.push(c);
            }
            state.note_activity();
            Ok(())
        }
        _ => Err(Unbound),
    }
}

// ------------------------------------------------------------------ vault ---

fn vault_key(state: &mut AppState, key: KeyEvent) -> Result<(), Unbound> {
    // While the search bar has focus, plain letters belong to the query and the
    // letter shortcuts step aside. Ctrl-F stays available as the filter toggle
    // because a control-modified key can never be search text.
    let searching = state.searching;

    if searching && !key.modifiers.contains(KeyModifiers::CONTROL) {
        return search_key(state, key);
    }

    match key.code {
        KeyCode::Char('q') => {
            state.should_quit = true;
            Ok(())
        }
        KeyCode::Char('/') => {
            state.begin_search();
            state.note_activity();
            Ok(())
        }
        KeyCode::Char('n') => {
            state.begin_new();
            state.note_activity();
            Ok(())
        }
        KeyCode::Char('e') | KeyCode::Enter => {
            state.begin_edit();
            state.note_activity();
            Ok(())
        }
        KeyCode::Char('d') => {
            state.request_delete_selected();
            state.note_activity();
            Ok(())
        }
        KeyCode::Char('f') if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            state.toggle_favorite();
            state.note_activity();
            Ok(())
        }
        KeyCode::Char('f') => {
            state.toggle_filter();
            state.note_activity();
            Ok(())
        }
        KeyCode::Char('p') => {
            state.copy_password();
            state.note_activity();
            Ok(())
        }
        KeyCode::Char('u') => {
            state.copy_username();
            state.note_activity();
            Ok(())
        }
        KeyCode::Char('r') => {
            state.toggle_reveal();
            state.note_activity();
            Ok(())
        }
        KeyCode::Char('g') => {
            let _ = state.generate_password();
            state.note_activity();
            Ok(())
        }
        KeyCode::Char(',') => {
            state.screen = Screen::Settings;
            state.note_activity();
            Ok(())
        }
        KeyCode::Char('L') => {
            state.lock();
            state.note_activity();
            Ok(())
        }
        KeyCode::Tab => {
            state.toggle_focus();
            state.note_activity();
            Ok(())
        }
        KeyCode::Down | KeyCode::Char('j') => {
            state.move_selection(1);
            state.note_activity();
            Ok(())
        }
        KeyCode::Up | KeyCode::Char('k') => {
            state.move_selection(-1);
            state.note_activity();
            Ok(())
        }
        KeyCode::PageDown => {
            // A page is half the visible list, which is the convention that
            // makes paging land on an overlapping row rather than skipping one.
            state.move_selection(page_step(state));
            state.note_activity();
            Ok(())
        }
        KeyCode::PageUp => {
            state.move_selection(-page_step(state));
            state.note_activity();
            Ok(())
        }
        KeyCode::Home => {
            state.move_selection(i64::MIN / 2);
            state.note_activity();
            Ok(())
        }
        KeyCode::End => {
            state.move_selection(i64::MAX / 2);
            state.note_activity();
            Ok(())
        }
        KeyCode::Esc => {
            state.toggle_focus();
            state.note_activity();
            Ok(())
        }
        _ => Err(Unbound),
    }
}

/// Keys routed to the search query rather than to shortcuts.
fn search_key(state: &mut AppState, key: KeyEvent) -> Result<(), Unbound> {
    match key.code {
        KeyCode::Char(c) => {
            state.set_query(format!("{}{}", state.query, c));
            state.note_activity();
            Ok(())
        }
        KeyCode::Backspace => {
            let mut q = state.query.clone();
            q.pop();
            state.set_query(q);
            state.note_activity();
            Ok(())
        }
        KeyCode::Esc => {
            // Escape leaves the search bar and hands the keyboard back to the
            // list. Focus lands on the list rather than the detail pane because
            // that is where the user was before they started typing a query,
            // and where they will want to move with the arrows next.
            state.end_search();
            state.focus = Focus::List;
            state.note_activity();
            Ok(())
        }
        KeyCode::Enter => {
            // Enter accepts the query and moves to the detail pane, which is
            // where a user who searched wants to land.
            state.end_search();
            state.focus = Focus::Detail;
            state.note_activity();
            Ok(())
        }
        KeyCode::Down => {
            state.move_selection(1);
            state.note_activity();
            Ok(())
        }
        KeyCode::Up => {
            state.move_selection(-1);
            state.note_activity();
            Ok(())
        }
        _ => Err(Unbound),
    }
}

/// How far PageUp and PageDown travel.
///
/// The renderer knows the pane height and the state machine does not, so this
/// is a fixed step rather than a measured one. A tenth of the list keeps a
/// large vault paged usefully and a small one still moves.
fn page_step(state: &AppState) -> i64 {
    let len = state.rows.len();
    if len == 0 {
        return 1;
    }
    ((len / 10) as i64).clamp(1, 20)
}

// ------------------------------------------------------------------- edit ---

fn edit_key(state: &mut AppState, key: KeyEvent) -> Result<(), Unbound> {
    if is_ctrl(key, KeyCode::Char('s')) {
        save(state);
        return Ok(());
    }
    if is_ctrl(key, KeyCode::Char('g')) {
        let _ = state.generate_password();
        state.note_activity();
        return Ok(());
    }

    match key.code {
        KeyCode::Esc => {
            state.cancel_form();
            state.note_activity();
            Ok(())
        }
        KeyCode::Enter => {
            // Enter advances a field at a time; the last field saves, so a long
            // form can be filled without a modifier and still ends in a save.
            let focused = state.form.as_ref().map(|f| f.focused);
            match focused {
                None => Err(Unbound),
                Some(field) if field == *Field::ALL.last().expect("Field::ALL is non-empty") => {
                    save(state);
                    Ok(())
                }
                Some(field) => {
                    if let Some(form) = state.form.as_mut() {
                        form.focused = field.next();
                    }
                    state.note_activity();
                    Ok(())
                }
            }
        }
        KeyCode::Tab | KeyCode::BackTab => {
            let forward = key.code == KeyCode::Tab && !key.modifiers.contains(KeyModifiers::SHIFT);
            if let Some(form) = state.form.as_mut() {
                form.focused = if forward { form.focused.next() } else { form.focused.prev() };
            }
            state.note_activity();
            Ok(())
        }
        KeyCode::Down => {
            if let Some(form) = state.form.as_mut() {
                form.focused = form.focused.next();
            }
            state.note_activity();
            Ok(())
        }
        KeyCode::Up => {
            if let Some(form) = state.form.as_mut() {
                form.focused = form.focused.prev();
            }
            state.note_activity();
            Ok(())
        }
        KeyCode::Backspace => {
            if let Some(form) = state.form.as_mut() {
                let field = form.focused;
                form.backspace(field);
            }
            state.note_activity();
            Ok(())
        }
        KeyCode::Char(c) => {
            if let Some(form) = state.form.as_mut() {
                let field = form.focused;
                if field.is_text() {
                    form.insert_char(field, c);
                }
            }
            state.note_activity();
            Ok(())
        }
        _ => Err(Unbound),
    }
}

fn save(state: &mut AppState) {
    let outcome = state.save_form();
    report(state, outcome, "Entry saved");
    state.note_activity();
}

// --------------------------------------------------------------- settings ---

fn settings_key(state: &mut AppState, key: KeyEvent) -> Result<(), Unbound> {
    match key.code {
        KeyCode::Esc | KeyCode::Enter => {
            state.screen = Screen::Vault;
            state.note_activity();
            Ok(())
        }
        KeyCode::Char('q') => {
            state.should_quit = true;
            Ok(())
        }
        KeyCode::Up | KeyCode::Char('k') => {
            state.move_settings_row(-1);
            state.note_activity();
            Ok(())
        }
        KeyCode::Down | KeyCode::Char('j') => {
            state.move_settings_row(1);
            state.note_activity();
            Ok(())
        }
        KeyCode::Left => {
            state.step_auto_lock(-1);
            state.note_activity();
            Ok(())
        }
        KeyCode::Right => {
            state.step_auto_lock(1);
            state.note_activity();
            Ok(())
        }
        KeyCode::Char('d') => {
            open_row_editor(state);
            state.note_activity();
            Ok(())
        }
        KeyCode::Char('x') if state.settings_row == ROW_RESET => {
            state.request_reset_vault();
            state.note_activity();
            Ok(())
        }
        KeyCode::Char('L') => {
            state.lock_from_settings();
            state.note_activity();
            Ok(())
        }
        _ => Err(Unbound),
    }
}

/// Opens the editor the highlighted settings row offers.
fn open_row_editor(state: &mut AppState) {
    match state.settings_row {
        ROW_VAULT => state.begin_vault_dir_change(),
        ROW_MASTER_PASSWORD => state.begin_master_password_change(),
        ROW_KDF => state.notify(Status::info("Key derivation cost is set when the vault is created")),
        _ => {}
    }
}

/// The one-line help shown under the active screen.
pub fn hint(state: &AppState) -> String {
    if let Some(modal) = &state.modal {
        return match modal {
            Modal::Confirm { yes_label, .. } => format!("y {yes_label}  n cancel  esc cancel"),
            _ => "enter accept  esc cancel".to_string(),
        };
    }
    match state.screen {
        Screen::Setup => {
            "type a password  tab confirm  enter create  esc quit".to_string()
        }
        Screen::Unlock => "type your password  enter unlock  esc quit".to_string(),
        Screen::Vault => {
            if state.query.is_empty() {
                concat!(
                    "/ search  n new  e edit  d delete  f favorite  ",
                    "p copy pw  u copy user  L lock  , settings  q quit"
                )
                .to_string()
            } else {
                "type to filter  backspace erase  esc clear  ctrl+f favorites".to_string()
            }
        }
        Screen::Edit => "enter next field  ctrl+g generate  ctrl+s save  esc cancel".to_string(),
        Screen::Settings => {
            "up/down choose  left/right change  d edit  x erase vault  esc back".to_string()
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{Filter, PendingAction};
    use crate::testkit::{self, ctrl, key, press};
    use crossterm::event::KeyCode;
    use crate::vault_store::testing::TempVault;

    /// An unlocked vault with one entry, sitting on the list screen.
    fn on_list() -> (TempVault, AppState) {
        let tmp = TempVault::new();
        let mut state = testkit::state_at(tmp.paths());
        state.kdf = crate::vault_store::test_params();
        state.create_vault("horse", "horse").expect("the vault is created");
        state.begin_new();
        if let Some(form) = state.form.as_mut() {
            form.title = "GitHub".into();
            form.username = "ada".into();
            form.password = "hunter2".into();
        }
        state.save_form().expect("the entry saves");
        (tmp, state)
    }

    fn setup_screen() -> (TempVault, AppState) {
        let tmp = TempVault::new();
        let state = testkit::state_at(tmp.paths());
        (tmp, state)
    }

    // ----------------------------------------------------------- dispatch

    #[test]
    fn a_key_release_is_ignored() {
        // Terminals that report both Press and Release would otherwise double
        // every keystroke.
        let (_tmp, mut state) = on_list();
        let mut k = press('j');
        k.kind = KeyEventKind::Release;
        assert!(handle(&mut state, k).is_err());
    }

    #[test]
    fn ctrl_c_quits_from_any_screen() {
        for screen in [Screen::Setup, Screen::Unlock, Screen::Vault, Screen::Edit, Screen::Settings] {
            let (_tmp, mut state) = on_list();
            state.screen = screen;
            handle(&mut state, ctrl('c')).expect("ctrl+c is always bound");
            assert!(state.should_quit, "ctrl+c must quit from {screen:?}");
        }
    }

    #[test]
    fn ctrl_c_quits_even_with_a_dialog_open() {
        let (_tmp, mut state) = on_list();
        state.request_delete_selected();
        assert!(state.modal.is_some());
        handle(&mut state, ctrl('c')).expect("ctrl+c is always bound");
        assert!(state.should_quit, "a dialog must not trap the user");
    }

    // -------------------------------------------------------------- setup

    #[test]
    fn typing_on_the_setup_screen_builds_the_password() {
        let (_tmp, mut state) = setup_screen();
        assert_eq!(state.screen, Screen::Setup);
        testkit::type_text(&mut state, "abc");
        assert_eq!(state.password, "abc");
    }

    #[test]
    fn tab_moves_the_setup_keystrokes_to_the_confirmation() {
        let (_tmp, mut state) = setup_screen();
        testkit::type_text(&mut state, "abc");
        testkit::send(&mut state, key(KeyCode::Tab));
        testkit::type_text(&mut state, "xyz");
        assert_eq!(state.password, "abc");
        assert_eq!(state.confirm, "xyz");
    }

    #[test]
    fn the_setup_password_is_capped_rather_than_growing_without_limit() {
        let (_tmp, mut state) = setup_screen();
        for _ in 0..(crate::state::MAX_PASSWORD_LENGTH + 50) {
            testkit::send(&mut state, press('a'));
        }
        assert_eq!(
            state.password.chars().count(),
            crate::state::MAX_PASSWORD_LENGTH
        );
    }

    #[test]
    fn backspace_on_setup_erases_the_focused_field_only() {
        let (_tmp, mut state) = setup_screen();
        testkit::type_text(&mut state, "abc");
        testkit::send(&mut state, key(KeyCode::Tab));
        testkit::type_text(&mut state, "xy");
        testkit::send(&mut state, key(KeyCode::Backspace));
        assert_eq!(state.confirm, "x");
        assert_eq!(state.password, "abc");
    }

    // ------------------------------------------------------------- unlock

    #[test]
    fn a_wrong_password_is_reported_and_can_be_corrected_in_place() {
        let (_tmp, mut state) = on_list();
        state.lock();
        testkit::type_text(&mut state, "nope");
        testkit::send(&mut state, key(KeyCode::Enter));
        assert_eq!(state.screen, Screen::Unlock, "a wrong password does not open the vault");
        assert_eq!(state.password, "nope", "the text is kept so it can be edited");

        testkit::send(&mut state, key(KeyCode::Backspace));
        testkit::type_text(&mut state, "e");
        assert_eq!(state.password, "nope"[..3].to_string() + "e");
    }

    #[test]
    fn the_right_password_opens_the_vault() {
        let (_tmp, mut state) = on_list();
        state.lock();
        testkit::type_text(&mut state, "horse");
        testkit::send(&mut state, key(KeyCode::Enter));
        assert_eq!(state.screen, Screen::Vault);
        assert!(state.session.is_some());
        assert!(state.password.is_empty(), "the password is dropped on success");
    }

    // -------------------------------------------------------------- vault

    #[test]
    fn j_and_k_walk_the_list_and_stop_at_the_ends() {
        let (_tmp, mut state) = on_list();
        testkit::send(&mut state, press('j'));
        assert_eq!(state.selected, 0, "only one entry");
        testkit::send(&mut state, press('k'));
        assert_eq!(state.selected, 0);
    }

    #[test]
    fn slash_opens_the_search_and_typing_then_goes_into_the_query() {
        let (_tmp, mut state) = on_list();
        testkit::send(&mut state, press('/'));
        testkit::type_text(&mut state, "git");
        assert_eq!(state.query, "git");
        assert_eq!(state.filtered_count(), 1);
    }

    #[test]
    fn letters_are_search_text_rather_than_shortcuts_while_a_query_is_open() {
        // Without this, typing a query that contains "d" or "n" would delete
        // entries or open the editor instead of narrowing the list.
        let (_tmp, mut state) = on_list();
        testkit::send(&mut state, press('/'));
        testkit::type_text(&mut state, "zzz");
        assert_eq!(state.query, "zzz");
        assert_eq!(state.screen, Screen::Vault, "typing must not leave the screen");
        assert!(state.form.is_none(), "typing must not open the editor");
    }

    #[test]
    fn backspace_erases_the_query_and_escape_leaves_the_search_keeping_it() {
        let (_tmp, mut state) = on_list();
        testkit::send(&mut state, press('/'));
        testkit::type_text(&mut state, "git");
        testkit::send(&mut state, key(KeyCode::Backspace));
        assert_eq!(state.query, "gi");

        testkit::send(&mut state, key(KeyCode::Esc));
        assert!(!state.searching, "escape leaves the search bar");
        assert_eq!(state.query, "gi", "and keeps the query for next time");
        assert_eq!(
            state.focus,
            Focus::List,
            "escape puts the keyboard back on the list, where the user started"
        );

        // A second escape, now that the shortcuts are live again, moves focus.
        testkit::send(&mut state, key(KeyCode::Esc));
        assert_eq!(state.focus, Focus::Detail);
    }

    #[test]
    fn enter_on_a_search_moves_focus_to_the_details() {
        let (_tmp, mut state) = on_list();
        testkit::send(&mut state, press('/'));
        testkit::type_text(&mut state, "git");
        testkit::send(&mut state, key(KeyCode::Enter));
        assert!(!state.searching);
        assert_eq!(state.focus, Focus::Detail, "a search ends on the details");
        assert_eq!(state.query, "git", "and keeps the query it accepted");
    }

    #[test]
    fn shortcuts_work_again_immediately_after_escaping_the_search() {
        // The bug this pins: after `/`, a typed query stayed focused even after
        // escape, so the next keystroke was swallowed as more search text and
        // "d" could not reach the delete flow.
        let (_tmp, mut state) = on_list();
        testkit::send(&mut state, press('/'));
        testkit::type_text(&mut state, "git");
        testkit::send(&mut state, key(KeyCode::Esc));

        testkit::send(&mut state, press('d'));
        assert!(state.modal.is_some(), "d must reach the delete flow after a search");
    }

    #[test]
    fn n_opens_a_new_entry_and_escape_leaves_without_saving() {
        let (_tmp, mut state) = on_list();
        let before = state.filtered_count();
        testkit::send(&mut state, press('n'));
        assert_eq!(state.screen, Screen::Edit);

        testkit::send(&mut state, key(KeyCode::Esc));
        assert_eq!(state.screen, Screen::Vault);
        assert_eq!(state.filtered_count(), before);
    }

    #[test]
    fn d_asks_before_deleting_and_y_carries_it_out() {
        let (_tmp, mut state) = on_list();
        testkit::send(&mut state, press('d'));
        assert!(state.modal.is_some(), "a delete asks first");
        assert_eq!(state.filtered_count(), 1, "nothing is deleted yet");

        testkit::send(&mut state, press('y'));
        assert!(state.modal.is_none());
        assert_eq!(state.filtered_count(), 0);
    }

    #[test]
    fn n_escapes_out_of_a_delete_dialog() {
        let (_tmp, mut state) = on_list();
        testkit::send(&mut state, press('d'));
        testkit::send(&mut state, press('n'));
        assert!(state.modal.is_none());
        assert_eq!(state.filtered_count(), 1, "the entry survived");
    }

    #[test]
    fn a_modal_swallows_the_shortcuts_underneath_it() {
        // The screen's letter shortcuts must not act while a dialog is up: "q"
        // must not quit, and "u" must not reach the clipboard.
        let (_tmp, mut state) = on_list();
        testkit::send(&mut state, press('d'));
        assert!(state.modal.is_some());

        // "n" and Esc are the dialog's own cancel keys and are tested above, so
        // they are left out here; every other letter must be swallowed.
        for k in [press('q'), press('d'), press('u'), press('/'), press('f'), press('L')] {
            let _ = handle(&mut state, k);
        }
        assert!(!state.should_quit, "a dialog must swallow q");
        assert_eq!(state.screen, Screen::Vault, "a dialog must swallow the editor key");
        assert!(state.modal.is_some(), "the dialog is still the one open");
        assert_eq!(state.filtered_count(), 1, "nothing was deleted");
        assert_eq!(state.pending_copy, None, "a dialog must swallow the copy keys");
        assert_eq!(state.filter, Filter::All, "a dialog must swallow the filter toggle");
    }

    #[test]
    fn f_toggles_a_favorite_and_ctrl_f_toggles_the_filter() {
        let (_tmp, mut state) = on_list();
        testkit::send(&mut state, press('f'));
        assert!(state.row_label(0).2, "plain f marked the entry as a favorite");

        testkit::send(&mut state, press('f'));
        assert!(!state.row_label(0).2, "and pressing it again undoes that");

        testkit::send(&mut state, ctrl('f'));
        assert_eq!(state.filter, Filter::Favorites, "ctrl+f is the filter toggle");
    }

    #[test]
    fn ctrl_f_filters_the_list_to_the_favorites() {
        let (_tmp, mut state) = on_list();
        assert_eq!(state.filtered_count(), 1);
        testkit::send(&mut state, ctrl('f'));
        assert_eq!(state.filtered_count(), 0, "nothing is a favorite yet");
        testkit::send(&mut state, ctrl('f'));
        assert_eq!(state.filtered_count(), 1);
    }

    #[test]
    fn p_queues_the_password_for_the_clipboard() {
        let (_tmp, mut state) = on_list();
        testkit::send(&mut state, press('p'));
        assert_eq!(state.pending_copy.as_deref(), Some("hunter2"));
    }

    #[test]
    fn uppercase_l_locks_the_vault() {
        let (_tmp, mut state) = on_list();
        testkit::send(&mut state, press('L'));
        assert_eq!(state.screen, Screen::Unlock);
        assert!(state.session.is_none());
    }

    #[test]
    fn comma_opens_the_settings_and_escape_returns() {
        let (_tmp, mut state) = on_list();
        testkit::send(&mut state, press(','));
        assert_eq!(state.screen, Screen::Settings);
        testkit::send(&mut state, key(KeyCode::Esc));
        assert_eq!(state.screen, Screen::Vault);
    }

    #[test]
    fn q_quits_but_only_when_no_query_is_open() {
        let (_tmp, mut state) = on_list();
        testkit::send(&mut state, press('q'));
        assert!(state.should_quit);

        let (_tmp, mut state) = on_list();
        testkit::send(&mut state, press('/'));
        testkit::type_text(&mut state, "q");
        assert!(!state.should_quit, "q is search text while searching");
        assert_eq!(state.query, "q");
    }

    // --------------------------------------------------------------- edit

    #[test]
    fn enter_walks_the_fields_and_saves_on_the_last_one() {
        let (_tmp, mut state) = on_list();
        testkit::send(&mut state, press('n'));
        let last = Field::ALL.last().copied().expect("there is at least one field");

        // Walk to the last field without leaving the editor.
        for _ in 0..Field::ALL.len() {
            assert_eq!(state.screen, Screen::Edit);
            testkit::send(&mut state, key(KeyCode::Enter));
        }
        assert_eq!(state.screen, Screen::Edit, "still editing, with the title empty");

        let form = state.form.as_mut().expect("the editor is open");
        assert_eq!(form.focused, last, "the walk ends on the last field");
    }

    #[test]
    fn typing_in_the_editor_fills_the_focused_field() {
        let (_tmp, mut state) = on_list();
        testkit::send(&mut state, press('n'));
        testkit::type_text(&mut state, "My title");
        let form = state.form.as_ref().expect("the editor is open");
        assert_eq!(form.title, "My title");
        assert_eq!(form.username, "", "nothing leaked into another field");
    }

    #[test]
    fn tab_and_shift_tab_move_between_fields_in_both_directions() {
        let (_tmp, mut state) = on_list();
        testkit::send(&mut state, press('n'));
        let focused = |s: &AppState| s.form.as_ref().expect("open").focused;

        assert_eq!(focused(&state), Field::Title);
        testkit::send(&mut state, key(KeyCode::Tab));
        assert_eq!(focused(&state), Field::Username, "tab advances");

        // A terminal reports shift+tab as BackTab, not as Tab with SHIFT set,
        // so both spellings have to be handled.
        testkit::send(&mut state, key(KeyCode::BackTab));
        assert_eq!(focused(&state), Field::Title, "backtab goes back");

        let mut shifted = key(KeyCode::Tab);
        shifted.modifiers = KeyModifiers::SHIFT;
        testkit::send(&mut state, shifted);
        assert_eq!(
            focused(&state),
            *Field::ALL.last().expect("non-empty"),
            "shift+tab wraps to the end"
        );
    }

    #[test]
    fn ctrl_s_saves_the_editor() {
        let (_tmp, mut state) = on_list();
        testkit::send(&mut state, press('n'));
        testkit::type_text(&mut state, "Saved");
        testkit::send(&mut state, ctrl('s'));
        assert_eq!(state.screen, Screen::Vault);
        assert_eq!(state.filtered_count(), 2);

        // The list is sorted by title, and "GitHub" precedes "Saved".
        let titles: Vec<String> = (0..2).map(|i| state.row_label(i).0).collect();
        assert_eq!(titles, vec!["GitHub".to_string(), "Saved".to_string()]);
    }

    #[test]
    fn ctrl_g_generates_a_password_without_leaving_the_editor() {
        let (_tmp, mut state) = on_list();
        testkit::send(&mut state, press('n'));
        testkit::send(&mut state, ctrl('g'));
        assert_eq!(state.screen, Screen::Edit);
        let form = state.form.as_ref().expect("the editor is open");
        assert!(!form.password.is_empty(), "a password was generated");
    }

    #[test]
    fn a_non_text_field_swallows_typing() {
        // Category and Favorite are toggles, not text; typing into them would
        // put characters nowhere.
        let (_tmp, mut state) = on_list();
        testkit::send(&mut state, press('n'));
        if let Some(form) = state.form.as_mut() {
            form.focused = Field::Favorite;
        }
        testkit::type_text(&mut state, "abc");
        let form = state.form.as_ref().expect("the editor is open");
        assert_eq!(form.title, "");
        assert_eq!(form.password, "");
    }

    // ----------------------------------------------------------- settings

    #[test]
    fn the_settings_cursor_moves_with_the_arrows_and_jk() {
        let (_tmp, mut state) = on_list();
        testkit::send(&mut state, press(','));
        testkit::send(&mut state, key(KeyCode::Down));
        assert_eq!(state.settings_row, 1);
        testkit::send(&mut state, press('j'));
        assert_eq!(state.settings_row, 2);
        testkit::send(&mut state, press('k'));
        assert_eq!(state.settings_row, 1);
    }

    #[test]
    fn left_and_right_change_the_auto_lock_delay() {
        let (_tmp, mut state) = on_list();
        testkit::send(&mut state, press(','));
        // Move to the auto-lock row.
        while state.settings_row != crate::state::ROW_AUTO_LOCK {
            testkit::send(&mut state, key(KeyCode::Down));
        }
        let before = state.auto_lock_secs;
        testkit::send(&mut state, key(KeyCode::Right));
        assert_ne!(state.auto_lock_secs, before, "right steps the delay up");
        testkit::send(&mut state, key(KeyCode::Left));
        assert_eq!(state.auto_lock_secs, before, "and left steps it back");
    }

    #[test]
    fn x_on_the_reset_row_asks_before_erasing() {
        let (_tmp, mut state) = on_list();
        testkit::send(&mut state, press(','));
        while state.settings_row != crate::state::ROW_RESET {
            testkit::send(&mut state, key(KeyCode::Down));
        }
        testkit::send(&mut state, press('x'));
        assert!(state.modal.is_some(), "a reset asks first");
        assert_eq!(
            state.modal.as_ref().and_then(|m| m.action()),
            Some(PendingAction::ResetVault)
        );
        assert_eq!(state.filtered_count(), 1, "nothing is erased yet");

        testkit::send(&mut state, press('n'));
        assert_eq!(state.filtered_count(), 1);
    }

    // ------------------------------------------------------- auto-lock

    #[test]
    fn every_bound_key_resets_the_idle_timer() {
        // A binding that forgets note_activity shows up as the vault locking
        // itself while the user is typing.
        let (_tmp, mut state) = on_list();
        state.auto_lock_secs = 60;
        state.idle_secs = 50;

        for k in [press('j'), key(KeyCode::Down), press('/'), press('n'), key(KeyCode::Esc)] {
            state.idle_secs = 50;
            let _ = handle(&mut state, k);
            assert_eq!(state.idle_secs, 0, "the idle timer was not reset");
        }
    }

    // ------------------------------------------------------------ hints

    #[test]
    fn the_hint_line_reflects_the_screen_and_the_search_state() {
        let (_tmp, mut state) = on_list();
        assert!(hint(&state).contains("search"));

        state.set_query("git".into());
        assert!(hint(&state).contains("filter"));

        state.set_query(String::new());
        state.request_delete_selected();
        assert!(hint(&state).contains("cancel"), "a dialog explains itself");
    }
}
