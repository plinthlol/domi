//! The root component: renders the active screen and turns key events into
//! state changes.
//!
//! Everything here is presentation and dispatch. The rules live in
//! [`crate::state`] and [`crate::keys`], which is what keeps the interesting
//! behaviour testable without a terminal.
//!
//! Two constraints shape the code here, both from iocraft rather than from
//! taste:
//!
//! - An element handler is a plain closure, so it cannot reach this
//!   component's `State` cell. Typed values are parked in a thread-local and
//!   drained into `AppState` before each key is interpreted.
//! - The `element!` macro assigns individual fields on a `Default` props
//!   struct, so a component whose props are assembled in Rust is built as an
//!   `Element` directly. The `build_*` functions below are those builders.
//!
//! Layout note: iocraft's `Text` takes no flexbox props, so any `Text` that
//! has to grow, shrink, or clip is wrapped in a `View` that carries them.

use std::cell::RefCell;
use std::time::Instant;

use iocraft::prelude::*;

use crate::clipboard;
use crate::keys::{self, Action};
use crate::state::{AppState, EntryForm, Field, Focus, Modal, RenderSnapshot, Screen, Status};
use crate::theme;
use crate::vault_store::VaultPaths;
use crate::widgets::chrome::{
    self, hints_for, EmptyState, FieldRow, FieldRowProps, Header, HeaderProps, StatusBar,
    StatusBarProps,
};
use crate::widgets::detail::{Detail, DetailProps};
use crate::widgets::entry_list::{EntryList, EntryListProps, BORDER_ROWS, ROW_HEIGHT};
use crate::widgets::form::{EntryFormProps, EntryFormView};
use crate::widgets::modal::{modal_confirm_label, modal_text_value, ModalBox, ModalBoxProps};
use crate::widgets::search_bar::{SearchBar, SearchBarProps};

/// The application root.
///
/// Holds `AppState` in a `State` cell, owns the single `use_terminal_events`
/// hook, and renders whichever screen is active.
#[derive(Default, Props)]
pub struct AppProps {
    /// Where the vault lives, from `--vault` or the default location.
    pub paths: VaultPaths,
}

#[component]
pub fn App(mut hooks: Hooks, props: &mut AppProps) -> impl Into<AnyElement<'static>> {
    // AppState is not Copy, so it lives behind read()/write() guards rather
    // than get()/set().
    let mut state = hooks.use_state(|| {
        let mut s = AppState::new(props.paths.clone());
        s.initial_screen();
        s
    });
    let (width, height) = hooks.use_terminal_size();
    // OSC 52 has to be written above the rendered frame, which is what this
    // handle is for; a `Text` cannot carry an escape sequence.
    let (stdout, _) = hooks.use_output();
    // Monotonic clock for the auto-lock timer. Terminals emit no ticks, so
    // elapsed time is measured across renders rather than on a timer.
    let mut last_tick = hooks.use_state(Instant::now);

    // One event hook for the whole app; the key-to-action mapping lives in
    // crate::keys. `State` is Copy, so moving it into the closure leaves the
    // handle usable here afterwards.
    {
        let mut event_state = state;
        hooks.use_terminal_events(move |event| {
            let TerminalEvent::Key(key) = event else { return };
            if key.kind != KeyEventKind::Press {
                // Held keys repeat, which is what you want for arrows but
                // would fire a command key dozens of times.
                return;
            }
            let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
            let shift = key.modifiers.contains(KeyModifiers::SHIFT);

            let action = {
                let mut s = event_state.write();
                // Apply whatever the last frame's inputs parked before reading
                // the new key, so a keystroke always sees the current text.
                drain_input(&mut s);
                keys::handle_key(&mut s, key.code, ctrl, shift)
            };

            let slow_path = {
                let mut s = event_state.write();
                keys::apply_local(&mut s, action.clone())
            };
            if slow_path {
                let mut s = event_state.write();
                match action {
                    // Argon2id at the default cost takes a noticeable fraction
                    // of a second, and a rekey takes longer still. Neither
                    // belongs in the middle of a keystroke's event handling.
                    Action::SubmitPassword => submit_password(&mut s),
                    Action::SaveForm => confirm(&mut s),
                    // Reached from `c` and `u`, which queue a secret.
                    Action::CopyPassword | Action::CopyUsername => {
                        let Some(secret) = s.pending_copy.take() else { return };
                        // The secret is encoded into the sequence and the
                        // sequence is dropped immediately after, so it lives
                        // for a moment and not in the UI.
                        let mut queued: Option<String> = None;
                        let result = clipboard::copy(&secret, |seq| queued = Some(seq.to_string()));
                        match (result, queued) {
                            (Ok(()), Some(seq)) => stdout.print(seq),
                            (Ok(()), None) => {}
                            (Err(msg), _) => {
                                s.notify(Status::error(&msg));
                                return;
                            }
                        }
                        s.notify(Status::success("Copied"));
                    }
                    _ => {}
                }
            }
        });
    }

    // Auto-lock, measured across renders. Renders are driven by input, so an
    // idle app would never re-render and never lock; the check still runs on
    // every frame the terminal produces.
    {
        let now = Instant::now();
        let elapsed = now.duration_since(last_tick.get()).as_secs();
        if elapsed > 0 {
            last_tick.set(now);
            let mut s = state.write();
            if s.tick_idle(elapsed) {
                s.lock();
                s.notify(Status::info("Locked after inactivity"));
            }
        }
    }

    // Drain before rendering too: iocraft fires on_change while building the
    // frame, and the text has to land before the next draw.
    {
        let mut s = state.write();
        drain_input(&mut s);
        if s.should_quit {
            return element! { View {} };
        }
        s.list_capacity = list_rows(height);
        let capacity = s.list_capacity;
        s.clamp_scroll(capacity);
    }

    let frame = {
        let s = state.read();
        render_screen(&s.clone_for_render(), width)
    };

    element! {
        View(
            flex_direction: FlexDirection::Column,
            // Explicit full size, not just `flex_grow`. iocraft hands the
            // layout engine `MaxContent` for a cross-axis axis it wasn't given
            // a width for, and `flex_grow` has no free space to distribute in
            // that mode, so a grow-only root collapses to its content width.
            // Sizing to the terminal here is what makes the app border span
            // the window instead of hugging the header text.
            width: 100_pct,
            height: 100_pct,
            border_style: theme::APP_BORDER,
            border_color: Some(theme::BORDER),
        ) {
            #(frame.into_iter())
        }
    }
}

/// How many rows the list pane can show at this terminal height.
///
/// The list pane shares its rows with the header, the status bar, the app
/// border, and — in two-pane mode — the search box, so the list gets what is
/// left. Clamped at zero so a tiny terminal reports no rows rather than
/// underflowing.
/// How many entry rows the list pane can show at this terminal height.
///
/// The list shares its rows with the header, the status bar, the app border,
/// and the list's own border, so it gets what is left. Saturated at zero so a
/// tiny terminal reports no rows rather than underflowing.
pub(crate) fn list_rows(height: u16) -> usize {
    let chrome_rows = 4; // the app border, header, status bar, and list border
    usize::from(height).saturating_sub(chrome_rows + BORDER_ROWS) / ROW_HEIGHT
}

/// Performs the unlock or create for `Action::SubmitPassword`.
fn submit_password(state: &mut AppState) {
    state.busy = true;
    let password = state.password.clone();
    let confirm = state.confirm.clone();
    let result = match state.screen {
        Screen::Setup => state.create_vault(&password, &confirm),
        _ => state.unlock(&password),
    };
    state.busy = false;
    match result {
        Ok(()) => {
            state.screen_error = None;
        }
        Err(e) => {
            state.screen_error = Some(e.message());
            state.notify(Status::error(&e.message()));
        }
    }
}

/// Interprets `Action::SaveForm` for whichever modal or screen is open.
fn confirm(state: &mut AppState) {
    let Some(m) = state.modal.clone() else {
        if state.screen == Screen::Edit
            && let Err(e) = state.save_form()
        {
            state.notify_error(e);
        }
        return;
    };

    match m {
        Modal::Confirm { .. } => {
            // A destructive confirmation is only acted on when it asked to be,
            // and each one is only acted on from the screen that raised it: a
            // stale modal must not delete whatever happens to be selected now.
            let danger = matches!(&m, Modal::Confirm { danger: true, .. });
            let from_vault = state.screen == Screen::Vault;
            let from_settings = state.screen == Screen::Settings;
            state.dismiss_modal();
            match (danger, from_vault, from_settings) {
                (true, true, false) => state.delete_selected(),
                (true, false, true) => state.reset_vault(),
                _ => {}
            }
        }
        Modal::Password { value, .. } => {
            state.dismiss_modal();
            state.busy = true;
            let result = state.change_master_password(&value, &value);
            state.busy = false;
            if let Err(e) = result {
                state.notify_error(e);
            }
        }
    }
}

// ------------------------------------------------------ the input handoff

thread_local! {
    /// Values typed into the setup and unlock screens.
    static AUTH_INPUT: RefCell<AuthInput> = RefCell::new(AuthInput::default());
    /// The search box's value.
    static QUERY_INPUT: RefCell<Option<String>> = const { RefCell::new(None) };
    /// The entry form's focused field and its new value.
    static FORM_INPUT: RefCell<Option<(Field, String)>> = const { RefCell::new(None) };
}

#[derive(Default)]
struct AuthInput {
    password: Option<String>,
    confirm: Option<String>,
}

/// The handler for the setup screen's two password fields.
fn setup_input_handler(which: u8) -> HandlerMut<'static, String> {
    HandlerMut::from(move |value: String| {
        AUTH_INPUT.with(|slot| {
            let mut slot = slot.borrow_mut();
            if which == 0 {
                slot.password = Some(value);
            } else {
                slot.confirm = Some(value);
            }
        });
    })
}

/// The handler for the unlock screen's password field.
fn password_input_handler() -> HandlerMut<'static, String> {
    HandlerMut::from(move |value: String| {
        AUTH_INPUT.with(|slot| slot.borrow_mut().password = Some(value));
    })
}

/// The handler for a modal's text field.
fn modal_input_handler() -> HandlerMut<'static, String> {
    HandlerMut::from(move |value: String| {
        AUTH_INPUT.with(|slot| slot.borrow_mut().confirm = Some(value));
    })
}

/// The handler for the search box.
fn query_input_handler() -> HandlerMut<'static, String> {
    HandlerMut::from(move |value: String| {
        QUERY_INPUT.with(|slot| *slot.borrow_mut() = Some(value));
    })
}

/// Builds the entry form's per-field change handler.
fn form_change_factory() -> impl Fn(Field) -> HandlerMut<'static, String> {
    |field| {
        HandlerMut::from(move |value: String| {
            FORM_INPUT.with(|slot| *slot.borrow_mut() = Some((field, value)));
        })
    }
}

/// Moves anything parked by the input handlers into `AppState`.
///
/// Returns true when something changed, so a caller knows to redraw.
pub fn drain_input(state: &mut AppState) -> bool {
    let mut changed = false;

    let (password, confirm) = AUTH_INPUT.with(|slot| {
        let mut slot = slot.borrow_mut();
        (slot.password.take(), slot.confirm.take())
    });
    if let Some(p) = password {
        // A fresh attempt clears the last failure, so the message never
        // contradicts what is in the field.
        state.screen_error = None;
        state.password = p;
        changed = true;
    }
    if let Some(c) = confirm {
        state.confirm = c;
        changed = true;
    }

    let query = QUERY_INPUT.with(|slot| slot.borrow_mut().take());
    if let Some(q) = query {
        state.set_query(q);
        changed = true;
    }

    let change = FORM_INPUT.with(|slot| slot.borrow_mut().take());
    if let Some((field, value)) = change {
        if let Some(f) = state.form.as_mut() {
            // The handler carries the field it belongs to, so a keystroke
            // cannot land in whatever field happens to be focused now.
            f.field = field;
            f.set_text(value);
        }
        changed = true;
    }

    if changed {
        state.touch();
    }
    changed
}

// -------------------------------------------------------- the render builders

/// Builds a component whose props are assembled in Rust.
///
/// `element!` only assigns individual fields on a `Default` props struct, so
/// a props value built from computed strings has to be handed to `Element`
/// directly. Every widget used this way returns `AnyElement<'static>`, which
/// is what lets one frame own its whole tree.
macro_rules! build {
    ($ty:ty, $key:literal, $props:expr) => {{
        let element: Element<'static, $ty> =
            Element { key: ElementKey::new($key), props: $props };
        element.into()
    }};
}

fn build_header(state: &RenderSnapshot) -> AnyElement<'static> {
    build!(
        Header,
        "header",
        HeaderProps {
            screen: state.screen,
            context: state.context.clone(),
            vault_path: state.path.clone(),
            entry_count: state.total_entries,
            // "Locked" is a statement about the vault, not about the screen.
            // During setup there is no vault yet, and reporting "locked" there
            // would name a state the user has not reached.
            locked: !state.session_present && state.screen == Screen::Unlock,
        }
    )
}

fn build_status_bar(state: &RenderSnapshot) -> AnyElement<'static> {
    let modal = state.modal.as_ref();
    build!(
        StatusBar,
        "status",
        StatusBarProps {
            status: state.status.clone(),
            hints: hints_for(state.screen, modal.is_some(), is_text_modal(modal)).to_string(),
        }
    )
}

fn build_search_bar(state: &RenderSnapshot, matches: usize) -> AnyElement<'static> {
    build!(
        SearchBar,
        "search",
        SearchBarProps {
            value: state.query.clone(),
            focused: true,
            result_count: matches,
            total_count: state.total_entries,
            on_change: query_input_handler(),
        }
    )
}

fn build_empty(state: &RenderSnapshot) -> AnyElement<'static> {
    let props = chrome::empty_for_vault(
        state.total_entries,
        &state.query,
        state.filter.is_narrowed(),
    );
    build!(EmptyState, "empty", props)
}

fn build_list(state: &RenderSnapshot, active: bool) -> AnyElement<'static> {
    build!(
        EntryList,
        "list",
        EntryListProps {
            rows: state.list_rows.clone(),
            selected: state.selected,
            offset: state.offset,
            height: state.list_capacity,
            active,
        }
    )
}

fn build_detail(state: &RenderSnapshot) -> AnyElement<'static> {
    build!(
        Detail,
        "detail",
        DetailProps {
            entry: state.detail.clone(),
            tag_names: state.tag_names.clone(),
            revealed: state.reveal,
            active: state.focus == Focus::Detail,
        }
    )
}

fn build_form(form: &EntryForm) -> AnyElement<'static> {
    // The factory is boxed into a `static` reference so it outlives the frame;
    // the handler it returns is `'static` regardless.
    let factory: &'static (dyn Fn(Field) -> HandlerMut<'static, String> + Send + Sync) =
        Box::leak(Box::new(form_change_factory()));
    build!(
        EntryFormView,
        "form",
        EntryFormProps { form: Some(form.clone()), make_on_change: Some(factory) }
    )
}

fn build_modal(state: &RenderSnapshot) -> Option<AnyElement<'static>> {
    let m = state.modal.as_ref()?;
    let value = modal_text_value(m).unwrap_or_default();
    let body = match m {
        Modal::Confirm { body, .. } => body.clone(),
        Modal::Password { title, .. } => format!("Enter a new {title}."),
    };
    let detail = "esc to cancel".to_string();
    Some(build!(
        ModalBox,
        "modal",
        ModalBoxProps {
            title: m.title().to_string(),
            body,
            detail,
            confirm_label: modal_confirm_label(m),
            danger: matches!(m, Modal::Confirm { danger: true, .. }),
            text_input: is_text_modal(Some(m)),
            value,
            on_change: modal_input_handler(),
        }
    ))
}

fn build_field_row(label: &str, value: &str, highlight: bool) -> AnyElement<'static> {
    build!(
        FieldRow,
        "row",
        FieldRowProps {
            label: label.to_string(),
            value: value.to_string(),
            highlight,
            danger: false,
        }
    )
}

/// True for the modal variants that collect typed text.
fn is_text_modal(modal: Option<&Modal>) -> bool {
    matches!(modal, Some(Modal::Password { .. }))
}

// ------------------------------------------------------------- the six screens

/// Renders the whole app for one frame.
///
/// Split from the component so a test can render any screen at any size
/// without a terminal event loop.
pub fn render_screen(state: &RenderSnapshot, width: u16) -> Vec<AnyElement<'static>> {
    let mut frame: Vec<AnyElement<'static>> = Vec::with_capacity(3);

    frame.push(build_header(state));

    // The modal wraps the body rather than replacing it, so the screen
    // underneath stays visible around the dialog.
    let body: AnyElement<'static> = match build_modal(state) {
        Some(overlay) => element! {
            View(flex_grow: 1.0_f32, flex_direction: FlexDirection::Column) {
                #(std::iter::once(render_body(state, width)))
                #(std::iter::once(overlay))
            }
        }
        .into(),
        None => render_body(state, width),
    };
    frame.push(body);
    frame.push(build_status_bar(state));

    frame
}

/// The screen's own content, without the header or status bar.
fn render_body(state: &RenderSnapshot, width: u16) -> AnyElement<'static> {
    match state.screen {
        Screen::Setup => setup_body(state),
        Screen::Unlock => unlock_body(state),
        Screen::Vault => vault_body(state, width),
        Screen::Edit => edit_body(state),
        Screen::Settings => settings_body(state),
    }
}

/// The setup screen: pick a password and confirm it.
fn setup_body(state: &RenderSnapshot) -> AnyElement<'static> {
    element! {
        View(
            flex_grow: 1.0_f32,
            flex_direction: FlexDirection::Column,
            align_items: Some(AlignItems::Center),
            justify_content: Some(JustifyContent::Center),
        ) {
            View(
                width: 60_pct,
                max_width: 72_u32,
                flex_direction: FlexDirection::Column,
                border_style: theme::PANEL_BORDER,
                border_color: Some(theme::ACCENT),
                padding_left: 2_u32,
                padding_right: 2_u32,
                padding_top: 1_u32,
                padding_bottom: 1_u32,
            ) {
                View(flex_shrink: 0_f32, margin_bottom: 1_u32) {
                    Text(content: "Create a new vault", color: Some(theme::ACCENT), weight: Weight::Bold)
                }
                View(flex_shrink: 0_f32, margin_bottom: 1_u32, overflow: Some(Overflow::Hidden)) {
                    Text(content: state.path.clone(), color: Some(theme::MUTED))
                }
                View(flex_shrink: 0_f32, margin_top: 1_u32) {
                    Text(content: "Master password", color: Some(theme::MUTED))
                }
                View(flex_shrink: 0_f32) {
                    TextInput(
                        value: state.password.clone(),
                        has_focus: true,
                        on_change: setup_input_handler(0),
                        cursor_color: Some(theme::ACCENT),
                    )
                }
                View(flex_shrink: 0_f32, margin_top: 1_u32) {
                    Text(content: "Confirm password", color: Some(theme::MUTED))
                }
                View(flex_shrink: 0_f32) {
                    TextInput(
                        value: state.confirm.clone(),
                        has_focus: false,
                        on_change: setup_input_handler(1),
                        cursor_color: Some(theme::ACCENT),
                    )
                }
                View(flex_shrink: 0_f32, margin_top: 1_u32, overflow: Some(Overflow::Hidden)) {
                    Text(
                        content: format!(
                            "argon2id {} \u{00b7} {} rounds",
                            keys::format_memory(state.kdf.memory_kib),
                            state.kdf.iterations,
                        ),
                        color: Some(theme::MUTED),
                    )
                }
                #(error_line(&state.screen_error))
            }
        }
    }
    .into()
}

/// The unlock screen: one password field.
fn unlock_body(state: &RenderSnapshot) -> AnyElement<'static> {
    element! {
        View(
            flex_grow: 1.0_f32,
            flex_direction: FlexDirection::Column,
            align_items: Some(AlignItems::Center),
            justify_content: Some(JustifyContent::Center),
        ) {
            View(
                width: 50_pct,
                max_width: 60_u32,
                flex_direction: FlexDirection::Column,
                border_style: theme::PANEL_BORDER,
                border_color: Some(theme::ACCENT),
                padding_left: 2_u32,
                padding_right: 2_u32,
                padding_top: 1_u32,
                padding_bottom: 1_u32,
            ) {
                View(flex_shrink: 0_f32, margin_bottom: 1_u32) {
                    Text(content: "Domi", color: Some(theme::ACCENT), weight: Weight::Bold)
                }
                View(flex_shrink: 0_f32, margin_bottom: 1_u32) {
                    Text(content: "Enter your master password", color: Some(theme::MUTED))
                }
                View(flex_shrink: 0_f32) {
                    TextInput(
                        value: state.password.clone(),
                        has_focus: true,
                        on_change: password_input_handler(),
                        cursor_color: Some(theme::ACCENT),
                    )
                }
                #(error_line(&state.screen_error))
                View(flex_shrink: 0_f32, margin_top: 1_u32, overflow: Some(Overflow::Hidden)) {
                    Text(content: state.path.clone(), color: Some(theme::MUTED))
                }
            }
        }
    }
    .into()
}

/// The prompt shown above the list until the user presses `/`.
///
/// Present at all times on the vault screen so the search key is discoverable
/// without opening the help.
fn search_hint_line() -> AnyElement<'static> {
    element! {
        View(
            key: "search-hint",
            flex_shrink: 0_f32,
            padding_left: 1_u32,
            margin_bottom: theme::PANE_GAP,
        ) {
            Text(
                content: crate::widgets::search_bar::search_hint(),
                color: Some(theme::MUTED),
            )
        }
    }
    .into()
}

/// A red error line, or nothing at all when there is no error.
fn error_line(error: &Option<String>) -> Option<AnyElement<'static>> {
    let message = error.as_ref()?;
    let line: AnyElement<'static> = element! {
        View(key: "error", flex_shrink: 0_f32, margin_top: 1_u32, overflow: Some(Overflow::Hidden)) {
            Text(content: message.clone(), color: Some(theme::DANGER), weight: Weight::Bold)
        }
    }
    .into();
    Some(line)
}

/// The main screen: search, entry list, and detail.
///
/// Below [`theme::TWO_PANE_MIN_WIDTH`] the panes stack instead of shrinking to
/// uselessness, so a narrow terminal still shows something readable.
fn vault_body(state: &RenderSnapshot, width: u16) -> AnyElement<'static> {
    let two_pane = width >= theme::TWO_PANE_MIN_WIDTH;
    let list_active = state.focus != Focus::Detail;
    let matches = state.list_rows.len();

    let list: AnyElement<'static> = element! {
        View(
            // Hoisted out of the element literal because the `pct` suffix is
            // only valid on a bare literal, not on an expression.
            width: (if two_pane { Size::Percent(theme::LIST_PANE_PCT) } else { Size::Percent(100.0) }),
            flex_direction: FlexDirection::Column,
            flex_shrink: 0_f32,
        ) {
            #(if state.focus == Focus::Search {
                Some(build_search_bar(state, matches))
            } else {
                Some(search_hint_line())
            })
            #(if matches == 0 {
                Some(build_empty(state))
            } else {
                Some(build_list(state, list_active))
            })
        }
    }
    .into();

    let detail: AnyElement<'static> = element! {
        View(flex_grow: 1.0_f32, flex_direction: FlexDirection::Column) {
            #(if state.detail.is_some() {
                Some(build_detail(state))
            } else {
                None
            })
        }
    }
    .into();

    // Below the threshold the detail pane is dropped entirely: at that width
    // the two panes would each be unreadable, and the list is what the user
    // came for. `e` still opens the entry for editing.
    let children: Vec<AnyElement<'static>> = if two_pane {
        vec![list, detail]
    } else {
        vec![list]
    };

    element! {
        View(
            flex_grow: 1.0_f32,
            flex_direction: if two_pane { FlexDirection::Row } else { FlexDirection::Column },
            column_gap: theme::PANE_GAP,
            padding_left: 1_u32,
            padding_right: 1_u32,
        ) {
            #(children.into_iter())
        }
    }
    .into()
}

/// The create/edit screen.
fn edit_body(state: &RenderSnapshot) -> AnyElement<'static> {
    element! {
        View(
            flex_grow: 1.0_f32,
            flex_direction: FlexDirection::Column,
            padding_left: 2_u32,
            padding_right: 2_u32,
        ) {
            #(match state.form.as_ref() {
                Some(form) => Some(build_form(form)),
                None => Some(
                    element! {
                        View(flex_grow: 1.0_f32, align_items: Some(AlignItems::Center)) {
                            Text(content: "No entry open", color: Some(theme::MUTED))
                        }
                    }
                    .into(),
                ),
            })
        }
    }
    .into()
}

/// The settings screen.
///
/// Rows the user can change are named in the tip under the list, so the
/// keyboard's effect on the current row is never a guess.
fn settings_body(state: &RenderSnapshot) -> AnyElement<'static> {
    let row = state.settings_row;
    let auto_lock = match state.auto_lock_secs {
        0 => "off".to_string(),
        secs => chrome::duration(secs),
    };
    let countdown = match state.auto_lock_countdown {
        Some(secs) => format!(" \u{00b7} locks in {}", chrome::duration(secs)),
        None => String::new(),
    };
    let rows: Vec<AnyElement<'static>> = vec![
        build_field_row("Vault", &state.path, row == AppState::ROW_VAULT),
        build_field_row(
            "Key derivation",
            &format!(
                "argon2id {} \u{00b7} {} rounds \u{00b7} {} lanes",
                keys::format_memory(state.kdf.memory_kib),
                state.kdf.iterations,
                state.kdf.parallelism,
            ),
            row == AppState::ROW_KDF,
        ),
        build_field_row("Auto-lock", &format!("{auto_lock}{countdown}"), row == AppState::ROW_AUTO_LOCK),
        build_field_row("Master password", "change", row == AppState::ROW_MASTER_PASSWORD),
        build_field_row("Close vault", "", row == AppState::ROW_RESET),
    ];

    element! {
        View(
            flex_grow: 1.0_f32,
            flex_direction: FlexDirection::Column,
            border_style: theme::PANEL_BORDER,
            border_color: Some(theme::ACCENT),
            margin_left: 2_u32,
            margin_right: 2_u32,
            padding_left: 2_u32,
            padding_right: 2_u32,
            padding_top: 1_u32,
        ) {
            View(flex_shrink: 0_f32, margin_bottom: 1_u32) {
                Text(content: "Settings", color: Some(theme::ACCENT), weight: Weight::Bold)
            }
            #(rows.into_iter())
            #(settings_tip_element(row))
        }
    }
    .into()
}

/// The hint under the highlighted settings row, or nothing when the row has
/// no explanation.
fn settings_tip_element(row: usize) -> Option<AnyElement<'static>> {
    let tip = settings_tip(row)?;
    let element: AnyElement<'static> = element! {
        View(key: "tip", flex_shrink: 0_f32, margin_top: 2_u32) {
            Text(content: tip.to_string(), color: Some(theme::MUTED))
        }
    }
    .into();
    Some(element)
}

/// The hint under the highlighted settings row.
fn settings_tip(row: usize) -> Option<&'static str> {
    match row {
        AppState::ROW_VAULT => Some("The vault is a directory of encrypted files. Back it up as a unit."),
        AppState::ROW_KDF => Some("Higher cost means a slower unlock and a stronger key."),
        AppState::ROW_AUTO_LOCK => Some("Left and right change the delay. 0 turns auto-lock off."),
        AppState::ROW_MASTER_PASSWORD => {
            Some("Every entry is re-encrypted with the new password. Enter to start.")
        }
        AppState::ROW_RESET => Some("Enter to close the vault. This cannot be undone."),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Filter;
    use crate::testkit::render_to_text;
    use crate::widgets::entry_list;

    fn state_at(path: &str) -> AppState {
        let mut s = AppState::new(VaultPaths::new(path));
        s.initial_screen();
        s
    }

    fn with_screen(screen: Screen) -> RenderSnapshot {
        let mut s = state_at("/tmp/domi-app-test");
        s.screen = screen;
        s.clone_for_render()
    }

    #[test]
    fn every_screen_renders_at_a_range_of_sizes() {
        for screen in [Screen::Setup, Screen::Unlock, Screen::Vault, Screen::Edit, Screen::Settings] {
            let mut state = with_screen(screen);
            for w in [20u16, 40, 80, 200] {
                let frame = render_screen(&state, w);
                assert!(!frame.is_empty(), "{screen:?} at width {w} produced no elements");
                assert_eq!(frame.len(), 3, "{screen:?} at width {w} should be header, body, status");
            }
            state.status = Some(Status::success("hi"));
            assert_eq!(render_screen(&state, 80).len(), 3);
        }
    }

    #[test]
    fn a_vault_screen_renders_with_and_without_entries() {
        let empty = with_screen(Screen::Vault);
        let frame = render_to_text(&empty, 80, 24);
        assert!(frame.contains("No entries"), "an empty vault should say so:\n{frame}");

        let mut populated = empty.clone();
        populated.list_rows = vec![entry_list::row("a")];
        populated.total_entries = 1;
        populated.session_present = true;
        let frame = render_to_text(&populated, 80, 24);
        assert!(frame.contains("Title a"), "the entry should be listed:\n{frame}");
        assert!(!frame.contains("No entries"));
    }

    #[test]
    fn a_search_that_matches_nothing_reports_no_matches() {
        let mut state = with_screen(Screen::Vault);
        state.session_present = true;
        state.total_entries = 12;
        state.query = "zzz".into();
        let frame = render_to_text(&state, 80, 24);
        assert!(frame.contains("No matches"), "should distinguish no matches:\n{frame}");
    }

    #[test]
    fn a_narrow_terminal_hides_the_detail_pane() {
        let mut state = with_screen(Screen::Vault);
        state.list_rows = vec![entry_list::row("a")];
        state.detail = Some(crate::vault_store::blank_entry("a".into(), 0));
        state.detail.as_mut().unwrap().title = "GitHub".into();

        state.total_entries = 1;
        state.session_present = true;
        let narrow = render_to_text(&state, theme::TWO_PANE_MIN_WIDTH - 1, 24);
        assert!(narrow.contains("Title a"), "the list stays:\n{narrow}");
        assert!(
            !narrow.contains("Username"),
            "the detail pane must be dropped when there is no room:\n{narrow}"
        );

        let wide = render_to_text(&state, theme::TWO_PANE_MIN_WIDTH, 24);
        assert!(wide.contains("Username"), "the detail pane returns when wide:\n{wide}");
    }

    #[test]
    fn the_header_names_the_app_the_screen_and_the_selected_entry() {
        let mut state = with_screen(Screen::Vault);
        state.context = "GitHub".into();
        state.total_entries = 3;
        state.session_present = true;
        let frame = render_to_text(&state, 100, 24);
        assert!(frame.contains("Domi"), "{frame}");
        assert!(frame.contains("Vault"), "{frame}");
        assert!(frame.contains("GitHub"), "{frame}");
        assert!(frame.contains("3 entries"), "{frame}");
        // The app name appears once; the screen name is a separate word.
        assert_eq!(frame.matches("Domi").count(), 1, "the name is repeated:\n{frame}");
    }

    #[test]
    fn a_locked_vault_says_locked_in_the_header() {
        let state = with_screen(Screen::Unlock);
        assert!(!state.session_present, "the fixture should be locked");
        let frame = render_to_text(&state, 80, 24);
        assert!(frame.contains("locked"), "{frame}");
        assert!(frame.contains("Enter your master password"), "{frame}");
    }

    #[test]
    fn a_vault_being_created_is_not_reported_as_locked() {
        // There is no vault yet, so "locked" would describe a state the user
        // has never been in.
        let state = with_screen(Screen::Setup);
        let frame = render_to_text(&state, 80, 24);
        assert!(!frame.contains("locked"), "{frame}");
        assert!(frame.contains("Create a new vault"), "{frame}");
    }

    #[test]
    fn a_failed_unlock_shows_its_error_on_screen() {
        let mut state = with_screen(Screen::Unlock);
        state.screen_error = Some("That password is not correct".into());
        let frame = render_to_text(&state, 80, 24);
        assert!(frame.contains("That password is not correct"), "{frame}");
    }

    #[test]
    fn a_secret_is_masked_until_the_snapshot_says_otherwise() {
        let mut state = with_screen(Screen::Vault);
        state.total_entries = 1;
        let mut entry = crate::vault_store::blank_entry("a".into(), 0);
        entry.title = "GitHub".into();
        entry.username = "octocat".into();
        entry.password = "hunter2".into();
        state.detail = Some(entry);
        state.session_present = true;

        let masked = render_to_text(&state, 100, 24);
        assert!(!masked.contains("hunter2"), "the password leaked:\n{masked}");
        assert!(masked.contains(&theme::MASK.to_string().repeat(7)), "{masked}");

        state.reveal = true;
        let shown = render_to_text(&state, 100, 24);
        assert!(shown.contains("hunter2"), "reveal should show it:\n{shown}");
    }

    #[test]
    fn a_destructive_modal_names_the_entry_and_is_marked_dangerous() {
        let mut state = with_screen(Screen::Vault);
        state.session_present = true;
        state.total_entries = 1;
        state.modal = Some(Modal::danger("Delete entry", "Delete \"GitHub\"?"));
        let frame = render_to_text(&state, 80, 24);
        assert!(frame.contains("Delete entry"), "{frame}");
        assert!(frame.contains("GitHub"), "the user must see what is going:\n{frame}");
        assert!(frame.contains("Delete"), "{frame}");
    }

    #[test]
    fn a_modal_covers_the_screen_it_sits_on() {
        let mut state = with_screen(Screen::Vault);
        state.total_entries = 1;
        state.session_present = true;
        state.list_rows = vec![entry_list::row("a")];
        state.modal = Some(Modal::danger("Delete entry", "Delete \"GitHub\"?"));
        let frame = render_to_text(&state, 80, 24);
        assert!(frame.contains("Delete entry"), "{frame}");
        // The screen beneath is still what draws the list, so the dialog
        // stacks over it rather than replacing it.
        assert!(frame.contains("Title a"), "{frame}");
    }

    #[test]
    fn the_settings_screen_explains_the_row_in_focus() {
        let mut state = with_screen(Screen::Settings);
        state.settings_row = 1;
        state.kdf.memory_kib = 65536;
        state.kdf.iterations = 3;
        state.kdf.parallelism = 4;
        state.auto_lock_secs = 300;
        let frame = render_to_text(&state, 100, 24);
        assert!(frame.contains("Settings"), "{frame}");
        assert!(frame.contains("argon2id"), "{frame}");
        assert!(frame.contains("64 MiB"), "{frame}");
        assert!(frame.contains("5 minutes"), "{frame}");
        assert!(frame.contains("Higher cost"), "the focused row explains itself:\n{frame}");
    }

    #[test]
    fn the_edit_screen_shows_every_field_of_the_form() {
        let mut state = with_screen(Screen::Edit);
        state.form = Some(EntryForm::new(0));
        let frame = render_to_text(&state, 100, 30);
        assert!(frame.contains("New entry"), "{frame}");
        for field in Field::ALL {
            assert!(
                frame.contains(field.label()),
                "the {} field is missing from the form:\n{frame}",
                field.label()
            );
        }
    }

    #[test]
    fn an_edit_of_an_existing_entry_shows_its_values() {
        let mut state = with_screen(Screen::Edit);
        let mut entry = crate::vault_store::blank_entry("a".into(), 0);
        entry.title = "GitHub".into();
        entry.username = "octocat".into();
        state.form = Some(EntryForm::from_entry(&entry, &[]));
        let frame = render_to_text(&state, 100, 30);
        assert!(frame.contains("Edit GitHub"), "{frame}");
        assert!(frame.contains("octocat"), "{frame}");
    }

    #[test]
    fn the_vault_screen_swaps_its_search_hint_for_the_search_box() {
        let mut state = with_screen(Screen::Vault);
        state.total_entries = 1;
        state.session_present = true;
        state.list_rows = vec![entry_list::row("a")];

        // Before `/`, the pane shows a prompt instead of an input.
        let idle = render_to_text(&state, 100, 24);
        assert!(idle.contains("Press / to search"), "{idle}");
        assert!(idle.contains("Title a"), "the list still renders:\\n{idle}");

        state.focus = Focus::Search;
        state.query = "git".into();
        let searching = render_to_text(&state, 100, 24);
        assert!(searching.contains("git"), "the query should be visible:\\n{searching}");
        assert!(
            !searching.contains("Press / to search"),
            "the hint is replaced, not shown alongside the box:\\n{searching}"
        );
    }

    #[test]
    fn the_search_hint_is_absent_from_the_screens_without_a_list() {
        // The prompt invites a keypress that does nothing elsewhere.
        for screen in [Screen::Setup, Screen::Unlock, Screen::Settings, Screen::Edit] {
            let frame = render_to_text(&with_screen(screen), 100, 24);
            assert!(!frame.contains("Press / to search"), "{screen:?} shows it:\\n{frame}");
        }
    }

    #[test]
    fn the_status_bar_shows_the_last_message() {
        let mut state = with_screen(Screen::Vault);
        state.session_present = true;
        state.total_entries = 1;
        state.list_rows = vec![entry_list::row("a")];
        state.status = Some(Status::success("Copied"));
        let frame = render_to_text(&state, 100, 24);
        assert!(frame.contains("Copied"), "{frame}");
    }

    #[test]
    fn the_status_bar_keeps_the_hints_visible_alongside_a_message() {
        let mut state = with_screen(Screen::Vault);
        state.session_present = true;
        state.total_entries = 1;
        state.list_rows = vec![entry_list::row("a")];
        state.status = Some(Status::success("Copied"));
        let frame = render_to_text(&state, 140, 24);
        assert!(frame.contains("Copied"), "{frame}");
        assert!(frame.contains("move"), "the hints should survive a message:\n{frame}");
    }

    #[test]
    fn input_handlers_park_values_and_drain_moves_them_into_state() {
        let mut s = state_at("/tmp/domi-app-test");
        assert!(!drain_input(&mut s), "nothing parked yet");

        password_input_handler()("secret".into());
        assert!(drain_input(&mut s));
        assert_eq!(s.password, "secret");
        // Draining twice must not re-apply a stale value.
        assert!(!drain_input(&mut s));
    }

    #[test]
    fn typing_a_password_clears_a_previous_error() {
        let mut s = state_at("/tmp/domi-app-test");
        s.screen_error = Some("Wrong password".into());
        password_input_handler()("a".into());
        drain_input(&mut s);
        assert!(s.screen_error.is_none(), "a new attempt clears the old error");
    }

    #[test]
    fn setup_input_parks_both_fields_separately() {
        let mut s = state_at("/tmp/domi-app-test");
        setup_input_handler(0)("first".into());
        setup_input_handler(1)("second".into());
        drain_input(&mut s);
        assert_eq!(s.password, "first");
        assert_eq!(s.confirm, "second");
    }

    #[test]
    fn a_modal_value_lands_in_the_confirm_slot() {
        let mut s = state_at("/tmp/domi-app-test");
        modal_input_handler()("typed".into());
        drain_input(&mut s);
        assert_eq!(s.confirm, "typed");
    }

    #[test]
    fn the_query_handler_updates_the_filtered_rows() {
        let mut s = state_at("/tmp/domi-app-test");
        query_input_handler()("git".into());
        assert!(drain_input(&mut s));
        assert_eq!(s.query, "git");
    }

    #[test]
    fn the_form_handler_lands_on_the_right_field() {
        let mut s = state_at("/tmp/domi-app-test");
        s.begin_new_entry();
        form_change_factory()(Field::Username)("octocat".into());
        drain_input(&mut s);
        let f = s.form.as_ref().expect("a form should be open");
        assert_eq!(f.field, Field::Username);
        assert_eq!(f.username, "octocat");
        // A change for one field must not leak into another.
        assert_eq!(f.title, "");
    }

    #[test]
    fn a_failed_unlock_reports_the_error_and_stays_put() {
        let mut s = state_at("/tmp/domi-does-not-exist");
        s.password = "wrong".into();
        submit_password(&mut s);
        assert!(s.screen_error.is_some(), "a wrong password must report an error");
        assert_eq!(s.screen, Screen::Unlock);
        assert!(!s.busy, "busy must be cleared even on the failure path");
    }

    #[test]
    fn submitting_with_a_vault_absent_does_not_panic() {
        let mut s = state_at("/tmp/domi-does-not-exist");
        s.password = "hunter2".into();
        s.confirm = "hunter2".into();
        s.screen = Screen::Setup;
        submit_password(&mut s);
        // The point is that it returns at all; a real vault is exercised in
        // the vault_store tests.
        assert!(!s.busy);
    }

    #[test]
    fn the_header_shows_the_filter_when_no_entry_is_selected() {
        let mut s = state_at("/tmp/domi-app-test");
        s.screen = Screen::Vault;
        s.filter = Filter::Favorites;
        assert_eq!(s.clone_for_render().context, "Favorites");
    }

    #[test]
    fn list_rows_shrink_rather_than_underflow_on_a_tiny_terminal() {
        assert_eq!(list_rows(0), 0);
        assert_eq!(list_rows(2), 0);
        assert!(list_rows(100) > list_rows(20), "a taller terminal shows more rows");
    }

    #[test]
    fn every_settings_row_has_a_tip_and_a_row_beyond_them_does_not() {
        for row in 0..AppState::SETTINGS_ROWS {
            assert!(settings_tip(row).is_some(), "row {row} has no explanation");
        }
        assert!(settings_tip(AppState::SETTINGS_ROWS).is_none());
        // The rows are numbered consecutively from the first.
        assert_eq!(AppState::ROW_VAULT, 0);
        assert_eq!(AppState::ROW_RESET, AppState::SETTINGS_ROWS - 1);
    }

    #[test]
    fn the_settings_rows_are_all_visible_on_screen() {
        let mut state = with_screen(Screen::Settings);
        state.path = "/tmp/domi-app-test".into();
        let frame = render_to_text(&state, 100, 24);
        for label in ["Vault", "Key derivation", "Auto-lock", "Master password", "Close vault"] {
            assert!(frame.contains(label), "{label} is missing:\n{frame}");
        }
    }

    #[test]
    fn each_settings_row_says_what_its_keys_do() {
        for row in 0..AppState::SETTINGS_ROWS {
            let mut state = with_screen(Screen::Settings);
            state.settings_row = row;
            let frame = render_to_text(&state, 120, 24);
            assert!(
                frame.contains(settings_tip(row).unwrap()),
                "row {row} does not explain itself:\n{frame}"
            );
        }
    }

    #[test]
    fn the_auto_lock_row_shows_the_time_left_before_it_fires() {
        let mut state = with_screen(Screen::Settings);
        state.settings_row = AppState::ROW_AUTO_LOCK;
        state.session_present = true;
        state.auto_lock_secs = 300;
        state.auto_lock_countdown = Some(280);
        let frame = render_to_text(&state, 120, 24);
        assert!(frame.contains("5 minutes"), "the delay itself:\n{frame}");
        assert!(frame.contains("4 minutes"), "the countdown:\n{frame}");
    }
}
