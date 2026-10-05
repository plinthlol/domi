//! Drawing: [`AppState`] in, terminal frame out.
//!
//! Every screen is a pure function of state, so a given buffer always renders
//! the same way and a test can assert on cell contents without a terminal. The
//! render entry point is [`draw`]; the `screen_*` functions below it each own
//! one screen.
//!
//! Layout is plain `Rect` arithmetic rather than a constraint solver. The app
//! has a handful of fixed shapes, so a solver would add a dependency and a
//! layer of indirection to compute four numbers.

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, Gauge, List, ListItem, Paragraph, Scrollbar,
    ScrollbarOrientation, ScrollbarState, Wrap,
};
use ratatui::Frame;

use crate::state::{
    AppState, EntryForm, Field, Focus, Modal, Screen, StatusKind, ROW_AUTO_LOCK, ROW_KDF,
    ROW_MASTER_PASSWORD, ROW_RESET, ROW_VAULT, SETTINGS_ROWS, settings_window,
};
use crate::theme;

/// Draws whichever screen is active, then any modal over it.
pub fn draw(frame: &mut Frame, state: &AppState) {
    let area = frame.area();
    match state.screen {
        Screen::Setup => screen_setup(frame, state, area),
        Screen::Unlock => screen_unlock(frame, state, area),
        Screen::Vault => screen_vault(frame, state, area),
        Screen::Edit => screen_edit(frame, state, area),
        Screen::Settings => screen_settings(frame, state, area),
    }

    // A modal sits on top of a `Clear` block so the screen behind it does not
    // show through the dialog's transparent centre.
    if let Some(modal) = &state.modal {
        draw_modal(frame, state, modal, area);
    }
}

/// A bordered box whose border tint says whether it has focus.
fn panel(title: &str, focused: bool) -> Block<'static> {
    let style = if focused { theme::BORDER_FOCUS } else { theme::BORDER_IDLE };
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(style)
        .title(Span::styled(
            format!(" {title} "),
            if focused { theme::title() } else { theme::muted() },
        ))
}

// ------------------------------------------------------------------ setup ---

/// First run: choose a master password.
fn screen_setup(frame: &mut Frame, state: &AppState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .split(area);

    frame.render_widget(
        Paragraph::new("No vault exists yet.\nCreate one by choosing a master password.")
            .style(theme::body())
            .alignment(Alignment::Center)
            .block(panel("Set up vault", true)),
        chunks[0],
    );

    let confirm_focused = state.setup_field == 1;
    draw_password_field(
        frame,
        chunks[1],
        "Master password",
        &state.password,
        !confirm_focused,
    );
    draw_password_field(frame, chunks[2], "Confirm", &state.confirm, confirm_focused);

    frame.render_widget(
        Paragraph::new(error_line(state)).style(theme::danger()),
        chunks[3],
    );
    frame.render_widget(Paragraph::new(crate::keys::hint(state)).style(theme::muted()), chunks[4]);
}

/// One password line, rendered as dots unless it is the focused field.
///
/// The focused field reveals nothing: a shoulder-surfer's read of a six-line
/// box should not find a plaintext master password on screen.
fn draw_password_field(
    frame: &mut Frame,
    area: Rect,
    label: &str,
    value: &str,
    focused: bool,
) {
    let dots = "*".repeat(value.chars().count());
    let caret = if focused { "_" } else { "" };
    let style = if focused { theme::focused_field() } else { theme::body() };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(format!("{label:<16} "), theme::muted()),
            Span::styled(dots, style),
            Span::styled(caret, theme::focused_field()),
        ])),
        area,
    );
}

// ----------------------------------------------------------------- unlock ---

fn screen_unlock(frame: &mut Frame, state: &AppState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(1), Constraint::Length(1), Constraint::Min(0)])
        .split(area);

    let name = state
        .paths
        .root()
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "vault".to_string());

    frame.render_widget(
        Paragraph::new(format!("Vault: {}", state.paths.root().display()))
            .style(theme::body())
            .alignment(Alignment::Center)
            .block(panel("Unlock", true)),
        chunks[0],
    );
    let _ = name;

    draw_password_field(frame, chunks[1], "Master password", &state.password, true);
    frame.render_widget(
        Paragraph::new(error_line(state)).style(theme::danger()),
        chunks[2],
    );
    frame.render_widget(Paragraph::new(crate::keys::hint(state)).style(theme::muted()), chunks[3]);
}

fn error_line(state: &AppState) -> String {
    state
        .screen_error
        .as_deref()
        .map(|e| format!("! {e}"))
        .unwrap_or_default()
}

// ------------------------------------------------------------------ vault ---

fn screen_vault(frame: &mut Frame, state: &AppState, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(3), Constraint::Length(1)])
        .split(area);

    draw_search_bar(frame, state, rows[0]);

    // A horizontal split, list on the left, detail on the right. The list keeps
    // a floor so the detail pane stays readable on a narrow terminal.
    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(rows[1]);

    draw_entry_list(frame, state, panes[0]);
    draw_detail(frame, state, panes[1]);
    draw_footer(frame, state, rows[2]);
}

fn draw_search_bar(frame: &mut Frame, state: &AppState, area: Rect) {
    let searching = !state.query.is_empty();

    let mut spans = vec![
        Span::styled(
            state.screen.label().to_uppercase(),
            theme::title(),
        ),
        Span::raw("  "),
        Span::styled("/", theme::muted()),
        Span::styled(state.query.clone(), theme::focused_field()),
    ];
    if searching {
        spans.push(Span::styled("_", theme::accent()));
    }
    spans.push(Span::raw("   "));
    spans.push(Span::styled(
        format!("[{}]", state.filter.label()),
        if state.filter == crate::state::Filter::Favorites {
            theme::accent()
        } else {
            theme::muted()
        },
    ));
    spans.push(Span::styled(
        format!("   {} of {}", state.filtered_count(), state.total_entry_count()),
        theme::muted(),
    ));

    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_entry_list(frame: &mut Frame, state: &AppState, area: Rect) {
    let focused = state.focus == Focus::List;
    let inner_width = area.width.saturating_sub(2).max(1) as usize;
    // The number of rows the pane can actually show. Deriving it from the
    // drawn rect rather than from a cached value is what keeps the list honest
    // across a terminal resize, which is the only thing that changes it.
    let capacity = area.height.saturating_sub(2).max(1) as usize;

    // An empty list still needs a row of its own, or the list widget draws
    // nothing at all and the pane looks broken.
    if state.rows.is_empty() {
        let message = if state.query.is_empty() {
            "No entries yet. Press n to add one."
        } else {
            "Nothing matches this search."
        };
        frame.render_widget(
            Paragraph::new(message)
                .style(theme::muted())
                .block(panel("Entries", focused)),
            area,
        );
        return;
    }

    // The window is derived here rather than read off the state, because only
    // the drawn height says how many rows fit.
    let offset = state.offset.min(state.rows.len().saturating_sub(capacity));

    let items: Vec<ListItem> = (offset..(offset + capacity).min(state.rows.len()))
        .map(|i| {
            let (title, username, favorite) = state.row_label(i);
            let selected = i == state.selected;
            let marker = if favorite { "* " } else { "  " };
            let base = if selected { theme::selected() } else { theme::row() };
            let title_style = if selected {
                base
            } else if favorite {
                base.fg(theme::ACCENT)
            } else {
                base
            };
            ListItem::new(Line::from(vec![
                Span::styled(marker.to_string(), theme::ACCENT),
                Span::styled(truncate(&title, inner_width.saturating_sub(2)), title_style),
                Span::styled(
                    format!("  {}", truncate(&username, inner_width / 3)),
                    if selected { base } else { theme::muted() },
                ),
            ]))
        })
        .collect();

    let title = format!("Entries ({})", state.filtered_count());
    let list = List::new(items)
        .block(panel(&title, focused))
        .highlight_style(theme::selected())
        .highlight_symbol("");
    frame.render_widget(list, area);

    // The scrollbar eats a column, so it only appears once the list is long
    // enough that losing one column is worth the position indicator.
    if let Some((scrollbar, scrollbar_state)) = list_scrollbar(state, capacity) {
        frame.render_stateful_widget(
            scrollbar,
            Rect { width: 1, ..area },
            &mut { scrollbar_state },
        );
    }
}

fn draw_detail(frame: &mut Frame, state: &AppState, area: Rect) {
    let focused = state.focus == Focus::Detail;
    let Some(entry) = state.detail() else {
        frame.render_widget(
            Paragraph::new("Select an entry to see its details.")
                .style(theme::muted())
                .block(panel("Details", focused)),
            area,
        );
        return;
    };

    let mask = |value: &str| -> String {
        if value.is_empty() {
            return "-".to_string();
        }
        if state.reveal {
            value.to_string()
        } else {
            "*".repeat(value.chars().count())
        }
    };

    let lines = vec![
        Line::from(vec![
            Span::styled("Title    ", theme::muted()),
            Span::styled(entry.title.clone(), theme::body()),
        ]),
        Line::from(vec![
            Span::styled("Username ", theme::muted()),
            Span::styled(pick(&entry.username, "-"), theme::body()),
        ]),
        Line::from(vec![
            Span::styled("Password ", theme::muted()),
            Span::styled(
                mask(&entry.password),
                if state.reveal { theme::secret() } else { theme::body() },
            ),
        ]),
        Line::from(vec![
            Span::styled("URL      ", theme::muted()),
            Span::styled(pick(&entry.url, "-"), theme::body()),
        ]),
        Line::from(vec![
            Span::styled("TOTP     ", theme::muted()),
            Span::styled(
                entry.totp_secret.as_deref().map(pick_none).unwrap_or_else(|| "-".into()),
                theme::body(),
            ),
        ]),
        Line::from(vec![
            Span::styled("Category ", theme::muted()),
            Span::raw(format!("{:?}", entry.category)),
        ]),
        Line::from(vec![
            Span::styled("Tags     ", theme::muted()),
            Span::styled(pick(&state.tag_names_for(entry).join(", "), "-"), theme::body()),
        ]),
        Line::from(vec![
            Span::styled("Favorite ", theme::muted()),
            Span::styled(if entry.favorite { "yes" } else { "no" }, theme::body()),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            if entry.notes.is_empty() { "No notes".to_string() } else { entry.notes.clone() },
            theme::body(),
        )),
    ];

    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(panel("Details", focused)),
        area,
    );
}

fn pick(value: &str, fallback: &str) -> String {
    if value.is_empty() { fallback.to_string() } else { value.to_string() }
}

fn pick_none(value: &str) -> String {
    pick(value, "-")
}

fn draw_footer(frame: &mut Frame, state: &AppState, area: Rect) {
    // The countdown only appears when auto-lock is actually armed, so an
    // "off" setting never implies a timer the user does not have.
    let countdown = match state.auto_lock_countdown() {
        Some(secs) if state.screen == Screen::Vault => Span::styled(
            format!("  locks in {}s", secs),
            if secs <= 30 { theme::danger() } else { theme::muted() },
        ),
        _ => Span::raw(""),
    };

    frame.render_widget(
        Paragraph::new(Line::from(vec![status_span(state), countdown])),
        area,
    );
}

/// The status message, or the key hint when there is nothing to report.
fn status_span(state: &AppState) -> Span<'static> {
    match &state.status {
        Some(s) => {
            let style = match s.kind {
                StatusKind::Success => theme::success(),
                StatusKind::Error => theme::danger(),
                StatusKind::Info => theme::muted(),
            };
            Span::styled(s.text.clone(), style)
        }
        None => Span::styled(crate::keys::hint(state), theme::muted()),
    }
}

/// The status line on its own, for screens with no countdown beside it.
fn draw_status(state: &AppState) -> Paragraph<'static> {
    Paragraph::new(Line::from(status_span(state)))
}

// ------------------------------------------------------------------- edit ---

fn screen_edit(frame: &mut Frame, state: &AppState, area: Rect) {
    let Some(form) = state.form.as_ref() else {
        frame.render_widget(Paragraph::new("No entry is being edited."), area);
        return;
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(5),
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Min(0),
        ])
        .split(area);

    let title = if form.is_edit() { "Edit entry" } else { "New entry" };

    // Nine fields at two lines each will not fit in a short terminal, so the
    // form scrolls to keep the focused field on screen rather than letting it
    // fall off the bottom.
    let block = panel(title, true);
    let body_height = chunks[0].height.saturating_sub(2).max(1) as usize;
    let lines_per_field = 2;
    let visible_fields = (body_height / lines_per_field).max(1);
    let focused_index = Field::ALL
        .iter()
        .position(|f| *f == form.focused)
        .unwrap_or(0);
    let first_field = focused_index.saturating_sub(visible_fields - 1);

    let mut lines: Vec<Line> = Vec::new();
    for field in Field::ALL.iter().skip(first_field).take(visible_fields) {
        lines.extend(form_row(form, *field));
    }
    frame.render_widget(Paragraph::new(lines).block(block), chunks[0]);

    // A gauge reads faster than a number for "how strong is this".
    let strength = domi_core::password::check_strength(&form.password);
    frame.render_widget(
        Gauge::default()
            .block(panel("Strength", false))
            .gauge_style(strength_style(strength))
            .ratio(f64::from(strength) / 100.0)
            .label(format!("{strength}/100")),
        chunks[1],
    );

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Generator  ", theme::muted()),
            Span::styled(
                format!(
                    "len {}  upper {}  lower {}  digits {}  symbols {}",
                    form.generator.length,
                    on(form.generator.uppercase),
                    on(form.generator.lowercase),
                    on(form.generator.numbers),
                    on(form.generator.symbols)
                ),
                theme::body(),
            ),
        ])),
        chunks[2],
    );
    frame.render_widget(Paragraph::new(crate::keys::hint(state)).style(theme::muted()), chunks[3]);
}

fn on(v: bool) -> &'static str {
    if v { "on" } else { "off" }
}

fn strength_style(strength: u8) -> Style {
    let colour = match strength {
        0..=33 => theme::DANGER,
        34..=66 => theme::ACCENT,
        _ => theme::SUCCESS,
    };
    Style::default().fg(colour).add_modifier(Modifier::BOLD)
}

/// The two lines one form field occupies: the value, and a caret when focused.
fn form_row(form: &EntryForm, field: Field) -> Vec<Line<'static>> {
    let focused = form.focused == field;
    let mut value = form.text(field).to_string();
    let shown = if field == Field::Password && form.reveal {
        value.clone()
    } else {
        mask_value(field, &value)
    };
    value.clear();

    let mut spans = vec![
        Span::styled(format!("{:<10}", field.label()), theme::muted()),
        Span::styled(shown.clone(), if focused { theme::focused_field() } else { theme::body() }),
    ];
    if focused {
        spans.push(Span::styled("_", theme::accent()));
    }
    if field == Field::Favorite {
        spans = vec![
            Span::styled(format!("{:<10}", field.label()), theme::muted()),
            Span::styled(
                if form.favorite { "[x] yes" } else { "[ ] no" },
                if focused { theme::focused_field() } else { theme::body() },
            ),
        ];
    }
    vec![Line::from(spans), Line::raw("")]
}

/// Hides a secret field's characters while keeping its length visible.
fn mask_value(field: Field, value: &str) -> String {
    match field {
        Field::Password | Field::Totp => {
            if value.is_empty() { String::new() } else { "*".repeat(value.chars().count()) }
        }
        _ => value.to_string(),
    }
}

// --------------------------------------------------------------- settings ---

fn screen_settings(frame: &mut Frame, state: &AppState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            // The list is five rows of two lines each, plus two border rows.
            // Asking for exactly that keeps the last row on screen at the sizes
            // a real terminal gets, instead of Min(5) losing the space to the
            // rows underneath and clipping reset off the bottom.
            Constraint::Length((SETTINGS_ROWS as u16) * 2 + 2),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .split(area);

    let rows = vec![
        settings_row(state, ROW_VAULT, "Vault directory", state.paths.root().display().to_string()),
        settings_row(
            state,
            ROW_KDF,
            "Key derivation",
            format!(
                "{} KiB, {} rounds, p={}",
                state.kdf.memory_kib, state.kdf.iterations, state.kdf.parallelism
            ),
        ),
        settings_row(
            state,
            ROW_AUTO_LOCK,
            "Auto-lock",
            crate::state::auto_lock_label(state.auto_lock_secs),
        ),
        settings_row(state, ROW_MASTER_PASSWORD, "Master password", "press d to change"),
        settings_row(state, ROW_RESET, "Reset vault", "press x to erase everything"),
    ];

    // Each row takes two lines: the label and the blank one after it. On a
    // short terminal the list cannot fit, so the window follows the cursor the
    // same way the entry list does.
    let capacity = (chunks[0].height.saturating_sub(2) / 2) as usize;
    let offset = settings_window(state.settings_row, capacity);
    let visible: Vec<Line> = rows.into_iter().skip(offset).take(capacity).flatten().collect();

    frame.render_widget(
        Paragraph::new(visible).block(panel("Settings", true)),
        chunks[0],
    );

    frame.render_widget(
        Paragraph::new(format!("  {}", state.config_file.display())).style(theme::muted()),
        chunks[1],
    );

    // Settings changes report themselves here. Without this line a rejected
    // master-password change would close its dialog and leave no trace of why.
    frame.render_widget(draw_status(state), chunks[2]);
    frame.render_widget(Paragraph::new(crate::keys::hint(state)).style(theme::muted()), chunks[3]);
}

fn settings_row(state: &AppState, row: usize, label: &str, value: impl Into<String>) -> Vec<Line<'static>> {
    let value = value.into();
    let selected = state.settings_row == row;
    let marker = if selected { "> " } else { "  " };
    let style = if selected { theme::selected() } else { theme::body() };
    vec![
        Line::from(vec![
            Span::styled(marker, style),
            Span::styled(format!("{label:<18}"), style),
            Span::styled(value, if selected { style } else { theme::muted() }),
        ]),
        Line::raw(""),
    ]
}

// ------------------------------------------------------------------ modal ---

fn draw_modal(frame: &mut Frame, state: &AppState, modal: &Modal, area: Rect) {
    // Centred. The height follows the content rather than being a fixed
    // constant, so a longer confirmation body is never clipped mid-sentence.
    let width = (area.width * 3 / 5).clamp(24, area.width.saturating_sub(2));
    let body_lines = match modal {
        // The wrap width is the popup's inner width, and each body line may
        // occupy more than one row, so this counts wrapped rows.
        Modal::Confirm { body, .. } => {
            let inner = width.saturating_sub(2).max(1) as usize;
            body.split('\n')
                .map(|l| l.chars().count().div_ceil(inner).max(1))
                .sum::<usize>()
        }
        // Two password fields.
        Modal::Password { .. } => 2,
        Modal::Text { .. } => 1,
    };
    // Two border rows, a blank between body and hint, and the hint itself.
    let height = (body_lines + 4) as u16;
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height: height.min(area.height),
    };

    frame.render_widget(Clear, popup);

    let body = match modal {
        Modal::Confirm { body, .. } => {
            // Split on newlines rather than handing the whole string to one
            // Line, which would draw the breaks as literal spaces.
            let style = if modal.is_danger() { theme::danger() } else { theme::body() };
            Paragraph::new(
                body.split('\n')
                    .map(|l| Line::from(Span::styled(l.to_string(), style)))
                    .collect::<Vec<Line>>(),
            )
            .wrap(Wrap { trim: false })
        }
        Modal::Password { value, confirm, confirm_active, .. } => {
            let dots = |v: &str| "*".repeat(v.chars().count());
            Paragraph::new(vec![
                Line::from(vec![
                    Span::styled("password  ", theme::muted()),
                    Span::styled(dots(value), theme::focused_field()),
                    Span::styled(if *confirm_active { "" } else { "_" }, theme::accent()),
                ]),
                Line::from(vec![
                    Span::styled("confirm   ", theme::muted()),
                    Span::styled(dots(confirm), theme::focused_field()),
                    Span::styled(if *confirm_active { "_" } else { "" }, theme::accent()),
                ]),
            ])
        }
        Modal::Text { value, .. } => Paragraph::new(Line::from(vec![
            Span::styled(value.clone(), theme::focused_field()),
            Span::styled("_", theme::accent()),
        ]))
        .wrap(Wrap { trim: false }),
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(if modal.is_danger() { theme::danger() } else { theme::BORDER_FOCUS })
        .title(Span::styled(
            format!(" {} ", modal.title()),
            if modal.is_danger() { theme::danger() } else { theme::title() },
        ))
        .title_alignment(Alignment::Center);

    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    // The bottom line carries the key hints, unless submitting just raised an
    // error -- then the error takes the line, so a rejected password stays
    // visible without the dialog closing over it.
    let hint = match modal {
        Modal::Confirm { yes_label, .. } => format!("y {yes_label}   n cancel   esc cancel"),
        _ => "enter save   esc cancel".to_string(),
    };
    let bottom = Rect { y: inner.y + inner.height.saturating_sub(1), height: 1, ..inner };
    let (text, style) = match state.status.as_ref().filter(|s| s.kind == StatusKind::Error) {
        Some(s) => (s.text.clone(), theme::danger()),
        None => (hint, theme::muted()),
    };
    frame.render_widget(Paragraph::new(text).style(style), bottom);

    // The body takes whatever is left above the hint line.
    frame.render_widget(body, Rect { height: inner.height.saturating_sub(1), ..inner });
}


// ----------------------------------------------------------------- helpers ---

/// Cuts `value` to `width` columns, marking the cut with an ellipsis.
///
/// Truncating by char count rather than by display width is close enough for
/// the Latin text this app holds and cannot split a multi-byte character.
fn truncate(value: &str, width: usize) -> String {
    let count = value.chars().count();
    if count <= width {
        return value.to_string();
    }
    if width <= 1 {
        return "…".to_string();
    }
    let kept: String = value.chars().take(width - 1).collect();
    format!("{kept}…")
}

/// A scrollbar for the entry list, shown only when the list overflows.
///
/// Drawn beside the list rather than inside it so the title and the rows keep
/// their full width. The position and length live on the state object, not the
/// widget, which is why the caller builds both.
fn list_scrollbar(
    state: &AppState,
    capacity: usize,
) -> Option<(Scrollbar<'static>, ScrollbarState)> {
    if state.rows.len() <= capacity {
        return None;
    }
    let scrollbar_state = ScrollbarState::new(state.rows.len()).position(state.offset);
    let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
        .begin_symbol(None)
        .end_symbol(None);
    Some((scrollbar, scrollbar_state))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_title_is_cut_with_an_ellipsis() {
        assert_eq!(truncate("abcdef", 10), "abcdef");
        assert_eq!(truncate("abcdef", 4), "abc…");
        assert_eq!(truncate("abcdef", 1), "…");
    }

    #[test]
    fn truncating_never_splits_a_character() {
        // A cut in the middle of a multi-byte char would panic on slicing.
        let out = truncate("héllo wörld", 5);
        assert!(out.chars().count() <= 5);
        assert!(out.ends_with('…'));
    }
}