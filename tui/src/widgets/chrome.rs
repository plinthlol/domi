//! Reusable frame pieces: the outer shell, header, status bar, help line,
//! and the empty states.
//!
//! Every screen in the app is the same outer frame with a different body, so
//! that frame lives here once. Two rules hold throughout:
//!
//! - A secret is never rendered unless the user has explicitly revealed it.
//!   Reveals are per-session and reset on lock.
//! - The status line is the only place a transient message appears, so the
//!   body never has to render an alert that pushes the layout around.
//!
//! Note on layout: iocraft's `Text` takes no flexbox props, only styling. Any
//! `Text` that needs to grow, shrink, or clip is wrapped in a `View` that
//! carries those props, which is why so many of these rows are a `View` around
//! a single `Text`.

use iocraft::prelude::*;

use crate::state::{Screen, Status, StatusKind};
use crate::theme;

/// How a component signals that it currently owns the keyboard.
pub fn focus_ring(active: bool) -> (Color, BorderStyle) {
    if active {
        (theme::ACCENT, theme::PANEL_BORDER)
    } else {
        (theme::BORDER, theme::PANEL_BORDER)
    }
}

/// The app's top bar: app name, current screen, selected entry, vault path.
#[derive(Default, Props)]
pub struct HeaderProps {
    pub screen: Screen,
    /// The selected entry's title, or empty on screens without a selection.
    pub context: String,
    pub vault_path: String,
    pub entry_count: usize,
    pub locked: bool,
}

#[component]
pub fn Header(props: &mut HeaderProps) -> impl Into<AnyElement<'static>> {
    let screen_title = props.screen.title();
    let context = props.context.clone();
    let path = theme::truncate(&props.vault_path, 40);
    let count_label = if props.locked {
        "locked".to_string()
    } else {
        format!("{} entries", props.entry_count)
    };

    let mut left: Vec<Element<'static, Text>> = Vec::new();
    left.push(element! {
        Text(content: "Fuin", color: Some(theme::ACCENT), weight: Weight::Bold)
    });
    left.push(element! {
        Text(content: screen_title, color: Some(theme::BORDER))
    });
    if !context.is_empty() {
        left.push(element! {
            Text(
                content: format!("\u{203a} {context}"),
                color: Some(theme::ACCENT),
                weight: Weight::Bold,
            )
        });
    }

    element! {
        View(
            flex_direction: FlexDirection::Row,
            flex_shrink: 0_f32,
            justify_content: Some(JustifyContent::SpaceBetween),
            padding_left: 1_u32,
            padding_right: 1_u32,
        ) {
            View(
                flex_direction: FlexDirection::Row,
                flex_grow: 1.0_f32,
                column_gap: 2_u32,
                overflow: Some(Overflow::Hidden),
            ) {
                #(left.into_iter())
            }
            View(
                flex_direction: FlexDirection::Row,
                column_gap: 2_u32,
                flex_shrink: 0_f32,
            ) {
                Text(key: "count", content: count_label, color: Some(theme::MUTED))
                Text(key: "path", content: path, color: Some(theme::MUTED))
            }
        }
    }
}

/// How the status line renders, derived from the last message.
fn status_style(status: &Option<Status>) -> (Option<Color>, Weight) {
    match status.as_ref().map(|s| s.kind) {
        Some(StatusKind::Success) => (Some(theme::SUCCESS), Weight::Bold),
        Some(StatusKind::Error) => (Some(theme::DANGER), Weight::Bold),
        _ => (Some(theme::MUTED), Weight::Normal),
    }
}

/// The bottom bar: the transient message beside the key hints.
///
/// Both live on one row so a long status message pushes the hints off-screen
/// rather than wrapping into a second row of unpredictable height.
#[derive(Default, Props)]
pub struct StatusBarProps {
    pub status: Option<Status>,
    /// Pre-rendered hint text for the current screen, e.g. "n new  / search".
    pub hints: String,
}

#[component]
pub fn StatusBar(props: &mut StatusBarProps) -> impl Into<AnyElement<'static>> {
    let (color, weight) = status_style(&props.status);
    let text = props.status.as_ref().map(|s| s.text.clone()).unwrap_or_default();
    let hints = props.hints.clone();

    element! {
        View(
            flex_direction: FlexDirection::Row,
            flex_shrink: 0_f32,
            justify_content: Some(JustifyContent::SpaceBetween),
            column_gap: 2_u32,
            padding_left: 1_u32,
            padding_right: 1_u32,
        ) {
            View(flex_grow: 1.0_f32, overflow: Some(Overflow::Hidden)) {
                Text(content: text, color: color, weight: weight)
            }
            View(flex_shrink: 0_f32) {
                Text(content: hints, color: Some(theme::HELP_COL))
            }
        }
    }
}

/// The centred "nothing here" state.
///
/// The fields are owned rather than borrowed so callers can build the copy
/// from computed strings without leaking memory to get a `&'static str`.
#[derive(Default, Props)]
pub struct EmptyStateProps {
    /// A short noun for the thing that's missing: "entries", "matches".
    pub noun: String,
    /// The action that would fix it, e.g. "Press n to add one".
    pub hint: String,
    /// An icon or glyph shown above the text.
    pub glyph: String,
}

#[component]
pub fn EmptyState(props: &mut EmptyStateProps) -> impl Into<AnyElement<'static>> {
    let noun = props.noun.clone();
    let hint = props.hint.clone();
    let glyph = props.glyph.clone();

    let mut body: Vec<AnyElement<'static>> = vec![element! {
        View(flex_shrink: 0_f32) {
            Text(content: glyph, color: Some(theme::BORDER))
        }
    }.into()];
    body.push(element! {
        View(flex_shrink: 0_f32) {
            Text(content: format!("No {noun}"), color: Some(theme::MUTED))
        }
    }
    .into());
    if !hint.is_empty() {
        body.push(element! {
            View(flex_shrink: 0_f32) {
                Text(content: hint, color: Some(theme::MUTED))
            }
        }
        .into());
    }

    element! {
        View(
            flex_grow: 1.0_f32,
            flex_direction: FlexDirection::Column,
            align_items: Some(AlignItems::Center),
            justify_content: Some(JustifyContent::Center),
            padding_left: 2_u32,
            padding_right: 2_u32,
            min_height: 7_u32,
        ) {
            #(body.into_iter())
        }
    }
}

/// Chooses the empty-state copy from whether the list is empty because the
/// vault is empty or because a filter excluded everything.
///
/// Pure so the list widget and its tests agree on the wording.
pub fn empty_state_for(
    entry_total: usize,
    query: &str,
    filter_narrowed: bool,
) -> (&'static str, &'static str, &'static str) {
    if entry_total == 0 {
        ("\u{25c7}", "entries", "Press n to add your first entry")
    } else if !query.trim().is_empty() || filter_narrowed {
        ("\u{25c7}", "matches", "Try a different search")
    } else {
        ("\u{25c7}", "entries", "Press n to add one")
    }
}

/// Builds the empty state for the current filter, kept beside the hint table
/// so both are one edit when the wording changes.
pub fn empty_for_vault(entry_total: usize, query: &str, narrowed: bool) -> EmptyStateProps {
    let (glyph, noun, hint) = empty_state_for(entry_total, query, narrowed);
    EmptyStateProps { noun: noun.to_string(), hint: hint.to_string(), glyph: glyph.to_string() }
}

/// A labelled key/value line, the building block of the detail pane.
#[derive(Default, Props)]
pub struct FieldRowProps {
    /// Owned so the row can be built from a temporary and rendered for as long
    /// as the frame needs, with no borrow of the underlying entry.
    pub label: String,
    pub value: String,
    /// Draw the value in the accent colour, for the focused row.
    pub highlight: bool,
    /// Draw the value in red.
    pub danger: bool,
}

#[component]
pub fn FieldRow(props: &mut FieldRowProps) -> impl Into<AnyElement<'static>> {
    let label = props.label.clone();
    let value = props.value.clone();
    let color = if props.danger {
        theme::DANGER
    } else if props.highlight {
        theme::ACCENT
    } else {
        Color::Reset
    };
    let weight = if props.highlight { Weight::Bold } else { Weight::Normal };

    element! {
        View(flex_direction: FlexDirection::Row, flex_shrink: 0_f32, column_gap: 1_u32) {
            View(flex_shrink: 0_f32) {
                Text(content: format!("{label:<16}"), color: Some(theme::MUTED))
            }
            View(flex_grow: 1.0_f32, overflow: Some(Overflow::Hidden)) {
                Text(content: value, color: Some(color), weight: weight)
            }
        }
    }
}

/// A horizontal strength meter: a filled and an empty bar plus a word.
///
/// Rendered as text rather than a widget so it survives any terminal width.
#[derive(Default, Props)]
pub struct StrengthMeterProps {
    pub score: u8,
}

#[component]
pub fn StrengthMeter(props: &mut StrengthMeterProps) -> impl Into<AnyElement<'static>> {
    let score = props.score;
    let color = theme::strength_color(score);
    let label = theme::strength_label(score);
    // Four cells is enough to read at a glance without dominating the row.
    let filled = ((score as usize * 4) / 100).min(4);
    let bar = "\u{2588}".repeat(filled) + &"\u{2591}".repeat(4 - filled);

    element! {
        View(flex_direction: FlexDirection::Row, flex_shrink: 0_f32, column_gap: 1_u32) {
            Text(content: bar, color: Some(color))
            Text(content: label, color: Some(color))
            Text(content: format!("{score}"), color: Some(theme::MUTED))
        }
    }
}

/// Renders either a secret or its mask, depending on the reveal flag.
///
/// The single place that decides whether a secret reaches the screen.
pub fn secret_display(secret: &str, revealed: bool) -> String {
    if revealed {
        secret.to_string()
    } else {
        theme::mask(secret)
    }
}

/// Formats a duration in the largest unit that stays exact, e.g. "90 seconds"
/// or "5 minutes".
///
/// Exactness matters here because the value round-trips: the user reads it,
/// changes it with the arrow keys, and it has to mean what it said.
pub fn duration(secs: u64) -> String {
    const MINUTE: u64 = 60;
    const HOUR: u64 = MINUTE * 60;
    match secs {
        s if s < MINUTE => plural(s, "second"),
        s if s < HOUR => plural(s / MINUTE, "minute"),
        s if s % HOUR == 0 => plural(s / HOUR, "hour"),
        s => plural(s / MINUTE, "minute"),
    }
}

fn plural(n: u64, unit: &str) -> String {
    if n == 1 {
        format!("{n} {unit}")
    } else {
        format!("{n} {unit}s")
    }
}

/// The key hints for a screen, as a single line.
pub fn hints_for(screen: Screen, has_modal: bool, modal_is_text: bool) -> &'static str {
    if has_modal {
        return if modal_is_text {
            "enter accept   esc cancel"
        } else {
            "y/enter confirm   esc cancel"
        };
    }
    match screen {
        Screen::Setup => "enter create   tab field   esc quit",
        Screen::Unlock => "enter unlock   esc quit",
        Screen::Vault => {
            "\u{2191}\u{2193} move   n new   e edit   d delete   f favorite   c copy   / search   s settings   q lock"
        }
        Screen::Edit => "tab next field   ctrl+s save   g generate   esc cancel",
        Screen::Settings => "\u{2191}\u{2193} change   enter apply   esc back   q lock",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_is_masked_until_revealed() {
        assert_eq!(secret_display("hunter2", false), "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}");
        assert_eq!(secret_display("hunter2", true), "hunter2");
        assert_eq!(secret_display("", true), "");
    }

    #[test]
    fn masking_never_leaks_the_secret() {
        let shown = secret_display("correct horse battery staple", false);
        assert!(!shown.contains("horse"));
        assert!(shown.chars().all(|c| c == theme::MASK));
    }

    #[test]
    fn empty_state_distinguishes_empty_vault_from_no_matches() {
        let (_, noun, hint) = empty_state_for(0, "", false);
        assert_eq!(noun, "entries");
        assert!(hint.contains("first entry"), "should invite creating one: {hint}");

        let (_, noun, hint) = empty_state_for(12, "zzz", false);
        assert_eq!(noun, "matches");
        assert!(hint.contains("search"), "should suggest adjusting search: {hint}");

        let (_, noun, _) = empty_state_for(12, "", true);
        assert_eq!(noun, "matches", "a narrowed filter also reads as no matches");
    }

    #[test]
    fn empty_state_ignores_a_whitespace_only_query() {
        let (_, noun, _) = empty_state_for(5, "   ", false);
        assert_eq!(noun, "entries", "a blank search is not a search");
    }

    #[test]
    fn empty_for_vault_owns_its_strings() {
        let props = empty_for_vault(0, "", false);
        assert!(!props.noun.is_empty());
        assert!(!props.hint.is_empty());
        assert!(!props.glyph.is_empty());
    }

    #[test]
    fn empty_state_hints_cover_every_screen() {
        for screen in
            [Screen::Setup, Screen::Unlock, Screen::Vault, Screen::Edit, Screen::Settings]
        {
            let hints = hints_for(screen, false, false);
            assert!(!hints.is_empty());
            assert!(!hints.contains('\n'), "hints must stay on one line: {hints}");
        }
    }

    #[test]
    fn modal_hints_take_priority_over_screen_hints() {
        assert!(hints_for(Screen::Vault, true, false).contains("confirm"));
        assert!(hints_for(Screen::Vault, true, true).contains("accept"));
    }

    #[test]
    fn status_style_colours_by_kind() {
        let (color, weight) = status_style(&Some(Status::error("bad")));
        assert_eq!(color, Some(theme::DANGER));
        assert_eq!(weight, Weight::Bold);

        let (color, _) = status_style(&Some(Status::success("ok")));
        assert_eq!(color, Some(theme::SUCCESS));

        // No message at all still needs a colour, so the line doesn't reset.
        let (color, weight) = status_style(&None);
        assert_eq!(color, Some(theme::MUTED));
        assert_eq!(weight, Weight::Normal);
    }

    #[test]
    fn focus_ring_marks_the_active_pane() {
        assert_eq!(focus_ring(true).0, theme::ACCENT);
        assert_eq!(focus_ring(false).0, theme::BORDER);
        assert_eq!(focus_ring(true).1, focus_ring(false).1);
    }



    #[test]
    fn durations_pick_a_readable_unit() {
        assert_eq!(duration(0), "0 seconds");
        assert_eq!(duration(1), "1 second");
        assert_eq!(duration(45), "45 seconds");
        assert_eq!(duration(60), "1 minute");
        assert_eq!(duration(300), "5 minutes");
        assert_eq!(duration(3600), "1 hour");
    }

    #[test]
    fn every_duration_the_settings_screen_offers_reads_back_cleanly() {
        // The user reads this value and changes it with the arrow keys, so
        // every reachable delay has to render as a whole number of one unit,
        // never as a fraction of it.
        for (secs, expected) in [
            (0u64, "0 seconds"),
            (30, "30 seconds"),
            (60, "1 minute"),
            (120, "2 minutes"),
            (300, "5 minutes"),
            (1800, "30 minutes"),
            (3600, "1 hour"),
        ] {
            assert_eq!(duration(secs), expected, "{secs}s rendered wrong");
        }
    }

    #[test]
    fn hours_are_used_only_when_the_minutes_divide_exactly() {
        // 90 minutes is 1.5 hours; rounding it would misreport the delay.
        assert_eq!(duration(5400), "90 minutes");
        assert_eq!(duration(3600), "1 hour");
        assert_eq!(duration(10800), "3 hours");
    }
}
