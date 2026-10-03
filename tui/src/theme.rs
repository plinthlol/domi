//! Visual constants.
//!
//! One place for every colour, border, and spacing decision, so the TUI reads
//! as one design system instead of a pile of ad-hoc choices.
//!
//! Palette discipline: cyan is the only accent, grey is structure, red appears
//! *only* on destructive actions. Nothing else gets a colour, which is what
//! keeps a dense two-pane screen readable.

use iocraft::prelude::*;

/// Accent for the focused element and the current selection.
pub const ACCENT: Color = Color::Cyan;

/// Panel borders and dividers.
pub const BORDER: Color = Color::Grey;

/// Destructive actions only (delete, discard).
pub const DANGER: Color = Color::Red;

/// Muted text: placeholders, hints, timestamps.
pub const MUTED: Color = Color::Grey;

/// Positive confirmation (saved, copied).
pub const SUCCESS: Color = Color::Green;

/// Panel outline.
pub const PANEL_BORDER: BorderStyle = BorderStyle::Round;


/// The outer app frame.
pub const APP_BORDER: BorderStyle = BorderStyle::Single;

/// Standard interior padding.
pub const PAD: u32 = 1;

/// Gap between the two panes.
pub const PANE_GAP: u32 = 1;

/// Below this width the two-pane layout gets too cramped, so the UI stacks into
/// one pane instead of shrinking both to uselessness.
pub const TWO_PANE_MIN_WIDTH: u16 = 80;

/// Left pane width when side-by-side, as a percentage of the terminal.
pub const LIST_PANE_PCT: f32 = 34.0;

/// Width of the tab stop in the help line.
pub const HELP_COL: Color = MUTED;

/// The masked character for hidden secrets.
pub const MASK: char = '•';

/// Strength meter colour for a 0–100 score.
pub fn strength_color(score: u8) -> Color {
    match score {
        0..=29 => Color::Red,
        30..=59 => Color::Yellow,
        60..=79 => Color::Cyan,
        _ => Color::Green,
    }
}

/// A short word for a strength score, for the meter label.
pub fn strength_label(score: u8) -> &'static str {
    match score {
        0..=29 => "weak",
        30..=59 => "fair",
        60..=79 => "good",
        _ => "strong",
    }
}

/// Renders a secret as fixed-width dots, so its length doesn't leak its
/// content but the field still looks filled in.
pub fn mask(secret: &str) -> String {
    MASK.to_string().repeat(secret.chars().count())
}

/// Formats a Unix timestamp as a short local-agnostic string.
///
/// Deliberately avoids a date crate: the TUI only needs a rough relative age
/// ("3d ago"), which is computable from the current time with no formatting
/// machinery.
pub fn relative_time(unix_secs: i64) -> String {
    let now = domi_core::now_unix();
    let delta = now - unix_secs;
    if delta < 60 {
        "just now".to_string()
    } else if delta < 3600 {
        format!("{}m ago", delta / 60)
    } else if delta < 86_400 {
        format!("{}h ago", delta / 3600)
    } else if delta < 30 * 86_400 {
        format!("{}d ago", delta / 86_400)
    } else {
        format!("{}mo ago", delta / (30 * 86_400))
    }
}

/// Truncates to `max` display columns, appending an ellipsis when cut.
///
/// Used everywhere a user-supplied string meets a fixed-width panel, so a long
/// title can't smear into the neighbouring pane.
pub fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    if max <= 1 {
        return "…".to_string();
    }
    let kept: String = text.chars().take(max - 1).collect();
    format!("{kept}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_length_matches_secret_length() {
        assert_eq!(mask("abc"), "•••");
        assert_eq!(mask(""), "");
        for secret in ["a longer pass phrase", "p@ss w0rd!", "🔐emoji secret🔐"] {
            assert_eq!(mask(secret).chars().count(), secret.chars().count());
        }
    }

    #[test]
    fn mask_does_not_leak_content() {
        let m = mask("hunter2");
        assert!(!m.contains('h'));
        assert!(!m.contains('7'));
    }

    #[test]
    fn truncate_leaves_short_values_alone() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("exactly-10", 10), "exactly-10");
    }

    #[test]
    fn truncate_cuts_and_marks_with_ellipsis() {
        assert_eq!(truncate("abcdefghij", 5), "abcd…");
        assert_eq!(truncate("abcdefghij", 5).chars().count(), 5);
    }

    #[test]
    fn truncate_handles_degenerate_widths() {
        assert_eq!(truncate("abc", 1), "…");
        assert_eq!(truncate("abc", 0), "…");
    }

    #[test]
    fn truncate_counts_characters_not_bytes() {
        // Multi-byte characters must not be split mid-sequence.
        let out = truncate("héllo wörld", 5);
        assert_eq!(out, "héll…");
    }

    #[test]
    fn strength_labels_and_colors_cover_every_score() {
        for score in [0u8, 1, 29, 30, 59, 60, 79, 80, 100] {
            let _ = strength_color(score);
            assert!(!strength_label(score).is_empty());
        }
        // Weak should read as danger, strong as success.
        assert_eq!(strength_color(10), Color::Red);
        assert_eq!(strength_color(95), Color::Green);
    }

    #[test]
    fn relative_time_is_recent_for_now() {
        let now = domi_core::now_unix();
        assert_eq!(relative_time(now), "just now");
        assert_eq!(relative_time(now - 120), "2m ago");
        assert_eq!(relative_time(now - 7200), "2h ago");
        assert_eq!(relative_time(now - 172_800), "2d ago");
    }

    #[test]
    fn relative_time_tolerates_future_timestamps() {
        // Clock skew or a bad import shouldn't produce nonsense like "-3m ago".
        let now = domi_core::now_unix();
        let out = relative_time(now + 500);
        assert_eq!(out, "just now");
    }
}