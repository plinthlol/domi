//! The app's colours, in one place.
//!
//! Kept apart from the widgets that use them so a theme change is one edit and
//! so the palette can be checked for contrast without rendering anything.
//!
//! Colours are plain constants rather than a themed trait because the app
//! ships one theme. The trade is deliberate: indirection would cost a
//! parameter on every widget draw to support a second palette nobody asked
//! for, and the constants keep each draw site readable.

use ratatui::style::{Color, Modifier, Style};

/// The accent: titles, the focused pane's border, selection.
pub const ACCENT: Color = Color::Cyan;

/// Ordinary borders.
pub const PANEL_BORDER: Color = Color::DarkGray;

/// De-emphasised text: hints, placeholders, counts.
pub const MUTED: Color = Color::DarkGray;

/// Destructive actions and errors.
pub const DANGER: Color = Color::Red;

/// Confirmations and other good news.
pub const SUCCESS: Color = Color::Green;

/// A secret that is currently revealed.
pub const SECRET: Color = Color::Yellow;

/// Body text.
pub const TEXT: Color = Color::Gray;

/// The focused row's background, kept dark so text stays readable.
pub const SELECTION_BG: Color = Color::Rgb(30, 50, 60);

/// Text on top of [`SELECTION_BG`].
pub const SELECTION_FG: Color = Color::White;

/// A pane border that has focus.
pub const BORDER_FOCUS: Style = Style::new().fg(ACCENT);

/// A pane border without focus.
pub const BORDER_IDLE: Style = Style::new().fg(PANEL_BORDER);

/// The selected row.
pub fn selected() -> Style {
    Style::default().bg(SELECTION_BG).fg(SELECTION_FG).add_modifier(Modifier::BOLD)
}

/// A row the mouse or keyboard is not on.
pub fn row() -> Style {
    Style::default().fg(TEXT)
}

/// A screen title.
pub fn title() -> Style {
    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
}

/// Ordinary body text.
pub fn body() -> Style {
    Style::default().fg(TEXT)
}

/// A hint or other secondary text.
pub fn muted() -> Style {
    Style::default().fg(MUTED)
}

/// A destructive action.
pub fn danger() -> Style {
    Style::default().fg(DANGER).add_modifier(Modifier::BOLD)
}

/// A successful action.
pub fn success() -> Style {
    Style::default().fg(SUCCESS)
}

/// A revealed secret.
pub fn secret() -> Style {
    Style::default().fg(SECRET)
}

/// A field the user is typing in.
pub fn focused_field() -> Style {
    Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
}

/// The text caret shown in whichever field is taking input.
pub fn accent() -> Style {
    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The relative luminance of a colour, per WCAG.
    fn luminance(c: Color) -> f64 {
        let (r, g, b) = match c {
            Color::Rgb(r, g, b) => (r as f64, g as f64, b as f64),
            // The named colours are the 16 ANSI values on a 0-255 scale.
            Color::Black => (0.0, 0.0, 0.0),
            Color::Red => (205.0, 0.0, 0.0),
            Color::Green => (0.0, 205.0, 0.0),
            Color::Yellow => (205.0, 205.0, 0.0),
            Color::Blue => (0.0, 0.0, 238.0),
            Color::Magenta => (205.0, 0.0, 205.0),
            Color::Cyan => (0.0, 205.0, 205.0),
            Color::Gray => (229.0, 229.0, 229.0),
            Color::DarkGray => (127.0, 127.0, 127.0),
            Color::LightRed => (255.0, 0.0, 0.0),
            Color::LightGreen => (0.0, 255.0, 0.0),
            Color::LightYellow => (255.0, 255.0, 0.0),
            Color::LightBlue => (0.0, 0.0, 255.0),
            Color::LightMagenta => (255.0, 0.0, 255.0),
            Color::LightCyan => (0.0, 255.0, 255.0),
            Color::White => (255.0, 255.0, 255.0),
            _ => (127.0, 127.0, 127.0),
        };
        let f = |v: f64| {
            let v = v / 255.0;
            if v <= 0.03928 { v / 12.92 } else { ((v + 0.055) / 1.055).powf(2.4) }
        };
        0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)
    }

    /// The WCAG contrast ratio between two colours, from 1.0 to 21.0.
    fn contrast(a: Color, b: Color) -> f64 {
        let (hi, lo) = {
            let (x, y) = (luminance(a), luminance(b));
            if x > y { (x, y) } else { (y, x) }
        };
        (hi + 0.05) / (lo + 0.05)
    }

    #[test]
    fn body_text_is_readable_against_the_selection_background() {
        // The selected row is the one place two colours meet, and it is the
        // row a user reads most, so this pair has to clear AA.
        let ratio = contrast(SELECTION_FG, SELECTION_BG);
        assert!(ratio >= 4.5, "selection contrast is only {ratio:.2}:1");
    }

    #[test]
    fn every_foreground_is_readable_on_black() {
        // The app never sets a light background, so black is the worst case.
        for (name, colour) in [
            ("text", TEXT),
            ("muted", MUTED),
            ("accent", ACCENT),
            ("secret", SECRET),
            ("danger", DANGER),
            ("success", SUCCESS),
        ] {
            let ratio = contrast(colour, Color::Black);
            assert!(ratio >= 3.0, "{name} on black is only {ratio:.2}:1");
        }
    }

    #[test]
    fn muted_text_is_dimmer_than_body_text() {
        // Muted is used for hints, so it must read as secondary rather than
        // competing with the content.
        assert!(luminance(MUTED) < luminance(TEXT), "hints should be dimmer");
    }

    #[test]
    fn the_border_styles_are_distinguishable_from_each_other() {
        assert_eq!(BORDER_FOCUS.fg, Some(ACCENT));
        assert_eq!(BORDER_IDLE.fg, Some(PANEL_BORDER));
        assert_ne!(BORDER_FOCUS.fg, BORDER_IDLE.fg, "focus must be visible");
    }
}