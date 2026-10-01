//! The search box at the top of the list pane.
//!
//! Deliberately a plain `TextInput` rather than a custom widget: the only
//! thing that makes it a search field is the surrounding chrome and the
//! placeholder, both of which the caller supplies.

use iocraft::prelude::*;

use crate::theme;

/// The search field with a live result count.
///
/// The value is owned rather than borrowed so a caller can build this in Rust
/// and return a `static` element; see `crate::app::build_search_bar`.
#[derive(Default, Props)]
pub struct SearchBarProps {
    pub value: String,
    /// The input owns the keyboard.
    pub focused: bool,
    /// How many entries the current query matches.
    pub result_count: usize,
    /// Total entries, so the count can read "3 of 20".
    pub total_count: usize,
    pub on_change: HandlerMut<'static, String>,
}

/// "12 results" or "12 of 20".
fn count_label(matches: usize, total: usize) -> String {
    if matches == total {
        format!("{total}")
    } else {
        format!("{matches} of {total}")
    }
}

#[component]
pub fn SearchBar(props: &mut SearchBarProps) -> impl Into<AnyElement<'static>> {
    let value = props.value.clone();
    let focused = props.focused;
    let has_value = !value.is_empty();
    let on_change = props.on_change.take();
    let count = count_label(props.result_count, props.total_count);
    let (border_color, _) = crate::widgets::chrome::focus_ring(focused);

    element! {
        View(
            flex_shrink: 0_f32,
            flex_direction: FlexDirection::Column,
            border_style: BorderStyle::Single,
            border_color: Some(border_color),
            margin_bottom: theme::PANE_GAP,
        ) {
            View(
                flex_direction: FlexDirection::Row,
                flex_shrink: 0_f32,
                column_gap: 1_u32,
                padding_left: 1_u32,
                padding_right: 1_u32,
            ) {
                View(flex_shrink: 0_f32) {
                    Text(content: "/", color: Some(if focused { theme::ACCENT } else { theme::MUTED }))
                }
                View(flex_grow: 1.0_f32) {
                    TextInput(
                        value: value.clone(),
                        has_focus: focused,
                        on_change: on_change,
                        cursor_color: Some(theme::ACCENT),
                    )
                }
                #(if has_value {
                    Some(element! {
                        View(flex_shrink: 0_f32) {
                            Text(content: count, color: Some(theme::MUTED))
                        }
                    })
                } else {
                    None
                })
            }
        }
    }
}

/// The "no search active" prompt shown before the user presses `/`.
pub fn search_hint() -> &'static str {
    "Press / to search"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unfiltered_count_shows_the_total() {
        assert_eq!(count_label(20, 20), "20");
    }

    #[test]
    fn a_filtered_count_reads_as_a_fraction() {
        assert_eq!(count_label(3, 20), "3 of 20");
    }

    #[test]
    fn an_empty_vault_reports_zero() {
        assert_eq!(count_label(0, 0), "0");
    }

    #[test]
    fn search_hint_is_a_real_hint() {
        assert!(search_hint().contains('/'));
    }
}
