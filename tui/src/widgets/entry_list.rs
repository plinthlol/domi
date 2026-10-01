//! The scrollable entry list.
//!
//! Rows are two lines each (title, then username/url) so a title is readable
//! without widening the pane, which matters because the detail pane needs the
//! room more. The selected row is marked with a left bar in the accent colour
//! rather than a background wash, because a background fill on one row of a
//! dense list is the fastest way to make a TUI look dated.

use iocraft::prelude::*;

use crate::theme;

/// One row's worth of display data, prepared by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListRow {
    pub id: String,
    pub title: String,
    /// Secondary line: the username, or the URL when there's no username.
    pub subtitle: String,
    pub favorite: bool,
    /// True when this entry has a TOTP secret, shown as a trailing marker.
    pub has_totp: bool,
}

/// Rows per entry, including the focus bar. Fixed so the caller can compute
/// a scroll window without measuring rendered output.
pub const ROW_HEIGHT: usize = 2;

/// Rows the list's own border and padding consume, subtracted by the caller
/// when working out how much of the terminal height is left for rows.
pub const BORDER_ROWS: usize = 2;

/// The visible slice of a row list, computed by [`visible_window`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Window {
    /// Index of the first row shown.
    pub start: usize,
    /// The rows to draw, already sliced to the visible count.
    pub rows: Vec<ListRow>,
    /// True when rows exist above the window.
    pub has_above: bool,
    /// True when rows exist below the window.
    pub has_below: bool,
}

/// Slices `rows` to a window of `height` rows that contains `selected`.
///
/// Pure so the scroll arithmetic is testable without a terminal, which matters
/// because getting it wrong is the classic off-by-one in a list widget.
pub fn visible_window(
    rows: &[ListRow],
    selected: usize,
    offset: usize,
    height: usize,
) -> Window {
    if rows.is_empty() || height == 0 {
        return Window { start: 0, rows: Vec::new(), has_above: false, has_below: false };
    }

    let capacity = height / ROW_HEIGHT;
    if capacity == 0 {
        // Not even one row fits; show nothing rather than a clipped mess.
        return Window { start: 0, rows: Vec::new(), has_above: false, has_below: true };
    }

    // Keep the selected row inside the window.
    let mut start = offset;
    if selected < start {
        start = selected;
    }
    if selected >= start + capacity {
        start = selected + 1 - capacity;
    }
    let max_start = rows.len().saturating_sub(capacity);
    start = start.min(max_start);

    let end = (start + capacity).min(rows.len());
    Window {
        start,
        rows: rows[start..end].to_vec(),
        has_above: start > 0,
        has_below: end < rows.len(),
    }
}

/// The character shown in the focus bar column.
const BAR: char = '\u{2588}';
/// Placeholder where the bar would be on unselected rows.
const BAR_GAP: char = ' ';

/// The single-line body of the list pane, without the border.
///
/// The rows are owned rather than borrowed so a caller can build this
/// component in Rust and hand back a `static` element; see
/// `crate::app::build_list`.
#[derive(Default, Props)]
pub struct EntryListProps {
    pub rows: Vec<ListRow>,
    pub selected: usize,
    pub offset: usize,
    /// Rows the caller intends this pane to show, used only to decide how many
    /// entries fit in the window.
    ///
    /// Zero means "as many as fit". iocraft's layout already sizes the pane
    /// from `flex_grow`, and a fixed `height` of zero would collapse it.
    pub height: usize,
    /// Cyan border and bar when the list owns the keyboard.
    pub active: bool,
}

#[component]
pub fn EntryList(props: &mut EntryListProps) -> impl Into<AnyElement<'static>> {
    let requested = if props.height == 0 {
        // Rendered height is a taffy value, not a row count. `UNSET` keeps the
        // measured size, and the capacity then falls back to "all of them".
        Size::Unset
    } else {
        Size::Length((props.height * ROW_HEIGHT) as u32)
    };
    let window = visible_window(&props.rows, props.selected, props.offset, props.height);
    let selected_id = props.rows.get(props.selected).map(|r| r.id.clone());
    let (border_color, _) = crate::widgets::chrome::focus_ring(props.active);

    let mut body: Vec<AnyElement<'static>> = Vec::new();
    for row in &window.rows {
        let is_selected = Some(&row.id) == selected_id.as_ref();
        body.push(entry_row(row, is_selected, props.active).into());
    }

    element! {
        View(
            height: requested,
            flex_grow: 1.0_f32,
            flex_direction: FlexDirection::Column,
            border_style: theme::PANEL_BORDER,
            border_color: Some(border_color),
            padding_left: theme::PAD,
            padding_right: theme::PAD,
        ) {
            ScrollView(
                // Keyboard scrolling is off because the list drives its own
                // cursor; arrow keys move the selection, not the scroll offset.
                keyboard_scroll: false,
                scrollbar: false,
            ) {
                #(body.into_iter())
            }
        }
    }
}

/// One entry: a focus bar, the title, and a secondary line.
fn entry_row<'a>(row: &ListRow, is_selected: bool, pane_active: bool) -> Element<'a, View> {
    let bar_color = if is_selected { theme::ACCENT } else { Color::Reset };
    // The bar only appears when the list has focus, so it never suggests a
    // selection the user can't act on.
    let bar_text = if is_selected && pane_active {
        BAR.to_string()
    } else {
        BAR_GAP.to_string()
    };

    // A star marks favorites inline, where the eye already is.
    let star = if row.favorite { "\u{2605} " } else { "" };
    let totp = if row.has_totp { "  \u{23f1}" } else { "" };
    let title = format!("{star}{}{totp}", row.title);
    let title_color = if is_selected { theme::ACCENT } else { Color::Reset };
    let title_weight = if is_selected { Weight::Bold } else { Weight::Normal };

    element! {
        View(
            key: row.id.clone(),
            flex_direction: FlexDirection::Column,
            flex_shrink: 0_f32,
        ) {
            View(flex_direction: FlexDirection::Row, flex_shrink: 0_f32, column_gap: 1_u32) {
                View(flex_shrink: 0_f32) {
                    Text(content: bar_text, color: Some(bar_color), weight: Weight::Bold)
                }
                View(flex_grow: 1.0_f32, overflow: Some(Overflow::Hidden)) {
                    Text(content: title, color: Some(title_color), weight: title_weight)
                }
            }
            View(flex_direction: FlexDirection::Row, flex_shrink: 0_f32, column_gap: 1_u32) {
                View(flex_shrink: 0_f32) {
                    Text(content: BAR_GAP.to_string(), color: Some(theme::MUTED))
                }
                View(flex_grow: 1.0_f32, overflow: Some(Overflow::Hidden)) {
                    Text(content: row.subtitle.clone(), color: Some(theme::MUTED))
                }
            }
        }
    }
}

/// A minimal row, for tests that only need the shape.
#[cfg(test)]
pub fn row(id: &str) -> ListRow {
    ListRow {
        id: id.to_string(),
        title: format!("Title {id}"),
        subtitle: "user".to_string(),
        favorite: false,
        has_totp: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(n: usize) -> Vec<ListRow> {
        (0..n).map(|i| row(&format!("id{i}"))).collect()
    }

    #[test]
    fn a_default_row_is_the_shape_the_list_expects() {
        let r = row("id1");
        assert_eq!(r.id, "id1");
        assert!(!r.favorite && !r.has_totp);
    }

    #[test]
    fn an_empty_list_produces_an_empty_window() {
        let w = visible_window(&[], 0, 0, 10);
        assert!(w.rows.is_empty());
        assert!(!w.has_above);
        assert!(!w.has_below);
    }

    #[test]
    fn a_zero_height_pane_shows_nothing() {
        let w = visible_window(&rows(5), 0, 0, 0);
        assert!(w.rows.is_empty());
    }

    #[test]
    fn a_pane_too_short_for_one_row_shows_nothing_but_reports_more_below() {
        // ROW_HEIGHT is 2, so a one-row pane has no room for an entry.
        let w = visible_window(&rows(5), 0, 0, 1);
        assert!(w.rows.is_empty());
        assert!(w.has_below, "the user should be told there is more");
    }

    #[test]
    fn a_window_that_fits_everything_shows_it_all() {
        let all = rows(3);
        let w = visible_window(&all, 0, 0, 10);
        assert_eq!(w.rows.len(), 3);
        assert_eq!(w.start, 0);
        assert!(!w.has_above);
        assert!(!w.has_below);
    }

    #[test]
    fn the_window_scrolls_to_keep_the_selection_visible() {
        let all = rows(20);
        // 10 rows of height fits 5 entries.
        let w = visible_window(&all, 0, 0, 10);
        assert_eq!(w.rows.len(), 5);
        assert!(!w.has_above);

        // Selecting the last row must scroll down.
        let w = visible_window(&all, 19, 0, 10);
        assert!(w.has_above);
        assert!(!w.has_below, "the last row should be at the bottom");
        assert_eq!(w.rows.last().unwrap().id, "id19", "the selection must be visible");
    }

    #[test]
    fn the_window_scrolls_up_when_the_selection_moves_above_it() {
        let all = rows(20);
        let w = visible_window(&all, 0, 15, 10);
        assert_eq!(w.start, 0, "scrolled back to the top");
        assert!(!w.has_above);
        assert!(w.has_below);
    }

    #[test]
    fn the_window_never_scrolls_past_the_end() {
        let all = rows(6);
        // A window that fits 2 entries, scrolled past the end: the last page
        // shows the final entries rather than blank space.
        let w = visible_window(&all, 5, 99, 4);
        assert_eq!(w.start, 4, "start is capped at len - capacity");
        assert_eq!(w.rows.len(), 2);
        assert!(!w.has_below);
        assert!(w.has_above);
    }

    #[test]
    fn a_window_larger_than_the_list_starts_at_the_top() {
        let all = rows(6);
        let w = visible_window(&all, 5, 99, 40);
        assert_eq!(w.start, 0, "everything fits, so there is nothing to scroll");
        assert_eq!(w.rows.len(), 6);
        assert!(!w.has_below);
    }

    #[test]
    fn the_window_holds_the_selection_across_every_position() {
        let all = rows(20);
        for selected in 0..20 {
            let w = visible_window(&all, selected, 0, 10);
            let visible: Vec<&str> = w.rows.iter().map(|r| r.id.as_str()).collect();
            assert!(
                visible.contains(&all[selected].id.as_str()),
                "selection {selected} not visible in {visible:?}"
            );
        }
    }

    #[test]
    fn an_out_of_range_selection_still_yields_a_sane_window() {
        let all = rows(5);
        // Defensive: a stale index must not panic.
        let w = visible_window(&all, 99, 0, 10);
        assert!(!w.rows.is_empty());
    }


}
