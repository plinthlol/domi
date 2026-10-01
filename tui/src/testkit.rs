//! Rendering a frame to text, for tests.
//!
//! iocraft's built-in `mock_terminal_render_loop` needs a terminal backend, and
//! the stock one reports no size, so every widget would collapse to nothing.
//! This runs the real layout engine instead: it lays the frame out into a
//! [`Canvas`] at a known size and flattens the result to a string. That makes
//! the assertions worth having — a test checks what the user would actually
//! see, not just that a function returned something.

use iocraft::prelude::*;

use crate::app::render_screen;

/// Renders `state` at `width` x `height` and returns the visible text.
///
/// The list capacity is filled in from the same measurement the component
/// makes, so a test sees the window the user would see.
///
/// Trailing blank space is trimmed so a test can assert on whole lines.
#[cfg(test)]
pub fn render_to_text(state: &crate::state::RenderSnapshot, width: u16, height: u16) -> String {
    let mut state = state.clone();
    state.list_capacity = crate::app::list_rows(height);

    let frame = render_screen(&state, width);
    let mut element = element! {
        View(flex_direction: FlexDirection::Column, flex_grow: 1.0_f32) {
            #(frame.into_iter())
        }
    };

    let canvas = element.render(Some(width as usize));
    let text = canvas.to_string();
    text.lines()
        .map(|line| line.trim_end())
        .collect::<Vec<_>>()
        .join("\n")
        .trim_end()
        .to_string()
}
