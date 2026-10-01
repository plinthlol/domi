//! Custom widgets for the Fuin TUI.
//!
//! iocraft ships a minimal component set — a `View`, some `Text`, a
//! `TextInput`, a `Button`, and a `ScrollView` — and no layout primitives like
//! boxes, lists, or tables. Everything a password manager's interface needs
//! beyond that is built here as small, composable components so screens stay
//! declarative and the visual rules stay in one place.

pub mod chrome;
pub mod detail;
pub mod entry_list;
pub mod form;
pub mod modal;
pub mod search_bar;
