//! Modal dialogs drawn over whatever screen is active.
//!
//! A modal is an overlay, not a new screen: it keeps the underlying screen
//! rendered but unreachable, so `Tab` cycling and every keybinding beneath it
//! are disabled for as long as it is up. That is the whole reason `Modal` is a
//! separate type from `Screen`.
//!
//! The overlay is built by stacking the dimmed background and the dialog in a
//! column with the dialog centred, rather than using true transparency, which
//! iocraft has no primitive for. The background is simply left visible above
//! and below the box.

use iocraft::prelude::*;

use crate::state::Modal;
use crate::theme;

/// A centred dialog box.
///
/// Every string is owned rather than borrowed so a caller can build this in
/// Rust and return a `static` element; see `crate::app::render_modal`.
#[derive(Default, Props)]
pub struct ModalBoxProps {
    pub title: String,
    pub body: String,
    /// The confirm button's label, e.g. "Delete" or "Confirm".
    pub confirm_label: String,
    /// Red border and label, for destructive confirmations.
    pub danger: bool,
    /// The dialog collects typed text instead of a yes/no answer.
    pub text_input: bool,
    /// Current value, for the text variant.
    pub value: String,
    pub on_change: HandlerMut<'static, String>,
    /// A longer explanation, e.g. what a delete does to the data.
    pub detail: String,
}

#[component]
pub fn ModalBox(props: &mut ModalBoxProps) -> impl Into<AnyElement<'static>> {
    let title = props.title.to_string();
    let body = props.body.to_string();
    let detail = props.detail.to_string();
    let confirm_label = props.confirm_label.to_string();
    let value = props.value.to_string();
    let danger = props.danger;
    let text_input = props.text_input;
    let on_change = props.on_change.take();
    let has_detail = !detail.is_empty();

    let accent = if danger { theme::DANGER } else { theme::ACCENT };
    let label = if confirm_label.is_empty() { "OK".to_string() } else { confirm_label };
    let has_input = text_input;

    let mut body_rows: Vec<AnyElement<'static>> = vec![element! {
        View(key: "body", flex_shrink: 0_f32) {
            Text(content: body, color: Some(Color::Reset))
        }
    }.into()];
    if has_detail {
        body_rows.push(element! {
            View(key: "detail", flex_shrink: 0_f32, margin_top: 1_u32) {
                Text(content: detail, color: Some(theme::MUTED))
            }
        }.into());
    }
    if has_input {
        body_rows.push(element! {
            View(key: "input", flex_shrink: 0_f32, margin_top: 1_u32) {
                TextInput(
                    value: value.clone(),
                    has_focus: true,
                    on_change: on_change,
                    cursor_color: Some(accent),
                )
            }
        }.into());
    }

    element! {
        View(
            flex_grow: 1.0_f32,
            flex_direction: FlexDirection::Column,
            align_items: Some(AlignItems::Center),
            justify_content: Some(JustifyContent::Center),
            padding_left: 2_u32,
            padding_right: 2_u32,
        ) {
            View(
                width: 60_pct,
                max_width: 70_u32,
                min_width: 40_u32,
                flex_direction: FlexDirection::Column,
                border_style: BorderStyle::Round,
                border_color: Some(accent),
                background_color: Some(Color::Black),
                padding_left: 2_u32,
                padding_right: 2_u32,
                padding_top: 1_u32,
                padding_bottom: 1_u32,
            ) {
                View(flex_shrink: 0_f32, margin_bottom: 1_u32) {
                    Text(content: title, color: Some(accent), weight: Weight::Bold)
                }
                #(body_rows.into_iter())
                View(
                    flex_direction: FlexDirection::Row,
                    flex_shrink: 0_f32,
                    justify_content: Some(JustifyContent::FlexEnd),
                    margin_top: 1_u32,
                    column_gap: 2_u32,
                ) {
                    Text(content: "esc cancel", color: Some(theme::MUTED))
                    Text(content: label, color: Some(accent), weight: Weight::Bold)
                }
            }
        }
    }
}

/// Whether a modal variant needs a text input, and what it starts with.
pub fn modal_text_value(modal: &Modal) -> Option<String> {
    match modal {
        Modal::Password { value, .. } => Some(value.clone()),
        Modal::Confirm { .. } => None,
    }
}

/// The confirm button's label, defaulting sensibly per variant.
pub fn modal_confirm_label(modal: &Modal) -> String {
    match modal {
        Modal::Confirm { yes_label, .. } => yes_label.clone(),
        Modal::Password { .. } => "Set".to_string(),
    }
}

/// A destructive confirmation's body text, naming the entry.
pub fn delete_confirmation(title: &str) -> Modal {
    Modal::danger(
        "Delete entry",
        &format!("Delete \"{title}\"? It will be removed from this vault."),
    )
}

/// The confirmation for the settings row that closes the vault.
///
/// Marked dangerous because there is no way back from it: the entries are the
/// only copy of the data, and re-creating the vault starts from nothing.
pub fn reset_confirmation() -> Modal {
    Modal::danger("Close this vault", "This removes the vault and every entry in it. It cannot be undone.")
}

#[cfg(test)]
mod tests {
    use super::*;




    #[test]
    fn the_password_variant_collects_a_value_and_the_confirm_does_not() {
        assert_eq!(
            modal_text_value(&Modal::Password { title: "t".into(), value: "v".into() }),
            Some("v".to_string())
        );
        assert_eq!(modal_text_value(&Modal::confirm("t", "b")), None);
        assert_eq!(modal_text_value(&Modal::danger("t", "b")), None);
    }

    #[test]
    fn confirm_labels_say_what_the_button_does() {
        assert_eq!(modal_confirm_label(&Modal::confirm("t", "b")), "Confirm");
        assert_eq!(
            modal_confirm_label(&Modal::danger("t", "b")),
            "Delete",
            "a destructive button should say what it does"
        );
        assert_eq!(
            modal_confirm_label(&Modal::Password { title: "t".into(), value: String::new() }),
            "Set"
        );
    }

    #[test]
    fn delete_confirmation_names_the_entry_and_is_marked_dangerous() {
        let m = delete_confirmation("GitHub");
        assert_eq!(m.title(), "Delete entry");
        match &m {
            Modal::Confirm { body, danger, yes_label, .. } => {
                assert!(body.contains("GitHub"), "the user must see what is being deleted: {body}");
                assert!(danger);
                assert_eq!(yes_label, "Delete");
            }
            other => panic!("expected Confirm, got {other:?}"),
        }
    }


    #[test]
    fn closing_the_vault_is_presented_as_destructive_and_irreversible() {
        let m = reset_confirmation();
        match &m {
            Modal::Confirm { body, danger, yes_label, .. } => {
                assert!(danger, "losing the vault must read as destructive");
                assert!(body.contains("cannot be undone"), "the user must know it is final: {body}");
                assert_eq!(yes_label, "Delete");
            }
            other => panic!("expected Confirm, got {other:?}"),
        }
    }
}
