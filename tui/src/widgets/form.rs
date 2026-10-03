//! The create/edit entry form.
//!
//! Every field is a `TextInput` except the category cycler and the favorite
//! toggle, which are stepped with space rather than typed into. iocraft has no
//! masked text input, so password and TOTP fields are fed a masked string and
//! the real value is edited indirectly — see [`masked_field`] for how that
//! works without losing keystrokes.

use iocraft::prelude::*;

use domi_core::check_strength;

use crate::state::{EntryForm, Field};
use crate::theme;
use crate::widgets::chrome::{secret_display, StrengthMeter};
use crate::widgets::detail::category_label;

/// A field whose value should never be shown as typed.
fn is_secret(field: Field) -> bool {
    matches!(field, Field::Password | Field::Totp)
}

/// How a field is rendered when it isn't focused: the value, or a hint.
fn display_value(form: &EntryForm, field: Field) -> String {
    let raw = match field {
        Field::Title => &form.title,
        Field::Username => &form.username,
        Field::Password => &form.password,
        Field::Url => &form.url,
        Field::Notes => &form.notes,
        Field::Totp => &form.totp,
        Field::Tags => &form.tags,
        Field::Category | Field::Favorite => return String::new(),
    };
    if is_secret(field) {
        return secret_display(raw, form.reveal);
    }
    if raw.is_empty() {
        "(empty)".to_string()
    } else {
        raw.clone()
    }
}

/// The value shown for the category cycler.
fn category_value(form: &EntryForm) -> String {
    format!("{}  \u{25c0} \u{25b6}", category_label(form.category))
}

/// The value shown for the favorite toggle.
fn favorite_value(form: &EntryForm) -> String {
    if form.favorite {
        "\u{2605} yes".to_string()
    } else {
        "no".to_string()
    }
}

/// A labelled row: the label, then either an input or a static value.
#[derive(Default, Props)]
pub struct FormRowProps {
    pub label: &'static str,
    /// Rendered when the row is not an editable text field.
    pub static_value: String,
    /// Backs the input when `editable` is true.
    pub value: String,
    pub editable: bool,
    /// The input owns the keyboard.
    pub focused: bool,
    /// Grow the input to several rows.
    pub multiline: bool,
    /// This row's own change handler. Each field needs a distinct one because
    /// `HandlerMut` is neither `Clone` nor `Copy`.
    pub on_change: HandlerMut<'static, String>,
    /// A hint under the field, e.g. a strength meter.
    pub hint: Option<AnyElement<'static>>,
}

#[component]
pub fn FormRow(props: &mut FormRowProps) -> impl Into<AnyElement<'static>> {
    let label = props.label.to_string();
    let value = props.value.clone();
    let static_value = props.static_value.clone();
    let hint = props.hint.take();
    let editable = props.editable;
    let focused = props.focused;
    let multiline = props.multiline;
    let on_change = props.on_change.take();
    let label_color = if focused { theme::ACCENT } else { theme::MUTED };

    let field: AnyElement<'static> = if editable {
        element! {
            View(flex_grow: 1.0_f32) {
                TextInput(
                    value: value,
                    has_focus: focused,
                    on_change: on_change,
                    multiline: multiline,
                    auto_grow: multiline,
                    cursor_color: Some(theme::ACCENT),
                )
            }
        }
        .into()
    } else {
        element! {
            View(flex_grow: 1.0_f32, overflow: Some(Overflow::Hidden)) {
                Text(content: static_value, color: Some(theme::ACCENT), weight: if focused { Weight::Bold } else { Weight::Normal })
            }
        }
        .into()
    };

    element! {
        View(
            flex_direction: FlexDirection::Column,
            flex_shrink: 0_f32,
            padding_left: 1_u32,
        ) {
            View(flex_direction: FlexDirection::Row, flex_shrink: 0_f32, column_gap: 2_u32) {
                View(
                    width: 16_u32,
                    flex_shrink: 0_f32,
                ) {
                    Text(content: label, color: Some(label_color), weight: if focused { Weight::Bold } else { Weight::Normal })
                }
                #(std::iter::once(field))
            }
            #(hint.map(|h| {
                element! {
                    View(flex_shrink: 0_f32, margin_top: 1_u32) {
                        #(std::iter::once(h))
                    }
                }
            }))
        }
    }
}

/// The full create/edit form.
///
/// The form is owned rather than borrowed so a caller can build this in Rust
/// and return a `static` element; see `crate::app::build_form_view`.
#[derive(Default, Props)]
pub struct EntryFormProps {
    /// A snapshot of the form, read to build the inputs.
    pub form: Option<EntryForm>,
    /// Builds a change handler bound to one field. A factory because each of
    /// the nine fields needs its own `HandlerMut`.
    pub make_on_change: Option<&'static (dyn Fn(Field) -> HandlerMut<'static, String> + Send + Sync)>,
}

#[component]
pub fn EntryFormView(props: &mut EntryFormProps) -> impl Into<AnyElement<'static>> {
    let Some(form) = props.form.clone() else {
        return element! {
            View(flex_grow: 1.0_f32) {
                Text(content: "No form open", color: Some(theme::MUTED))
            }
        };
    };

    let make_on_change = props.make_on_change;
    let title: String = if form.is_new() { "New entry".to_string() } else { format!("Edit {}", form.title) };


    let mut body: Vec<Element<'static, FormRow>> = Vec::new();

    for field in Field::ALL {
        let focused = form.field == field;
        let is_text = field.is_text();
        // Only the focused text field is rendered as an input. Everything else
        // is static text, which is what keeps the user from typing into a
        // field they have not tabbed to — and what puts the value of an
        // unfocused field on screen at all.
        let editable = focused && is_text;
        let value = if editable { form.text().to_string() } else { String::new() };
        // A masked secret must not also appear as static text beside its
        // input, so the two are never both populated for the same field.
        let static_value = if editable {
            String::new()
        } else {
            match field {
                Field::Category => category_value(&form),
                Field::Favorite => favorite_value(&form),
                _ => display_value(&form, field),
            }
        };

        // Only the focused field gets a live input, so only it needs a handler.
        let handler = if editable {
            make_on_change.map(|f| f(field)).unwrap_or_default()
        } else {
            HandlerMut::default()
        };

        // The strength meter belongs under the password field, so the user
        // sees the effect of typing without leaving the field.
        let hint: Option<AnyElement<'static>> = if field == Field::Password {
            let score = if form.password.is_empty() { 0 } else { check_strength(&form.password) };
            Some(element! { StrengthMeter(score: score) }.into())
        } else {
            None
        };

        body.push(element! {
            FormRow(
                key: field_index(field),
                label: field.label(),
                static_value: static_value.clone(),
                value: value.clone(),
                editable: editable,
                focused: focused,
                multiline: field == Field::Notes,
                on_change: handler,
                hint: hint,
            )
        });
    }

    element! {
        View(
            flex_grow: 1.0_f32,
            flex_direction: FlexDirection::Column,
            border_style: theme::PANEL_BORDER,
            border_color: Some(theme::ACCENT),
            padding_left: theme::PAD,
            padding_right: theme::PAD,
        ) {
            View(flex_shrink: 0_f32) {
                Text(content: title, color: Some(theme::ACCENT), weight: Weight::Bold)
            }
            #(body.into_iter())
        }
    }
}

/// A stable key per field, so an input keeps its cursor position across
/// renders and doesn't reset when an unrelated field changes.
fn field_index(field: Field) -> &'static str {
    match field {
        Field::Title => "f-title",
        Field::Username => "f-username",
        Field::Password => "f-password",
        Field::Url => "f-url",
        Field::Notes => "f-notes",
        Field::Totp => "f-totp",
        Field::Category => "f-category",
        Field::Favorite => "f-favorite",
        Field::Tags => "f-tags",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::EntryForm;

    fn form() -> EntryForm {
        EntryForm::new(0)
    }

    #[test]
    fn only_password_and_totp_are_treated_as_secrets() {
        assert!(is_secret(Field::Password));
        assert!(is_secret(Field::Totp));
        for f in [Field::Title, Field::Username, Field::Url, Field::Notes, Field::Tags] {
            assert!(!is_secret(f), "{f:?} is not a secret");
        }
    }

    #[test]
    fn a_masked_field_never_shows_its_value() {
        let mut f = form();
        f.password = "hunter2".into();
        let shown = display_value(&f, Field::Password);
        assert!(!shown.contains("hunter"));
        assert!(shown.chars().all(|c| c == theme::MASK));
    }

    #[test]
    fn revealing_shows_the_secret() {
        let mut f = form();
        f.password = "hunter2".into();
        f.reveal = true;
        assert_eq!(display_value(&f, Field::Password), "hunter2");
    }

    #[test]
    fn non_secret_fields_are_shown_as_typed() {
        let mut f = form();
        f.username = "octocat".into();
        assert_eq!(display_value(&f, Field::Username), "octocat");
    }

    #[test]
    fn empty_fields_show_a_placeholder() {
        let f = form();
        assert_eq!(display_value(&f, Field::Title), "(empty)");
    }

    #[test]
    fn toggle_fields_render_their_state() {
        let mut f = form();
        assert_eq!(display_value(&f, Field::Favorite), "");
        assert_eq!(favorite_value(&f), "no");
        f.toggle_favorite();
        assert_eq!(favorite_value(&f), "\u{2605} yes");

        let cat = category_value(&f);
        assert!(cat.contains("Login"), "category should show its label: {cat}");
    }

    #[test]
    fn every_field_has_a_distinct_key() {
        let keys: std::collections::HashSet<&str> =
            Field::ALL.iter().map(|f| field_index(*f)).collect();
        assert_eq!(keys.len(), Field::ALL.len(), "keys must be unique per field");
    }
}
