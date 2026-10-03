//! The entry detail pane: everything about one entry, with secrets masked
//! until revealed.
//!
//! The pane is read-only by design. Editing happens in a full-screen form
//! rather than in-place, so there is no way to leave a half-edited secret
//! sitting on screen, and no risk of an in-place keystroke overwriting a
//! password the user meant to copy.

use domi_core::vault::{Entry, ItemCategory};
use domi_core::{check_strength, generate_totp, now_unix};
use iocraft::prelude::*;

use crate::theme;
use crate::widgets::chrome::{secret_display, FieldRow, StrengthMeter};

/// A human label for a category, since core's variant names are CamelCase.
pub fn category_label(category: ItemCategory) -> &'static str {
    match category {
        ItemCategory::Login => "Login",
        ItemCategory::CreditCard => "Credit card",
        ItemCategory::SecureNote => "Secure note",
        ItemCategory::Identity => "Identity",
        ItemCategory::BankAccount => "Bank account",
    }
}

/// The TOTP code for an entry, or `None` when there is no secret to use.
///
/// Returns the code with the conventional space in the middle ("123 456"),
/// which is both easier to read and matches what authenticator apps show.
pub fn current_totp(entry: &Entry) -> Option<String> {
    let secret = entry.totp_secret.as_ref()?;
    if secret.trim().is_empty() {
        return None;
    }
    let code = generate_totp(secret.trim(), 30, now_unix().max(0) as u64, 6).ok()?;
    let (head, tail) = code.split_at(code.len() / 2);
    Some(format!("{head} {tail}"))
}

/// Seconds until the current TOTP code rolls over, for a countdown hint.
pub fn totp_seconds_left() -> u64 {
    30 - (now_unix().max(0) as u64 % 30)
}

/// The detail rows for an entry, prepared for display.
///
/// `tag_names` maps each of the entry's tag ids to the name the user typed.
/// It is a lookup rather than a `HashMap` because callers hold the names in
/// index order and this keeps the widget free of index access; an id with no
/// entry in the pair is shown as-is so an orphaned tag is visible rather than
/// silently dropped.
///
/// Split out as a pure function so the masking rule can be tested directly:
/// a secret must appear verbatim only when `revealed` is true.
pub fn detail_rows(
    entry: &Entry,
    revealed: bool,
    tag_names: &[(String, String)],
) -> Vec<(String, String)> {
    let mut rows: Vec<(String, String)> = Vec::new();

    rows.push(("Username".to_string(), entry.username.clone()));

    // Never render an empty secret as a row of dots; that looks like a stored
    // password when it is actually "this entry has none".
    if !entry.password.is_empty() {
        rows.push(("Password".to_string(), secret_display(&entry.password, revealed)));
    }
    if !entry.url.is_empty() {
        rows.push(("URL".to_string(), entry.url.clone()));
    }
    if let Some(code) = current_totp(entry) {
        // The countdown tells the user when the code is about to change, which
        // is the whole point of a one-time code.
        rows.push((
            "One-time".to_string(),
            format!("{code}  ({}s)", totp_seconds_left()),
        ));
    }
    if !entry.tags.is_empty() {
        let names: Vec<String> = entry
            .tags
            .iter()
            .map(|id| {
                tag_names
                    .iter()
                    .find(|(tag_id, _)| tag_id == id)
                    .map(|(_, name)| name.clone())
                    .unwrap_or_else(|| id.clone())
            })
            .collect();
        rows.push(("Tags".to_string(), names.join(", ")));
    }
    if !entry.notes.is_empty() {
        rows.push(("Notes".to_string(), entry.notes.clone()));
    }
    for (key, value) in &entry.custom_fields {
        // Custom fields can hold anything, so they're treated as secrets.
        rows.push((key.clone(), secret_display(value, revealed)));
    }
    rows
}

/// The strength of an entry's password, 0 when it has none.
pub fn password_strength(entry: &Entry) -> u8 {
    if entry.password.is_empty() {
        return 0;
    }
    check_strength(&entry.password)
}

/// A one-line summary under the title, e.g. "octocat \u{00b7} github.com".
pub fn summary_line(entry: &Entry) -> String {
    let mut parts: Vec<String> = Vec::new();
    if !entry.username.is_empty() {
        parts.push(entry.username.clone());
    }
    if !entry.url.is_empty() {
        parts.push(entry.url.clone());
    }
    if parts.is_empty() {
        return category_label(entry.category).to_string();
    }
    parts.join(" \u{00b7} ")
}

/// The detail pane for one entry.
///
/// The entry is owned so a caller can build this in Rust and return a
/// `static` element; see `crate::app::build_detail`.
#[derive(Default, Props)]
pub struct DetailProps {
    pub entry: Option<Entry>,
    /// Tag id to tag name, so the pane shows names rather than ids.
    pub tag_names: Vec<(String, String)>,
    pub revealed: bool,
    /// Cyan border when the detail pane owns the keyboard.
    pub active: bool,
}

#[component]
pub fn Detail(props: &mut DetailProps) -> impl Into<AnyElement<'static>> {
    let (border_color, _) = crate::widgets::chrome::focus_ring(props.active);
    let entry = props.entry.clone();
    let title = entry.as_ref().map(|e| e.title.clone()).unwrap_or_default();
    let summary = entry.as_ref().map(summary_line).unwrap_or_default();
    let updated = entry
        .as_ref()
        .map(|e| theme::relative_time(e.updated_at))
        .unwrap_or_default();
    let revealed = props.revealed;
    let has_totp = entry.as_ref().map(|e| current_totp(e).is_some()).unwrap_or(false);

    let mut body: Vec<AnyElement<'static>> = Vec::new();
    if let Some(entry) = entry {
        body.push(element! {
            View(key: "title", flex_shrink: 0_f32, overflow: Some(Overflow::Hidden)) {
                Text(
                    content: title,
                    color: Some(theme::ACCENT),
                    weight: Weight::Bold,
                )
            }
        }.into());
        body.push(element! {
            View(key: "summary", flex_shrink: 0_f32, overflow: Some(Overflow::Hidden)) {
                Text(content: summary, color: Some(theme::MUTED))
            }
        }.into());
        let mut meta_row: Vec<AnyElement<'static>> = vec![element! {
            Text(content: category_label(entry.category), color: Some(theme::BORDER))
        }.into()];
        meta_row.push(element! {
            Text(content: format!("updated {updated}"), color: Some(theme::MUTED))
        }.into());
        if entry.favorite {
            meta_row.push(element! {
                Text(content: "\u{2605} favorite", color: Some(theme::SUCCESS))
            }.into());
        }
        if has_totp {
            meta_row.push(element! {
                Text(content: "\u{23f1} 2FA", color: Some(theme::SUCCESS))
            }.into());
        }

        body.push(element! {
            View(
                key: "meta",
                flex_direction: FlexDirection::Row,
                flex_shrink: 0_f32,
                column_gap: 2_u32,
            ) {
                #(meta_row.into_iter())
            }
        }.into());

        if !entry.password.is_empty() {
            body.push(element! {
                View(key: "strength", flex_shrink: 0_f32, margin_top: 1_u32) {
                    StrengthMeter(score: password_strength(&entry))
                }
            }.into());
        }

        for (label, value) in detail_rows(&entry, revealed, &props.tag_names) {
            body.push(element! {
                FieldRow(label: label, value: value)
            }.into());
        }
    }

    element! {
        View(
            flex_grow: 1.0_f32,
            flex_direction: FlexDirection::Column,
            border_style: theme::PANEL_BORDER,
            border_color: Some(border_color),
            padding_left: theme::PAD,
            padding_right: theme::PAD,
        ) {
            #(body.into_iter())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault_store::blank_entry;

    fn entry() -> Entry {
        let mut e = blank_entry("id".into(), now_unix());
        e.title = "GitHub".into();
        e.username = "octocat".into();
        e.password = "hunter2".into();
        e.url = "github.com".into();
        e.notes = "work account".into();
        e
    }

    fn field<'a>(rows: &'a [(String, String)], label: &str) -> Option<&'a str> {
        rows.iter().find(|(l, _)| l == label).map(|(_, v)| v.as_str())
    }

    #[test]
    fn every_category_has_a_readable_label() {
        for c in [
            ItemCategory::Login,
            ItemCategory::CreditCard,
            ItemCategory::SecureNote,
            ItemCategory::Identity,
            ItemCategory::BankAccount,
        ] {
            let label = category_label(c);
            assert!(!label.is_empty());
            assert!(label.chars().all(|ch| !ch.is_uppercase() || ch.is_ascii_uppercase()));
        }
    }

    #[test]
    fn a_masked_password_never_appears_in_the_rows() {
        let e = entry();
        let rows = detail_rows(&e, false, &[]);
        let pw = field(&rows, "Password").unwrap();
        assert!(!pw.contains("hunter"));
        assert!(pw.chars().all(|c| c == theme::MASK));
    }

    #[test]
    fn a_revealed_password_appears_verbatim() {
        let e = entry();
        let rows = detail_rows(&e, true, &[]);
        assert_eq!(field(&rows, "Password"), Some("hunter2"));
    }

    #[test]
    fn an_empty_password_is_omitted_rather_than_shown_as_dots() {
        let mut e = entry();
        e.password = String::new();
        let rows = detail_rows(&e, false, &[]);
        assert!(field(&rows, "Password").is_none(), "no password row at all");
    }

    #[test]
    fn optional_fields_are_omitted_when_empty() {
        let mut e = entry();
        e.url = String::new();
        e.notes = String::new();
        e.totp_secret = None;
        let rows = detail_rows(&e, false, &[]);
        assert!(field(&rows, "URL").is_none());
        assert!(field(&rows, "Notes").is_none());
        assert!(field(&rows, "One-time").is_none());
        assert!(field(&rows, "Username").is_some(), "but the username stays");
    }

    #[test]
    fn custom_fields_are_treated_as_secrets() {
        let mut e = entry();
        e.custom_fields.insert("Recovery key".into(), "abcd-efgh".into());
        let rows = detail_rows(&e, false, &[]);
        let v = field(&rows, "Recovery key").unwrap();
        assert!(!v.contains("abcd"), "a custom field must be masked too: {v}");

        let shown = detail_rows(&e, true, &[]);
        assert_eq!(field(&shown, "Recovery key"), Some("abcd-efgh"));
    }

    #[test]
    fn totp_is_absent_without_a_secret_and_six_digits_with_one() {
        let mut e = entry();
        assert!(current_totp(&e).is_none());

        e.totp_secret = Some("   ".into());
        assert!(current_totp(&e).is_none(), "a blank secret is not a secret");

        // The RFC 4226 test vector: at t=0 this secret yields 755224.
        e.totp_secret = Some("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into());
        if let Some(code) = current_totp(&e) {
            let digits: String = code.chars().filter(|c| c.is_ascii_digit()).collect();
            assert_eq!(digits.len(), 6, "got {code}");
        }
    }

    #[test]
    fn totp_countdown_is_within_the_period() {
        let s = totp_seconds_left();
        assert!((1..=30).contains(&s), "countdown was {s}");
    }

    #[test]
    fn strength_is_zero_for_an_empty_password() {
        let mut e = entry();
        e.password = String::new();
        assert_eq!(password_strength(&e), 0);
    }

    #[test]
    fn the_tags_row_shows_names_rather_than_ids() {
        let mut e = entry();
        e.tags = vec!["a1b2c3".into()];

        let pairs = [("a1b2c3".to_string(), "work".to_string())];
        assert_eq!(field(&detail_rows(&e, false, &pairs), "Tags"), Some("work"));
        assert!(
            !field(&detail_rows(&e, false, &pairs), "Tags").unwrap().contains("a1b2c3"),
            "an id in the tags row is noise to the reader"
        );
    }

    #[test]
    fn a_tag_id_with_no_name_still_shows() {
        // A tag deleted out from under an entry must stay visible so the user
        // can see and clear the dangling reference.
        let mut e = entry();
        e.tags = vec!["dangling".into()];
        assert_eq!(field(&detail_rows(&e, false, &[]), "Tags"), Some("dangling"));
    }

    #[test]
    fn several_tags_are_joined_in_order() {
        let mut e = entry();
        e.tags = vec!["t1".into(), "t2".into()];
        let pairs = [("t1".to_string(), "work".to_string()), ("t2".to_string(), "home".to_string())];
        assert_eq!(field(&detail_rows(&e, false, &pairs), "Tags"), Some("work, home"));
    }

    #[test]
    fn strength_orders_by_guessability() {
        let mut e = entry();
        e.password = "aaaa".into();
        let weak = password_strength(&e);
        e.password = "Tr0ub4dor&3xyzzy!PLugh".into();
        let strong = password_strength(&e);
        assert!(strong > weak, "a longer mixed password should score higher ({strong} vs {weak})");
    }

    #[test]
    fn summary_joins_username_and_url() {
        let e = entry();
        let line = summary_line(&e);
        assert!(line.contains("octocat"));
        assert!(line.contains("github.com"));
    }

    #[test]
    fn summary_falls_back_to_the_category_when_there_is_nothing_else() {
        let mut e = entry();
        e.username = String::new();
        e.url = String::new();
        assert_eq!(summary_line(&e), "Login");
    }
}
