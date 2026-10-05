//! What can go wrong, and how each failure is phrased to the user.
//!
//! The rule this file exists to enforce: an error message is the only place a
//! user learns what went wrong, so each variant carries a sentence a person
//! can act on rather than a type name they cannot. [`AppError::message`] is
//! that sentence, and it is what the status line prints.
//!
//! Internal detail stays available through `Display` for a log or a panic
//! message, while `message()` is deliberately shorter and free of paths that
//! would wrap badly in a one-line status bar.

use std::fmt;

/// A failure the user can see.
///
/// `Display` is the developer-facing form and `message()` the user-facing one.
/// They differ deliberately; see the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppError {
    /// The vault directory already holds a vault.
    ///
    /// Separate from a storage failure because the fix is different: the user
    /// picks a different directory rather than retrying.
    VaultExists,
    /// No vault exists at the configured path yet.
    NoVault,
    /// The password did not open the vault.
    ///
    /// Core reports the same thing for a wrong password and for a corrupted
    /// blob, because telling a caller which one it was would tell an attacker
    /// something. The message here follows that rule.
    WrongPassword,
    /// The user typed something the app refuses: a blank title, a password
    /// with no character classes, a path that is a file.
    BadInput(String),
    /// The filesystem refused: permissions, a full disk, a missing directory.
    Storage(String),
}

impl AppError {
    /// The one-line message shown in the status bar.
    ///
    /// Kept short because the status bar is a single row; a message that wraps
    /// would push the key hints off screen. `Storage` keeps its detail because
    /// "could not save" without the reason is not actionable.
    pub fn message(&self) -> String {
        match self {
            AppError::VaultExists => "A vault already exists at this location".to_string(),
            AppError::NoVault => "No vault exists at this location".to_string(),
            AppError::WrongPassword => "Wrong password, or the vault is damaged".to_string(),
            AppError::BadInput(msg) if msg.is_empty() => "That value is not valid".to_string(),
            AppError::BadInput(msg) => msg.clone(),
            AppError::Storage(msg) => msg.clone(),
        }
    }

    /// Whether this is worth telling the user about at all.
    ///
    /// The app cancels work the user asked for when it fails, so every variant
    /// is worth reporting. The hook exists so that decision is made once, in
    /// one place, rather than re-decided at each call site.
    pub fn is_user_facing(&self) -> bool {
        true
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::VaultExists => write!(f, "vault already exists"),
            AppError::NoVault => write!(f, "no vault at this location"),
            AppError::WrongPassword => write!(f, "wrong password"),
            AppError::BadInput(msg) => write!(f, "bad input: {msg}"),
            AppError::Storage(msg) => write!(f, "storage: {msg}"),
        }
    }
}

impl std::error::Error for AppError {}

impl From<AppError> for String {
    fn from(e: AppError) -> String {
        e.message()
    }
}

/// Turns a core error into the variant a user can act on.
///
/// The split matters: core reports wrong-password and corrupted-vault the same
/// way, and collapsing that distinction here would leak which one it was. A
/// `BadInput` is passed through, and anything else is storage.
pub fn friendly(core: domi_core::CoreError, context: &str) -> AppError {
    use domi_core::CoreError;
    match core {
        // Core reports a wrong password and a damaged vault identically, and
        // this preserves that. Telling them apart would confirm to an attacker
        // that a guessed password was correct.
        CoreError::DecryptionFailed | CoreError::InvalidFormat(_) => {
            let _ = context;
            AppError::WrongPassword
        }
        // Core's "that value is not acceptable" cases, named so the message
        // survives to the user instead of becoming a storage error.
        CoreError::InvalidOperation(msg) => AppError::BadInput(msg),
        CoreError::NotFound(what) => AppError::BadInput(format!("{context}: {what} not found")),
        other => AppError::Storage(format!("{context}: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_message_is_a_sentence_a_user_can_act_on() {
        for err in [
            AppError::VaultExists,
            AppError::NoVault,
            AppError::WrongPassword,
            AppError::BadInput("Title is required".into()),
            AppError::Storage("/tmp/v: permission denied".into()),
        ] {
            let msg = err.message();
            assert!(!msg.is_empty(), "{err:?} has no message");
            assert!(!msg.ends_with('.'), "status-line messages skip the period: {msg:?}");
            // A message that wraps would break the single-row status bar.
            assert!(msg.chars().count() <= 80, "too long for one row: {msg:?}");
        }
    }

    #[test]
    fn every_display_form_differs_from_the_user_message() {
        // The two forms are deliberately separate, so a change to one should
        // not silently change the other.
        let err = AppError::Storage("/tmp/v: permission denied".into());
        assert_ne!(err.to_string(), err.message());
    }

    #[test]
    fn wrong_password_and_a_damaged_vault_read_the_same() {
        // Core cannot tell them apart, and saying which one it was would tell
        // an attacker. Both must collapse to the same user message.
        let damaged = friendly(domi_core::CoreError::InvalidFormat("bad header".into()), "vault");
        assert_eq!(damaged, AppError::WrongPassword);
        assert_eq!(damaged.message(), AppError::WrongPassword.message());
    }

    #[test]
    fn a_core_rejected_operation_keeps_its_text() {
        let err = friendly(domi_core::CoreError::InvalidOperation("title too long".into()), "entry");
        assert_eq!(err, AppError::BadInput("title too long".into()));
        assert!(err.message().contains("title too long"));
    }

    #[test]
    fn a_core_not_found_names_what_was_missing() {
        let err = friendly(domi_core::CoreError::NotFound("entry".into()), "save");
        assert_eq!(err, AppError::BadInput("save: entry not found".into()));
    }

    #[test]
    fn an_unexpected_core_error_becomes_storage() {
        let err = friendly(
            domi_core::CoreError::AlreadyExists("manifest".into()),
            "vault",
        );
        match err {
            AppError::Storage(msg) => {
                assert!(msg.contains("vault"), "the context should be kept: {msg}");
                assert!(msg.contains("manifest"), "the cause should be kept: {msg}");
            }
            other => panic!("expected a storage error, got {other:?}"),
        }
    }

    #[test]
    fn every_variant_is_worth_reporting() {
        for err in [
            AppError::VaultExists,
            AppError::NoVault,
            AppError::WrongPassword,
            AppError::BadInput("x".into()),
            AppError::Storage("x".into()),
        ] {
            assert!(err.is_user_facing(), "{err:?} would be silently swallowed");
        }
    }

    #[test]
    fn a_bad_input_with_no_text_still_produces_a_usable_line() {
        // An empty error is the one failure a user cannot diagnose, so the
        // variant substitutes rather than printing nothing.
        let err = AppError::BadInput(String::new());
        assert!(!err.message().is_empty(), "an empty message tells the user nothing");
    }
}