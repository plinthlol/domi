//! Human-facing error messages.
//!
//! The Core Rule (see AUDIT.md) is that raw `CoreError` text must never reach
//! the user. Two reasons: the messages leak internals (file paths, tag ids,
//! version numbers), and `DecryptionFailed` must read as "wrong password" so the
//! UI can't be used to distinguish a wrong password from a corrupted vault.
//!
//! Every `CoreError` maps to a short sentence a user can act on. Nothing else.

use fuin_core::CoreError;

/// What went wrong, phrased for someone looking at a password manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppError {
    /// Unlock failed. Deliberately does not distinguish wrong password from a
    /// corrupt vault — that distinction would help someone probing the file.
    WrongPassword,
    /// A vault already exists at the configured path.
    VaultExists,
    /// No vault exists at the configured path yet.
    NoVault,
    /// Entry references a tag or collection that no longer exists.
    MissingReference(String),
    /// A vault written by a newer version of the app.
    TooNew(u32),
    /// The name is already taken (duplicate tag or collection).
    AlreadyTaken(String),
    /// Bad input, e.g. an empty name.
    BadInput(String),
    /// The vault directory could not be read or written.
    Storage(String),
}

impl AppError {
    /// The line shown in the status bar.
    pub fn message(&self) -> String {
        match self {
            AppError::WrongPassword => "Wrong password, or the vault is damaged.".to_string(),
            AppError::VaultExists => "A vault already exists at this location.".to_string(),
            AppError::NoVault => "No vault found at this location.".to_string(),
            AppError::MissingReference(what) => format!("Referenced {what} no longer exists."),
            AppError::TooNew(v) => {
                format!("This vault was written by a newer version of Fuin (format {v}).")
            }
            AppError::AlreadyTaken(what) => format!("That {what} is already in use."),
            AppError::BadInput(what) => what.clone(),
            AppError::Storage(what) => format!("Could not access vault storage: {what}"),
        }
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for AppError {}

/// Maps a core error onto a user-facing one.
///
/// `context` names the operation ("tag", "collection") so `NotFound` messages
/// can say which kind of thing went missing without echoing core's internal
/// wording.
pub fn friendly(core: CoreError, context: &str) -> AppError {
    match core {
        // Anything that failed to decrypt is reported identically. A corrupt
        // index and a wrong password are indistinguishable to the caller
        // anyway, and conflating them avoids leaking which one it was.
        CoreError::DecryptionFailed => AppError::WrongPassword,
        CoreError::VaultLocked => AppError::WrongPassword,
        CoreError::NotFound(_) => AppError::MissingReference(context.to_string()),
        CoreError::UnsupportedVersion(v) => AppError::TooNew(v),
        CoreError::InvalidFormat(m) => AppError::BadInput(m),
        CoreError::AlreadyExists(m) => AppError::AlreadyTaken(m),
        CoreError::InvalidOperation(m) => AppError::BadInput(m),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decryption_failure_reads_as_wrong_password() {
        // Core's text is "wrong password or corrupted vault"; the UI must not
        // surface it verbatim.
        let e = friendly(CoreError::DecryptionFailed, "entry");
        assert_eq!(e, AppError::WrongPassword);
        assert_eq!(e.message(), "Wrong password, or the vault is damaged.");
    }

    #[test]
    fn locked_vault_maps_to_wrong_password() {
        assert_eq!(friendly(CoreError::VaultLocked, "entry"), AppError::WrongPassword);
    }

    #[test]
    fn not_found_uses_the_supplied_context_not_core_wording() {
        let e = friendly(CoreError::NotFound("tag 9f3a".to_string()), "tag");
        assert_eq!(e, AppError::MissingReference("tag".to_string()));
        assert_eq!(e.message(), "Referenced tag no longer exists.");
        assert!(!e.message().contains("9f3a"), "leaked the internal id");
    }

    #[test]
    fn unsupported_version_surfaces_the_format_number() {
        let e = friendly(CoreError::UnsupportedVersion(7), "vault");
        assert_eq!(e, AppError::TooNew(7));
        assert!(e.message().contains('7'));
    }

    #[test]
    fn every_core_variant_maps_to_something_with_a_message() {
        let all = [
            CoreError::DecryptionFailed,
            CoreError::VaultLocked,
            CoreError::NotFound("x".into()),
            CoreError::UnsupportedVersion(1),
            CoreError::InvalidFormat("bad".into()),
            CoreError::AlreadyExists("dup".into()),
            CoreError::InvalidOperation("nope".into()),
        ];
        for core in all {
            let msg = friendly(core, "thing").message();
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn messages_are_single_line() {
        // A multi-line message would wreck the one-line status bar layout.
        let all = [
            AppError::WrongPassword,
            AppError::VaultExists,
            AppError::NoVault,
            AppError::MissingReference("tag".into()),
            AppError::TooNew(3),
            AppError::AlreadyTaken("name".into()),
            AppError::BadInput("something".into()),
            AppError::Storage("disk".into()),
        ];
        for e in all {
            assert!(!e.message().contains('\n'), "multi-line message: {e:?}");
        }
    }
}