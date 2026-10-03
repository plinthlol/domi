use crate::errors::CoreError;
use crate::vault::{Entry, PasswordHistoryItem};

const MAX_HISTORY_ENTRIES: usize = 25;

/// Records the entry's *current* password into its history before it is
/// overwritten with `new_password`.  Keeps at most 25 items (oldest removed
/// first).  No-op if the new password equals the current one.
pub fn record_password_change(entry: &mut Entry, new_password: String, now: i64) {
    if entry.password == new_password {
        return;
    }
    entry.password_history.push(PasswordHistoryItem {
        password: entry.password.clone(),
        updated_at: now,
    });
    if entry.password_history.len() > MAX_HISTORY_ENTRIES {
        entry.password_history.remove(0);
    }
    entry.password = new_password;
    entry.updated_at = now;
}

/// Returns a reference to the password history slice, newest-first.
pub fn get_password_history(entry: &Entry) -> Vec<&PasswordHistoryItem> {
    entry.password_history.iter().rev().collect()
}

/// Restores a historical password by index (0 = most recent historical entry).
/// Pushes the *current* password into history first.
pub fn restore_password(
    entry: &mut Entry,
    history_index: usize,
    now: i64,
) -> Result<(), CoreError> {
    let history_len = entry.password_history.len();
    if history_index >= history_len {
        return Err(CoreError::NotFound(format!(
            "history index {history_index} out of range (len {history_len})"
        )));
    }
    let restored = entry.password_history[history_len - 1 - history_index]
        .password
        .clone();
    record_password_change(entry, restored, now);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_entry(password: &str) -> Entry {
        Entry {
            id: "e1".into(),
            title: "Test".into(),
            username: "user".into(),
            password: password.into(),
            url: "".into(),
            notes: "".into(),
            totp_secret: None,
            custom_fields: HashMap::new(),
            updated_at: 0,
            deleted: false,
            tags: vec![],
            collection_id: None,
            favorite: false,
            alias_provider: None,
            alias_id: None,
            alias_email: None,
            category: crate::vault::ItemCategory::Login,
            password_history: vec![],
            attachments: vec![],
        }
    }

    #[test]
    fn records_history_on_password_change() {
        let mut entry = make_entry("old_pass");
        record_password_change(&mut entry, "new_pass".into(), 100);
        assert_eq!(entry.password, "new_pass");
        assert_eq!(entry.password_history.len(), 1);
        assert_eq!(entry.password_history[0].password, "old_pass");
    }

    #[test]
    fn no_op_when_password_is_same() {
        let mut entry = make_entry("same_pass");
        record_password_change(&mut entry, "same_pass".into(), 100);
        assert_eq!(entry.password_history.len(), 0);
    }

    #[test]
    fn caps_history_at_max() {
        let mut entry = make_entry("p0");
        for i in 1..=(MAX_HISTORY_ENTRIES + 5) {
            record_password_change(&mut entry, format!("p{i}"), i as i64);
        }
        assert_eq!(entry.password_history.len(), MAX_HISTORY_ENTRIES);
    }

    #[test]
    fn restore_password_roundtrip() {
        let mut entry = make_entry("original");
        record_password_change(&mut entry, "second".into(), 1);
        record_password_change(&mut entry, "third".into(), 2);
        // Restore index 0 = most recent historical = "second"
        restore_password(&mut entry, 0, 3).unwrap();
        assert_eq!(entry.password, "second");
    }
}
