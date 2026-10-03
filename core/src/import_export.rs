/// Vault import / export support.
///
/// This module converts between the `domi-core` [`Entry`] model and
/// well-known password-manager interchange formats.  **No networking** is
/// performed here — callers supply raw bytes and receive structured data (or
/// vice-versa).
///
/// Supported formats
/// -----------------
/// | Format              | Import | Export |
/// |---------------------|--------|--------|
/// | Bitwarden JSON      | ✅     | ✅     |
/// | Generic CSV         | ✅     | ✅     |
/// | 1Password CSV       | ✅     | ❌     |
/// | Proton Pass CSV     | ✅     | ❌     |
use crate::errors::CoreError;
use crate::vault::{Entry, ItemCategory};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ──────────────────────────────────────────────────────────────────────────────
// Bitwarden JSON
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
struct BwLoginUri {
    #[serde(rename = "uri")]
    uri: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct BwLogin {
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    uris: Option<Vec<BwLoginUri>>,
}

#[derive(Serialize, Deserialize, Debug)]
struct BwField {
    name: Option<String>,
    value: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BwItem {
    #[serde(rename = "type")]
    item_type: u32,
    name: String,
    notes: Option<String>,
    login: Option<BwLogin>,
    fields: Option<Vec<BwField>>,
}

#[derive(Serialize, Deserialize, Debug)]
struct BwExport {
    items: Vec<BwItem>,
}

/// Marker custom field used to round-trip a category Bitwarden's format has
/// no native `type` for (currently just [`ItemCategory::BankAccount`]).
/// Written by `export_bitwarden_json`, consumed (and stripped back out of
/// `custom_fields`) by `import_bitwarden_json`. Any Bitwarden-side client
/// just sees an ordinary custom field and ignores it.
const CATEGORY_OVERRIDE_FIELD: &str = "_domi_original_category";

/// Parse a Bitwarden JSON export (unencrypted vault export from
/// bitwarden.com → Tools → Export).
pub fn import_bitwarden_json(json_bytes: &[u8]) -> Result<Vec<Entry>, CoreError> {
    let export: BwExport = serde_json::from_slice(json_bytes)
        .map_err(|e| CoreError::InvalidFormat(format!("invalid Bitwarden JSON: {e}")))?;

    let mut entries = Vec::new();
    let now = crate::now_unix();

    for item in export.items {
        let login = item.login.as_ref();
        let url = login
            .and_then(|l| l.uris.as_ref())
            .and_then(|uris| uris.first())
            .and_then(|u| u.uri.clone())
            .unwrap_or_default();

        let mut category = match item.item_type {
            1 => ItemCategory::Login,
            2 => ItemCategory::SecureNote,
            3 => ItemCategory::CreditCard,
            4 => ItemCategory::Identity,
            _ => ItemCategory::Login,
        };

        let mut custom_fields = item
            .fields
            .unwrap_or_default()
            .into_iter()
            .filter_map(|f| Some((f.name?, f.value.unwrap_or_default())))
            .collect::<HashMap<_, _>>();

        // Restore a category Bitwarden's `type` can't represent natively, if
        // this export was produced by export_bitwarden_json — see
        // CATEGORY_OVERRIDE_FIELD. Strip the marker either way so it doesn't
        // show up as a visible junk custom field.
        if let Some(marker) = custom_fields.remove(CATEGORY_OVERRIDE_FIELD)
            && marker == "BankAccount"
        {
            category = ItemCategory::BankAccount;
        }

        entries.push(Entry {
            id: new_id()?,
            title: item.name,
            username: login
                .and_then(|l| l.username.clone())
                .unwrap_or_default(),
            password: login
                .and_then(|l| l.password.clone())
                .unwrap_or_default(),
            url,
            notes: item.notes.unwrap_or_default(),
            totp_secret: login.and_then(|l| l.totp.clone()),
            custom_fields,
            updated_at: now,
            deleted: false,
            tags: vec![],
            collection_id: None,
            favorite: false,
            alias_provider: None,
            alias_id: None,
            alias_email: None,
            category,
            password_history: vec![],
            attachments: vec![],
        });
    }

    Ok(entries)
}

/// Serialize the given entries as a Bitwarden-compatible JSON export.
pub fn export_bitwarden_json(entries: &[Entry]) -> Result<Vec<u8>, CoreError> {
    let items: Vec<BwItem> = entries
        .iter()
        .filter(|e| !e.deleted)
        .map(|e| BwItem {
            item_type: match e.category {
                ItemCategory::Login => 1,
                ItemCategory::SecureNote => 2,
                ItemCategory::CreditCard => 3,
                ItemCategory::Identity => 4,
                ItemCategory::BankAccount => 1,
            },
            name: e.title.clone(),
            notes: if e.notes.is_empty() {
                None
            } else {
                Some(e.notes.clone())
            },
            login: Some(BwLogin {
                username: Some(e.username.clone()),
                password: Some(e.password.clone()),
                totp: e.totp_secret.clone(),
                uris: if e.url.is_empty() {
                    None
                } else {
                    Some(vec![BwLoginUri {
                        uri: Some(e.url.clone()),
                    }])
                },
            }),
            fields: {
                let mut fields: Vec<BwField> = e
                    .custom_fields
                    .iter()
                    .map(|(k, v)| BwField {
                        name: Some(k.clone()),
                        value: Some(v.clone()),
                    })
                    .collect();
                if e.category == ItemCategory::BankAccount {
                    fields.push(BwField {
                        name: Some(CATEGORY_OVERRIDE_FIELD.to_string()),
                        value: Some("BankAccount".to_string()),
                    });
                }
                if fields.is_empty() { None } else { Some(fields) }
            },
        })
        .collect();

    serde_json::to_vec_pretty(&BwExport { items })
        .map_err(|e| CoreError::InvalidFormat(format!("failed to serialize Bitwarden JSON: {e}")))
}

// ──────────────────────────────────────────────────────────────────────────────
// Generic CSV
// ──────────────────────────────────────────────────────────────────────────────

/// Parse a generic password CSV with headers:
/// `title,username,password,url,notes`
pub fn import_csv(csv_bytes: &[u8]) -> Result<Vec<Entry>, CoreError> {
    let text = std::str::from_utf8(csv_bytes)
        .map_err(|e| CoreError::InvalidFormat(format!("CSV is not valid UTF-8: {e}")))?;

    let mut entries = Vec::new();
    let now = crate::now_unix();

    let mut records = csv_records(text).into_iter();
    let header = records
        .next()
        .ok_or_else(|| CoreError::InvalidFormat("CSV has no header row".into()))?;

    let cols: Vec<String> = split_csv_row(header);
    let col_idx = |name: &str| cols.iter().position(|c| c.eq_ignore_ascii_case(name));

    let title_idx = col_idx("title").or_else(|| col_idx("name"));
    let user_idx = col_idx("username").or_else(|| col_idx("login"));
    let pass_idx = col_idx("password");
    let url_idx = col_idx("url").or_else(|| col_idx("website"));
    let notes_idx = col_idx("notes").or_else(|| col_idx("note"));

    for record in records {
        if record.trim().is_empty() {
            continue;
        }
        let fields = split_csv_row(record);
        // split_csv_row already stripped quotes and un-escaped `""`, so the
        // field is the real value already — no further trimming needed (and
        // trimming here was the bug: see split_csv_row's doc comment).
        // strip_formula_escape undoes csv_field's spreadsheet-injection guard.
        let get = |idx: Option<usize>| -> String {
            idx.and_then(|i| fields.get(i))
                .map(|v| strip_formula_escape(v))
                .unwrap_or_default()
        };

        entries.push(Entry {
            id: new_id()?,
            title: get(title_idx),
            username: get(user_idx),
            password: get(pass_idx),
            url: get(url_idx),
            notes: get(notes_idx),
            totp_secret: None,
            custom_fields: HashMap::new(),
            updated_at: now,
            deleted: false,
            tags: vec![],
            collection_id: None,
            favorite: false,
            alias_provider: None,
            alias_id: None,
            alias_email: None,
            category: ItemCategory::Login,
            password_history: vec![],
            attachments: vec![],
        });
    }

    Ok(entries)
}

/// Serialize entries to a generic CSV with headers:
/// `title,username,password,url,notes`
pub fn export_csv(entries: &[Entry]) -> Vec<u8> {
    let mut out = String::from("title,username,password,url,notes\n");
    for e in entries.iter().filter(|e| !e.deleted) {
        out.push_str(&csv_field(&e.title));
        out.push(',');
        out.push_str(&csv_field(&e.username));
        out.push(',');
        out.push_str(&csv_field(&e.password));
        out.push(',');
        out.push_str(&csv_field(&e.url));
        out.push(',');
        out.push_str(&csv_field(&e.notes));
        out.push('\n');
    }
    out.into_bytes()
}

// ──────────────────────────────────────────────────────────────────────────────
// 1Password CSV (Title,Username,Password,URL,OTPAuth,Notes)
// ──────────────────────────────────────────────────────────────────────────────

/// Parse a 1Password CSV export file.
pub fn import_1password_csv(csv_bytes: &[u8]) -> Result<Vec<Entry>, CoreError> {
    // 1Password exports use the same column names as generic CSV plus `OTPAuth`
    // for TOTP. We run the generic importer first then patch TOTP.
    let text = std::str::from_utf8(csv_bytes)
        .map_err(|e| CoreError::InvalidFormat(format!("1Password CSV is not valid UTF-8: {e}")))?;

    let now = crate::now_unix();
    let mut entries = Vec::new();
    let mut records = csv_records(text).into_iter();

    let header = records
        .next()
        .ok_or_else(|| CoreError::InvalidFormat("1Password CSV has no header row".into()))?;
    let cols: Vec<String> = split_csv_row(header);
    let col_idx = |name: &str| cols.iter().position(|c| c.eq_ignore_ascii_case(name));

    let title_idx = col_idx("title");
    let user_idx = col_idx("username");
    let pass_idx = col_idx("password");
    let url_idx = col_idx("url");
    let notes_idx = col_idx("notes");
    let totp_idx = col_idx("otpauth").or_else(|| col_idx("one-time password"));

    for record in records {
        if record.trim().is_empty() {
            continue;
        }
        let fields = split_csv_row(record);
        // split_csv_row already stripped quotes and un-escaped `""`, so the
        // field is the real value already — no further trimming needed (and
        // trimming here was the bug: see split_csv_row's doc comment).
        // strip_formula_escape undoes csv_field's spreadsheet-injection guard.
        let get = |idx: Option<usize>| -> String {
            idx.and_then(|i| fields.get(i))
                .map(|v| strip_formula_escape(v))
                .unwrap_or_default()
        };

        let totp_raw = get(totp_idx);
        let totp_secret = if totp_raw.starts_with("otpauth://") {
            extract_totp_secret_from_uri(&totp_raw)
        } else if !totp_raw.is_empty() {
            Some(totp_raw)
        } else {
            None
        };

        entries.push(Entry {
            id: new_id()?,
            title: get(title_idx),
            username: get(user_idx),
            password: get(pass_idx),
            url: get(url_idx),
            notes: get(notes_idx),
            totp_secret,
            custom_fields: HashMap::new(),
            updated_at: now,
            deleted: false,
            tags: vec![],
            collection_id: None,
            favorite: false,
            alias_provider: None,
            alias_id: None,
            alias_email: None,
            category: ItemCategory::Login,
            password_history: vec![],
            attachments: vec![],
        });
    }

    Ok(entries)
}

/// Serialize entries to a 1Password-compatible CSV with headers:
/// `Title,Username,Password,URL,OTPAuth,Notes`
pub fn export_1password_csv(entries: &[Entry]) -> Vec<u8> {
    let mut out = String::from("Title,Username,Password,URL,OTPAuth,Notes\n");
    for e in entries.iter().filter(|e| !e.deleted) {
        out.push_str(&csv_field(&e.title));
        out.push(',');
        out.push_str(&csv_field(&e.username));
        out.push(',');
        out.push_str(&csv_field(&e.password));
        out.push(',');
        out.push_str(&csv_field(&e.url));
        out.push(',');
        if let Some(secret) = &e.totp_secret {
            // title/username can contain arbitrary characters (':', '?',
            // '&', ...) — percent-encode them so the URI's query string
            // boundary is unambiguous. Otherwise a title like "Is this a
            // bank?" would shift where extract_totp_secret_from_uri thinks
            // the query starts, and the secret would silently fail to
            // round-trip back in on import.
            let title_enc = crate::oauth::percent_encode(&e.title);
            let user_enc = crate::oauth::percent_encode(&e.username);
            out.push_str(&csv_field(&format!(
                "otpauth://totp/{title_enc}:{user_enc}?secret={secret}&issuer={title_enc}"
            )));
        }
        out.push(',');
        out.push_str(&csv_field(&e.notes));
        out.push('\n');
    }
    out.into_bytes()
}

// ──────────────────────────────────────────────────────────────────────────────
// Proton Pass CSV
// ──────────────────────────────────────────────────────────────────────────────

/// Parse a Proton Pass CSV export file.
///
/// Proton Pass exports use these headers:
/// `name, url, email, password, note, totp`
pub fn import_protonpass_csv(csv_bytes: &[u8]) -> Result<Vec<Entry>, CoreError> {
    let text = std::str::from_utf8(csv_bytes)
        .map_err(|e| CoreError::InvalidFormat(format!("Proton Pass CSV is not valid UTF-8: {e}")))?;

    let now = crate::now_unix();
    let mut entries = Vec::new();
    let mut records = csv_records(text).into_iter();

    let header = records
        .next()
        .ok_or_else(|| CoreError::InvalidFormat("Proton Pass CSV has no header row".into()))?;
    let cols: Vec<String> = split_csv_row(header);
    let col_idx = |name: &str| cols.iter().position(|c| c.eq_ignore_ascii_case(name));

    let name_idx = col_idx("name");
    let url_idx = col_idx("url");
    let email_idx = col_idx("email").or_else(|| col_idx("username"));
    let pass_idx = col_idx("password");
    let note_idx = col_idx("note").or_else(|| col_idx("notes"));
    let totp_idx = col_idx("totp");

    for record in records {
        if record.trim().is_empty() {
            continue;
        }
        let fields = split_csv_row(record);
        // split_csv_row already stripped quotes and un-escaped `""`, so the
        // field is the real value already — no further trimming needed (and
        // trimming here was the bug: see split_csv_row's doc comment).
        // strip_formula_escape undoes csv_field's spreadsheet-injection guard.
        let get = |idx: Option<usize>| -> String {
            idx.and_then(|i| fields.get(i))
                .map(|v| strip_formula_escape(v))
                .unwrap_or_default()
        };

        let totp_raw = get(totp_idx);
        let totp_secret = if totp_raw.starts_with("otpauth://") {
            extract_totp_secret_from_uri(&totp_raw)
        } else if !totp_raw.is_empty() {
            Some(totp_raw)
        } else {
            None
        };

        entries.push(Entry {
            id: new_id()?,
            title: get(name_idx),
            username: get(email_idx),
            password: get(pass_idx),
            url: get(url_idx),
            notes: get(note_idx),
            totp_secret,
            custom_fields: HashMap::new(),
            updated_at: now,
            deleted: false,
            tags: vec![],
            collection_id: None,
            favorite: false,
            alias_provider: None,
            alias_id: None,
            alias_email: None,
            category: ItemCategory::Login,
            password_history: vec![],
            attachments: vec![],
        });
    }

    Ok(entries)
}

/// Serialize entries to a Proton Pass-compatible CSV with headers:
/// `name,url,email,password,note,totp`
pub fn export_protonpass_csv(entries: &[Entry]) -> Vec<u8> {
    let mut out = String::from("name,url,email,password,note,totp\n");
    for e in entries.iter().filter(|e| !e.deleted) {
        out.push_str(&csv_field(&e.title));
        out.push(',');
        out.push_str(&csv_field(&e.url));
        out.push(',');
        out.push_str(&csv_field(&e.username));
        out.push(',');
        out.push_str(&csv_field(&e.password));
        out.push(',');
        out.push_str(&csv_field(&e.notes));
        out.push(',');
        if let Some(secret) = &e.totp_secret {
            out.push_str(&csv_field(secret));
        }
        out.push('\n');
    }
    out.into_bytes()
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Generates a random RFC 4122 version-4 UUID, used as the id for every
/// entry produced by import. Must be a real CSPRNG draw, not a hash of
/// coarse, low-entropy inputs: this id is used to key entries in the vault
/// index and to name their `entries/{id}.enc` file on disk, so two entries
/// getting the same id during a bulk import silently overwrite one another.
/// (getrandom is already used everywhere else in this crate for exactly this
/// kind of unique/secret value, and already has wasm32 support configured in
/// Cargo.toml, so this works identically on native and in the browser build.)
fn new_id() -> Result<String, CoreError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| CoreError::InvalidFormat("failed to generate random id".to_string()))?;
    // RFC 4122 §4.4: set version (4) and variant (RFC 4122) bits.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ))
}

/// Leading characters that make a spreadsheet evaluate a cell as a formula
/// instead of showing it as text. Quoting does *not* help here: a quoted
/// `"=1+1"` is still evaluated by Excel, Sheets, and Numbers, so the only
/// mitigation is to change the leading byte of the value.
const FORMULA_TRIGGERS: [char; 6] = ['=', '+', '-', '@', '\t', '\r'];

/// Prefix written in front of a formula-triggering field by [`csv_field`].
const FORMULA_ESCAPE: char = '\'';

/// True if `value` would be executed as a formula when the exported file is
/// opened in a spreadsheet.
fn starts_formula(value: &str) -> bool {
    value.starts_with(|c| FORMULA_TRIGGERS.contains(&c))
}

/// Undoes the [`FORMULA_ESCAPE`] prefix added by [`csv_field`].
///
/// Only strips a leading `'` when the character right after it is itself a
/// formula trigger, so an ordinary value that happens to start with an
/// apostrophe (a French quote, say) survives a round-trip untouched.
fn strip_formula_escape(value: &str) -> String {
    match value.strip_prefix(FORMULA_ESCAPE) {
        Some(rest) if starts_formula(rest) => rest.to_string(),
        _ => value.to_string(),
    }
}

/// Renders one field for CSV output.
///
/// Quotes when the value contains a delimiter, a quote, or **either** newline
/// convention — a lone `\r` must be quoted too, otherwise `csv_records` treats
/// it as a record terminator and silently truncates the value on re-import.
/// (`\r\n` was already covered by the `\n` check; the bare-`\r` case was not.)
///
/// A value that would be executed as a spreadsheet formula is prefixed with
/// [`FORMULA_ESCAPE`] so it round-trips as literal text. `strip_formula_escape`
/// removes that prefix on import.
fn csv_field(value: &str) -> String {
    let needs_quotes = value.contains(',')
        || value.contains('"')
        || value.contains('\n')
        || value.contains('\r');

    let escaped = if starts_formula(value) {
        format!("{FORMULA_ESCAPE}{value}")
    } else {
        value.to_string()
    };

    if needs_quotes {
        format!("\"{}\"", escaped.replace('"', "\"\""))
    } else {
        escaped
    }
}

/// Splits CSV text into logical records, honoring RFC 4180 quoting: a newline
/// only terminates a record when it is *outside* a quoted field. A field like
/// `"line one\nline two"` therefore stays a single record instead of splitting
/// into two, which is what `str::lines()` did before (it cuts on every raw
/// newline, producing a phantom extra entry for every embedded line break —
/// including the ones Domi's own `export_*_csv` functions write).
///
/// The returned records keep their embedded newlines verbatim; `split_csv_row`
/// strips the surrounding quotes and un-escapes doubled `""` afterwards.
fn csv_records(text: &str) -> Vec<&str> {
    let mut records = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let bytes = text.as_bytes();

    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                // Inside a quoted field, `""` is a literal quote and must not
                // toggle quoting state. Mirrors split_csv_row's handling so
                // the two passes agree on where quotes open and close.
                if in_quotes && bytes.get(i + 1) == Some(&b'"') {
                    i += 1;
                } else {
                    in_quotes = !in_quotes;
                }
            }
            b'\r' | b'\n' if !in_quotes => {
                records.push(&text[start..i]);
                // Treat CRLF as a single terminator rather than two, so
                // Windows-origin exports (common from 1Password / Proton
                // Pass on Windows) don't yield an empty record between
                // every row.
                if bytes[i] == b'\r' && bytes.get(i + 1) == Some(&b'\n') {
                    i += 1;
                }
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start < bytes.len() {
        records.push(&text[start..]);
    }
    records
}

/// RFC 4180 field splitter. Unlike a naive quote-toggling splitter, this
/// actually consumes the surrounding quotes and un-escapes a doubled `""`
/// into a literal `"` as it goes, so callers get the real field value
/// directly — no separate `trim_matches('"')` pass is needed (and doing that
/// afterwards was the bug: it strips quote characters from both ends of the
/// raw token irrespective of how many of them were content vs. delimiters,
/// corrupting any field with an embedded escaped quote, e.g. `"Say ""Hi"""`
/// coming back as `Say "Hi"`).
fn split_csv_row(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if in_quotes {
            if c == '"' {
                if chars.get(i + 1) == Some(&'"') {
                    field.push('"');
                    i += 1; // consume the escaped pair together
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(c);
            }
        } else {
            match c {
                '"' => in_quotes = true,
                ',' => fields.push(std::mem::take(&mut field)),
                _ => field.push(c),
            }
        }
        i += 1;
    }
    fields.push(field);
    fields
}

fn extract_totp_secret_from_uri(uri: &str) -> Option<String> {
    uri.split('?')
        .nth(1)?
        .split('&')
        .find_map(|param| {
            let (k, v) = param.split_once('=')?;
            if k.eq_ignore_ascii_case("secret") {
                Some(v.to_string())
            } else {
                None
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bulk_import_produces_unique_ids() {
        // Regression test for the old new_id() implementation, which hashed
        // only a coarse clock reading + the (unchanging, within one loop)
        // thread id — entries imported back-to-back could collide and
        // silently overwrite each other. Import a decent-sized batch in a
        // tight loop (the worst case for a weak clock-based id) and check
        // every id came out distinct.
        let mut csv = String::from("title,username,password,url,notes\n");
        for i in 0..500 {
            csv.push_str(&format!("Item {i},user{i},pass{i},,\n"));
        }
        let entries = import_csv(csv.as_bytes()).unwrap();
        assert_eq!(entries.len(), 500);
        let unique: std::collections::HashSet<_> = entries.iter().map(|e| e.id.clone()).collect();
        assert_eq!(unique.len(), 500, "import produced duplicate entry ids");
    }

    #[test]
    fn onepassword_totp_roundtrip_survives_question_mark_in_title() {
        // Regression test: title/username used to be spliced unescaped into
        // the otpauth:// URI, so a literal '?' in the title shifted where
        // extract_totp_secret_from_uri thought the query string started,
        // silently dropping the secret on export -> reimport.
        let entries = vec![Entry {
            id: "test".into(),
            title: "Is this a bank?".into(),
            username: "alice".into(),
            password: "s3cr3t".into(),
            url: "".into(),
            notes: "".into(),
            totp_secret: Some("JBSWY3DPEHPK3PXP".into()),
            custom_fields: HashMap::new(),
            updated_at: 0,
            deleted: false,
            tags: vec![],
            collection_id: None,
            favorite: false,
            alias_provider: None,
            alias_id: None,
            alias_email: None,
            category: ItemCategory::Login,
            password_history: vec![],
            attachments: vec![],
        }];

        let exported = export_1password_csv(&entries);
        let reimported = import_1password_csv(&exported).unwrap();
        assert_eq!(reimported[0].totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn bitwarden_json_roundtrip() {
        let json = br#"{
            "items": [{
                "type": 1,
                "name": "GitHub",
                "notes": "work account",
                "login": {
                    "username": "dev@example.com",
                    "password": "s3cr3t!",
                    "totp": "JBSWY3DPEHPK3PXP",
                    "uris": [{"uri": "https://github.com"}]
                },
                "fields": [{"name": "recovery", "value": "abc123"}]
            }]
        }"#;

        let entries = import_bitwarden_json(json).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "GitHub");
        assert_eq!(entries[0].username, "dev@example.com");
        assert_eq!(entries[0].password, "s3cr3t!");
        assert_eq!(entries[0].url, "https://github.com");
        assert_eq!(entries[0].notes, "work account");
        assert_eq!(
            entries[0].totp_secret.as_deref(),
            Some("JBSWY3DPEHPK3PXP")
        );
        assert_eq!(
            entries[0].custom_fields.get("recovery").map(|s| s.as_str()),
            Some("abc123")
        );

        let exported = export_bitwarden_json(&entries).unwrap();
        let reimported = import_bitwarden_json(&exported).unwrap();
        assert_eq!(reimported[0].username, "dev@example.com");
    }

    #[test]
    fn bitwarden_json_roundtrip_preserves_bank_account_category() {
        // Bitwarden's `type` field has no bank-account value, so this used to
        // silently and permanently downgrade to Login on export. It should
        // now round-trip back to BankAccount via the marker custom field.
        let entries = vec![Entry {
            id: "test".into(),
            title: "My Bank".into(),
            username: "".into(),
            password: "".into(),
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
            category: ItemCategory::BankAccount,
            password_history: vec![],
            attachments: vec![],
        }];

        let exported = export_bitwarden_json(&entries).unwrap();
        // Still a valid, plain Bitwarden Login item — type 1 — for any
        // Bitwarden-side client that opens this export.
        let text = String::from_utf8(exported.clone()).unwrap();
        assert!(text.contains("\"type\": 1"));

        let reimported = import_bitwarden_json(&exported).unwrap();
        assert_eq!(reimported[0].category, ItemCategory::BankAccount);
        // Marker field shouldn't leak through as a visible custom field.
        assert!(!reimported[0].custom_fields.contains_key(CATEGORY_OVERRIDE_FIELD));
    }

    #[test]
    fn csv_roundtrip() {
        let csv = b"title,username,password,url,notes\nGitHub,user,pass123,https://github.com,work\n";
        let entries = import_csv(csv).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "GitHub");
        assert_eq!(entries[0].password, "pass123");

        let exported = export_csv(&entries);
        let reimported = import_csv(&exported).unwrap();
        assert_eq!(reimported[0].title, "GitHub");
        assert_eq!(reimported[0].password, "pass123");
    }

    #[test]
    fn onepassword_csv_extracts_totp_from_uri() {
        let csv = b"Title,Username,Password,URL,OTPAuth,Notes\nSlack,alice,s3cr3t,https://slack.com,otpauth://totp/Slack:alice?secret=JBSWY3DPEHPK3PXP&issuer=Slack,\n";
        let entries = import_1password_csv(csv).unwrap();
        assert_eq!(entries[0].totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn csv_handles_escaped_quotes_in_quoted_fields() {
        // RFC 4180: a literal `"` inside a quoted field is written as `""`.
        // Regression test for the split_csv_row bug where a trailing
        // trim_matches('"') pass mangled fields like this instead of the
        // parser itself consuming/un-escaping the quotes.
        let csv = b"title,username,password,url,notes\n\"Say \"\"Hi\"\"\",user,pass,,\n";
        let entries = import_csv(csv).unwrap();
        assert_eq!(entries[0].title, "Say \"Hi\"");
    }

    #[test]
    fn csv_handles_commas_in_quoted_fields() {
        let csv = b"title,username,password,url,notes\n\"Smith, John\",user,pass,,\"note with, comma\"\n";
        let entries = import_csv(csv).unwrap();
        assert_eq!(entries[0].title, "Smith, John");
        assert_eq!(entries[0].username, "user");
        assert_eq!(entries[0].notes, "note with, comma");
    }

    #[test]
    fn protonpass_csv_import() {
        let csv = b"name,url,email,password,note,totp\nGitHub,https://github.com,alice@example.com,s3cr3t!,work account,otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\nProton Mail,https://mail.proton.me,bob@proton.me,p@ss123,,\n";
        let entries = import_protonpass_csv(csv).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].title, "GitHub");
        assert_eq!(entries[0].username, "alice@example.com");
        assert_eq!(entries[0].password, "s3cr3t!");
        assert_eq!(entries[0].url, "https://github.com");
        assert_eq!(entries[0].notes, "work account");
        assert_eq!(entries[0].totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(entries[1].title, "Proton Mail");
        assert_eq!(entries[1].totp_secret, None);
    }

    #[test]
    fn protonpass_csv_handles_raw_totp_secret() {
        let csv = b"name,url,email,password,note,totp\nSlack,https://slack.com,user@x.com,pass123,,JBSWY3DPEHPK3PXP\n";
        let entries = import_protonpass_csv(csv).unwrap();
        assert_eq!(entries[0].totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn onepassword_csv_export_roundtrip() {
        let csv = b"Title,Username,Password,URL,OTPAuth,Notes\nSlack,alice,s3cr3t,https://slack.com,otpauth://totp/Slack:alice?secret=JBSWY3DPEHPK3PXP&issuer=Slack,work\nGitHub,bob,p@ss,https://github.com,,personal\n";
        let entries = import_1password_csv(csv).unwrap();
        assert_eq!(entries.len(), 2);

        let exported = export_1password_csv(&entries);
        let reimported = import_1password_csv(&exported).unwrap();
        assert_eq!(reimported.len(), 2);
        assert_eq!(reimported[0].title, "Slack");
        assert_eq!(reimported[0].username, "alice");
        assert_eq!(reimported[0].password, "s3cr3t");
        assert_eq!(reimported[0].url, "https://slack.com");
        assert_eq!(reimported[0].totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(reimported[0].notes, "work");
        assert_eq!(reimported[1].title, "GitHub");
        assert_eq!(reimported[1].totp_secret, None);
    }

    #[test]
    fn onepassword_csv_export_without_totp() {
        let entries = vec![Entry {
            id: "test".into(),
            title: "No TOTP".into(),
            username: "alice".into(),
            password: "pass".into(),
            url: "https://example.com".into(),
            notes: "notes".into(),
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
            category: ItemCategory::Login,
            password_history: vec![],
            attachments: vec![],
        }];
        let exported = export_1password_csv(&entries);
        let text = String::from_utf8(exported).unwrap();
        // OTPAuth column should be empty
        assert!(text.contains("No TOTP,alice,pass,https://example.com,,notes"));
    }

    #[test]
    fn protonpass_csv_export_roundtrip() {
        let csv = b"name,url,email,password,note,totp\nGitHub,https://github.com,alice@example.com,s3cr3t!,work account,otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\nProton Mail,https://mail.proton.me,bob@proton.me,p@ss123,,\n";
        let entries = import_protonpass_csv(csv).unwrap();
        assert_eq!(entries.len(), 2);

        let exported = export_protonpass_csv(&entries);
        let reimported = import_protonpass_csv(&exported).unwrap();
        assert_eq!(reimported.len(), 2);
        assert_eq!(reimported[0].title, "GitHub");
        assert_eq!(reimported[0].username, "alice@example.com");
        assert_eq!(reimported[0].password, "s3cr3t!");
        assert_eq!(reimported[0].url, "https://github.com");
        assert_eq!(reimported[0].notes, "work account");
        assert_eq!(reimported[0].totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(reimported[1].title, "Proton Mail");
        assert_eq!(reimported[1].totp_secret, None);
    }

    #[test]
    fn protonpass_csv_export_raw_totp_passthrough() {
        let csv = b"name,url,email,password,note,totp\nSlack,https://slack.com,user@x.com,pass123,,JBSWY3DPEHPK3PXP\n";
        let entries = import_protonpass_csv(csv).unwrap();

        let exported = export_protonpass_csv(&entries);
        let reimported = import_protonpass_csv(&exported).unwrap();
        assert_eq!(reimported[0].totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn export_skips_deleted_entries() {
        let entries = vec![
            Entry {
                id: "1".into(),
                title: "Keep".into(),
                username: "u".into(),
                password: "p".into(),
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
                category: ItemCategory::Login,
                password_history: vec![],
                attachments: vec![],
            },
            Entry {
                id: "2".into(),
                title: "Deleted".into(),
                username: "u".into(),
                password: "p".into(),
                url: "".into(),
                notes: "".into(),
                totp_secret: None,
                custom_fields: HashMap::new(),
                updated_at: 0,
                deleted: true,
                tags: vec![],
                collection_id: None,
                favorite: false,
                alias_provider: None,
                alias_id: None,
                alias_email: None,
                category: ItemCategory::Login,
                password_history: vec![],
                attachments: vec![],
            },
        ];

        let exported_1p = export_1password_csv(&entries);
        let text_1p = String::from_utf8(exported_1p).unwrap();
        assert!(text_1p.contains("Keep"));
        assert!(!text_1p.contains("Deleted"));

        let exported_pp = export_protonpass_csv(&entries);
        let text_pp = String::from_utf8(exported_pp).unwrap();
        assert!(text_pp.contains("Keep"));
        assert!(!text_pp.contains("Deleted"));
    }

    // ---- Multi-line (RFC 4180 quoted) CSV fields --------------------------
    //
    // All three CSV importers used to split records with `str::lines()`,
    // which cuts on every raw newline and ignores quoting entirely. A field
    // with an embedded line break — a multi-line note, a pasted passphrase —
    // therefore split into extra records, each importing as its own entry
    // with the continuation line's text landing in the first column. This
    // also broke Domi's own export → import round-trip, since every
    // `export_*_csv` below legitimately writes quoted multi-line fields.

    #[test]
    fn csv_records_keeps_quoted_newlines_inside_one_record() {
        let records = csv_records("a,\"line one\nline two\"\nc\n");
        assert_eq!(records, vec!["a,\"line one\nline two\"", "c"]);
    }

    #[test]
    fn csv_records_does_not_toggle_quotes_on_escaped_pairs() {
        // `""` inside a quoted field is a literal quote, not a close+reopen,
        // so the newline after it is still inside the quoted field.
        let records = csv_records("a,\"say \"\"hi\"\"\nthere\"\nb\n");
        assert_eq!(records, vec!["a,\"say \"\"hi\"\"\nthere\"", "b"]);
    }

    #[test]
    fn csv_records_handles_crlf_and_missing_trailing_newline() {
        assert_eq!(csv_records("a,b\r\nc,d\r\n"), vec!["a,b", "c,d"]);
        assert_eq!(csv_records("a,b"), vec!["a,b"]);
        assert_eq!(csv_records(""), Vec::<&str>::new());
    }

    #[test]
    fn generic_csv_import_keeps_multiline_note_as_single_entry() {
        let csv = "title,username,password,url,notes\n\
                   Bank,me,pw,bank.com,\"first line\nsecond line\"\n\
                   Email,me,pw,mail.com,single\n";
        let entries = import_csv(csv.as_bytes()).unwrap();

        assert_eq!(entries.len(), 2, "multi-line note must not create a phantom entry");
        assert_eq!(entries[0].title, "Bank");
        assert_eq!(entries[0].username, "me");
        assert_eq!(entries[0].notes, "first line\nsecond line");
        assert_eq!(entries[1].title, "Email");
        assert_eq!(entries[1].notes, "single");
    }

    #[test]
    fn onepassword_csv_import_keeps_multiline_note_as_single_entry() {
        let csv = "Title,Username,Password,URL,OTPAuth,Notes\n\
                   Bank,me,pw,bank.com,,\"first line\nsecond line\"\n\
                   Email,me,pw,mail.com,,single\n";
        let entries = import_1password_csv(csv.as_bytes()).unwrap();

        assert_eq!(entries.len(), 2, "multi-line note must not create a phantom entry");
        assert_eq!(entries[0].title, "Bank");
        assert_eq!(entries[0].notes, "first line\nsecond line");
        assert_eq!(entries[1].title, "Email");
    }

    #[test]
    fn protonpass_csv_import_keeps_multiline_note_as_single_entry() {
        let csv = "name,url,email,password,note,totp\n\
                   Bank,bank.com,me,pw,\"first line\nsecond line\",\n\
                   Email,mail.com,me,pw,single,\n";
        let entries = import_protonpass_csv(csv.as_bytes()).unwrap();

        assert_eq!(entries.len(), 2, "multi-line note must not create a phantom entry");
        assert_eq!(entries[0].title, "Bank");
        assert_eq!(entries[0].notes, "first line\nsecond line");
        assert_eq!(entries[1].title, "Email");
    }

    #[test]
    fn generic_csv_export_import_roundtrip_preserves_multiline_notes() {
        let entries = vec![Entry {
            id: "e1".into(),
            title: "Multi".into(),
            username: "u".into(),
            password: "p".into(),
            url: "https://x.com".into(),
            notes: "line one\nline two".into(),
            totp_secret: None,
            custom_fields: HashMap::new(),
            updated_at: 1,
            deleted: false,
            tags: vec![],
            collection_id: None,
            favorite: false,
            alias_provider: None,
            alias_id: None,
            alias_email: None,
            category: ItemCategory::Login,
            password_history: vec![],
            attachments: vec![],
        }];

        let exported = export_csv(&entries);
        let reimported = import_csv(&exported).unwrap();

        assert_eq!(reimported.len(), 1);
        assert_eq!(reimported[0].notes, "line one\nline two");
        assert_eq!(reimported[0].title, "Multi");
    }

    #[test]
    fn onepassword_and_protonpass_roundtrips_preserve_multiline_notes() {
        let entries = vec![Entry {
            id: "e1".into(),
            title: "Multi".into(),
            username: "u".into(),
            password: "p".into(),
            url: "https://x.com".into(),
            notes: "line one\nline two".into(),
            totp_secret: Some("JBSWY3DPEHPK3PXP".into()),
            custom_fields: HashMap::new(),
            updated_at: 1,
            deleted: false,
            tags: vec![],
            collection_id: None,
            favorite: false,
            alias_provider: None,
            alias_id: None,
            alias_email: None,
            category: ItemCategory::Login,
            password_history: vec![],
            attachments: vec![],
        }];

        let reimported_1p = import_1password_csv(&export_1password_csv(&entries)).unwrap();
        assert_eq!(reimported_1p.len(), 1);
        assert_eq!(reimported_1p[0].notes, "line one\nline two");

        let reimported_pp = import_protonpass_csv(&export_protonpass_csv(&entries)).unwrap();
        assert_eq!(reimported_pp.len(), 1);
        assert_eq!(reimported_pp[0].notes, "line one\nline two");
    }

    #[test]
    fn csv_import_multiline_title_stays_in_title_column() {
        // Guards the specific column-alignment failure mode: previously the
        // continuation line was parsed as its own row, so the text after the
        // newline landed in `title` rather than the notes field it came from.
        let csv = "title,username,password,url,notes\n\
                   \"Acme Corp\nHoldings\",u,p,,unrelated\n";
        let entries = import_csv(csv.as_bytes()).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "Acme Corp\nHoldings");
        assert_eq!(entries[0].notes, "unrelated");
    }

    // ---- Lone carriage returns --------------------------------------------
    //
    // csv_field used to quote on ',', '"' and '\n' but not '\r'. A field with
    // a lone CR was therefore written unquoted, and csv_records — correctly,
    // per RFC 4180 — treated that CR as a record terminator. The value was
    // silently truncated at the CR and a phantom entry appeared.

    #[test]
    fn csv_field_quotes_lone_carriage_return() {
        assert_eq!(csv_field("a\rb"), "\"a\rb\"");
        // \n and \r\n were already quoted; make sure that still holds.
        assert_eq!(csv_field("a\nb"), "\"a\nb\"");
        assert_eq!(csv_field("a\r\nb"), "\"a\r\nb\"");
        // Plain values stay unquoted.
        assert_eq!(csv_field("plain"), "plain");
    }

    #[test]
    fn csv_roundtrip_preserves_lone_carriage_return() {
        for raw in ["a\rb", "a\nb", "a\r\nb", "\rleading", "trailing\r"] {
            let entries = vec![Entry {
                id: "e1".into(),
                title: raw.into(),
                username: "u".into(),
                password: "p".into(),
                url: "".into(),
                notes: raw.into(),
                totp_secret: None,
                custom_fields: HashMap::new(),
                updated_at: 1,
                deleted: false,
                tags: vec![],
                collection_id: None,
                favorite: false,
                alias_provider: None,
                alias_id: None,
                alias_email: None,
                category: ItemCategory::Login,
                password_history: vec![],
                attachments: vec![],
            }];

            let back = import_csv(&export_csv(&entries)).unwrap();
            assert_eq!(back.len(), 1, "lone CR split {raw:?} into extra entries");
            assert_eq!(back[0].title, raw, "title mangled for {raw:?}");
            assert_eq!(back[0].notes, raw, "notes mangled for {raw:?}");
        }
    }

    #[test]
    fn onepassword_and_protonpass_roundtrip_preserve_lone_carriage_return() {
        let entries = vec![Entry {
            id: "e1".into(),
            title: "a\rb".into(),
            username: "u".into(),
            password: "p".into(),
            url: "https://x.com".into(),
            notes: "a\rb".into(),
            totp_secret: Some("JBSWY3DPEHPK3PXP".into()),
            custom_fields: HashMap::new(),
            updated_at: 1,
            deleted: false,
            tags: vec![],
            collection_id: None,
            favorite: false,
            alias_provider: None,
            alias_id: None,
            alias_email: None,
            category: ItemCategory::Login,
            password_history: vec![],
            attachments: vec![],
        }];

        let back_1p = import_1password_csv(&export_1password_csv(&entries)).unwrap();
        assert_eq!(back_1p.len(), 1);
        assert_eq!(back_1p[0].title, "a\rb");
        assert_eq!(back_1p[0].notes, "a\rb");

        let back_pp = import_protonpass_csv(&export_protonpass_csv(&entries)).unwrap();
        assert_eq!(back_pp.len(), 1);
        assert_eq!(back_pp[0].title, "a\rb");
        assert_eq!(back_pp[0].notes, "a\rb");
    }

    // ---- Spreadsheet formula injection ------------------------------------

    #[test]
    fn csv_field_neutralizes_formula_triggers() {
        // Quoting alone does not stop a spreadsheet evaluating a cell, so the
        // value's leading byte has to change.
        assert_eq!(csv_field("=1+1"), "'=1+1");
        assert_eq!(csv_field("+cmd"), "'+cmd");
        assert_eq!(csv_field("-2+3"), "'-2+3");
        assert_eq!(csv_field("@SUM(A1)"), "'@SUM(A1)");
        assert_eq!(csv_field("\t=evil"), "'\t=evil");
        assert_eq!(csv_field("\r=evil"), "\"'\r=evil\"");
        // Not triggers — left alone.
        assert_eq!(csv_field("normal"), "normal");
        assert_eq!(csv_field("1+1"), "1+1");
    }

    #[test]
    fn strip_formula_escape_only_removes_real_escapes() {
        // A genuine export escape is undone...
        assert_eq!(strip_formula_escape("'=1+1"), "=1+1");
        assert_eq!(strip_formula_escape("'+cmd"), "+cmd");
        assert_eq!(strip_formula_escape("'@x"), "@x");
        // ...but an apostrophe that isn't an escape is left alone.
        assert_eq!(strip_formula_escape("'quoted"), "'quoted");
        assert_eq!(strip_formula_escape("'"), "'");
        assert_eq!(strip_formula_escape("it's fine"), "it's fine");
        assert_eq!(strip_formula_escape("plain"), "plain");
    }

    #[test]
    fn formula_prefixed_export_roundtrips_to_the_original_value() {
        for raw in [
            "=1+1",
            "+cmd|calc",
            "-2+3",
            "@SUM(A1)",
            "\t=evil",
            "\r=evil",
            "'quoted",
            "normal",
            "1+1",
        ] {
            let entries = vec![Entry {
                id: "e1".into(),
                title: raw.into(),
                username: raw.into(),
                password: "p".into(),
                url: "".into(),
                notes: raw.into(),
                totp_secret: None,
                custom_fields: HashMap::new(),
                updated_at: 1,
                deleted: false,
                tags: vec![],
                collection_id: None,
                favorite: false,
                alias_provider: None,
                alias_id: None,
                alias_email: None,
                category: ItemCategory::Login,
                password_history: vec![],
                attachments: vec![],
            }];

            let csv = String::from_utf8(export_csv(&entries)).unwrap();
            let back = import_csv(csv.as_bytes()).unwrap();

            assert_eq!(back.len(), 1, "{raw:?} split into extra entries");
            assert_eq!(back[0].title, raw, "title changed for {raw:?}");
            assert_eq!(back[0].username, raw, "username changed for {raw:?}");
            assert_eq!(back[0].notes, raw, "notes changed for {raw:?}");

            // The exported text itself must not begin a cell with a live
            // formula trigger — that's the whole point of the guard.
            let first_field = csv.lines().nth(1).unwrap();
            let cell = first_field.split(',').next().unwrap().trim_matches('"');
            assert!(
                !starts_formula(cell),
                "export still begins with a formula trigger: {cell:?}"
            );
        }
    }

    #[test]
    fn importing_third_party_csv_preserves_leading_equals_signs() {
        // A CSV produced by another password manager (no Domi escape prefix)
        // must import its values verbatim — we only strip a prefix we wrote.
        let csv = "title,username,password,url,notes\n=cmd,=SUM(A1),p,,plain\n";
        let entries = import_csv(csv.as_bytes()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "=cmd");
        assert_eq!(entries[0].username, "=SUM(A1)");
        assert_eq!(entries[0].notes, "plain");
    }

    #[test]
    fn onepassword_and_protonpass_formula_roundtrips() {
        let entries = vec![Entry {
            id: "e1".into(),
            title: "=1+1".into(),
            username: "@SUM(A1)".into(),
            password: "p".into(),
            url: "https://x.com".into(),
            notes: "+cmd".into(),
            totp_secret: Some("JBSWY3DPEHPK3PXP".into()),
            custom_fields: HashMap::new(),
            updated_at: 1,
            deleted: false,
            tags: vec![],
            collection_id: None,
            favorite: false,
            alias_provider: None,
            alias_id: None,
            alias_email: None,
            category: ItemCategory::Login,
            password_history: vec![],
            attachments: vec![],
        }];

        let back_1p = import_1password_csv(&export_1password_csv(&entries)).unwrap();
        assert_eq!(back_1p.len(), 1);
        assert_eq!(back_1p[0].title, "=1+1");
        assert_eq!(back_1p[0].username, "@SUM(A1)");
        assert_eq!(back_1p[0].notes, "+cmd");

        let back_pp = import_protonpass_csv(&export_protonpass_csv(&entries)).unwrap();
        assert_eq!(back_pp.len(), 1);
        assert_eq!(back_pp[0].title, "=1+1");
        assert_eq!(back_pp[0].notes, "+cmd");
    }
}
