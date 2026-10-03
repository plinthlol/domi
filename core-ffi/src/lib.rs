// UniFFI's generated scaffolding (written into target/ by build.rs) trips
// clippy's `empty_line_after_doc_comments` lint. It isn't our code and can't
// be edited, so silence that one lint at the crate level rather than leaving
// the warning permanently unfixable.
#![allow(clippy::empty_line_after_doc_comments)]

use base64::Engine;
use domi_core::{
    assign_tag,
    check_strength as core_check_strength,
    create_collection,
    create_tag,
    delete_collection,
    delete_tag,
    generate_password as core_generate_password,
    generate_totp as core_generate_totp,
    generate_pkce as core_generate_pkce,
    generate_oauth_state as core_generate_oauth_state,
    build_auth_url as core_build_auth_url,
    build_token_exchange_request as core_build_token_exchange_request,
    parse_token_response as core_parse_token_response,
    list_children,
    list_favorites,
    list_root,
    list_tags,
    merge,
    move_entry,
    provider_for,
    remove_tag_from_entry,
    rename_collection,
    rename_tag,
    record_password_change as core_record_password_change,
    restore_password as core_restore_password,
    import_bitwarden_json as core_import_bitwarden_json,
    export_bitwarden_json as core_export_bitwarden_json,
    import_csv as core_import_csv,
    export_csv as core_export_csv,
    import_1password_csv as core_import_1password_csv,
    export_1password_csv as core_export_1password_csv,
    import_protonpass_csv as core_import_protonpass_csv,
    export_protonpass_csv as core_export_protonpass_csv,
    get_breach_hash_parts as core_get_breach_hash_parts,
    BreachHashParts,
    search::SearchCache,
    search_by_collection,
    search_by_tag,
    search_favorites,
    set_favorite,
    Attachment,
    CoreError,
    Entry,
    FavoriteSort,
    Index,
    KdfParams,
    Vault,
    VaultManifest,
    ConflictStrategy,
    PendingChanges,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

uniffi::include_scaffolding!("domi");

const BASE64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

#[derive(Debug, thiserror::Error)]
pub enum DomiError {
    #[error("wrong password or corrupted vault")]
    DecryptionFailed,
    #[error("vault is locked")]
    VaultLocked,
    #[error("entry not found: {id}")]
    NotFound { id: String },
    #[error("vault version {version} is newer than this app supports")]
    UnsupportedVersion { version: u32 },
    #[error("malformed data: {message}")]
    InvalidFormat { message: String },
    #[error("already exists: {message}")]
    AlreadyExists { message: String },
    #[error("invalid operation: {message}")]
    InvalidOperation { message: String },
}

impl From<CoreError> for DomiError {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::DecryptionFailed => DomiError::DecryptionFailed,
            CoreError::VaultLocked => DomiError::VaultLocked,
            CoreError::NotFound(id) => DomiError::NotFound { id },
            CoreError::UnsupportedVersion(v) => DomiError::UnsupportedVersion { version: v },
            CoreError::InvalidFormat(msg) => DomiError::InvalidFormat { message: msg },
            CoreError::AlreadyExists(msg) => DomiError::AlreadyExists { message: msg },
            CoreError::InvalidOperation(msg) => DomiError::InvalidOperation { message: msg },
        }
    }
}

fn base64_decode(s: &str) -> Result<Vec<u8>, DomiError> {
    BASE64.decode(s).map_err(|e| DomiError::InvalidFormat {
        message: format!("base64 decode error: {e}"),
    })
}

fn to_json<T: serde::Serialize>(value: &T) -> Result<String, DomiError> {
    serde_json::to_string(value).map_err(|e| DomiError::InvalidFormat { message: e.to_string() })
}

fn parse_index(json: &str) -> Result<Index, DomiError> {
    serde_json::from_str(json)
        .map_err(|e| DomiError::InvalidFormat { message: format!("bad index: {e}") })
}

fn parse_entry(json: &str) -> Result<Entry, DomiError> {
    serde_json::from_str(json)
        .map_err(|e| DomiError::InvalidFormat { message: format!("bad entry: {e}") })
}

// --- Opaque vault handle registry -----------------------------------------
//
// The Vault (and the zeroize-on-drop Key inside it) never leaves this
// process, let alone this crate: Swift/Kotlin only ever see an opaque u64
// handle. This replaces the previous design where create_vault/unlock_vault
// derived the key a second time and returned it as a base64 String — see
// AUDIT.md §1 / DOMI_AUDIT_FINDINGS.md [HIGH] for why that was unsafe.
// Dropping a handle's entry (lock_vault, or process exit) runs Key's
// ZeroizeOnDrop as normal.

fn vaults() -> &'static Mutex<HashMap<u64, Vault>> {
    static VAULTS: OnceLock<Mutex<HashMap<u64, Vault>>> = OnceLock::new();
    VAULTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_handle() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::SeqCst)
}

fn with_vault<T>(
    handle: u64,
    f: impl FnOnce(&Vault) -> Result<T, CoreError>,
) -> Result<T, DomiError> {
    let guard = vaults().lock().map_err(|_| DomiError::InvalidFormat {
        message: "vault registry lock poisoned".into(),
    })?;
    let vault = guard.get(&handle).ok_or(DomiError::VaultLocked)?;
    f(vault).map_err(DomiError::from)
}

fn with_vault_mut<T>(
    handle: u64,
    f: impl FnOnce(&mut Vault) -> Result<T, CoreError>,
) -> Result<T, DomiError> {
    let mut guard = vaults().lock().map_err(|_| DomiError::InvalidFormat {
        message: "vault registry lock poisoned".into(),
    })?;
    let vault = guard.get_mut(&handle).ok_or(DomiError::VaultLocked)?;
    f(vault).map_err(DomiError::from)
}

pub struct CreateVaultResult {
    pub manifest_json: String,
    pub index_enc_b64: String,
    pub handle: u64,
}

pub fn create_vault(password: String) -> Result<CreateVaultResult, DomiError> {
    let params = KdfParams::default();
    let (vault, manifest, index_enc) = Vault::create(&password, params).map_err(DomiError::from)?;
    let handle = next_handle();
    vaults().lock().map_err(|_| DomiError::InvalidFormat {
        message: "vault registry lock poisoned".into(),
    })?.insert(handle, vault);
    Ok(CreateVaultResult {
        manifest_json: serde_json::to_string(&manifest)
            .map_err(|e| DomiError::InvalidFormat { message: e.to_string() })?,
        index_enc_b64: BASE64.encode(&index_enc),
        handle,
    })
}

pub struct UnlockVaultResult {
    pub index_json: String,
    pub handle: u64,
}

pub fn unlock_vault(
    manifest_json: String,
    index_enc_b64: String,
    password: String,
) -> Result<UnlockVaultResult, DomiError> {
    let manifest: VaultManifest = serde_json::from_str(&manifest_json)
        .map_err(|e| DomiError::InvalidFormat { message: format!("bad manifest: {e}") })?;
    let index_enc = base64_decode(&index_enc_b64)?;
    let (vault, index) = Vault::unlock(&manifest, &index_enc, &password).map_err(DomiError::from)?;
    let handle = next_handle();
    vaults().lock().map_err(|_| DomiError::InvalidFormat {
        message: "vault registry lock poisoned".into(),
    })?.insert(handle, vault);
    Ok(UnlockVaultResult {
        index_json: serde_json::to_string(&index)
            .map_err(|e| DomiError::InvalidFormat { message: e.to_string() })?,
        handle,
    })
}

/// Drops the vault (and zeroizes its key) and invalidates the handle.
/// Safe to call on an already-locked/unknown handle (no-op).
pub fn lock_vault(handle: u64) {
    if let Ok(mut guard) = vaults().lock() {
        guard.remove(&handle);
    }
}

pub fn vault_encrypt(handle: u64, plaintext: Vec<u8>, aad: Vec<u8>) -> Result<String, DomiError> {
    let ciphertext = with_vault(handle, |v| v.encrypt(&plaintext, &aad))?;
    Ok(BASE64.encode(ciphertext))
}

pub fn vault_decrypt(handle: u64, ciphertext_b64: String, aad: Vec<u8>) -> Result<Vec<u8>, DomiError> {
    let ciphertext = base64_decode(&ciphertext_b64)?;
    with_vault(handle, |v| v.decrypt(&ciphertext, &aad))
}

pub fn vault_decrypt_entry(
    handle: u64,
    entry_enc_b64: String,
    entry_id: String,
) -> Result<String, DomiError> {
    let entry_enc = base64_decode(&entry_enc_b64)?;
    let entry = with_vault(handle, |v| v.decrypt_entry(&entry_enc, &entry_id))?;
    serde_json::to_string(&entry).map_err(|e| DomiError::InvalidFormat { message: e.to_string() })
}

pub struct PutEntryResult {
    pub entry_enc_b64: String,
    pub index_enc_b64: String,
    pub index_json: String,
}

pub fn vault_put_entry(
    handle: u64,
    index_json: String,
    entry_json: String,
) -> Result<PutEntryResult, DomiError> {
    let mut index: Index = serde_json::from_str(&index_json)
        .map_err(|e| DomiError::InvalidFormat { message: format!("bad index: {e}") })?;
    let entry: Entry = serde_json::from_str(&entry_json)
        .map_err(|e| DomiError::InvalidFormat { message: format!("bad entry: {e}") })?;

    let (entry_enc, index_enc) = with_vault(handle, |v| v.put_entry(&mut index, entry))?;

    Ok(PutEntryResult {
        entry_enc_b64: BASE64.encode(entry_enc),
        index_enc_b64: BASE64.encode(index_enc),
        index_json: serde_json::to_string(&index)
            .map_err(|e| DomiError::InvalidFormat { message: e.to_string() })?,
    })
}

pub struct RekeyEntryInputFfi {
    pub id: String,
    pub entry_enc_b64: String,
}

pub struct RekeyEntryOutputFfi {
    pub id: String,
    pub new_entry_enc_b64: String,
}

pub struct RekeyResultFfi {
    pub manifest_json: String,
    pub index_enc_b64: String,
    pub reencrypted_entries: Vec<RekeyEntryOutputFfi>,
}

pub fn vault_rekey(
    handle: u64,
    index_json: String,
    entries: Vec<RekeyEntryInputFfi>,
    new_password: String,
) -> Result<RekeyResultFfi, DomiError> {
    let index = parse_index(&index_json)?;
    let mut decoded_entries = Vec::with_capacity(entries.len());
    for item in &entries {
        let bytes = base64_decode(&item.entry_enc_b64)?;
        decoded_entries.push((item.id.clone(), bytes));
    }
    let refs: Vec<(&str, &[u8])> = decoded_entries
        .iter()
        .map(|(id, bytes)| (id.as_str(), bytes.as_slice()))
        .collect();

    let params = KdfParams::default();
    let res = with_vault_mut(handle, |v| v.rekey(&index, &refs, &new_password, params))?;

    let manifest_json = serde_json::to_string(&res.manifest)
        .map_err(|e| DomiError::InvalidFormat { message: e.to_string() })?;
    let index_enc_b64 = BASE64.encode(&res.index_enc);
    let reencrypted_entries = res
        .entries_enc
        .into_iter()
        .map(|(id, bytes)| RekeyEntryOutputFfi {
            id,
            new_entry_enc_b64: BASE64.encode(bytes),
        })
        .collect();

    Ok(RekeyResultFfi {
        manifest_json,
        index_enc_b64,
        reencrypted_entries,
    })
}

// --- Everything below is unchanged: none of it ever touched key material ---

pub fn generate_password(
    length: u32,
    uppercase: bool,
    lowercase: bool,
    numbers: bool,
    symbols: bool,
) -> Result<String, DomiError> {
    core_generate_password(length as usize, uppercase, lowercase, numbers, symbols)
        .map_err(DomiError::from)
}

pub fn check_strength(password: String) -> u8 {
    core_check_strength(&password)
}

pub fn generate_totp(
    secret_base32: String,
    time_step_seconds: u64,
    current_unix_time: u64,
    digits: u32,
) -> Result<String, DomiError> {
    core_generate_totp(&secret_base32, time_step_seconds, current_unix_time, digits)
        .map_err(DomiError::from)
}

pub fn get_breach_hash_parts(password: String) -> Result<BreachHashParts, DomiError> {
    core_get_breach_hash_parts(&password).map_err(DomiError::from)
}

pub fn search_index(index_json: String, term: String) -> Result<String, DomiError> {
    let index: Index = serde_json::from_str(&index_json)
        .map_err(|e| DomiError::InvalidFormat { message: format!("bad index: {e}") })?;
    let cache = SearchCache::rebuild_from_index(&index);
    let items = cache.query(&term);
    serde_json::to_string(&items)
        .map_err(|e| DomiError::InvalidFormat { message: e.to_string() })
}

pub fn merge_indexes(local_json: String, remote_json: String) -> Result<String, DomiError> {
    let local: Index = serde_json::from_str(&local_json)
        .map_err(|e| DomiError::InvalidFormat { message: format!("bad local index: {e}") })?;
    let remote: Index = serde_json::from_str(&remote_json)
        .map_err(|e| DomiError::InvalidFormat { message: format!("bad remote index: {e}") })?;
    let result = merge(&local, &remote).map_err(DomiError::from)?;
    serde_json::to_string(&result)
        .map_err(|e| DomiError::InvalidFormat { message: e.to_string() })
}

pub struct PkcePair {
    pub code_verifier: String,
    pub code_challenge: String,
}

pub fn generate_pkce() -> Result<PkcePair, DomiError> {
    let pair = core_generate_pkce().map_err(DomiError::from)?;
    Ok(PkcePair {
        code_verifier: pair.code_verifier,
        code_challenge: pair.code_challenge,
    })
}

pub fn generate_oauth_state() -> Result<String, DomiError> {
    core_generate_oauth_state().map_err(DomiError::from)
}

pub struct OAuthTokensFfi { pub access_token: String, pub refresh_token: Option<String>, pub expires_at: Option<i64> }
impl From<domi_core::OAuthTokens> for OAuthTokensFfi { fn from(t: domi_core::OAuthTokens) -> Self { Self { access_token: t.access_token, refresh_token: t.refresh_token, expires_at: t.expires_at } } }

pub fn build_auth_url(provider: String, client_id: String, redirect_uri: String, pkce_json: String, state: String) -> Result<String, DomiError> {
    let provider = parse_oauth_provider(&provider)?;
    let pkce: domi_core::PkcePair = serde_json::from_str(&pkce_json).map_err(|e| DomiError::InvalidFormat { message: e.to_string() })?;
    Ok(core_build_auth_url(provider, &client_id, &redirect_uri, &pkce, &state))
}
pub fn build_token_exchange_request(token_url: String, client_id: String, code: String, redirect_uri: String, verifier: String) -> HttpRequestSpecFfi {
    core_build_token_exchange_request(&token_url, &client_id, &code, &redirect_uri, &verifier).into()
}
pub fn parse_token_response(response_body: Vec<u8>, current_unix_time: i64) -> Result<OAuthTokensFfi, DomiError> { core_parse_token_response(&response_body, current_unix_time).map(Into::into).map_err(Into::into) }
pub fn vault_encrypt_tokens(handle: u64, tokens_json: String) -> Result<String, DomiError> { let tokens: domi_core::OAuthTokens = serde_json::from_str(&tokens_json).map_err(|e| DomiError::InvalidFormat { message: e.to_string() })?; Ok(BASE64.encode(with_vault(handle, |v| v.encrypt_tokens(&tokens))?)) }
pub fn vault_decrypt_tokens(handle: u64, ciphertext_b64: String) -> Result<OAuthTokensFfi, DomiError> { let bytes = base64_decode(&ciphertext_b64)?; with_vault(handle, |v| v.decrypt_tokens(&bytes)).map(Into::into) }
pub fn vault_save_search_cache(handle: u64, index_json: String) -> Result<String, DomiError> { let index = parse_index(&index_json)?; let cache = SearchCache::rebuild_from_index(&index); Ok(BASE64.encode(with_vault(handle, |v| v.save_search_cache(&cache))?)) }
pub fn vault_load_search_cache_query(handle: u64, ciphertext_b64: String, term: String) -> Result<String, DomiError> { let bytes = base64_decode(&ciphertext_b64)?; let items = with_vault(handle, |v| v.load_search_cache(&bytes).map(|c| c.query(&term).into_iter().cloned().collect::<Vec<_>>()))?; to_json(&items) }

fn parse_oauth_provider(provider: &str) -> Result<domi_core::OAuthProvider, DomiError> { match provider.to_lowercase().as_str() { "googledrive" | "google" => Ok(domi_core::OAuthProvider::GoogleDrive), "dropbox" => Ok(domi_core::OAuthProvider::Dropbox), "onedrive" | "microsoft" => Ok(domi_core::OAuthProvider::OneDrive), other => Err(DomiError::InvalidFormat { message: format!("unknown OAuth provider: {other}") }) } }
pub fn sync_pending_apply(pending_json: String, operation: String, id: String) -> Result<String, DomiError> { let mut p: PendingChanges = serde_json::from_str(&pending_json).map_err(|e| DomiError::InvalidFormat { message: e.to_string() })?; match operation.as_str() { "enqueue" => p.enqueue(&id), "dequeue" => p.dequeue(&id), "reset_retry" => p.reset_retry(&id), "record_failure" => { p.record_failure(&id); }, other => return Err(DomiError::InvalidOperation { message: format!("unknown pending operation: {other}") }) }; to_json(&p) }
pub fn sync_retry_backoff(attempt: u32) -> u64 { domi_core::retry_backoff_seconds(attempt) }
pub fn sync_resolve_conflict(local_json: String, remote_json: String, strategy: String) -> Result<String, DomiError> { let local: domi_core::IndexEntry = serde_json::from_str(&local_json).map_err(|e| DomiError::InvalidFormat { message: e.to_string() })?; let remote: domi_core::IndexEntry = serde_json::from_str(&remote_json).map_err(|e| DomiError::InvalidFormat { message: e.to_string() })?; let strategy = match strategy.as_str() { "local" => ConflictStrategy::KeepLocal, "remote" => ConflictStrategy::KeepRemote, "newest" => ConflictStrategy::KeepNewest, other => return Err(DomiError::InvalidOperation { message: format!("unknown conflict strategy: {other}") }) }; to_json(&domi_core::resolve_conflict(&local, &remote, strategy)) }

// ---------------------------------------------------------------------------
// Password History
// ---------------------------------------------------------------------------

pub fn entry_record_password_change(entry_json: String, new_password: String, now: i64) -> Result<String, DomiError> {
    let mut entry: Entry = serde_json::from_str(&entry_json).map_err(|e| DomiError::InvalidFormat { message: e.to_string() })?;
    core_record_password_change(&mut entry, new_password, now);
    to_json(&entry)
}

pub fn entry_restore_password(entry_json: String, history_index: u32, now: i64) -> Result<String, DomiError> {
    let mut entry: Entry = serde_json::from_str(&entry_json).map_err(|e| DomiError::InvalidFormat { message: e.to_string() })?;
    core_restore_password(&mut entry, history_index as usize, now)?;
    to_json(&entry)
}

pub fn entry_get_password_history(entry_json: String) -> Result<String, DomiError> {
    let entry: Entry = serde_json::from_str(&entry_json).map_err(|e| DomiError::InvalidFormat { message: e.to_string() })?;
    let history = domi_core::get_password_history(&entry);
    to_json(&history)
}

// ---------------------------------------------------------------------------
// Attachments
// ---------------------------------------------------------------------------

pub fn vault_encrypt_attachment(handle: u64, attachment_json: String, entry_id: String) -> Result<String, DomiError> {
    let attachment: Attachment = serde_json::from_str(&attachment_json).map_err(|e| DomiError::InvalidFormat { message: e.to_string() })?;
    let enc = with_vault(handle, |v| v.encrypt_attachment(&attachment, &entry_id))?;
    Ok(BASE64.encode(enc))
}

pub fn vault_decrypt_attachment(handle: u64, ciphertext_b64: String, entry_id: String, attachment_id: String) -> Result<String, DomiError> {
    let bytes = base64_decode(&ciphertext_b64)?;
    let attachment = with_vault(handle, |v| v.decrypt_attachment(&bytes, &entry_id, &attachment_id))?;
    to_json(&attachment)
}

// ---------------------------------------------------------------------------
// Import / Export
// ---------------------------------------------------------------------------

pub fn import_bitwarden_json(json_b64: String) -> Result<String, DomiError> {
    let bytes = base64_decode(&json_b64)?;
    let entries = core_import_bitwarden_json(&bytes)?;
    to_json(&entries)
}

pub fn export_bitwarden_json(entries_json: String) -> Result<String, DomiError> {
    let entries: Vec<Entry> = serde_json::from_str(&entries_json).map_err(|e| DomiError::InvalidFormat { message: e.to_string() })?;
    let bytes = core_export_bitwarden_json(&entries)?;
    Ok(BASE64.encode(bytes))
}

pub fn import_csv(csv_b64: String) -> Result<String, DomiError> {
    let bytes = base64_decode(&csv_b64)?;
    let entries = core_import_csv(&bytes)?;
    to_json(&entries)
}

pub fn export_csv(entries_json: String) -> Result<String, DomiError> {
    let entries: Vec<Entry> = serde_json::from_str(&entries_json).map_err(|e| DomiError::InvalidFormat { message: e.to_string() })?;
    Ok(BASE64.encode(core_export_csv(&entries)))
}

pub fn import_1password_csv(csv_b64: String) -> Result<String, DomiError> {
    let bytes = base64_decode(&csv_b64)?;
    let entries = core_import_1password_csv(&bytes)?;
    to_json(&entries)
}

pub fn import_protonpass_csv(csv_b64: String) -> Result<String, DomiError> {
    let bytes = base64_decode(&csv_b64)?;
    let entries = core_import_protonpass_csv(&bytes)?;
    to_json(&entries)
}

pub fn export_1password_csv(entries_json: String) -> Result<String, DomiError> {
    let entries: Vec<Entry> = serde_json::from_str(&entries_json).map_err(|e| DomiError::InvalidFormat { message: e.to_string() })?;
    Ok(BASE64.encode(core_export_1password_csv(&entries)))
}

pub fn export_protonpass_csv(entries_json: String) -> Result<String, DomiError> {
    let entries: Vec<Entry> = serde_json::from_str(&entries_json).map_err(|e| DomiError::InvalidFormat { message: e.to_string() })?;
    Ok(BASE64.encode(core_export_protonpass_csv(&entries)))
}

// ---------------------------------------------------------------------------
// Tags
// ---------------------------------------------------------------------------

pub struct TagResult {
    pub tag_json: String,
    pub index_json: String,
}

pub fn tags_create(index_json: String, id: String, name: String, now: i64) -> Result<TagResult, DomiError> {
    let mut index = parse_index(&index_json)?;
    let tag = create_tag(&mut index, id, &name, now).map_err(DomiError::from)?;
    Ok(TagResult { tag_json: to_json(&tag)?, index_json: to_json(&index)? })
}

pub fn tags_rename(index_json: String, tag_id: String, new_name: String, now: i64) -> Result<String, DomiError> {
    let mut index = parse_index(&index_json)?;
    rename_tag(&mut index, &tag_id, &new_name, now).map_err(DomiError::from)?;
    to_json(&index)
}

pub struct TagDeleteResult {
    pub index_json: String,
    pub affected_entry_ids: Vec<String>,
}

pub fn tags_delete(index_json: String, tag_id: String, now: i64) -> Result<TagDeleteResult, DomiError> {
    let mut index = parse_index(&index_json)?;
    let affected_entry_ids = delete_tag(&mut index, &tag_id, now).map_err(DomiError::from)?;
    Ok(TagDeleteResult { index_json: to_json(&index)?, affected_entry_ids })
}

pub fn tags_list(index_json: String) -> Result<String, DomiError> {
    let index = parse_index(&index_json)?;
    to_json(&list_tags(&index))
}

pub fn tags_search(index_json: String, tag_id: String) -> Result<String, DomiError> {
    let index = parse_index(&index_json)?;
    to_json(&search_by_tag(&index, &tag_id))
}

pub struct EntryTagResult {
    pub entry_json: String,
    pub changed: bool,
}

/// Assigns `tag_id` to the decrypted entry in `entry_json`. Validates the tag
/// exists against `index_json` (see [`assign_tag`]) — callers should pass the
/// same index the tag was created in. `changed` is `false` if the entry
/// already had the tag.
pub fn entry_assign_tag(index_json: String, entry_json: String, tag_id: String) -> Result<EntryTagResult, DomiError> {
    let index = parse_index(&index_json)?;
    let mut entry = parse_entry(&entry_json)?;
    let changed = assign_tag(&index, &mut entry, &tag_id).map_err(DomiError::from)?;
    Ok(EntryTagResult { entry_json: to_json(&entry)?, changed })
}

pub fn entry_remove_tag(entry_json: String, tag_id: String) -> Result<EntryTagResult, DomiError> {
    let mut entry = parse_entry(&entry_json)?;
    let changed = remove_tag_from_entry(&mut entry, &tag_id);
    Ok(EntryTagResult { entry_json: to_json(&entry)?, changed })
}

// ---------------------------------------------------------------------------
// Collections
// ---------------------------------------------------------------------------

pub struct CollectionResult {
    pub collection_json: String,
    pub index_json: String,
}

pub fn collections_create(
    index_json: String,
    id: String,
    name: String,
    parent_id: Option<String>,
    now: i64,
) -> Result<CollectionResult, DomiError> {
    let mut index = parse_index(&index_json)?;
    let collection = create_collection(&mut index, id, &name, parent_id, now).map_err(DomiError::from)?;
    Ok(CollectionResult { collection_json: to_json(&collection)?, index_json: to_json(&index)? })
}

pub fn collections_rename(
    index_json: String,
    collection_id: String,
    new_name: String,
    now: i64,
) -> Result<String, DomiError> {
    let mut index = parse_index(&index_json)?;
    rename_collection(&mut index, &collection_id, &new_name, now).map_err(DomiError::from)?;
    to_json(&index)
}

pub struct CollectionDeleteResult {
    pub index_json: String,
    pub affected_entry_ids: Vec<String>,
}

pub fn collections_delete(index_json: String, collection_id: String, now: i64) -> Result<CollectionDeleteResult, DomiError> {
    let mut index = parse_index(&index_json)?;
    let affected_entry_ids = delete_collection(&mut index, &collection_id, now).map_err(DomiError::from)?;
    Ok(CollectionDeleteResult { index_json: to_json(&index)?, affected_entry_ids })
}

pub fn collections_list_root(index_json: String) -> Result<String, DomiError> {
    let index = parse_index(&index_json)?;
    to_json(&list_root(&index))
}

pub fn collections_list_children(index_json: String, parent_id: String) -> Result<String, DomiError> {
    let index = parse_index(&index_json)?;
    to_json(&list_children(&index, &parent_id))
}

pub fn collections_search(index_json: String, collection_id: String) -> Result<String, DomiError> {
    let index = parse_index(&index_json)?;
    to_json(&search_by_collection(&index, &collection_id))
}

pub fn entry_move_to_collection(entry_json: String, collection_id: Option<String>) -> Result<String, DomiError> {
    let mut entry = parse_entry(&entry_json)?;
    move_entry(&mut entry, collection_id);
    to_json(&entry)
}

// ---------------------------------------------------------------------------
// Favorites
// ---------------------------------------------------------------------------

pub fn entry_set_favorite(entry_json: String, favorite: bool) -> Result<String, DomiError> {
    let mut entry = parse_entry(&entry_json)?;
    set_favorite(&mut entry, favorite);
    to_json(&entry)
}

pub enum FavoriteSortFfi {
    TitleAscending,
    RecentlyUpdatedFirst,
}

impl From<FavoriteSortFfi> for FavoriteSort {
    fn from(s: FavoriteSortFfi) -> Self {
        match s {
            FavoriteSortFfi::TitleAscending => FavoriteSort::TitleAscending,
            FavoriteSortFfi::RecentlyUpdatedFirst => FavoriteSort::RecentlyUpdatedFirst,
        }
    }
}

pub fn favorites_list(index_json: String, sort: FavoriteSortFfi) -> Result<String, DomiError> {
    let index = parse_index(&index_json)?;
    to_json(&list_favorites(&index, sort.into()))
}

pub fn favorites_search(index_json: String, term: String) -> Result<String, DomiError> {
    let index = parse_index(&index_json)?;
    to_json(&search_favorites(&index, &term))
}

// ---------------------------------------------------------------------------
// Email alias manager
// ---------------------------------------------------------------------------
//
// These wrappers only build/parse HTTP request specs — same "no sockets in
// core (or its bindings)" rule as everywhere else in this file. Swift/Kotlin
// performs the actual HTTP call with whatever networking stack it prefers,
// then hands the raw response bytes back to the parse_* functions.

pub enum AliasProviderKindFfi {
    AddyIo,
    SimpleLogin,
}

impl From<AliasProviderKindFfi> for domi_core::AliasProviderKind {
    fn from(k: AliasProviderKindFfi) -> Self {
        match k {
            AliasProviderKindFfi::AddyIo => domi_core::AliasProviderKind::AddyIo,
            AliasProviderKindFfi::SimpleLogin => domi_core::AliasProviderKind::SimpleLogin,
        }
    }
}

pub struct CreateAliasOptionsFfi {
    pub local_part: Option<String>,
    pub domain: Option<String>,
    pub description: Option<String>,
}

impl From<CreateAliasOptionsFfi> for domi_core::CreateAliasOptions {
    fn from(o: CreateAliasOptionsFfi) -> Self {
        domi_core::CreateAliasOptions {
            local_part: o.local_part,
            domain: o.domain,
            description: o.description,
        }
    }
}

pub struct AliasRecordFfi {
    pub provider_id: String,
    pub email: String,
    pub enabled: bool,
    pub description: Option<String>,
}

impl From<domi_core::AliasRecord> for AliasRecordFfi {
    fn from(r: domi_core::AliasRecord) -> Self {
        AliasRecordFfi {
            provider_id: r.provider_id,
            email: r.email,
            enabled: r.enabled,
            description: r.description,
        }
    }
}

pub struct AliasAccountInfoFfi {
    pub display_name: Option<String>,
    pub quota_remaining: Option<i64>,
}

impl From<domi_core::AliasAccountInfo> for AliasAccountInfoFfi {
    fn from(i: domi_core::AliasAccountInfo) -> Self {
        AliasAccountInfoFfi { display_name: i.display_name, quota_remaining: i.quota_remaining }
    }
}

pub struct HttpHeaderFfi {
    pub name: String,
    pub value: String,
}

pub struct HttpRequestSpecFfi {
    pub url: String,
    pub method: String,
    pub headers: Vec<HttpHeaderFfi>,
    pub body: Vec<u8>,
}

impl From<domi_core::HttpRequestSpec> for HttpRequestSpecFfi {
    fn from(spec: domi_core::HttpRequestSpec) -> Self {
        HttpRequestSpecFfi {
            url: spec.url,
            method: spec.method,
            headers: spec
                .headers
                .into_iter()
                .map(|(name, value)| HttpHeaderFfi { name, value })
                .collect(),
            body: spec.body,
        }
    }
}

pub fn alias_create_request(
    provider: AliasProviderKindFfi,
    api_key: String,
    options: CreateAliasOptionsFfi,
) -> HttpRequestSpecFfi {
    provider_for(provider.into()).create_alias_request(&api_key, &options.into()).into()
}

pub fn alias_parse_response(provider: AliasProviderKindFfi, response_body: Vec<u8>) -> Result<AliasRecordFfi, DomiError> {
    provider_for(provider.into())
        .parse_alias_response(&response_body)
        .map(Into::into)
        .map_err(DomiError::from)
}

pub fn alias_delete_request(provider: AliasProviderKindFfi, api_key: String, provider_id: String) -> HttpRequestSpecFfi {
    provider_for(provider.into()).delete_alias_request(&api_key, &provider_id).into()
}

pub fn alias_enable_request(provider: AliasProviderKindFfi, api_key: String, provider_id: String) -> HttpRequestSpecFfi {
    provider_for(provider.into()).enable_alias_request(&api_key, &provider_id).into()
}

pub fn alias_disable_request(provider: AliasProviderKindFfi, api_key: String, provider_id: String) -> HttpRequestSpecFfi {
    provider_for(provider.into()).disable_alias_request(&api_key, &provider_id).into()
}

pub fn alias_list_request(provider: AliasProviderKindFfi, api_key: String) -> HttpRequestSpecFfi {
    provider_for(provider.into()).list_aliases_request(&api_key).into()
}

pub fn alias_parse_list_response(
    provider: AliasProviderKindFfi,
    response_body: Vec<u8>,
) -> Result<Vec<AliasRecordFfi>, DomiError> {
    let records = provider_for(provider.into())
        .parse_alias_list_response(&response_body)
        .map_err(DomiError::from)?;
    Ok(records.into_iter().map(Into::into).collect())
}

pub fn alias_account_info_request(provider: AliasProviderKindFfi, api_key: String) -> HttpRequestSpecFfi {
    provider_for(provider.into()).account_info_request(&api_key).into()
}

pub fn alias_parse_account_info_response(
    provider: AliasProviderKindFfi,
    response_body: Vec<u8>,
) -> Result<AliasAccountInfoFfi, DomiError> {
    provider_for(provider.into())
        .parse_account_info_response(&response_body)
        .map(Into::into)
        .map_err(DomiError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    // The FFI surface differs from the WASM one in kind, not just in style:
    // every fallible function returns a typed `Result<_, DomiError>` that
    // UniFFI maps onto a thrown exception in Swift/Kotlin. These tests pin the
    // mapping itself (CoreError -> DomiError variants) and the handle
    // lifecycle, since a mistake in either shows up as the wrong exception
    // type on a platform shell rather than as a compile error.

    fn create_vault_for_test() -> (u64, String, String) {
        let r = create_vault("master-pass".to_string()).unwrap();
        (r.handle, r.manifest_json, r.index_enc_b64)
    }

    fn empty_index_json() -> String {
        serde_json::json!({ "version": 0, "entries": [] }).to_string()
    }

    fn sample_entry_json(id: &str) -> String {
        serde_json::json!({
            "id": id,
            "title": "GitHub",
            "username": "octocat",
            "password": "supersecret",
            "url": "https://github.com",
            "notes": "",
            "custom_fields": {},
            "updated_at": 100,
            "deleted": false,
        })
        .to_string()
    }

    // --- Vault handle lifecycle -------------------------------------------

    #[test]
    fn create_unlock_put_and_decrypt_roundtrip() {
        let (handle, manifest_json, index_enc_b64) = create_vault_for_test();

        let unlocked = unlock_vault(
            manifest_json.clone(),
            index_enc_b64.clone(),
            "master-pass".to_string(),
        )
        .unwrap();
        assert_ne!(unlocked.handle, handle, "each unlock gets its own handle");

        let put = vault_put_entry(
            handle,
            empty_index_json(),
            sample_entry_json("entry-1"),
        )
        .unwrap();
        assert_eq!(put.index_json.matches("GitHub").count(), 1);

        let decrypted =
            vault_decrypt_entry(handle, put.entry_enc_b64.clone(), "entry-1".to_string()).unwrap();
        let entry: Value = serde_json::from_str(&decrypted).unwrap();
        assert_eq!(entry["password"], "supersecret");

        lock_vault(handle);
        lock_vault(unlocked.handle);
    }

    #[test]
    fn operations_on_unknown_handle_report_vault_locked() {
        // Swift/Kotlin map this onto a specific exception type, so the
        // variant must be exactly VaultLocked rather than a generic failure.
        assert!(matches!(
            vault_decrypt_entry(999_999, "AAAA".to_string(), "entry-1".to_string()),
            Err(DomiError::VaultLocked)
        ));
        assert!(matches!(
            vault_encrypt(999_999, b"x".to_vec(), b"aad".to_vec()),
            Err(DomiError::VaultLocked)
        ));
        assert!(matches!(
            vault_put_entry(999_999, empty_index_json(), sample_entry_json("e1")),
            Err(DomiError::VaultLocked)
        ));
    }

    #[test]
    fn lock_is_idempotent_and_invalidates_the_handle() {
        let (handle, _, _) = create_vault_for_test();
        lock_vault(handle);

        // Locking twice, or locking a handle that never existed, is a no-op.
        lock_vault(handle);
        lock_vault(424_242);

        assert!(matches!(
            vault_decrypt_entry(handle, "AAAA".to_string(), "e1".to_string()),
            Err(DomiError::VaultLocked)
        ));
    }

    #[test]
    fn unlock_with_wrong_password_maps_to_decryption_failed() {
        let (_, manifest_json, index_enc_b64) = create_vault_for_test();
        assert!(matches!(
            unlock_vault(manifest_json, index_enc_b64, "wrong-pass".to_string()),
            Err(DomiError::DecryptionFailed)
        ));
    }

    #[test]
    fn malformed_manifest_maps_to_invalid_format() {
        assert!(matches!(
            unlock_vault("not json".to_string(), "AAAA".to_string(), "pw".to_string()),
            Err(DomiError::InvalidFormat { .. })
        ));
        assert!(matches!(
            unlock_vault("{}".to_string(), "!!!not base64!!!".to_string(), "pw".to_string()),
            Err(DomiError::InvalidFormat { .. })
        ));
    }

    #[test]
    fn decrypt_entry_rejects_wrong_entry_id() {
        // AAD binds each blob to its entry id, so replaying one under a
        // different id must fail instead of returning the secret.
        let (handle, _, _) = create_vault_for_test();
        let put = vault_put_entry(handle, empty_index_json(), sample_entry_json("entry-1")).unwrap();

        assert!(matches!(
            vault_decrypt_entry(handle, put.entry_enc_b64, "entry-2".to_string()),
            Err(DomiError::DecryptionFailed)
        ));
        lock_vault(handle);
    }

    #[test]
    fn put_entry_with_unknown_tag_maps_to_not_found() {
        let (handle, _, _) = create_vault_for_test();
        let mut entry: Value = serde_json::from_str(&sample_entry_json("e1")).unwrap();
        entry["tags"] = Value::Array(vec![Value::String("ghost-tag".to_string())]);

        // Core formats this as "tag <id>"; assert on the id being surfaced rather
        // than on core's exact wording.
        match vault_put_entry(handle, empty_index_json(), entry.to_string()) {
            Err(DomiError::NotFound { id }) => assert!(id.contains("ghost-tag"), "got {id}"),
            Err(e) => panic!("expected NotFound, got {e:?}"),
            Ok(_) => panic!("expected NotFound, got Ok"),
        }
        lock_vault(handle);
    }

    // --- Base64 boundary ---------------------------------------------------

    #[test]
    fn invalid_base64_maps_to_invalid_format() {
        assert!(matches!(
            base64_decode("!!! not base64 !!!"),
            Err(DomiError::InvalidFormat { .. })
        ));
        assert_eq!(base64_decode("aGk=").unwrap(), b"hi");
    }

    #[test]
    fn generic_encrypt_decrypt_roundtrip_and_aad_binding() {
        let (handle, _, _) = create_vault_for_test();
        let ct = vault_encrypt(handle, b"secret".to_vec(), b"aad".to_vec()).unwrap();
        let pt = vault_decrypt(handle, ct.clone(), b"aad".to_vec()).unwrap();
        assert_eq!(pt, b"secret");

        assert!(matches!(
            vault_decrypt(handle, ct, b"different-aad".to_vec()),
            Err(DomiError::DecryptionFailed)
        ));
        lock_vault(handle);
    }

    // --- CoreError -> DomiError mapping ----------------------------------

    /// Predicate checking that a `DomiError` is the expected variant.
    type VariantCheck = fn(&DomiError) -> bool;

    #[test]
    fn core_errors_map_to_the_matching_ffi_variants() {
        // Each CoreError variant must land on the DomiError variant the UDL
        // declares, since that pairing drives the exception Swift/Kotlin catch.
        let cases: Vec<(CoreError, VariantCheck)> = vec![
            (CoreError::DecryptionFailed, |e| matches!(e, DomiError::DecryptionFailed)),
            (CoreError::VaultLocked, |e| matches!(e, DomiError::VaultLocked)),
            (
                CoreError::NotFound("id-1".to_string()),
                |e| matches!(e, DomiError::NotFound { id } if id == "id-1"),
            ),
            (
                CoreError::UnsupportedVersion(9),
                |e| matches!(e, DomiError::UnsupportedVersion { version } if *version == 9),
            ),
            (
                CoreError::InvalidFormat("bad".to_string()),
                |e| matches!(e, DomiError::InvalidFormat { message } if message == "bad"),
            ),
            (
                CoreError::AlreadyExists("dup".to_string()),
                |e| matches!(e, DomiError::AlreadyExists { message } if message == "dup"),
            ),
            (
                CoreError::InvalidOperation("nope".to_string()),
                |e| matches!(e, DomiError::InvalidOperation { message } if message == "nope"),
            ),
        ];

        for (core_err, check) in cases {
            let ffi_err = DomiError::from(core_err);
            assert!(check(&ffi_err), "variant mismatch: {ffi_err:?}");
        }
    }

    #[test]
    fn core_error_messages_are_preserved_for_the_shell() {
        // Message text is what a user sees, so the Display strings are part
        // of the observable contract.
        assert_eq!(
            DomiError::from(CoreError::NotFound("entry-7".to_string())).to_string(),
            "entry not found: entry-7"
        );
        assert_eq!(
            DomiError::from(CoreError::DecryptionFailed).to_string(),
            "wrong password or corrupted vault"
        );
    }

    // --- Pure pass-through functions ---------------------------------------

    #[test]
    fn generate_password_bounds_are_enforced() {
        assert_eq!(generate_password(24, true, true, true, true).unwrap().len(), 24);
        assert!(generate_password(0, true, true, true, true).is_err());
        assert!(generate_password(3, true, true, true, true).is_err());
        assert!(generate_password(100_000, true, true, true, true).is_err());
        assert!(generate_password(16, false, false, false, false).is_err());
    }

    #[test]
    fn totp_matches_rfc6238_vector() {
        let code =
            generate_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(), 30, 59, 6).unwrap();
        assert_eq!(code, "287082");
        assert!(generate_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(), 0, 59, 6).is_err());
        assert!(
            generate_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(), 30, 59, 100).is_err()
        );
    }

    #[test]
    fn breach_hash_parts_split_prefix_and_suffix() {
        let parts = get_breach_hash_parts("password".to_string()).unwrap();
        assert_eq!(parts.prefix, "5BAA6");
        assert_eq!(parts.suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    #[test]
    fn oauth_provider_parsing_accepts_common_spellings() {
        for spelling in ["googledrive", "Google", "GOOGLE"] {
            let url = build_auth_url(
                spelling.to_string(),
                "client-id".to_string(),
                "https://app.example/cb".to_string(),
                serde_json::json!({
                    "code_verifier": "verifier",
                    "code_challenge": "challenge",
                })
                .to_string(),
                "state-value".to_string(),
            )
            .unwrap();
            assert!(url.contains("code_challenge_method=S256"), "missing S256 in {url}");
            assert!(url.contains("state=state-value"), "missing state in {url}");
        }

        assert!(matches!(
            build_auth_url(
                "myspace".to_string(),
                "cid".to_string(),
                "https://cb".to_string(),
                serde_json::json!({ "code_verifier": "v", "code_challenge": "c" }).to_string(),
                "s".to_string()
            ),
            Err(DomiError::InvalidFormat { .. })
        ));
    }

    #[test]
    fn oauth_state_and_pkce_are_random_and_s256() {
        let a = generate_oauth_state().unwrap();
        let b = generate_oauth_state().unwrap();
        assert_ne!(a, b, "oauth state must be unpredictable per request");

        let pair = generate_pkce().unwrap();
        assert!(pair.code_verifier.len() >= 43, "verifier too short for RFC 7636");
        assert!(pair.code_challenge.len() >= 43);
        assert_ne!(pair.code_verifier, pair.code_challenge);
    }

    #[test]
    fn token_exchange_spec_carries_the_verifier() {
        let spec = build_token_exchange_request(
            "https://oauth.example/token".to_string(),
            "client-id".to_string(),
            "auth-code".to_string(),
            "https://app.example/cb".to_string(),
            "verifier-123".to_string(),
        );
        let body = String::from_utf8(spec.body).unwrap();
        assert_eq!(spec.method, "POST");
        assert!(body.contains("grant_type=authorization_code"));
        assert!(body.contains("code_verifier=verifier-123"));
        // Values are percent-encoded, so a redirect URI can't inject a field.
        assert!(body.contains("redirect_uri=https%3A%2F%2Fapp.example%2Fcb"));
    }

    // --- Sync / tags / collections ----------------------------------------

    #[test]
    fn sync_pending_apply_dispatches_operations() {
        let pending = serde_json::json!({
            "pending_entry_ids": [],
            "last_synced_index_version": 0,
        })
        .to_string();

        let enqueued = sync_pending_apply(pending.clone(), "enqueue".to_string(), "e1".to_string())
            .unwrap();
        let state: Value = serde_json::from_str(&enqueued).unwrap();
        assert_eq!(state["pending_entry_ids"][0], "e1");

        let dequeued = sync_pending_apply(enqueued, "dequeue".to_string(), "e1".to_string()).unwrap();
        let state: Value = serde_json::from_str(&dequeued).unwrap();
        assert!(state["pending_entry_ids"].as_array().unwrap().is_empty());

        assert!(matches!(
            sync_pending_apply(pending, "nonsense".to_string(), "e1".to_string()),
            Err(DomiError::InvalidOperation { .. })
        ));
    }

    #[test]
    fn retry_backoff_grows_and_caps() {
        assert_eq!(sync_retry_backoff(1), 2);
        assert_eq!(sync_retry_backoff(2), 4);
        assert_eq!(sync_retry_backoff(6), 64);
        assert_eq!(sync_retry_backoff(1_000), 64);
    }

    #[test]
    fn tag_lifecycle_roundtrips_through_json() {
        let created =
            tags_create(empty_index_json(), "t1".to_string(), "Work".to_string(), 10).unwrap();
        let tag: Value = serde_json::from_str(&created.tag_json).unwrap();
        assert_eq!(tag["name"], "Work");

        let listed = tags_list(created.index_json.clone()).unwrap();
        let tags: Value = serde_json::from_str(&listed).unwrap();
        assert_eq!(tags.as_array().unwrap().len(), 1);

        let renamed =
            tags_rename(created.index_json.clone(), "t1".to_string(), "Office".to_string(), 11)
                .unwrap();
        let after: Value = serde_json::from_str(&renamed).unwrap();
        assert_eq!(after["tags"][0]["name"], "Office");

        assert!(matches!(
            tags_rename(created.index_json, "missing".to_string(), "X".to_string(), 12),
            Err(DomiError::NotFound { .. })
        ));
    }

    #[test]
    fn collection_lifecycle_and_nested_delete() {
        let root = collections_create(
            empty_index_json(),
            "c1".to_string(),
            "Root".to_string(),
            None,
            1,
        )
        .unwrap();
        let child = collections_create(
            root.index_json.clone(),
            "c2".to_string(),
            "Child".to_string(),
            Some("c1".to_string()),
            2,
        )
        .unwrap();

        let listed = collections_list_children(child.index_json.clone(), "c1".to_string()).unwrap();
        let children: Value = serde_json::from_str(&listed).unwrap();
        assert_eq!(children.as_array().unwrap().len(), 1);

        // Deleting the root cascades to the nested child.
        let deleted =
            collections_delete(child.index_json, "c1".to_string(), 3).unwrap();
        let after: Value = serde_json::from_str(&deleted.index_json).unwrap();
        let all_deleted = after["collections"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["deleted"] == Value::Bool(true));
        assert!(all_deleted, "nested child must be soft-deleted with its parent");

        assert!(matches!(
            collections_delete(empty_index_json(), "nope".to_string(), 4),
            Err(DomiError::NotFound { .. })
        ));
    }

    // --- Import / export ---------------------------------------------------

    #[test]
    fn csv_import_export_roundtrip_through_ffi_boundary() {
        let csv = "title,username,password,url,notes\n\
                   Multi,u,p,https://x.com,\"line one\nline two\"\n";
        let imported = import_csv(BASE64.encode(csv.as_bytes())).unwrap();
        let entries: Value = serde_json::from_str(&imported).unwrap();
        assert_eq!(
            entries.as_array().unwrap().len(),
            1,
            "multi-line note must not split into two entries"
        );
        assert_eq!(entries[0]["notes"], "line one\nline two");

        let exported = export_csv(imported).unwrap();
        let reimported = import_csv(exported).unwrap();
        let entries: Value = serde_json::from_str(&reimported).unwrap();
        assert_eq!(entries.as_array().unwrap().len(), 1);
        assert_eq!(entries[0]["notes"], "line one\nline two");
    }

    #[test]
    fn import_rejects_invalid_base64() {
        assert!(matches!(
            import_csv("!!!not base64!!!".to_string()),
            Err(DomiError::InvalidFormat { .. })
        ));
    }

    // --- Alias requests ----------------------------------------------------

    #[test]
    fn alias_requests_carry_the_api_key_without_being_parseable_back() {
        let spec = alias_list_request(AliasProviderKindFfi::AddyIo, "secret-api-key".to_string());
        assert!(spec.url.starts_with("https://app.addy.io"), "unexpected url {}", spec.url);
        let auth = spec
            .headers
            .iter()
            .find(|h| h.name == "Authorization")
            .expect("missing Authorization header");
        assert_eq!(auth.value, "Bearer secret-api-key");
    }

    #[test]
    fn alias_parse_rejects_malformed_response() {
        assert!(alias_parse_response(AliasProviderKindFfi::AddyIo, b"not json".to_vec()).is_err());
        assert!(alias_parse_list_response(AliasProviderKindFfi::SimpleLogin, b"[]x".to_vec())
            .is_err());
    }

    // --- Favourites / history ---------------------------------------------

    #[test]
    fn favorites_sort_orders_by_title_and_recency() {
        let index = serde_json::json!({
            "version": 1,
            "entries": [
                { "id": "1", "title": "Zebra", "username": "z", "url": "",
                  "updated_at": 10, "deleted": false, "favorite": true },
                { "id": "2", "title": "apple", "username": "a", "url": "",
                  "updated_at": 20, "deleted": false, "favorite": true },
                { "id": "3", "title": "Hidden", "username": "h", "url": "",
                  "updated_at": 30, "deleted": false, "favorite": false },
            ]
        })
        .to_string();

        let by_title = favorites_list(index.clone(), FavoriteSortFfi::TitleAscending).unwrap();
        let titles: Value = serde_json::from_str(&by_title).unwrap();
        assert_eq!(titles[0]["title"], "apple", "case-insensitive title ordering");
        assert_eq!(titles.as_array().unwrap().len(), 2, "non-favorites excluded");

        let by_recency =
            favorites_list(index, FavoriteSortFfi::RecentlyUpdatedFirst).unwrap();
        let recents: Value = serde_json::from_str(&by_recency).unwrap();
        assert_eq!(recents[0]["title"], "apple");
    }

    #[test]
    fn password_history_records_and_restores() {
        let base = sample_entry_json("e1");
        let changed =
            entry_record_password_change(base.clone(), "newpass".to_string(), 100).unwrap();
        let entry: Value = serde_json::from_str(&changed).unwrap();
        assert_eq!(entry["password"], "newpass");
        assert_eq!(entry["password_history"][0]["password"], "supersecret");

        let history = entry_get_password_history(changed.clone()).unwrap();
        let items: Value = serde_json::from_str(&history).unwrap();
        assert_eq!(items.as_array().unwrap().len(), 1);

        let restored =
            entry_restore_password(changed, 0, 101).unwrap();
        let entry: Value = serde_json::from_str(&restored).unwrap();
        assert_eq!(entry["password"], "supersecret", "index 0 is the most recent");

        assert!(matches!(
            entry_restore_password(sample_entry_json("e1"), 0, 1),
            Err(DomiError::NotFound { .. })
        ));
    }

    // --- Attachments -------------------------------------------------------

    #[test]
    fn attachment_roundtrip_and_size_limits() {
        let (handle, _, _) = create_vault_for_test();
        let attachment = serde_json::json!({
            "meta": {
                "id": "att-1", "filename": "id.jpg", "size_bytes": 4,
                "mime_type": "image/jpeg", "updated_at": 1,
            },
            "data": [1, 2, 3, 4],
        })
        .to_string();

        let enc = vault_encrypt_attachment(handle, attachment, "entry-1".to_string()).unwrap();
        let dec = vault_decrypt_attachment(
            handle,
            enc.clone(),
            "entry-1".to_string(),
            "att-1".to_string(),
        )
        .unwrap();
        let out: Value = serde_json::from_str(&dec).unwrap();
        assert_eq!(out["data"], serde_json::json!([1, 2, 3, 4]));

        // A blob replayed under a different attachment id must fail: the AAD
        // binds both the entry id and the attachment id.
        assert!(vault_decrypt_attachment(
            handle,
            enc.clone(),
            "entry-1".to_string(),
            "att-2".to_string(),
        )
        .is_err());

        // A size_bytes that disagrees with the payload is rejected.
        let lying = serde_json::json!({
            "meta": {
                "id": "att-3", "filename": "x.bin", "size_bytes": 999,
                "mime_type": null, "updated_at": 1,
            },
            "data": [1, 2, 3, 4],
        })
        .to_string();
        assert!(matches!(
            vault_encrypt_attachment(handle, lying, "entry-1".to_string()),
            Err(DomiError::InvalidFormat { .. })
        ));

        lock_vault(handle);
    }

    // --- Search cache ------------------------------------------------------

    #[test]
    fn search_cache_roundtrips_through_the_vault_key() {
        let (handle, _, _) = create_vault_for_test();
        let index = serde_json::json!({
            "version": 7,
            "entries": [{
                "id": "e1", "title": "GitHub", "username": "octocat",
                "url": "github.com", "updated_at": 1, "deleted": false,
            }]
        })
        .to_string();

        let saved = vault_save_search_cache(handle, index).unwrap();
        let hits = vault_load_search_cache_query(handle, saved, "cat".to_string()).unwrap();
        let items: Value = serde_json::from_str(&hits).unwrap();
        assert_eq!(items.as_array().unwrap().len(), 1);
        assert_eq!(items[0]["title"], "GitHub");

        lock_vault(handle);
    }

    // --- Merge -------------------------------------------------------------

    #[test]
    fn merge_indexes_resolves_last_write_wins() {
        let local = serde_json::json!({
            "version": 1,
            "entries": [{ "id": "1", "title": "Local Newer", "username": "", "url": "",
                          "updated_at": 200, "deleted": false }],
        })
        .to_string();
        let remote = serde_json::json!({
            "version": 1,
            "entries": [{ "id": "1", "title": "Remote Older", "username": "", "url": "",
                          "updated_at": 100, "deleted": false }],
        })
        .to_string();

        let merged = merge_indexes(local.clone(), remote).unwrap();
        let result: Value = serde_json::from_str(&merged).unwrap();
        assert_eq!(result["merged_index"]["entries"][0]["title"], "Local Newer");
        assert_eq!(result["to_upload_entries"][0], "1");

        assert!(matches!(
            merge_indexes(local.clone(), "not json".to_string()),
            Err(DomiError::InvalidFormat { .. })
        ));
    }

    #[test]
    fn resolve_conflict_honours_each_strategy() {
        let local = serde_json::json!({
            "id": "1", "title": "Local", "username": "", "url": "",
            "updated_at": 100, "deleted": false,
        })
        .to_string();
        let remote = serde_json::json!({
            "id": "1", "title": "Remote", "username": "", "url": "",
            "updated_at": 200, "deleted": false,
        })
        .to_string();

        for (strategy, expected) in [
            ("local", "Local"),
            ("remote", "Remote"),
            ("newest", "Remote"),
        ] {
            let out = sync_resolve_conflict(
                local.clone(),
                remote.clone(),
                strategy.to_string(),
            )
            .unwrap();
            let entry: Value = serde_json::from_str(&out).unwrap();
            assert_eq!(entry["title"], expected, "strategy {strategy}");
        }

        assert!(matches!(
            sync_resolve_conflict(local, remote, "coin-flip".to_string()),
            Err(DomiError::InvalidOperation { .. })
        ));
    }

    // --- Rekey -------------------------------------------------------------

    #[test]
    fn rekey_rotates_material_and_retires_the_old_password() {
        let (handle, manifest_json, _) = create_vault_for_test();
        let put =
            vault_put_entry(handle, empty_index_json(), sample_entry_json("entry-1")).unwrap();

        let inputs = vec![RekeyEntryInputFfi {
            id: "entry-1".to_string(),
            entry_enc_b64: put.entry_enc_b64,
        }];
        let rekeyed = vault_rekey(
            handle,
            put.index_json,
            inputs,
            "brand-new-pass".to_string(),
        )
        .unwrap();

        let new_entry = &rekeyed.reencrypted_entries[0];
        assert_eq!(new_entry.id, "entry-1");
        let decrypted =
            vault_decrypt_entry(handle, new_entry.new_entry_enc_b64.clone(), "entry-1".to_string())
                .unwrap();
        let entry: Value = serde_json::from_str(&decrypted).unwrap();
        assert_eq!(entry["password"], "supersecret");

        // The new manifest unlocks under the new password only.
        assert!(unlock_vault(
            rekeyed.manifest_json.clone(),
            rekeyed.index_enc_b64.clone(),
            "brand-new-pass".to_string()
        )
        .is_ok());
        assert!(matches!(
            unlock_vault(manifest_json, rekeyed.index_enc_b64, "brand-new-pass".to_string()),
            Err(DomiError::DecryptionFailed)
        ));
        lock_vault(handle);
    }
}
