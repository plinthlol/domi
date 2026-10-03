use base64::Engine;
use domi_core::{
    assign_tag, check_strength, create_collection, create_tag, delete_collection, delete_tag,
    build_auth_url, build_token_exchange_request, generate_oauth_state,
    generate_password, generate_pkce, generate_totp, list_children,
    list_favorites, list_root, list_tags, merge, move_entry, provider_for, remove_tag_from_entry,
    rename_collection, rename_tag,
    record_password_change, restore_password,
    import_bitwarden_json, export_bitwarden_json, import_csv, export_csv, import_1password_csv, export_1password_csv, import_protonpass_csv, export_protonpass_csv,
    get_breach_hash_parts,
    search::SearchCache, search_by_collection, search_by_tag,
    search_favorites, set_favorite, AliasProviderKind, CoreError, CreateAliasOptions,
    Entry, FavoriteSort, Index, KdfParams, OAuthProvider, OAuthTokens, PkcePair,
    PendingChanges, ConflictStrategy, Vault, VaultManifest,
};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use wasm_bindgen::prelude::*;

const BASE64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

#[derive(Serialize)]
struct WasmResult<T: Serialize> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn ok_json<T: Serialize>(data: T) -> String {
    serde_json::to_string(&WasmResult {
        success: true,
        data: Some(data),
        error: None,
    })
    .unwrap_or_else(|_| r#"{"success":false,"error":"serialization failure"}"#.into())
}

fn err_json(msg: impl std::fmt::Display) -> String {
    serde_json::to_string(&WasmResult::<()> {
        success: false,
        data: None,
        error: Some(msg.to_string()),
    })
    .unwrap_or_else(|_| r#"{"success":false,"error":"error JSON formatting failed"}"#.into())
}

fn parse_index(index_json: &str) -> Result<Index, String> {
    serde_json::from_str(index_json).map_err(|e| format!("invalid index json: {e}"))
}

fn parse_entry(entry_json: &str) -> Result<Entry, String> {
    serde_json::from_str(entry_json).map_err(|e| format!("invalid entry json: {e}"))
}

/// Accepts a few spellings per provider so callers don't need to match an
/// exact casing convention across JS/Rust.
fn parse_alias_provider(provider: &str) -> Result<AliasProviderKind, String> {
    match provider.to_lowercase().replace(['_', '-'], "").as_str() {
        "addyio" | "addy" => Ok(AliasProviderKind::AddyIo),
        "simplelogin" => Ok(AliasProviderKind::SimpleLogin),
        other => Err(format!("unknown alias provider: {other}")),
    }
}

// --- Opaque vault handle registry -----------------------------------------
//
// The Vault (and the zeroize-on-drop Key inside it) never leaves Rust/WASM
// linear memory as a JS-visible value: JS only ever sees an opaque u64
// handle. This replaces the previous design where wasm_create_vault/
// wasm_unlock_vault derived the key a second time and returned it as a
// base64 String — see AUDIT.md §1 / DOMI_AUDIT_FINDINGS.md [HIGH].
// Call wasm_lock_vault to drop a handle's entry and zeroize its key.

fn vaults() -> &'static Mutex<HashMap<u64, Vault>> {
    static VAULTS: OnceLock<Mutex<HashMap<u64, Vault>>> = OnceLock::new();
    VAULTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_handle() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::SeqCst)
}

fn with_vault<T>(handle: u64, f: impl FnOnce(&Vault) -> Result<T, CoreError>) -> Result<T, String> {
    let guard = vaults()
        .lock()
        .map_err(|_| "vault registry lock poisoned".to_string())?;
    let vault = guard.get(&handle).ok_or_else(|| "vault is locked".to_string())?;
    f(vault).map_err(|e| e.to_string())
}

fn with_vault_mut<T>(handle: u64, f: impl FnOnce(&mut Vault) -> Result<T, CoreError>) -> Result<T, String> {
    let mut guard = vaults()
        .lock()
        .map_err(|_| "vault registry lock poisoned".to_string())?;
    let vault = guard.get_mut(&handle).ok_or_else(|| "vault is locked".to_string())?;
    f(vault).map_err(|e| e.to_string())
}

#[derive(Serialize)]
struct CreateVaultOutput {
    manifest: VaultManifest,
    index_enc_b64: String,
    handle: u64,
}

#[wasm_bindgen]
pub fn wasm_create_vault(password: &str) -> String {
    let params = KdfParams::default();
    match Vault::create(password, params) {
        Ok((vault, manifest, index_enc)) => {
            let handle = next_handle();
            match vaults().lock() {
                Ok(mut g) => {
                    g.insert(handle, vault);
                }
                Err(_) => return err_json("vault registry lock poisoned"),
            }
            let index_enc_b64 = BASE64.encode(&index_enc);
            ok_json(CreateVaultOutput { manifest, index_enc_b64, handle })
        }
        Err(e) => err_json(e),
    }
}

#[derive(Serialize)]
struct UnlockVaultOutput {
    index: Index,
    handle: u64,
}

#[wasm_bindgen]
pub fn wasm_unlock_vault(manifest_json: &str, index_enc_b64: &str, password: &str) -> String {
    let manifest: VaultManifest = match serde_json::from_str(manifest_json) {
        Ok(m) => m,
        Err(e) => return err_json(format!("invalid manifest: {e}")),
    };
    let index_enc = match BASE64.decode(index_enc_b64) {
        Ok(b) => b,
        Err(e) => return err_json(format!("invalid base64 index: {e}")),
    };

    match Vault::unlock(&manifest, &index_enc, password) {
        Ok((vault, index)) => {
            let handle = next_handle();
            match vaults().lock() {
                Ok(mut g) => {
                    g.insert(handle, vault);
                }
                Err(_) => return err_json("vault registry lock poisoned"),
            }
            ok_json(UnlockVaultOutput { index, handle })
        }
        Err(e) => err_json(e),
    }
}

/// Drops the vault (zeroizing its key) and invalidates the handle.
/// Safe to call on an already-locked/unknown handle (no-op).
#[wasm_bindgen]
pub fn wasm_lock_vault(handle: u64) {
    if let Ok(mut guard) = vaults().lock() {
        guard.remove(&handle);
    }
}

#[wasm_bindgen]
pub fn wasm_vault_encrypt(handle: u64, plaintext_b64: &str, aad_b64: &str) -> String {
    let plaintext = match BASE64.decode(plaintext_b64) {
        Ok(b) => b,
        Err(e) => return err_json(format!("invalid base64 plaintext: {e}")),
    };
    let aad = match BASE64.decode(aad_b64) {
        Ok(b) => b,
        Err(e) => return err_json(format!("invalid base64 aad: {e}")),
    };
    match with_vault(handle, |v| v.encrypt(&plaintext, &aad)) {
        Ok(ciphertext) => ok_json(BASE64.encode(ciphertext)),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_vault_decrypt(handle: u64, ciphertext_b64: &str, aad_b64: &str) -> String {
    let ciphertext = match BASE64.decode(ciphertext_b64) {
        Ok(b) => b,
        Err(e) => return err_json(format!("invalid base64 ciphertext: {e}")),
    };
    let aad = match BASE64.decode(aad_b64) {
        Ok(b) => b,
        Err(e) => return err_json(format!("invalid base64 aad: {e}")),
    };
    match with_vault(handle, |v| v.decrypt(&ciphertext, &aad)) {
        Ok(plaintext) => ok_json(BASE64.encode(plaintext)),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_vault_decrypt_entry(handle: u64, entry_enc_b64: &str, entry_id: &str) -> String {
    let entry_enc = match BASE64.decode(entry_enc_b64) {
        Ok(b) => b,
        Err(e) => return err_json(format!("invalid base64 entry: {e}")),
    };
    match with_vault(handle, |v| v.decrypt_entry(&entry_enc, entry_id)) {
        Ok(entry) => ok_json(entry),
        Err(e) => err_json(e),
    }
}

#[derive(Serialize)]
struct PutEntryOutput {
    entry_enc_b64: String,
    index_enc_b64: String,
    index: Index,
}

#[wasm_bindgen]
pub fn wasm_vault_put_entry(handle: u64, index_json: &str, entry_json: &str) -> String {
    let mut index: Index = match serde_json::from_str(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(format!("invalid index json: {e}")),
    };
    let entry: Entry = match serde_json::from_str(entry_json) {
        Ok(e) => e,
        Err(e) => return err_json(format!("invalid entry json: {e}")),
    };

    match with_vault(handle, |v| v.put_entry(&mut index, entry)) {
        Ok((entry_enc, index_enc)) => ok_json(PutEntryOutput {
            entry_enc_b64: BASE64.encode(entry_enc),
            index_enc_b64: BASE64.encode(index_enc),
            index,
        }),
        Err(e) => err_json(e),
    }
}

#[derive(serde::Deserialize)]
struct RekeyEntryInputWasm {
    id: String,
    entry_enc_b64: String,
}

#[derive(Serialize)]
struct RekeyEntryOutputWasm {
    id: String,
    new_entry_enc_b64: String,
}

#[derive(Serialize)]
struct RekeyOutputWasm {
    manifest: VaultManifest,
    index_enc_b64: String,
    reencrypted_entries: Vec<RekeyEntryOutputWasm>,
}

#[wasm_bindgen]
pub fn wasm_vault_rekey(
    handle: u64,
    index_json: &str,
    entries_json: &str,
    new_password: &str,
) -> String {
    let index: Index = match serde_json::from_str(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(format!("invalid index json: {e}")),
    };
    let entries: Vec<RekeyEntryInputWasm> = match serde_json::from_str(entries_json) {
        Ok(es) => es,
        Err(e) => return err_json(format!("invalid entries json: {e}")),
    };

    let mut decoded_entries = Vec::with_capacity(entries.len());
    for item in &entries {
        let bytes = match BASE64.decode(&item.entry_enc_b64) {
            Ok(b) => b,
            Err(e) => return err_json(format!("invalid base64 for entry {}: {e}", item.id)),
        };
        decoded_entries.push((item.id.clone(), bytes));
    }
    let refs: Vec<(&str, &[u8])> = decoded_entries
        .iter()
        .map(|(id, bytes)| (id.as_str(), bytes.as_slice()))
        .collect();

    let params = KdfParams::default();
    match with_vault_mut(handle, |v| v.rekey(&index, &refs, new_password, params)) {
        Ok(res) => {
            let index_enc_b64 = BASE64.encode(&res.index_enc);
            let reencrypted_entries = res
                .entries_enc
                .into_iter()
                .map(|(id, bytes)| RekeyEntryOutputWasm {
                    id,
                    new_entry_enc_b64: BASE64.encode(bytes),
                })
                .collect();

            ok_json(RekeyOutputWasm {
                manifest: res.manifest,
                index_enc_b64,
                reencrypted_entries,
            })
        }
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_generate_password(
    length: usize,
    uppercase: bool,
    lowercase: bool,
    numbers: bool,
    symbols: bool,
) -> String {
    match generate_password(length, uppercase, lowercase, numbers, symbols) {
        Ok(p) => ok_json(p),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_check_strength(password: &str) -> u8 {
    check_strength(password)
}

#[wasm_bindgen]
pub fn wasm_generate_totp(
    secret: &str,
    time_step: u64,
    current_time: u64,
    digits: u32,
) -> String {
    match generate_totp(secret, time_step, current_time, digits) {
        Ok(code) => ok_json(code),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_search_query(index_json: &str, term: &str) -> String {
    let index: Index = match serde_json::from_str(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(format!("invalid index json: {e}")),
    };
    let cache = SearchCache::rebuild_from_index(&index);
    let items = cache.query(term);
    ok_json(items)
}

#[wasm_bindgen]
pub fn wasm_merge_indexes(local_json: &str, remote_json: &str) -> String {
    let local: Index = match serde_json::from_str(local_json) {
        Ok(i) => i,
        Err(e) => return err_json(format!("invalid local index: {e}")),
    };
    let remote: Index = match serde_json::from_str(remote_json) {
        Ok(i) => i,
        Err(e) => return err_json(format!("invalid remote index: {e}")),
    };
    match merge(&local, &remote) {
        Ok(res) => ok_json(res),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_get_breach_hash_parts(password: &str) -> String {
    match get_breach_hash_parts(password) {
        Ok(parts) => ok_json(parts),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_generate_pkce() -> String {
    match generate_pkce() {
        Ok(p) => ok_json(p),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_generate_oauth_state() -> String {
    match generate_oauth_state() {
        Ok(s) => ok_json(s),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_build_auth_url(provider: &str, client_id: &str, redirect_uri: &str, pkce_json: &str, state: &str) -> String {
    let provider = match parse_oauth_provider(provider) { Ok(p) => p, Err(e) => return err_json(e) };
    let pkce: PkcePair = match serde_json::from_str(pkce_json) { Ok(p) => p, Err(e) => return err_json(format!("invalid PKCE json: {e}")) };
    ok_json(build_auth_url(provider, client_id, redirect_uri, &pkce, state))
}

#[wasm_bindgen]
pub fn wasm_build_token_exchange_request(token_url: &str, client_id: &str, code: &str, redirect_uri: &str, verifier: &str) -> String {
    ok_json(build_token_exchange_request(token_url, client_id, code, redirect_uri, verifier))
}

#[wasm_bindgen]
pub fn wasm_parse_token_response(response_b64: &str, current_unix_time: i64) -> String {
    let bytes = match BASE64.decode(response_b64) { Ok(b) => b, Err(e) => return err_json(format!("invalid base64 response: {e}")) };
    match domi_core::parse_token_response(&bytes, current_unix_time) { Ok(t) => ok_json(t), Err(e) => err_json(e) }
}

#[wasm_bindgen]
pub fn wasm_vault_encrypt_tokens(handle: u64, tokens_json: &str) -> String {
    let tokens: OAuthTokens = match serde_json::from_str(tokens_json) { Ok(t) => t, Err(e) => return err_json(format!("invalid token json: {e}")) };
    match with_vault(handle, |v| v.encrypt_tokens(&tokens)) { Ok(b) => ok_json(BASE64.encode(b)), Err(e) => err_json(e) }
}

#[wasm_bindgen]
pub fn wasm_vault_decrypt_tokens(handle: u64, ciphertext_b64: &str) -> String {
    let bytes = match BASE64.decode(ciphertext_b64) { Ok(b) => b, Err(e) => return err_json(format!("invalid base64 ciphertext: {e}")) };
    match with_vault(handle, |v| v.decrypt_tokens(&bytes)) { Ok(t) => ok_json(t), Err(e) => err_json(e) }
}

#[wasm_bindgen]
pub fn wasm_vault_save_search_cache(handle: u64, index_json: &str) -> String {
    let index = match parse_index(index_json) { Ok(i) => i, Err(e) => return err_json(e) };
    let cache = SearchCache::rebuild_from_index(&index);
    match with_vault(handle, |v| v.save_search_cache(&cache)) { Ok(b) => ok_json(BASE64.encode(b)), Err(e) => err_json(e) }
}

#[wasm_bindgen]
pub fn wasm_vault_load_search_cache_query(handle: u64, ciphertext_b64: &str, term: &str) -> String {
    let bytes = match BASE64.decode(ciphertext_b64) { Ok(b) => b, Err(e) => return err_json(format!("invalid base64 ciphertext: {e}")) };
    match with_vault(handle, |v| v.load_search_cache(&bytes).map(|c| c.query(term).into_iter().cloned().collect::<Vec<_>>())) { Ok(items) => ok_json(items), Err(e) => err_json(e) }
}

fn parse_oauth_provider(provider: &str) -> Result<OAuthProvider, String> {
    match provider.to_lowercase().as_str() { "googledrive" | "google" => Ok(OAuthProvider::GoogleDrive), "dropbox" => Ok(OAuthProvider::Dropbox), "onedrive" | "microsoft" => Ok(OAuthProvider::OneDrive), other => Err(format!("unknown OAuth provider: {other}")) }
}

#[wasm_bindgen]
pub fn wasm_sync_pending_apply(pending_json: &str, operation: &str, id: &str) -> String {
    let mut pending: PendingChanges = match serde_json::from_str(pending_json) { Ok(p) => p, Err(e) => return err_json(format!("invalid pending changes json: {e}")) };
    match operation { "enqueue" => pending.enqueue(id), "dequeue" => pending.dequeue(id), "reset_retry" => pending.reset_retry(id), "record_failure" => { pending.record_failure(id); }, other => return err_json(format!("unknown pending operation: {other}")) }
    ok_json(pending)
}

#[wasm_bindgen]
pub fn wasm_sync_retry_backoff(attempt: u32) -> u64 { domi_core::retry_backoff_seconds(attempt) }

#[wasm_bindgen]
pub fn wasm_sync_resolve_conflict(local_json: &str, remote_json: &str, strategy: &str) -> String {
    let local = match serde_json::from_str(local_json) { Ok(v) => v, Err(e) => return err_json(format!("invalid local entry: {e}")) };
    let remote = match serde_json::from_str(remote_json) { Ok(v) => v, Err(e) => return err_json(format!("invalid remote entry: {e}")) };
    let strategy = match strategy { "local" => ConflictStrategy::KeepLocal, "remote" => ConflictStrategy::KeepRemote, "newest" => ConflictStrategy::KeepNewest, other => return err_json(format!("unknown conflict strategy: {other}")) };
    ok_json(domi_core::resolve_conflict(&local, &remote, strategy))
}

// ---------------------------------------------------------------------------
// Tags
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct TagOutput {
    tag: domi_core::Tag,
    index: Index,
}

#[wasm_bindgen]
pub fn wasm_tags_create(index_json: &str, id: &str, name: &str, now: i64) -> String {
    let mut index = match parse_index(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(e),
    };
    match create_tag(&mut index, id.to_string(), name, now) {
        Ok(tag) => ok_json(TagOutput { tag, index }),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_tags_rename(index_json: &str, tag_id: &str, new_name: &str, now: i64) -> String {
    let mut index = match parse_index(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(e),
    };
    match rename_tag(&mut index, tag_id, new_name, now) {
        Ok(()) => ok_json(index),
        Err(e) => err_json(e),
    }
}

#[derive(Serialize)]
struct TagDeleteOutput {
    index: Index,
    affected_entry_ids: Vec<String>,
}

#[wasm_bindgen]
pub fn wasm_tags_delete(index_json: &str, tag_id: &str, now: i64) -> String {
    let mut index = match parse_index(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(e),
    };
    match delete_tag(&mut index, tag_id, now) {
        Ok(affected_entry_ids) => ok_json(TagDeleteOutput { index, affected_entry_ids }),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_tags_list(index_json: &str) -> String {
    let index = match parse_index(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(e),
    };
    ok_json(list_tags(&index))
}

#[wasm_bindgen]
pub fn wasm_tags_search(index_json: &str, tag_id: &str) -> String {
    let index = match parse_index(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(e),
    };
    ok_json(search_by_tag(&index, tag_id))
}

#[derive(Serialize)]
struct EntryTagOutput {
    entry: Entry,
    changed: bool,
}

#[wasm_bindgen]
pub fn wasm_entry_assign_tag(index_json: &str, entry_json: &str, tag_id: &str) -> String {
    let index = match parse_index(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(e),
    };
    let mut entry = match parse_entry(entry_json) {
        Ok(e) => e,
        Err(e) => return err_json(e),
    };
    match assign_tag(&index, &mut entry, tag_id) {
        Ok(changed) => ok_json(EntryTagOutput { entry, changed }),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_entry_remove_tag(entry_json: &str, tag_id: &str) -> String {
    let mut entry = match parse_entry(entry_json) {
        Ok(e) => e,
        Err(e) => return err_json(e),
    };
    let changed = remove_tag_from_entry(&mut entry, tag_id);
    ok_json(EntryTagOutput { entry, changed })
}

// ---------------------------------------------------------------------------
// Collections
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct CollectionOutput {
    collection: domi_core::Collection,
    index: Index,
}

#[wasm_bindgen]
pub fn wasm_collections_create(
    index_json: &str,
    id: &str,
    name: &str,
    parent_id: Option<String>,
    now: i64,
) -> String {
    let mut index = match parse_index(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(e),
    };
    match create_collection(&mut index, id.to_string(), name, parent_id, now) {
        Ok(collection) => ok_json(CollectionOutput { collection, index }),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_collections_rename(index_json: &str, collection_id: &str, new_name: &str, now: i64) -> String {
    let mut index = match parse_index(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(e),
    };
    match rename_collection(&mut index, collection_id, new_name, now) {
        Ok(()) => ok_json(index),
        Err(e) => err_json(e),
    }
}

#[derive(Serialize)]
struct CollectionDeleteOutput {
    index: Index,
    affected_entry_ids: Vec<String>,
}

#[wasm_bindgen]
pub fn wasm_collections_delete(index_json: &str, collection_id: &str, now: i64) -> String {
    let mut index = match parse_index(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(e),
    };
    match delete_collection(&mut index, collection_id, now) {
        Ok(affected_entry_ids) => ok_json(CollectionDeleteOutput { index, affected_entry_ids }),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_collections_list_root(index_json: &str) -> String {
    let index = match parse_index(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(e),
    };
    ok_json(list_root(&index))
}

#[wasm_bindgen]
pub fn wasm_collections_list_children(index_json: &str, parent_id: &str) -> String {
    let index = match parse_index(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(e),
    };
    ok_json(list_children(&index, parent_id))
}

#[wasm_bindgen]
pub fn wasm_collections_search(index_json: &str, collection_id: &str) -> String {
    let index = match parse_index(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(e),
    };
    ok_json(search_by_collection(&index, collection_id))
}

#[wasm_bindgen]
pub fn wasm_entry_move_to_collection(entry_json: &str, collection_id: Option<String>) -> String {
    let mut entry = match parse_entry(entry_json) {
        Ok(e) => e,
        Err(e) => return err_json(e),
    };
    move_entry(&mut entry, collection_id);
    ok_json(entry)
}

// ---------------------------------------------------------------------------
// Favorites
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn wasm_entry_set_favorite(entry_json: &str, favorite: bool) -> String {
    let mut entry = match parse_entry(entry_json) {
        Ok(e) => e,
        Err(e) => return err_json(e),
    };
    set_favorite(&mut entry, favorite);
    ok_json(entry)
}

/// `sort` accepts `"title"` (alphabetical) or `"recent"` (most-recently-
/// updated first); anything else is an error.
#[wasm_bindgen]
pub fn wasm_favorites_list(index_json: &str, sort: &str) -> String {
    let index = match parse_index(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(e),
    };
    let sort = match sort {
        "title" => FavoriteSort::TitleAscending,
        "recent" => FavoriteSort::RecentlyUpdatedFirst,
        other => return err_json(format!("unknown favorite sort: {other}")),
    };
    ok_json(list_favorites(&index, sort))
}

#[wasm_bindgen]
pub fn wasm_favorites_search(index_json: &str, term: &str) -> String {
    let index = match parse_index(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(e),
    };
    ok_json(search_favorites(&index, term))
}

// ---------------------------------------------------------------------------
// Email alias manager
// ---------------------------------------------------------------------------
//
// These only build/parse HTTP request specs -- no fetch() call happens in
// this crate. JS performs the actual request with whatever HTTP client it
// prefers, then hands the raw response body back to the parse_* functions.

#[wasm_bindgen]
pub fn wasm_alias_create_request(
    provider: &str,
    api_key: &str,
    local_part: Option<String>,
    domain: Option<String>,
    description: Option<String>,
) -> String {
    let provider = match parse_alias_provider(provider) {
        Ok(p) => p,
        Err(e) => return err_json(e),
    };
    let opts = CreateAliasOptions { local_part, domain, description };
    ok_json(provider_for(provider).create_alias_request(api_key, &opts))
}

#[wasm_bindgen]
pub fn wasm_alias_parse_response(provider: &str, response_body_b64: &str) -> String {
    let provider = match parse_alias_provider(provider) {
        Ok(p) => p,
        Err(e) => return err_json(e),
    };
    let body = match BASE64.decode(response_body_b64) {
        Ok(b) => b,
        Err(e) => return err_json(format!("invalid base64 response body: {e}")),
    };
    match provider_for(provider).parse_alias_response(&body) {
        Ok(record) => ok_json(record),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_alias_delete_request(provider: &str, api_key: &str, provider_id: &str) -> String {
    let provider = match parse_alias_provider(provider) {
        Ok(p) => p,
        Err(e) => return err_json(e),
    };
    ok_json(provider_for(provider).delete_alias_request(api_key, provider_id))
}

#[wasm_bindgen]
pub fn wasm_alias_enable_request(provider: &str, api_key: &str, provider_id: &str) -> String {
    let provider = match parse_alias_provider(provider) {
        Ok(p) => p,
        Err(e) => return err_json(e),
    };
    ok_json(provider_for(provider).enable_alias_request(api_key, provider_id))
}

#[wasm_bindgen]
pub fn wasm_alias_disable_request(provider: &str, api_key: &str, provider_id: &str) -> String {
    let provider = match parse_alias_provider(provider) {
        Ok(p) => p,
        Err(e) => return err_json(e),
    };
    ok_json(provider_for(provider).disable_alias_request(api_key, provider_id))
}

#[wasm_bindgen]
pub fn wasm_alias_list_request(provider: &str, api_key: &str) -> String {
    let provider = match parse_alias_provider(provider) {
        Ok(p) => p,
        Err(e) => return err_json(e),
    };
    ok_json(provider_for(provider).list_aliases_request(api_key))
}

#[wasm_bindgen]
pub fn wasm_alias_parse_list_response(provider: &str, response_body_b64: &str) -> String {
    let provider = match parse_alias_provider(provider) {
        Ok(p) => p,
        Err(e) => return err_json(e),
    };
    let body = match BASE64.decode(response_body_b64) {
        Ok(b) => b,
        Err(e) => return err_json(format!("invalid base64 response body: {e}")),
    };
    match provider_for(provider).parse_alias_list_response(&body) {
        Ok(records) => ok_json(records),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_alias_account_info_request(provider: &str, api_key: &str) -> String {
    let provider = match parse_alias_provider(provider) {
        Ok(p) => p,
        Err(e) => return err_json(e),
    };
    ok_json(provider_for(provider).account_info_request(api_key))
}

#[wasm_bindgen]
pub fn wasm_alias_parse_account_info_response(provider: &str, response_body_b64: &str) -> String {
    let provider = match parse_alias_provider(provider) {
        Ok(p) => p,
        Err(e) => return err_json(e),
    };
    let body = match BASE64.decode(response_body_b64) {
        Ok(b) => b,
        Err(e) => return err_json(format!("invalid base64 response body: {e}")),
    };
    match provider_for(provider).parse_account_info_response(&body) {
        Ok(info) => ok_json(info),
        Err(e) => err_json(e),
    }
}

// ---------------------------------------------------------------------------
// Password History
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn wasm_entry_record_password_change(entry_json: &str, new_password: &str, now: i64) -> String {
    let mut entry = match parse_entry(entry_json) {
        Ok(e) => e,
        Err(e) => return err_json(e),
    };
    record_password_change(&mut entry, new_password.to_string(), now);
    ok_json(entry)
}

#[wasm_bindgen]
pub fn wasm_entry_restore_password(entry_json: &str, history_index: u32, now: i64) -> String {
    let mut entry = match parse_entry(entry_json) {
        Ok(e) => e,
        Err(e) => return err_json(e),
    };
    match restore_password(&mut entry, history_index as usize, now) {
        Ok(()) => ok_json(entry),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_entry_get_password_history(entry_json: &str) -> String {
    let entry = match parse_entry(entry_json) {
        Ok(e) => e,
        Err(e) => return err_json(e),
    };
    let history = domi_core::get_password_history(&entry);
    ok_json(history)
}

// ---------------------------------------------------------------------------
// Attachments
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn wasm_vault_encrypt_attachment(handle: u64, attachment_json: &str, entry_id: &str) -> String {
    let attachment: domi_core::Attachment = match serde_json::from_str(attachment_json) {
        Ok(a) => a,
        Err(e) => return err_json(format!("invalid attachment json: {e}")),
    };
    match with_vault(handle, |v| v.encrypt_attachment(&attachment, entry_id)) {
        Ok(enc) => ok_json(BASE64.encode(enc)),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_vault_decrypt_attachment(handle: u64, ciphertext_b64: &str, entry_id: &str, attachment_id: &str) -> String {
    let bytes = match BASE64.decode(ciphertext_b64) {
        Ok(b) => b,
        Err(e) => return err_json(format!("invalid base64 ciphertext: {e}")),
    };
    match with_vault(handle, |v| v.decrypt_attachment(&bytes, entry_id, attachment_id)) {
        Ok(attachment) => ok_json(attachment),
        Err(e) => err_json(e),
    }
}

// ---------------------------------------------------------------------------
// Import / Export
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn wasm_import_bitwarden_json(json_b64: &str) -> String {
    let bytes = match BASE64.decode(json_b64) {
        Ok(b) => b,
        Err(e) => return err_json(format!("invalid base64: {e}")),
    };
    match import_bitwarden_json(&bytes) {
        Ok(entries) => ok_json(entries),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_export_bitwarden_json(entries_json: &str) -> String {
    let entries: Vec<Entry> = match serde_json::from_str(entries_json) {
        Ok(e) => e,
        Err(e) => return err_json(format!("invalid entries json: {e}")),
    };
    match export_bitwarden_json(&entries) {
        Ok(bytes) => ok_json(BASE64.encode(bytes)),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_import_csv(csv_b64: &str) -> String {
    let bytes = match BASE64.decode(csv_b64) {
        Ok(b) => b,
        Err(e) => return err_json(format!("invalid base64: {e}")),
    };
    match import_csv(&bytes) {
        Ok(entries) => ok_json(entries),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_export_csv(entries_json: &str) -> String {
    let entries: Vec<Entry> = match serde_json::from_str(entries_json) {
        Ok(e) => e,
        Err(e) => return err_json(format!("invalid entries json: {e}")),
    };
    ok_json(BASE64.encode(export_csv(&entries)))
}

#[wasm_bindgen]
pub fn wasm_import_1password_csv(csv_b64: &str) -> String {
    let bytes = match BASE64.decode(csv_b64) {
        Ok(b) => b,
        Err(e) => return err_json(format!("invalid base64: {e}")),
    };
    match import_1password_csv(&bytes) {
        Ok(entries) => ok_json(entries),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_import_protonpass_csv(csv_b64: &str) -> String {
    let bytes = match BASE64.decode(csv_b64) {
        Ok(b) => b,
        Err(e) => return err_json(format!("invalid base64: {e}")),
    };
    match import_protonpass_csv(&bytes) {
        Ok(entries) => ok_json(entries),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_export_1password_csv(entries_json: &str) -> String {
    let entries: Vec<Entry> = match serde_json::from_str(entries_json) {
        Ok(e) => e,
        Err(e) => return err_json(format!("invalid entries json: {e}")),
    };
    ok_json(BASE64.encode(export_1password_csv(&entries)))
}

#[wasm_bindgen]
pub fn wasm_export_protonpass_csv(entries_json: &str) -> String {
    let entries: Vec<Entry> = match serde_json::from_str(entries_json) {
        Ok(e) => e,
        Err(e) => return err_json(format!("invalid entries json: {e}")),
    };
    ok_json(BASE64.encode(export_protonpass_csv(&entries)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    // Every wasm_* function returns a JSON string rather than a Rust Result,
    // because a thrown JS exception can't cross the wasm-bindgen boundary the
    // way a typed error can. These tests pin down that envelope: callers must
    // be able to tell success from failure and read `data` / `error`.

    fn parse(json: &str) -> Value {
        serde_json::from_str(json)
            .unwrap_or_else(|e| panic!("wasm fn returned invalid JSON: {json} ({e})"))
    }

    fn assert_ok(json: &str) -> Value {
        let v = parse(json);
        assert_eq!(v["success"], Value::Bool(true), "expected success, got {json}");
        assert!(v.get("error").is_none(), "success must omit error key: {json}");
        v
    }

    fn assert_err(json: &str) -> String {
        let v = parse(json);
        assert_eq!(v["success"], Value::Bool(false), "expected failure, got {json}");
        assert!(v.get("data").is_none(), "failure must omit data key: {json}");
        v["error"].as_str().expect("error must be a string").to_string()
    }

    /// Creates a vault and returns (handle, manifest_json, index_enc_b64).
    fn make_vault() -> (u64, String, String) {
        let v = assert_ok(&wasm_create_vault("master-pass"));
        let data = &v["data"];
        (
            data["handle"].as_u64().unwrap(),
            data["manifest"].to_string(),
            data["index_enc_b64"].as_str().unwrap().to_string(),
        )
    }

    /// A minimal valid empty `Index` JSON. `Index.version` has no serde
    /// default, so callers must supply it — `{}` is rejected as malformed.
    fn empty_index_json() -> String {
        serde_json::json!({ "version": 0, "entries": [] }).to_string()
    }

    /// A fully-populated `Entry` JSON. Several `Entry` fields have no serde
    /// default (`custom_fields`, `updated_at`, `deleted`), so a partial
    /// object is rejected as malformed.
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

    // --- Success/failure envelope -----------------------------------------

    #[test]
    fn error_envelope_reports_failure_without_data() {
        let msg = assert_err(&wasm_vault_decrypt_entry(9999, "", "entry-1"));
        assert!(msg.contains("vault is locked"), "unexpected message: {msg}");
    }

    #[test]
    fn malformed_input_yields_error_envelope_not_panic() {
        // Each of these takes input that can't parse. None may panic or return
        // malformed JSON — the JS caller gets a structured error instead.
        assert_err(&wasm_vault_put_entry(1, "not json", "{}"));
        assert_err(&wasm_unlock_vault("not json", "", "pw"));
        assert_err(&wasm_generate_totp("!!!not-base32!!!", 30, 59, 6));
        assert_err(&wasm_vault_rekey(1, "{}", "[bad json", "newpw"));
        assert_err(&wasm_import_csv("!!! not base64 !!!"));
        assert_err(&wasm_favorites_list(&empty_index_json(), "not-a-sort"));
        assert_err(&wasm_collections_create(&empty_index_json(), "c1", "name", Some("ghost-parent".to_string()), 1));
    }

    // --- Vault handle lifecycle -------------------------------------------

    #[test]
    fn create_unlock_put_and_decrypt_roundtrip() {
        let (handle, manifest, index_enc_b64) = make_vault();

        // Unlock from the same manifest/index a second time yields a usable handle.
        let unlocked = assert_ok(&wasm_unlock_vault(&manifest, &index_enc_b64, "master-pass"));
        let h2 = unlocked["data"]["handle"].as_u64().unwrap();
        assert_ne!(h2, handle, "each unlock gets its own handle");

        let put = assert_ok(&wasm_vault_put_entry(handle, &empty_index_json(), &sample_entry_json("entry-1")));
        let entry_enc_b64 = put["data"]["entry_enc_b64"].as_str().unwrap().to_string();
        assert_eq!(put["data"]["index"]["entries"][0]["title"], "GitHub");

        let decrypted = assert_ok(&wasm_vault_decrypt_entry(handle, &entry_enc_b64, "entry-1"));
        assert_eq!(decrypted["data"]["password"], "supersecret");
        assert_eq!(decrypted["data"]["title"], "GitHub");

        wasm_lock_vault(handle);
        wasm_lock_vault(h2);
    }

    #[test]
    fn locked_handle_is_rejected_and_lock_is_idempotent() {
        let (handle, _, _) = make_vault();
        wasm_lock_vault(handle);

        let msg = assert_err(&wasm_vault_decrypt_entry(handle, "AAAA", "entry-1"));
        assert!(msg.contains("vault is locked"), "unexpected message: {msg}");

        // Locking an already-locked or never-existing handle is a no-op.
        wasm_lock_vault(handle);
        wasm_lock_vault(4242);
    }

    #[test]
    fn unlock_with_wrong_password_fails() {
        let (_, manifest, index_enc_b64) = make_vault();
        let msg = assert_err(&wasm_unlock_vault(&manifest, &index_enc_b64, "wrong-password"));
        assert!(
            msg.contains("wrong password or corrupted vault"),
            "unexpected message: {msg}"
        );
    }

    #[test]
    fn decrypt_entry_rejects_wrong_entry_id() {
        // AAD binds each entry blob to its id, so a blob replayed under a
        // different id must fail to decrypt rather than return the secret.
        let (handle, _, _) = make_vault();
        let put = assert_ok(&wasm_vault_put_entry(handle, &empty_index_json(), &sample_entry_json("entry-1")));
        let entry_enc_b64 = put["data"]["entry_enc_b64"].as_str().unwrap();

        assert_err(&wasm_vault_decrypt_entry(handle, entry_enc_b64, "entry-2"));
        wasm_lock_vault(handle);
    }

    #[test]
    fn rekey_rotates_key_and_old_password_stops_working() {
        let (handle, _, _) = make_vault();
        let put = assert_ok(&wasm_vault_put_entry(handle, &empty_index_json(), &sample_entry_json("entry-1")));
        let entry_enc_b64 = put["data"]["entry_enc_b64"].as_str().unwrap().to_string();
        let index = put["data"]["index"].to_string();

        let entries = serde_json::json!([{ "id": "entry-1", "entry_enc_b64": entry_enc_b64 }]);
        let rekeyed = assert_ok(&wasm_vault_rekey(
            handle,
            &index,
            &entries.to_string(),
            "brand-new-pass",
        ));
        let new_manifest = rekeyed["data"]["manifest"].to_string();
        let new_index_enc_b64 = rekeyed["data"]["index_enc_b64"].as_str().unwrap().to_string();
        let new_entry_enc_b64 = rekeyed["data"]["reencrypted_entries"][0]["new_entry_enc_b64"]
            .as_str()
            .unwrap()
            .to_string();

        // The mutated handle now works with the new material...
        let decrypted = assert_ok(&wasm_vault_decrypt_entry(handle, &new_entry_enc_b64, "entry-1"));
        assert_eq!(decrypted["data"]["password"], "supersecret");

        // ...the new manifest unlocks under the new password...
        let relocked =
            assert_ok(&wasm_unlock_vault(&new_manifest, &new_index_enc_b64, "brand-new-pass"));
        assert_eq!(relocked["data"]["index"]["entries"].as_array().unwrap().len(), 1);

        // ...and no longer under the original password.
        let (_old_handle, old_manifest, _old_index) = make_vault();
        assert_err(&wasm_unlock_vault(&old_manifest, &new_index_enc_b64, "brand-new-pass"));
        assert_err(&wasm_unlock_vault(&new_manifest, &new_index_enc_b64, "master-pass"));
        wasm_lock_vault(handle);
    }

    // --- Pure pass-through functions ---------------------------------------

    #[test]
    fn generate_password_respects_length_and_bounds() {
        let pw = assert_ok(&wasm_generate_password(24, true, true, true, true));
        assert_eq!(pw["data"].as_str().unwrap().len(), 24);

        assert_err(&wasm_generate_password(0, true, true, true, true));
        assert_err(&wasm_generate_password(3, true, true, true, true));
        assert_err(&wasm_generate_password(100_000, true, true, true, true));
        // Every character class disabled leaves no charset to draw from.
        assert_err(&wasm_generate_password(16, false, false, false, false));
    }

    #[test]
    fn totp_matches_rfc6238_vector() {
        let code = assert_ok(&wasm_generate_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 30, 59, 6));
        assert_eq!(code["data"], "287082");
        assert_err(&wasm_generate_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 0, 59, 6));
        assert_err(&wasm_generate_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 30, 59, 100));
    }

    #[test]
    fn breach_hash_parts_split_prefix_and_suffix() {
        let parts = assert_ok(&wasm_get_breach_hash_parts("password"));
        assert_eq!(parts["data"]["prefix"], "5BAA6");
        assert_eq!(parts["data"]["suffix"], "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    #[test]
    fn search_and_merge_operate_on_index_json() {
        let index = serde_json::json!({
            "version": 1,
            "entries": [{
                "id": "e1", "title": "GitHub", "username": "octocat",
                "url": "github.com", "updated_at": 1, "deleted": false
            }]
        })
        .to_string();

        let hits = assert_ok(&wasm_search_query(&index, "cat"));
        assert_eq!(hits["data"].as_array().unwrap().len(), 1);
        assert_eq!(hits["data"][0]["title"], "GitHub");

        let merged = assert_ok(&wasm_merge_indexes(&index, &index));
        assert_eq!(merged["data"]["merged_index"]["entries"].as_array().unwrap().len(), 1);
        assert_err(&wasm_merge_indexes(&index, "not json"));
    }

    #[test]
    fn sync_helpers_report_backoff_and_pending_state() {
        assert_eq!(wasm_sync_retry_backoff(1), 2);
        assert_eq!(wasm_sync_retry_backoff(2), 4);
        assert_eq!(wasm_sync_retry_backoff(50), 64);

        // `PendingChanges` has no serde defaults on its first two fields, so an empty
        // object is malformed — both must be present.
        let pending = serde_json::json!({
            "pending_entry_ids": [],
            "last_synced_index_version": 0,
        })
        .to_string();
        let enqueued = assert_ok(&wasm_sync_pending_apply(&pending, "enqueue", "e1"));
        assert_eq!(enqueued["data"]["pending_entry_ids"][0], "e1");

        let dequeued =
            assert_ok(&wasm_sync_pending_apply(&enqueued["data"].to_string(), "dequeue", "e1"));
        assert!(dequeued["data"]["pending_entry_ids"].as_array().unwrap().is_empty());

        assert_err(&wasm_sync_pending_apply(&pending, "not-an-operation", "e1"));
        assert_err(&wasm_sync_resolve_conflict("{}", "{}", "not-a-strategy"));
    }

    #[test]
    fn tag_lifecycle_roundtrips_through_json() {
        let created = assert_ok(&wasm_tags_create(&empty_index_json(), "t1", "Work", 10));
        assert_eq!(created["data"]["tag"]["name"], "Work");
        let index = created["data"]["index"].to_string();

        let listed = assert_ok(&wasm_tags_list(&index));
        assert_eq!(listed["data"].as_array().unwrap().len(), 1);

        let renamed = assert_ok(&wasm_tags_rename(&index, "t1", "Office", 11));
        let renamed_index = renamed["data"].to_string();
        let after_rename = assert_ok(&wasm_tags_list(&renamed_index));
        assert_eq!(after_rename["data"][0]["name"], "Office");

        // Unknown tag id is rejected rather than silently created.
        assert_err(&wasm_tags_rename(&index, "nope", "X", 12));
    }

    #[test]
    fn alias_provider_parsing_is_forgiving_of_spelling() {
        // JS callers shouldn't have to match one exact casing convention.
        for spelling in ["AddyIo", "addyio", "ADDY-IO"] {
            let spec = assert_ok(&wasm_alias_list_request(spelling, "api-key"));
            assert!(
                spec["data"]["url"].as_str().unwrap().starts_with("https://app.addy.io"),
                "unexpected url for {spelling}"
            );
        }
        assert_err(&wasm_alias_parse_response("unknown-provider", "e30="));
        assert_err(&wasm_alias_parse_response("addyio", "!!!not-base64!!!"));
    }

    #[test]
    fn csv_import_export_roundtrip_through_wasm_boundary() {
        let csv = "title,username,password,url,notes\n\
                   Multi,u,p,https://x.com,\"line one\nline two\"\n";
        let imported = assert_ok(&wasm_import_csv(&BASE64.encode(csv.as_bytes())));
        let entries = imported["data"].as_array().unwrap();
        assert_eq!(entries.len(), 1, "multi-line note must not split into two entries");
        assert_eq!(entries[0]["notes"], "line one\nline two");

        let exported = assert_ok(&wasm_export_csv(&imported["data"].to_string()));
        let reimported = assert_ok(&wasm_import_csv(exported["data"].as_str().unwrap()));
        assert_eq!(reimported["data"].as_array().unwrap().len(), 1);
        assert_eq!(reimported["data"][0]["notes"], "line one\nline two");
    }

    #[test]
    fn entry_helpers_operate_on_entry_json() {
        let base = sample_entry_json("e1");

        let changed = assert_ok(&wasm_entry_record_password_change(&base, "newpass", 100));
        assert_eq!(changed["data"]["password"], "newpass");
        assert_eq!(changed["data"]["password_history"][0]["password"], "supersecret");

        let history = assert_ok(&wasm_entry_get_password_history(&changed["data"].to_string()));
        assert_eq!(history["data"].as_array().unwrap().len(), 1);

        let faved = assert_ok(&wasm_entry_set_favorite(&base, true));
        assert_eq!(faved["data"]["favorite"], true);
    }

    #[test]
    fn vault_generic_encrypt_decrypt_roundtrip_and_bad_handle() {
        let (handle, _, _) = make_vault();
        let ct = assert_ok(&wasm_vault_encrypt(handle, &BASE64.encode(b"hello"), &BASE64.encode(b"aad")));
        let ct = ct["data"].as_str().unwrap().to_string();

        let pt = assert_ok(&wasm_vault_decrypt(handle, &ct, &BASE64.encode(b"aad")));
        assert_eq!(BASE64.decode(pt["data"].as_str().unwrap()).unwrap(), b"hello");

        // AAD mismatch must fail rather than return garbage.
        assert_err(&wasm_vault_decrypt(handle, &ct, &BASE64.encode(b"different-aad")));
        wasm_lock_vault(handle);
    }
}
