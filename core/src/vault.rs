use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::Zeroize;
use crate::crypto::{decrypt, derive_key, encrypt, generate_salt, Key, KdfParams};
use crate::errors::CoreError;
use crate::oauth::{decrypt_tokens, encrypt_tokens, OAuthTokens};
use crate::search::SearchCache;

pub const CURRENT_VAULT_VERSION: u32 = 1;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultManifest {
    pub version: u32,
    pub salt: [u8; 16],
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl VaultManifest {
    pub fn kdf_params(&self) -> KdfParams {
        KdfParams {
            memory_kib: self.memory_kib,
            iterations: self.iterations,
            parallelism: self.parallelism,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RekeyResult {
    pub manifest: VaultManifest,
    pub index_enc: Vec<u8>,
    pub entries_enc: HashMap<String, Vec<u8>>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ItemCategory {
    #[default]
    Login,
    CreditCard,
    SecureNote,
    Identity,
    BankAccount,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PasswordHistoryItem {
    pub password: String,
    pub updated_at: i64,
}

impl zeroize::Zeroize for PasswordHistoryItem {
    fn zeroize(&mut self) {
        self.password.zeroize();
    }
}

/// Attachments are meant for small identity documents (a photo of an ID
/// card, a PDF of a passport) — not general file storage. This bounds
/// worst-case memory use for a single attachment, which matters most for
/// the core-wasm binding running inside a memory-constrained browser
/// extension service worker.
pub const MAX_ATTACHMENT_SIZE_BYTES: u64 = 20 * 1024 * 1024;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AttachmentMeta {
    pub id: String,
    pub filename: String,
    pub size_bytes: u64,
    pub mime_type: Option<String>,
    pub updated_at: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Attachment {
    pub meta: AttachmentMeta,
    pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct IndexEntry {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub updated_at: i64,
    pub deleted: bool,
    /// IDs of the [`Tag`]s assigned to this entry. Kept in sync with the full
    /// `Entry.tags` field by [`Vault::put_entry`] so tag search/filtering never
    /// requires decrypting every entry blob.
    #[serde(default)]
    pub tags: Vec<String>,
    /// The [`Collection`] this entry belongs to, if any. Kept in sync with
    /// `Entry.collection_id` by [`Vault::put_entry`].
    #[serde(default)]
    pub collection_id: Option<String>,
    /// Kept in sync with `Entry.favorite` by [`Vault::put_entry`].
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub category: ItemCategory,
    #[serde(default)]
    pub attachments: Vec<AttachmentMeta>,
}

/// A user-defined tag. Tags are vault metadata (not secret material on their
/// own) but are still stored only inside the encrypted `Index` blob, never in
/// plaintext, per the Core Expansion Plan.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Tag {
    pub id: String,
    pub name: String,
    pub updated_at: i64,
    pub deleted: bool,
}

/// A logical grouping of entries. `parent_id` allows nested collections.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Collection {
    pub id: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub updated_at: i64,
    pub deleted: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct Index {
    pub version: u64,
    pub entries: Vec<IndexEntry>,
    #[serde(default)]
    pub tags: Vec<Tag>,
    #[serde(default)]
    pub collections: Vec<Collection>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub totp_secret: Option<String>,
    pub custom_fields: HashMap<String, String>,
    pub updated_at: i64,
    pub deleted: bool,
    /// IDs of assigned [`Tag`]s. See [`crate::tags`].
    #[serde(default)]
    pub tags: Vec<String>,
    /// The [`Collection`] this entry belongs to, if any. See [`crate::collections`].
    #[serde(default)]
    pub collection_id: Option<String>,
    /// See [`crate::favorites`].
    #[serde(default)]
    pub favorite: bool,
    /// Email-alias-manager metadata (see [`crate::aliases`]). All three are
    /// `Some` together once an alias is linked, `None` otherwise.
    #[serde(default)]
    pub alias_provider: Option<String>,
    #[serde(default)]
    pub alias_id: Option<String>,
    #[serde(default)]
    pub alias_email: Option<String>,
    #[serde(default)]
    pub category: ItemCategory,
    #[serde(default)]
    pub password_history: Vec<PasswordHistoryItem>,
    #[serde(default)]
    pub attachments: Vec<AttachmentMeta>,
}

impl zeroize::Zeroize for Entry {
    fn zeroize(&mut self) {
        self.password.zeroize();
        self.notes.zeroize();
        if let Some(ref mut totp) = self.totp_secret {
            totp.zeroize();
        }
        for v in self.custom_fields.values_mut() {
            v.zeroize();
        }
        for h in &mut self.password_history {
            h.zeroize();
        }
    }
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub struct Vault {
    key: Key,
}

impl Vault {
    pub fn create(password: &str, params: KdfParams) -> Result<(Self, VaultManifest, Vec<u8>), CoreError> {
        let salt = generate_salt()?;
        let key = derive_key(password, &salt, params)?;

        let manifest = VaultManifest {
            version: CURRENT_VAULT_VERSION,
            salt,
            memory_kib: params.memory_kib,
            iterations: params.iterations,
            parallelism: params.parallelism,
        };

        let empty_index = Index::default();
        let index_json = serde_json::to_vec(&empty_index)
            .map_err(|e| CoreError::InvalidFormat(format!("failed to serialize index: {e}")))?;
        let index_enc = encrypt(&key, &index_json, b"index")?;

        Ok((Vault { key }, manifest, index_enc))
    }

    pub fn unlock(
        manifest: &VaultManifest,
        index_enc: &[u8],
        password: &str,
    ) -> Result<(Self, Index), CoreError> {
        if manifest.version > CURRENT_VAULT_VERSION {
            return Err(CoreError::UnsupportedVersion(manifest.version));
        }

        let key = derive_key(password, &manifest.salt, manifest.kdf_params())?;
        let index_bytes = decrypt(&key, index_enc, b"index")?;
        let index: Index = serde_json::from_slice(&index_bytes)
            .map_err(|e| CoreError::InvalidFormat(format!("corrupt index json: {e}")))?;

        Ok((Vault { key }, index))
    }

    pub fn lock(self) {}

    pub fn rekey(
        &mut self,
        index: &Index,
        entries_enc: &[(&str, &[u8])],
        new_password: &str,
        new_params: KdfParams,
    ) -> Result<RekeyResult, CoreError> {
        let mut decrypted_entries = Vec::with_capacity(entries_enc.len());
        for &(id, enc) in entries_enc {
            let entry = self.decrypt_entry(enc, id)?;
            decrypted_entries.push(entry);
        }

        let new_salt = generate_salt()?;
        let new_key = derive_key(new_password, &new_salt, new_params)?;

        let new_manifest = VaultManifest {
            version: CURRENT_VAULT_VERSION,
            salt: new_salt,
            memory_kib: new_params.memory_kib,
            iterations: new_params.iterations,
            parallelism: new_params.parallelism,
        };

        let index_json = serde_json::to_vec(index)
            .map_err(|e| CoreError::InvalidFormat(format!("failed to serialize index: {e}")))?;
        let new_index_enc = encrypt(&new_key, &index_json, b"index")?;

        let mut reencrypted_entries = HashMap::with_capacity(decrypted_entries.len());
        for entry in decrypted_entries {
            let entry_id = entry.id.clone();
            let entry_json = serde_json::to_vec(&entry)
                .map_err(|e| CoreError::InvalidFormat(format!("failed to serialize entry: {e}")))?;
            let new_entry_enc = encrypt(&new_key, &entry_json, entry_id.as_bytes())?;
            reencrypted_entries.insert(entry_id, new_entry_enc);
        }

        self.key = new_key;

        Ok(RekeyResult {
            manifest: new_manifest,
            index_enc: new_index_enc,
            entries_enc: reencrypted_entries,
        })
    }

    /// Generic AEAD encrypt under the vault key, for callers that need to encrypt
    /// something other than an `Entry` (e.g. the search cache or OAuth tokens).
    /// This exists so shells never need the raw key bytes at all — see AUDIT.md §1.
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CoreError> {
        encrypt(&self.key, plaintext, aad)
    }

    /// Generic AEAD decrypt under the vault key. Counterpart to `encrypt` above.
    pub fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CoreError> {
        decrypt(&self.key, ciphertext, aad)
    }

    pub fn encrypt_tokens(&self, tokens: &OAuthTokens) -> Result<Vec<u8>, CoreError> {
        encrypt_tokens(&self.key, tokens)
    }

    pub fn decrypt_tokens(&self, ciphertext: &[u8]) -> Result<OAuthTokens, CoreError> {
        decrypt_tokens(&self.key, ciphertext)
    }

    pub fn save_search_cache(&self, cache: &SearchCache) -> Result<Vec<u8>, CoreError> {
        cache.save_encrypted(&self.key)
    }

    pub fn load_search_cache(&self, ciphertext: &[u8]) -> Result<SearchCache, CoreError> {
        SearchCache::load_encrypted(&self.key, ciphertext)
    }

    pub fn decrypt_entry(&self, entry_enc: &[u8], entry_id: &str) -> Result<Entry, CoreError> {
        let bytes = decrypt(&self.key, entry_enc, entry_id.as_bytes())?;
        serde_json::from_slice(&bytes)
            .map_err(|e| CoreError::InvalidFormat(format!("corrupt entry json: {e}")))
    }

    pub fn put_entry(
        &self,
        index: &mut Index,
        entry: Entry,
    ) -> Result<(Vec<u8>, Vec<u8>), CoreError> {
        if !entry.deleted {
            for tag_id in &entry.tags {
                if !index.tags.iter().any(|tag| tag.id == *tag_id && !tag.deleted) {
                    return Err(CoreError::NotFound(format!("tag {tag_id}")));
                }
            }
            if let Some(collection_id) = &entry.collection_id {
                if !index
                    .collections
                    .iter()
                    .any(|collection| collection.id == *collection_id && !collection.deleted)
                {
                    return Err(CoreError::NotFound(format!("collection {collection_id}")));
                }
            }
        }
        let entry_id = entry.id.clone();
        let index_item = IndexEntry {
            id: entry.id.clone(),
            title: entry.title.clone(),
            username: entry.username.clone(),
            url: entry.url.clone(),
            updated_at: entry.updated_at,
            deleted: entry.deleted,
            tags: entry.tags.clone(),
            collection_id: entry.collection_id.clone(),
            favorite: entry.favorite,
            category: entry.category,
            attachments: entry.attachments.clone(),
        };

        if let Some(pos) = index.entries.iter().position(|e| e.id == entry_id) {
            index.entries[pos] = index_item;
        } else {
            index.entries.push(index_item);
        }
        // Saturate: `index.version` can arrive near u64::MAX via a crafted or
        // corrupt index, and `+= 1` would overflow and panic. As in merge(),
        // the counter only orders cache invalidation, so saturating is safe.
        index.version = index.version.saturating_add(1);

        let entry_json = serde_json::to_vec(&entry)
            .map_err(|e| CoreError::InvalidFormat(format!("failed to serialize entry: {e}")))?;
        let entry_enc = encrypt(&self.key, &entry_json, entry_id.as_bytes())?;

        let index_json = serde_json::to_vec(index)
            .map_err(|e| CoreError::InvalidFormat(format!("failed to serialize index: {e}")))?;
        let index_enc = encrypt(&self.key, &index_json, b"index")?;

        Ok((entry_enc, index_enc))
    }

    pub fn encrypt_attachment(&self, attachment: &Attachment, entry_id: &str) -> Result<Vec<u8>, CoreError> {
        let actual_len = attachment.data.len() as u64;
        if actual_len != attachment.meta.size_bytes {
            return Err(CoreError::InvalidFormat(format!(
                "attachment size_bytes ({}) does not match actual data length ({})",
                attachment.meta.size_bytes, actual_len
            )));
        }
        if actual_len > MAX_ATTACHMENT_SIZE_BYTES {
            return Err(CoreError::InvalidFormat(format!(
                "attachment of {actual_len} bytes exceeds the {MAX_ATTACHMENT_SIZE_BYTES}-byte limit"
            )));
        }
        let json = serde_json::to_vec(attachment)
            .map_err(|e| CoreError::InvalidFormat(format!("failed to serialize attachment: {e}")))?;
        let aad = format!("attachment:{}:{}", entry_id, attachment.meta.id);
        self.encrypt(&json, aad.as_bytes())
    }

    pub fn decrypt_attachment(&self, ciphertext: &[u8], entry_id: &str, attachment_id: &str) -> Result<Attachment, CoreError> {
        let aad = format!("attachment:{}:{}", entry_id, attachment_id);
        let bytes = self.decrypt(ciphertext, aad.as_bytes())?;
        let attachment: Attachment = serde_json::from_slice(&bytes)
            .map_err(|e| CoreError::InvalidFormat(format!("corrupt attachment json: {e}")))?;
        // Defense in depth: re-check even on the read path, since the
        // ciphertext could in principle come from an untrusted sync backend
        // rather than from our own encrypt_attachment above.
        if attachment.data.len() as u64 > MAX_ATTACHMENT_SIZE_BYTES {
            return Err(CoreError::InvalidFormat(format!(
                "attachment of {} bytes exceeds the {MAX_ATTACHMENT_SIZE_BYTES}-byte limit",
                attachment.data.len()
            )));
        }
        Ok(attachment)
    }
}

impl zeroize::Zeroize for Attachment {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl Drop for Attachment {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> KdfParams {
        KdfParams { memory_kib: 8192, iterations: 1, parallelism: 1 }
    }

    #[test]
    fn vault_create_and_unlock_roundtrip() {
        let (vault, manifest, index_enc) = Vault::create("pass123", test_params()).unwrap();
        let (_unlocked_vault, index) = Vault::unlock(&manifest, &index_enc, "pass123").unwrap();
        assert_eq!(index.entries.len(), 0);
        vault.lock();
    }

    #[test]
    fn put_and_decrypt_entry() {
        let (vault, _manifest, _index_enc) = Vault::create("pass123", test_params()).unwrap();
        let mut index = Index::default();
        index.tags.push(Tag {
            id: "tag-1".into(),
            name: "Tag".into(),
            updated_at: 1,
            deleted: false,
        });
        index.collections.push(Collection {
            id: "col-1".into(),
            name: "Collection".into(),
            parent_id: None,
            updated_at: 1,
            deleted: false,
        });

        let entry = Entry {
            id: "uuid-1".into(),
            title: "Github".into(),
            username: "user".into(),
            password: "secretpassword".into(),
            url: "https://github.com".into(),
            notes: "note".into(),
            totp_secret: None,
            custom_fields: HashMap::new(),
            updated_at: 100,
            deleted: false,
            tags: vec!["tag-1".into()],
            collection_id: Some("col-1".into()),
            favorite: true,
            alias_provider: None,
            alias_id: None,
            alias_email: None,
            category: Default::default(),
            password_history: Vec::new(),
            attachments: Vec::new(),
        };

        let (entry_enc, _updated_index_enc) = vault.put_entry(&mut index, entry.clone()).unwrap();
        let decrypted = vault.decrypt_entry(&entry_enc, "uuid-1").unwrap();
        assert_eq!(decrypted, entry);
        assert_eq!(index.entries.len(), 1);
        assert_eq!(index.entries[0].title, "Github");
        assert_eq!(index.entries[0].tags, vec!["tag-1".to_string()]);
        assert_eq!(index.entries[0].collection_id.as_deref(), Some("col-1"));
        assert!(index.entries[0].favorite);
    }

    #[test]
    fn put_entry_rejects_deleted_or_missing_metadata_references() {
        let (vault, _manifest, _index_enc) = Vault::create("pass123", test_params()).unwrap();
        let mut index = Index::default();
        let entry = Entry {
            id: "uuid-1".into(),
            title: "Github".into(),
            username: "user".into(),
            password: "secretpassword".into(),
            url: "https://github.com".into(),
            notes: "note".into(),
            totp_secret: None,
            custom_fields: HashMap::new(),
            updated_at: 100,
            deleted: false,
            tags: vec!["deleted-tag".into()],
            collection_id: Some("missing-collection".into()),
            favorite: false,
            alias_provider: None,
            alias_id: None,
            alias_email: None,
            category: Default::default(),
            password_history: Vec::new(),
            attachments: Vec::new(),
        };

        assert!(matches!(
            vault.put_entry(&mut index, entry),
            Err(CoreError::NotFound(message)) if message == "tag deleted-tag"
        ));
    }

    #[test]
    fn rekey_updates_key_and_reencrypts_all_entries() {
        let (mut vault, _manifest, _index_enc) = Vault::create("old_pass", test_params()).unwrap();
        let mut index = Index::default();
        let entry = Entry {
            id: "entry-1".into(),
            title: "Secret".into(),
            username: "admin".into(),
            password: "supersecretpassword".into(),
            url: "https://example.com".into(),
            notes: "".into(),
            totp_secret: None,
            custom_fields: HashMap::new(),
            updated_at: 100,
            deleted: false,
            tags: Vec::new(),
            collection_id: None,
            favorite: false,
            alias_provider: None,
            alias_id: None,
            alias_email: None,
            category: Default::default(),
            password_history: Vec::new(),
            attachments: Vec::new(),
        };

        let (old_entry_enc, _index_enc) = vault.put_entry(&mut index, entry.clone()).unwrap();

        let rekey_res = vault
            .rekey(
                &index,
                &[("entry-1", &old_entry_enc)],
                "new_pass",
                test_params(),
            )
            .unwrap();

        // 1. New manifest has version & parameters
        assert_eq!(rekey_res.manifest.version, CURRENT_VAULT_VERSION);

        // 2. Vault can unlock using new manifest and new password
        let (unlocked_vault, unlocked_index) =
            Vault::unlock(&rekey_res.manifest, &rekey_res.index_enc, "new_pass").unwrap();
        assert_eq!(unlocked_index.entries.len(), 1);

        // 3. Re-encrypted entry decrypts with new key
        let new_entry_enc = &rekey_res.entries_enc["entry-1"];
        let decrypted = unlocked_vault.decrypt_entry(new_entry_enc, "entry-1").unwrap();
        assert_eq!(decrypted, entry);

        // 4. Mutated vault handle decrypts with new key
        let decrypted_mut = vault.decrypt_entry(new_entry_enc, "entry-1").unwrap();
        assert_eq!(decrypted_mut, entry);
    }

    #[test]
    fn entry_zeroizes_secrets_on_drop() {
        let mut custom_fields = HashMap::new();
        custom_fields.insert("pin".to_string(), "1234".to_string());

        let mut entry = Entry {
            id: "e1".into(),
            title: "Github".into(),
            username: "user".into(),
            password: "supersecretpassword".into(),
            url: "https://github.com".into(),
            notes: "secret notes".into(),
            totp_secret: Some("JBSWY3DPEHPK3PXP".into()),
            custom_fields,
            updated_at: 100,
            deleted: false,
            tags: Vec::new(),
            collection_id: None,
            favorite: false,
            alias_provider: None,
            alias_id: None,
            alias_email: None,
            category: Default::default(),
            password_history: Vec::new(),
            attachments: Vec::new(),
        };

        // Explicitly zeroize secrets
        entry.zeroize();

        assert_eq!(entry.password, "");
        assert_eq!(entry.notes, "");
        assert_eq!(entry.totp_secret.as_deref(), Some(""));
        assert_eq!(entry.custom_fields.get("pin").map(|s| s.as_str()), Some(""));
    }

    #[test]
    fn encrypt_attachment_rejects_size_mismatch() {
        let (vault, _manifest, _index_enc) = Vault::create("pass123", test_params()).unwrap();
        let attachment = Attachment {
            meta: AttachmentMeta {
                id: "att-1".into(),
                filename: "id.jpg".into(),
                size_bytes: 999, // lies about the real length below
                mime_type: Some("image/jpeg".into()),
                updated_at: 1,
            },
            data: vec![0u8; 10],
        };
        let err = vault.encrypt_attachment(&attachment, "entry-1").unwrap_err();
        assert!(matches!(err, CoreError::InvalidFormat(_)));
    }

    #[test]
    fn encrypt_attachment_rejects_oversized_data() {
        let (vault, _manifest, _index_enc) = Vault::create("pass123", test_params()).unwrap();
        let big_len = (MAX_ATTACHMENT_SIZE_BYTES + 1) as usize;
        let attachment = Attachment {
            meta: AttachmentMeta {
                id: "att-2".into(),
                filename: "huge.bin".into(),
                size_bytes: big_len as u64,
                mime_type: None,
                updated_at: 1,
            },
            data: vec![0u8; big_len],
        };
        let err = vault.encrypt_attachment(&attachment, "entry-1").unwrap_err();
        assert!(matches!(err, CoreError::InvalidFormat(_)));
    }

    #[test]
    fn encrypt_decrypt_attachment_roundtrip() {
        let (vault, _manifest, _index_enc) = Vault::create("pass123", test_params()).unwrap();
        let attachment = Attachment {
            meta: AttachmentMeta {
                id: "att-3".into(),
                filename: "id.jpg".into(),
                size_bytes: 4,
                mime_type: Some("image/jpeg".into()),
                updated_at: 1,
            },
            data: vec![1, 2, 3, 4],
        };
        let enc = vault.encrypt_attachment(&attachment, "entry-1").unwrap();
        let dec = vault.decrypt_attachment(&enc, "entry-1", "att-3").unwrap();
        assert_eq!(dec.data, vec![1, 2, 3, 4]);
    }

    // Regression: put_entry did `index.version += 1`, which overflowed and
    // panicked when the index already sat at u64::MAX — reachable by
    // unlocking a crafted or corrupt index and saving one entry.

    #[test]
    fn put_entry_saturates_index_version_instead_of_overflowing() {
        let (vault, _manifest, _index_enc) = Vault::create("pass123", test_params()).unwrap();
        let mut index = Index {
            version: u64::MAX,
            ..Default::default()
        };

        let entry = Entry {
            id: "e-max".into(),
            title: "Edge".into(),
            username: "u".into(),
            password: "p".into(),
            url: "".into(),
            notes: "".into(),
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
            category: ItemCategory::default(),
            password_history: vec![],
            attachments: vec![],
        };

        vault.put_entry(&mut index, entry).expect("put_entry must not overflow");
        assert_eq!(index.version, u64::MAX, "saturates at u64::MAX");
    }

    #[test]
    fn put_entry_still_increments_version_normally() {
        let (vault, _manifest, _index_enc) = Vault::create("pass123", test_params()).unwrap();
        let mut index = Index {
            version: 3,
            ..Default::default()
        };

        let entry = Entry {
            id: "e-inc".into(),
            title: "Inc".into(),
            username: "u".into(),
            password: "p".into(),
            url: "".into(),
            notes: "".into(),
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
            category: ItemCategory::default(),
            password_history: vec![],
            attachments: vec![],
        };

        vault.put_entry(&mut index, entry).unwrap();
        assert_eq!(index.version, 4, "ordinary case still increments");
    }
}
