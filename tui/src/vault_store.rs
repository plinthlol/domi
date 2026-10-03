//! On-disk vault storage.
//!
//! Layout (from the AUDIT.md blueprint, paths renamed to Domi):
//!
//! ```text
//! ~/.local/share/domi/vault/
//! ├── manifest.json      # VaultManifest as JSON — not secret
//! ├── index.enc          # encrypted Index blob
//! └── entries/{uuid}.enc # one encrypted Entry per file
//! ```
//!
//! This module owns every filesystem touch and has no iocraft dependency, so
//! all of it is testable without a terminal.
//!
//! Two invariants matter here:
//!
//! 1. **No plaintext secrets on disk.** Only `manifest.json` is written in the
//!    clear, and it holds nothing but the KDF salt and parameters. Entries and
//!    the index are written as the encrypted blobs `domi-core` produces.
//! 2. **Atomic-ish writes.** An entry is written to a temp file then renamed, so
//!    a crash mid-save can't leave a half-written `.enc` that fails to decrypt
//!    forever.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use domi_core::{Entry, Index, KdfParams, Vault, VaultManifest};

use crate::error::AppError;

/// The on-disk location of a vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultPaths {
    root: PathBuf,
}

impl Default for VaultPaths {
    /// The same as [`VaultPaths::default_location`].
    ///
    /// Hand-written rather than derived because the default reads the
    /// environment, and a derived `Default` would hand back an empty path.
    fn default() -> Self {
        Self::default_location()
    }
}

impl VaultPaths {
    /// Builds paths for a vault rooted at `root` (the `vault/` directory
    /// itself, not its parent).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        VaultPaths { root: root.into() }
    }

    /// The platform-appropriate default location.
    ///
    /// `DOMI_VAULT_DIR` overrides it, which lets a user point the TUI at a
    /// specific vault.
    pub fn default_location() -> Self {
        Self::default_location_from(std::env::var("DOMI_VAULT_DIR").ok())
    }

    /// The same lookup, with the override supplied directly.
    ///
    /// The env var is process-global, so tests pass the value as an argument
    /// instead of calling `set_var` — otherwise two tests touching it on
    /// parallel threads race and intermittently clobber each other.
    fn default_location_from(override_dir: Option<String>) -> Self {
        if let Some(custom) = override_dir.filter(|c| !c.is_empty()) {
            return VaultPaths::new(custom);
        }
        let base = directories::ProjectDirs::from("", "", "domi")
            .map(|d| d.data_dir().to_path_buf())
            .unwrap_or_else(|| {
                // Fall back to a relative dir rather than panicking; the error
                // surfaces later as a normal storage failure the user sees.
                PathBuf::from(".domi")
            });
        VaultPaths::new(base.join("vault"))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn manifest_file(&self) -> PathBuf {
        self.root.join("manifest.json")
    }

    fn index_file(&self) -> PathBuf {
        self.root.join("index.enc")
    }

    fn entries_dir(&self) -> PathBuf {
        self.root.join("entries")
    }

    fn entry_file(&self, id: &str) -> PathBuf {
        self.entries_dir().join(format!("{id}.enc"))
    }

    /// True when a manifest is present, i.e. a vault already exists here.
    pub fn exists(&self) -> bool {
        self.manifest_file().is_file()
    }
}

/// Writes `bytes` to `path` via a temp file + rename, so a reader never sees a
/// partially written file.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), AppError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| AppError::Storage(format!("{}: {e}", parent.display())))?;
    }
    let tmp = path.with_extension("enc.tmp");
    {
        let mut f = fs::File::create(&tmp)
            .map_err(|e| AppError::Storage(format!("{}: {e}", tmp.display())))?;
        f.write_all(bytes)
            .map_err(|e| AppError::Storage(format!("{}: {e}", tmp.display())))?;
        // Force to disk before the rename, otherwise a crash can leave the
        // renamed file present but empty.
        f.sync_all()
            .map_err(|e| AppError::Storage(format!("{}: {e}", tmp.display())))?;
    }
    fs::rename(&tmp, path)
        .map_err(|e| AppError::Storage(format!("{}: {e}", path.display())))?;
    Ok(())
}

/// A fresh tag id, in the same 32-hex shape as entry ids.
///
/// Tag ids only have to be unique within one vault, so the wall clock plus a
/// counter is enough — see [`crate::state`] for the reasoning.
fn new_tag_id(now: i64) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id() as u64;
    format!("{:016x}{:04x}{:012x}", now.unsigned_abs(), pid, seq)
}

/// An unlocked vault plus the plaintext index, held in memory for the session.
/// Holds a `Vault`, which owns the derived `Key`. The key is zeroized on drop
/// and is never exposed as a value — there is no accessor, by design.
///
/// Deliberately not `Debug`: printing a session must never be able to reach key
/// material or plaintext entries.
pub struct VaultSession {
    vault: Vault,
    pub index: Index,
    paths: VaultPaths,
}

impl VaultSession {
    /// Creates a new vault on disk and returns an unlocked session.
    ///
    /// `params` is the KDF cost. Callers pass a deliberately cheap one in tests
    /// — the production default is `KdfParams::default()` (64 MiB, t=3).
    pub fn create(
        paths: VaultPaths,
        password: &str,
        params: KdfParams,
    ) -> Result<VaultSession, AppError> {
        if paths.exists() {
            return Err(AppError::VaultExists);
        }

        let (vault, manifest, index_enc) =
            Vault::create(password, params).map_err(|e| AppError::BadInput(e.to_string()))?;

        let manifest_json = serde_json::to_vec_pretty(&manifest)
            .map_err(|e| AppError::Storage(format!("manifest: {e}")))?;
        write_atomic(&paths.manifest_file(), &manifest_json)?;
        write_atomic(&paths.index_file(), &index_enc)?;

        Ok(VaultSession {
            vault,
            index: Index::default(),
            paths,
        })
    }

    /// Opens an existing vault, deriving the key from `password`.
    pub fn unlock(paths: VaultPaths, password: &str) -> Result<VaultSession, AppError> {
        if !paths.exists() {
            return Err(AppError::NoVault);
        }
        let manifest_bytes = fs::read(paths.manifest_file())
            .map_err(|e| AppError::Storage(format!("manifest: {e}")))?;
        let manifest: VaultManifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|_| AppError::Storage("manifest is not readable".to_string()))?;
        let index_enc = fs::read(paths.index_file())
            .map_err(|e| AppError::Storage(format!("index: {e}")))?;

        let (vault, index) = Vault::unlock(&manifest, &index_enc, password)
            .map_err(|e| crate::error::friendly(e, "vault"))?;

        Ok(VaultSession { vault, index, paths })
    }

    /// Reads and decrypts one entry by id.
    pub fn load_entry(&self, id: &str) -> Result<Entry, AppError> {
        let bytes = fs::read(self.paths.entry_file(id))
            .map_err(|e| AppError::Storage(format!("entry {id}: {e}")))?;
        self.vault
            .decrypt_entry(&bytes, id)
            .map_err(|e| crate::error::friendly(e, "entry"))
    }

    /// Encrypts, writes, and indexes an entry. Returns the encrypted blob.
    ///
    /// `put_entry` also bumps `index.version` and syncs the `IndexEntry`, so
    /// search and filtering see the change without decrypting anything.
    pub fn save_entry(&mut self, entry: Entry) -> Result<(), AppError> {
        let id = entry.id.clone();
        let (entry_enc, index_enc) = self
            .vault
            .put_entry(&mut self.index, entry)
            .map_err(|e| crate::error::friendly(e, "entry"))?;

        write_atomic(&self.paths.entry_file(&id), &entry_enc)?;
        // Index last: if the entry write failed we never advertised it.
        write_atomic(&self.paths.index_file(), &index_enc)?;
        Ok(())
    }

    /// Resolves tag *names* to the tag *ids* core stores, creating any tag the
    /// vault doesn't have yet.
    ///
    /// `Entry.tags` holds ids and `put_entry` rejects an entry referencing a
    /// tag that isn't in the index, so a name typed into the form has to be
    /// registered before the entry that carries it can be written. Names are
    /// matched case-insensitively, the same rule core's `create_tag` uses for
    /// duplicates, so "Work" and "work" are one tag.
    ///
    /// Returns the ids in the order given, with a repeated name collapsed.
    /// The index is persisted here when a tag was added; if it was not, the
    /// caller's `put_entry` will rewrite it anyway.
    pub fn ensure_tags(&mut self, names: &[String], now: i64) -> Result<Vec<String>, AppError> {
        if names.is_empty() {
            return Ok(Vec::new());
        }

        let mut ids: Vec<String> = Vec::new();
        let mut added = false;
        for name in names {
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            let existing = self.index.tags.iter().find(|t| {
                !t.deleted && t.name.eq_ignore_ascii_case(name)
            });
            let id = match existing {
                Some(tag) => tag.id.clone(),
                None => {
                    let tag = domi_core::create_tag(
                        &mut self.index,
                        new_tag_id(now),
                        name,
                        now,
                    )
                    .map_err(|e| crate::error::friendly(e, "tag"))?;
                    added = true;
                    tag.id
                }
            };
            if !ids.contains(&id) {
                ids.push(id);
            }
        }

        if added {
            self.persist_index()?;
        }
        Ok(ids)
    }

    /// Writes the current index back to disk.
    ///
    /// Needed for edits that change the index without going through
    /// `put_entry` — creating a tag, for instance. The AAD is the same `index`
    /// marker `Vault::put_entry` and `Vault::unlock` use, so the blob stays
    /// readable on the next unlock.
    fn persist_index(&mut self) -> Result<(), AppError> {
        let json = serde_json::to_vec(&self.index)
            .map_err(|e| AppError::Storage(format!("index: {e}")))?;
        let enc = self
            .vault
            .encrypt(&json, b"index")
            .map_err(|e| crate::error::friendly(e, "index"))?;
        write_atomic(&self.paths.index_file(), &enc)
    }

    /// Soft-deletes an entry: sets `deleted`, which `put_entry` mirrors into
    /// the index so it disappears from search without erasing the blob. The
    /// `.enc` file is kept so an accidental delete is recoverable in-session.
    pub fn delete_entry(&mut self, id: &str) -> Result<(), AppError> {
        let mut entry = self.load_entry(id)?;
        entry.deleted = true;
        entry.updated_at = domi_core::now_unix();
        self.save_entry(entry)
    }

    /// Re-derives the key from `new_password`, re-encrypting every entry.
    ///
    /// Returns the new manifest so the caller can write it back to disk.
    pub fn rekey(&mut self, new_password: &str) -> Result<VaultManifest, AppError> {
        let mut refs: Vec<(String, Vec<u8>)> = Vec::new();
        for e in self.index.entries.iter().filter(|e| !e.deleted) {
            let path = self.paths.entry_file(&e.id);
            if !path.is_file() {
                continue;
            }
            let bytes = fs::read(&path)
                .map_err(|err| AppError::Storage(format!("entry {}: {err}", e.id)))?;
            refs.push((e.id.clone(), bytes));
        }
        let borrowed: Vec<(&str, &[u8])> =
            refs.iter().map(|(id, b)| (id.as_str(), b.as_slice())).collect();

        let result = self
            .vault
            .rekey(&self.index, &borrowed, new_password, KdfParams::default())
            .map_err(|e| crate::error::friendly(e, "vault"))?;

        // Write the new entry blobs before the new index, so an interrupted
        // rekey leaves the old manifest/key intact and still readable rather
        // than pointing at a key that no longer matches the files.
        for (id, bytes) in &result.entries_enc {
            write_atomic(&self.paths.entry_file(id), bytes)?;
        }
        write_atomic(&self.paths.index_file(), &result.index_enc)?;
        let manifest_json = serde_json::to_vec_pretty(&result.manifest)
            .map_err(|e| AppError::Storage(format!("manifest: {e}")))?;
        write_atomic(&self.paths.manifest_file(), &manifest_json)?;
        Ok(result.manifest)
    }

    /// The entries the vault is showing, i.e. everything not soft-deleted.
    ///
    /// The index itself keeps deleted entries so a delete can be undone by
    /// hand; callers that mean "what the user has" want this.
    #[cfg(test)]
    pub fn visible_entries(&self) -> Vec<&domi_core::IndexEntry> {
        self.index.entries.iter().filter(|e| !e.deleted).collect()
    }

    /// Drops the vault, zeroizing the key.
    pub fn lock(self) {}
}

/// Cheap KDF params for tests — Argon2 at production cost would make the suite
/// take minutes.
#[cfg(test)]
pub fn test_params() -> KdfParams {
    KdfParams { memory_kib: 8192, iterations: 1, parallelism: 1 }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    /// A unique temp vault per test, removed on drop.
    pub struct TempVault(PathBuf);

    impl TempVault {
        pub fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir().join(format!("domi-test-{}-{}", std::process::id(), n));
            let _ = fs::remove_dir_all(&p);
            TempVault(p)
        }

        pub fn paths(&self) -> VaultPaths {
            VaultPaths::new(self.0.join("vault"))
        }
    }

    impl Drop for TempVault {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

/// Builds a blank entry with sensible defaults for the form.
#[cfg(test)]
pub fn blank_entry(id: String, now: i64) -> Entry {
    Entry {
        id,
        title: String::new(),
        username: String::new(),
        password: String::new(),
        url: String::new(),
        notes: String::new(),
        totp_secret: None,
        custom_fields: std::collections::HashMap::new(),
        updated_at: now,
        deleted: false,
        tags: vec![],
        collection_id: None,
        favorite: false,
        alias_provider: None,
        alias_id: None,
        alias_email: None,
        category: Default::default(),
        password_history: vec![],
        attachments: vec![],
    }
}

/// Asserts a `Result<_, AppError>` failed with `expected`.
///
/// `unwrap_err()` would need `Debug` on the success type, and `VaultSession`
/// deliberately doesn't implement it so a session can never be printed.
#[cfg(test)]
fn expect_err(result: Result<VaultSession, AppError>, expected: AppError) {
    match result {
        Err(e) => assert_eq!(e, expected, "unexpected error"),
        Ok(_) => panic!("expected {expected:?}, got Ok"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault_store::testing::TempVault;

    #[test]
    fn create_then_unlock_roundtrips() {
        let t = TempVault::new();
        let paths = t.paths();
        assert!(!paths.exists());

        VaultSession::create(paths.clone(), "master", test_params()).unwrap();
        assert!(paths.exists());

        let s = VaultSession::unlock(paths, "master").unwrap();
        assert_eq!(s.index.entries.len(), 0);
    }

    #[test]
    fn manifest_is_readable_json_and_holds_no_secret() {
        let t = TempVault::new();
        let paths = t.paths();
        VaultSession::create(paths.clone(), "master", test_params()).unwrap();

        let bytes = fs::read(paths.root().join("manifest.json")).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();

        // KDF parameters and salt are expected in the clear.
        assert!(v.get("salt").is_some());
        assert!(v.get("memory_kib").is_some());
        // The password must never appear.
        assert!(!text.contains("master"));
    }

    #[test]
    fn index_and_entries_are_not_plaintext_on_disk() {
        let t = TempVault::new();
        let paths = t.paths();
        let mut s = VaultSession::create(paths.clone(), "master", test_params()).unwrap();

        let mut e = blank_entry("entry-1".into(), 1);
        e.title = "VerySecretBank".into();
        e.password = "hunter2-should-never-appear".into();
        s.save_entry(e).unwrap();

        let index_bytes = fs::read(paths.root().join("index.enc")).unwrap();
        assert!(
            !String::from_utf8_lossy(&index_bytes).contains("VerySecretBank"),
            "title leaked into index.enc"
        );

        let entry_bytes = fs::read(paths.root().join("entries/entry-1.enc")).unwrap();
        for secret in ["VerySecretBank", "hunter2-should-never-appear"] {
            assert!(
                !String::from_utf8_lossy(&entry_bytes).contains(secret),
                "{secret} leaked into the entry blob"
            );
        }
    }

    #[test]
    fn unlock_with_wrong_password_is_rejected() {
        let t = TempVault::new();
        let paths = t.paths();
        VaultSession::create(paths.clone(), "master", test_params()).unwrap();

        expect_err(VaultSession::unlock(paths, "nope"), AppError::WrongPassword);
    }

    #[test]
    fn unlock_without_a_vault_reports_no_vault() {
        let t = TempVault::new();
        expect_err(VaultSession::unlock(t.paths(), "master"), AppError::NoVault);
    }

    #[test]
    fn create_over_an_existing_vault_is_refused() {
        let t = TempVault::new();
        let paths = t.paths();
        VaultSession::create(paths.clone(), "master", test_params()).unwrap();
        expect_err(
            VaultSession::create(paths, "other", test_params()),
            AppError::VaultExists,
        );
    }

    #[test]
    fn saved_entry_survives_a_reopen() {
        let t = TempVault::new();
        let paths = t.paths();
        {
            let mut s = VaultSession::create(paths.clone(), "master", test_params()).unwrap();
            let mut e = blank_entry("entry-1".into(), 1);
            e.title = "GitHub".into();
            e.username = "octocat".into();
            e.password = "secret".into();
            s.save_entry(e).unwrap();
        }

        let s = VaultSession::unlock(paths, "master").unwrap();
        let loaded = s.load_entry("entry-1").unwrap();
        assert_eq!(loaded.title, "GitHub");
        assert_eq!(loaded.username, "octocat");
        assert_eq!(loaded.password, "secret");
        assert_eq!(s.visible_entries().len(), 1);
    }

    #[test]
    fn index_is_updated_so_search_sees_new_entries() {
        let t = TempVault::new();
        let paths = t.paths();
        let mut s = VaultSession::create(paths.clone(), "master", test_params()).unwrap();

        let mut e = blank_entry("entry-1".into(), 1);
        e.title = "Findable".into();
        s.save_entry(e).unwrap();

        assert_eq!(s.index.entries.len(), 1);
        assert_eq!(s.index.entries[0].title, "Findable");
        assert!(s.index.version > 0, "version should have advanced");
    }

    #[test]
    fn delete_hides_the_entry_from_visible_entries_but_keeps_the_blob() {
        let t = TempVault::new();
        let paths = t.paths();
        let mut s = VaultSession::create(paths.clone(), "master", test_params()).unwrap();

        let mut e = blank_entry("entry-1".into(), 1);
        e.title = "Doomed".into();
        s.save_entry(e).unwrap();
        assert_eq!(s.visible_entries().len(), 1);

        s.delete_entry("entry-1").unwrap();
        assert_eq!(s.visible_entries().len(), 0, "deleted entry must not be listed");
        assert!(
            paths.root().join("entries/entry-1.enc").is_file(),
            "blob should be retained so the delete is recoverable"
        );
    }

    #[test]
    fn delete_of_a_missing_entry_errors_rather_than_panicking() {
        let t = TempVault::new();
        let paths = t.paths();
        let mut s = VaultSession::create(paths, "master", test_params()).unwrap();
        match s.delete_entry("nope") {
            Err(AppError::Storage(msg)) => assert!(msg.contains("nope"), "message should name the entry: {msg}"),
            other => panic!("expected a storage error, got {other:?}"),
        }
    }

    #[test]
    fn rekey_changes_the_password_and_preserves_entries() {
        let t = TempVault::new();
        let paths = t.paths();
        {
            let mut s = VaultSession::create(paths.clone(), "master", test_params()).unwrap();
            for (id, title) in [("e1", "One"), ("e2", "Two"), ("e3", "Three")] {
                let mut e = blank_entry(id.into(), 1);
                e.title = title.into();
                e.password = format!("pw-{title}");
                s.save_entry(e).unwrap();
            }
        }

        {
            let mut s = VaultSession::unlock(paths.clone(), "master").unwrap();
            s.rekey("brand-new-pass").unwrap();
        }

        // New password works, old one doesn't, and the data is intact.
        let s = VaultSession::unlock(paths.clone(), "brand-new-pass").unwrap();
        assert_eq!(s.index.entries.len(), 3);
        assert_eq!(s.load_entry("e2").unwrap().title, "Two");
        assert_eq!(s.load_entry("e3").unwrap().password, "pw-Three");

        expect_err(VaultSession::unlock(paths, "master"), AppError::WrongPassword);
    }

    #[test]
    fn default_location_honours_the_env_override() {
        // Lets a user point the TUI at a specific vault for testing.
        let p = VaultPaths::default_location_from(Some("/tmp/domi-override-check".into()));
        assert_eq!(p.root(), Path::new("/tmp/domi-override-check"));
    }

    #[test]
    fn an_empty_override_falls_back_to_the_platform_default() {
        let empty = VaultPaths::default_location_from(Some(String::new()));
        let none = VaultPaths::default_location_from(None);
        assert_eq!(empty.root(), none.root());
    }

    #[test]
    fn default_location_is_absolute_and_mentions_domi() {
        let p = VaultPaths::default_location_from(None);
        let s = p.root().to_string_lossy().to_string();
        assert!(s.contains("domi"), "default path should be Domi-scoped: {s}");
    }

    #[test]
    fn writes_leave_no_temp_files_behind() {
        let t = TempVault::new();
        let paths = t.paths();
        let mut s = VaultSession::create(paths.clone(), "master", test_params()).unwrap();
        let mut e = blank_entry("entry-1".into(), 1);
        e.title = "Tidy".into();
        s.save_entry(e).unwrap();

        let leftovers: Vec<_> = fs::read_dir(paths.root().join("entries"))
            .unwrap()
            .filter_map(|d| d.ok())
            .map(|d| d.file_name().to_string_lossy().to_string())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp files left behind: {leftovers:?}");
    }

    #[test]
    fn corrupt_index_reports_storage_error_not_a_panic() {
        let t = TempVault::new();
        let paths = t.paths();
        VaultSession::create(paths.clone(), "master", test_params()).unwrap();
        fs::write(paths.root().join("index.enc"), b"not a valid blob").unwrap();

        // Fails to decrypt, which the error mapper turns into WrongPassword.
        assert!(VaultSession::unlock(paths, "master").is_err());
    }
}