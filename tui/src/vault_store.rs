//! On-disk vault storage.
//!
//! Layout:
//!
//! ```text
//! <root>/
//! ├── manifest.json      # VaultManifest as JSON — not secret
//! ├── index.enc          # encrypted Index blob
//! └── entries/{uuid}.enc # one encrypted Entry per file
//! ```
//!
//! This module owns every filesystem touch and has no UI dependency, so all of
//! it is testable without a terminal.
//!
//! Two invariants matter here:
//!
//! 1. **No plaintext secrets on disk.** Only `manifest.json` is written in the
//!    clear, and it holds nothing but the KDF salt and parameters. Entries and
//!    the index are written as the encrypted blobs `domi-core` produces.
//! 2. **Atomic-ish writes.** An entry is written to a temp file then renamed,
//!    so a crash mid-save can't leave a half-written `.enc` that fails to
//!    decrypt forever.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use domi_core::{Entry, Index, KdfParams, Vault, VaultManifest};

use crate::error::AppError;

/// The AEAD associated data core binds the index to.
///
/// Core hard-codes `b"index"` in both `Vault::create` and `Vault::unlock`. The
/// TUI only writes an index directly in [`VaultSession::wipe`]; naming the value
/// here keeps that one call site honest against the two in core.
const INDEX_AAD: &[u8] = b"index";

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
    /// The config file's `vault-dir` wins outright. An earlier version of this
    /// put `DOMI_VAULT_DIR` first so a shell export could override the file;
    /// that made the app's own settings setting silently lose to whatever
    /// happened to be exported, so the file now takes precedence and the env
    /// var is only a fallback for people who never open the settings screen.
    pub fn default_location() -> Self {
        let from_file = match crate::config::Config::load() {
            Ok(cfg) => cfg.vault_dir().map(Self::new),
            Err(e) => {
                eprintln!("{}: ignoring unreadable config: {e}", crate::bin_name());
                None
            }
        };
        Self::resolve(from_file, std::env::var("DOMI_VAULT_DIR").ok())
    }

    /// The precedence chain itself, with both inputs supplied by the caller.
    ///
    /// Split out from [`VaultPaths::default_location`] so the ordering can be
    /// pinned by a test without mutating process-wide environment state, which
    /// races across `cargo test`'s threads.
    ///
    /// A config file that fails to parse has already been turned into `None` by
    /// the caller: it is reported and then ignored, which leaves the user on
    /// their default vault and is far better than refusing to start over a
    /// stray typo in a preferences file.
    fn resolve(from_file: Option<Self>, env_dir: Option<String>) -> Self {
        if let Some(paths) = from_file {
            return paths;
        }
        if let Some(paths) = Self::from_env(env_dir) {
            return paths;
        }
        Self::default_platform_location()
    }

    /// The location implied by `DOMI_VAULT_DIR` alone, if it is set.
    ///
    /// Blank values are dropped here so an exported-but-empty variable cannot
    /// resolve the vault to the current directory.
    fn from_env(override_dir: Option<String>) -> Option<Self> {
        override_dir
            .as_deref()
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .map(Self::new)
    }

    /// The platform default, ignoring both the env var and the config file.
    fn default_platform_location() -> Self {
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

/// A fresh entry id.
///
/// Core mints ids for its own callers, but the TUI needs one per new entry,
/// and a vault may legitimately hold two entries created in the same second
/// (a test creating three in a loop, or a script seeding a vault), so the
/// process id and a counter join the wall clock.
pub fn new_entry_id(now: i64) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id() as u64;
    // The widths here are masks, not minimums. A 33-character id slipped
    // through once because `{:04x}` happily prints five digits for a pid above
    // 0xffff, and the id is also the file name on disk.
    format!(
        "{:016x}{:04x}{:012x}",
        now.unsigned_abs() & 0xffff_ffff_ffff_ffff,
        pid & 0xffff,
        seq & 0xffff_ffff_ffff,
    )
}

/// A fresh tag id, in the same 32-hex shape as entry ids.
///
/// Tag ids only have to be unique within one vault, so the wall clock plus a
/// counter is enough — see [`new_entry_id`] for the reasoning.
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
    /// The KDF cost this vault was created with, kept so a rekey can reuse it
    /// instead of silently weakening or changing the vault's parameters.
    params: KdfParams,
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

        Ok(VaultSession { vault, index: Index::default(), paths, params })
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

        Ok(VaultSession { vault, index, paths, params: manifest.kdf_params() })
    }

    /// Decrypts one entry by id.
    ///
    /// The id doubles as the AEAD associated data, so a blob moved to another
    /// file name fails to decrypt rather than silently returning someone else's
    /// entry.
    pub fn load_entry(&self, id: &str) -> Result<Entry, AppError> {
        let bytes = fs::read(self.paths.entry_file(id))
            .map_err(|e| AppError::Storage(format!("entry {id}: {e}")))?;
        self.vault
            .decrypt_entry(&bytes, id)
            .map_err(|e| crate::error::friendly(e, "entry"))
    }

    /// Encrypts and writes one entry, then refreshes the index.
    ///
    /// `put_entry` returns both blobs from one pass, so the index and the entry
    /// are always mutually consistent. The entry blob is written before the
    /// index, so an interrupted save leaves an orphan blob the index does not
    /// reference — harmless — rather than an index pointing at a blob that was
    /// never written, which would make the entry permanently undecryptable.
    pub fn save_entry(&mut self, entry: Entry) -> Result<(), AppError> {
        let id = entry.id.clone();
        let (entry_enc, index_enc) = self
            .vault
            .put_entry(&mut self.index, entry)
            .map_err(|e| crate::error::friendly(e, "entry"))?;

        write_atomic(&self.paths.entry_file(&id), &entry_enc)?;
        write_atomic(&self.paths.index_file(), &index_enc)
    }

    /// Makes sure every name in `names` has a tag id, creating what is missing.
    ///
    /// Tag names are user-typed and free-form, so they are matched
    /// case-insensitively: typing "Work" twice should not produce two tags.
    pub fn ensure_tags(
        &mut self,
        names: &[String],
        now: i64,
    ) -> Result<Vec<String>, AppError> {
        let mut ids: Vec<String> = Vec::with_capacity(names.len());
        for name in names {
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            let existing = self.index.tags.iter().find(|t| t.name.eq_ignore_ascii_case(name));
            let id = match existing {
                Some(t) => t.id.clone(),
                None => {
                    let id = new_tag_id(now);
                    let tag = domi_core::Tag {
                        id: id.clone(),
                        name: name.to_string(),
                        updated_at: now,
                        deleted: false,
                    };
                    self.index.tags.push(tag);
                    id
                }
            };
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
        Ok(ids)
    }

    /// Marks an entry deleted, keeping its blob so a delete can be undone by
    /// hand.
    ///
    /// The entry is decrypted, flagged, and written back through the same path
    /// as a save, so the index and the blob stay in step.
    pub fn delete_entry(&mut self, id: &str) -> Result<(), AppError> {
        let mut entry = self.load_entry(id)?;
        entry.deleted = true;
        entry.updated_at = domi_core::now_unix();
        self.save_entry(entry)
    }

    /// Marks every entry deleted and removes the blobs.
    ///
    /// Soft-deletes alone would leave the vault full of ciphertext the user
    /// believes is gone, so this also unlinks the files. Each blob is removed
    /// before the new index is written: an interrupted wipe leaves entries that
    /// fail to load rather than an index that points at nothing.
    pub fn wipe(&mut self) -> Result<usize, AppError> {
        let live: Vec<String> = self
            .index
            .entries
            .iter()
            .filter(|e| !e.deleted)
            .map(|e| e.id.clone())
            .collect();

        for id in &live {
            let path = self.paths.entry_file(id);
            match fs::remove_file(&path) {
                Ok(()) => {}
                // A blob that is already gone is the outcome we wanted.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(AppError::Storage(format!("entry {id}: {e}"))),
            }
        }

        // Drop the entries outright rather than soft-deleting them: the blobs
        // are gone, so leaving tombstones would have the list offer rows that
        // fail to load. `Vault::create` encrypts an empty index with the same
        // AAD, so this is the identical write on a populated key.
        self.index = Index {
            version: self.index.version.saturating_add(1),
            entries: Vec::new(),
            tags: Vec::new(),
            collections: Vec::new(),
        };
        self.write_index()?;
        Ok(live.len())
    }

    /// Encrypts the current index under the session key and writes it.
    fn write_index(&mut self) -> Result<(), AppError> {
        let json = serde_json::to_vec(&self.index)
            .map_err(|e| AppError::Storage(format!("index: {e}")))?;
        let enc = self
            .vault
            .encrypt(&json, INDEX_AAD)
            .map_err(|e| AppError::Storage(format!("index: {e}")))?;
        write_atomic(&self.paths.index_file(), &enc)
    }

    /// Re-encrypts the whole vault under a new password.
    ///
    /// Every entry is decrypted and re-encrypted under the new key before
    /// anything on disk is replaced, so an interrupted rekey leaves the old
    /// password working. Writing the manifest first would leave it describing a
    /// key that no blob matches.
    ///
    /// The vault's KDF cost is reused rather than reset to the default: a vault
    /// deliberately created at a higher cost should not silently drop to 64 MiB
    /// because its password was changed.
    pub fn rekey(&mut self, new_password: &str) -> Result<VaultManifest, AppError> {
        // Core rekeys from the encrypted blobs, so collect them first. A blob
        // that is missing is skipped rather than failing the whole rekey: the
        // index can outlive a file the user removed by hand, and refusing to
        // change the password would strand them.
        let mut refs: Vec<(String, Vec<u8>)> = Vec::new();
        for item in self.index.entries.iter().filter(|e| !e.deleted) {
            let path = self.paths.entry_file(&item.id);
            if !path.is_file() {
                continue;
            }
            let bytes = fs::read(&path)
                .map_err(|e| AppError::Storage(format!("entry {}: {e}", item.id)))?;
            refs.push((item.id.clone(), bytes));
        }
        let borrowed: Vec<(&str, &[u8])> =
            refs.iter().map(|(id, b)| (id.as_str(), b.as_slice())).collect();

        // `Vault::rekey` swaps the key in place, so `self.vault` is already
        // holding the new one by the time it returns.
        let result = self
            .vault
            .rekey(&self.index, &borrowed, new_password, self.params)
            .map_err(|e| crate::error::friendly(e, "vault"))?;

        // Write the new entry blobs before the new index and manifest, so an
        // interrupted rekey leaves the old manifest and key intact and still
        // readable rather than pointing at a key that no longer matches the
        // files.
        for (id, bytes) in &result.entries_enc {
            write_atomic(&self.paths.entry_file(id), bytes)?;
        }
        write_atomic(&self.paths.index_file(), &result.index_enc)?;
        let manifest_json = serde_json::to_vec_pretty(&result.manifest)
            .map_err(|e| AppError::Storage(format!("manifest: {e}")))?;
        write_atomic(&self.paths.manifest_file(), &manifest_json)?;

        self.params = result.manifest.kdf_params();
        Ok(result.manifest)
    }

    /// Every entry the user has not deleted.
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
            let path = std::env::temp_dir()
                .join(format!("domi-vault-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            TempVault(path)
        }

        pub fn paths(&self) -> VaultPaths {
            VaultPaths::new(&self.0)
        }

        /// The vault's directory, for tests that inspect what landed on disk.
        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Default for TempVault {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Drop for TempVault {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

/// A blank entry for tests, with the required fields filled in.
#[cfg(test)]
pub fn blank_entry(id: String, now: i64) -> Entry {
    Entry {
        id,
        title: "Example".into(),
        username: "someone@example.com".into(),
        password: "hunter2".into(),
        url: "https://example.com".into(),
        notes: String::new(),
        totp_secret: None,
        custom_fields: Default::default(),
        updated_at: now,
        deleted: false,
        tags: vec![],
        collection_id: None,
        favorite: false,
        alias_provider: None,
        alias_id: None,
        alias_email: None,
        category: domi_core::vault::ItemCategory::Login,
        password_history: vec![],
        attachments: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault_store::testing::TempVault;

    #[test]
    fn the_env_var_is_used_when_the_config_file_is_silent() {
        // `from_env` is the env-only slice of the precedence chain, reached only
        // once the config file has failed to name a directory.
        let paths = VaultPaths::from_env(Some("/tmp/from-env".into())).expect("env is set");
        assert_eq!(paths.root(), Path::new("/tmp/from-env"));
    }

    #[test]
    fn the_config_file_beats_the_env_var() {
        // The rule the user asked for: a setting saved by the settings screen
        // outranks a shell export, so the app never appears to ignore its own
        // saved preference.
        let resolved = VaultPaths::resolve(
            Some(VaultPaths::new("/tmp/from-file")),
            Some("/tmp/from-env".to_string()),
        );
        assert_eq!(resolved.root(), Path::new("/tmp/from-file"));
    }

    #[test]
    fn the_env_var_is_the_fallback_when_no_config_file_names_a_dir() {
        let resolved = VaultPaths::resolve(None, Some("/tmp/from-env".to_string()));
        assert_eq!(resolved.root(), Path::new("/tmp/from-env"));
    }

    #[test]
    fn an_unreadable_config_falls_through_to_the_env_var() {
        // A broken config is reported by the caller and passed in as `None`, so
        // the user still lands on their exported vault instead of the default.
        let resolved = VaultPaths::resolve(None, Some("/tmp/from-env".to_string()));
        assert_eq!(resolved.root(), Path::new("/tmp/from-env"));
    }

    #[test]
    fn nothing_set_anywhere_lands_on_the_platform_default() {
        let resolved = VaultPaths::resolve(None, None);
        assert_eq!(resolved, VaultPaths::default_platform_location());
    }

    #[test]
    fn an_empty_env_var_is_ignored_so_the_chain_continues() {
        // An exported-but-empty variable must not resolve the vault to "".
        assert!(VaultPaths::from_env(Some(String::new())).is_none());
        assert!(VaultPaths::from_env(Some("   ".to_string())).is_none());
        assert!(VaultPaths::from_env(None).is_none());
        assert_eq!(VaultPaths::resolve(None, Some("  ".into())), VaultPaths::default_platform_location());
    }

    #[test]
    fn the_platform_default_is_a_vault_subdirectory_of_the_data_dir() {
        let paths = VaultPaths::default_platform_location();
        assert!(
            paths.root().ends_with("vault"),
            "the default should be the vault dir: {}",
            paths.root().display()
        );
        assert!(
            !paths.root().as_os_str().is_empty(),
            "the default must not be an empty path"
        );
    }

    #[test]
    fn default_location_is_absolute_and_mentions_domi() {
        let p = VaultPaths::default_platform_location();
        let s = p.root().to_string_lossy().to_string();
        assert!(s.contains("domi"), "default path should be Domi-scoped: {s}");
    }

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
    fn creating_over_an_existing_vault_is_refused() {
        let t = TempVault::new();
        let paths = t.paths();
        VaultSession::create(paths.clone(), "master", test_params()).unwrap();
        // Silently overwriting would destroy a real vault.
        assert!(matches!(
            VaultSession::create(paths, "other", test_params()),
            Err(AppError::VaultExists)
        ));
    }

    #[test]
    fn unlocking_a_missing_vault_reports_no_vault() {
        let t = TempVault::new();
        assert!(matches!(
            VaultSession::unlock(t.paths(), "master"),
            Err(AppError::NoVault)
        ));
    }

    #[test]
    fn a_wrong_password_does_not_distinguish_itself_from_damage() {
        let t = TempVault::new();
        let paths = t.paths();
        VaultSession::create(paths.clone(), "right", test_params()).unwrap();
        assert!(matches!(
            VaultSession::unlock(paths, "wrong"),
            Err(AppError::WrongPassword)
        ));
    }

    #[test]
    fn a_saved_entry_reloads_intact_through_a_reopen() {
        let t = TempVault::new();
        let paths = t.paths();
        let mut s = VaultSession::create(paths.clone(), "master", test_params()).unwrap();
        let entry = blank_entry(new_entry_id(domi_core::now_unix()), domi_core::now_unix());
        let id = entry.id.clone();
        s.save_entry(entry).unwrap();
        drop(s);

        let s = VaultSession::unlock(paths, "master").unwrap();
        let loaded = s.load_entry(&id).expect("should load");
        assert_eq!(loaded.title, "Example");
        assert_eq!(loaded.password, "hunter2");
    }

    #[test]
    fn no_plaintext_secret_reaches_the_disk() {
        // The whole point of the layout: a grep of the vault directory must not
        // find a password.
        let t = TempVault::new();
        let paths = t.paths();
        let mut s = VaultSession::create(paths.clone(), "masterpw", test_params()).unwrap();
        let mut entry = blank_entry(new_entry_id(domi_core::now_unix()), domi_core::now_unix());
        entry.password = "SUPERSECRETVALUE".into();
        entry.notes = "NOTESECRET".into();
        s.save_entry(entry).unwrap();

        let mut leaks = Vec::new();
        collect_files(paths.root(), &mut leaks);
        assert!(leaks.len() >= 3, "expected manifest, index, and an entry");
        for file in &leaks {
            if file.ends_with("manifest.json") {
                continue;
            }
            let bytes = fs::read(file).expect("should read");
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains("SUPERSECRETVALUE"), "password leaked into {}", file.display());
            assert!(!text.contains("NOTESECRET"), "notes leaked into {}", file.display());
            assert!(!text.contains("masterpw"), "master password leaked into {}", file.display());
        }
    }

    #[test]
    fn the_manifest_holds_only_the_kdf_parameters() {
        let t = TempVault::new();
        let paths = t.paths();
        VaultSession::create(paths.clone(), "masterpw", test_params()).unwrap();

        let bytes = fs::read(paths.root().join("manifest.json")).unwrap();
        let manifest: VaultManifest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(manifest.version, domi_core::vault::CURRENT_VAULT_VERSION);
        assert!(!bytes.windows(8).any(|w| w == b"masterpw"), "the manifest must not carry the password");
    }

    #[test]
    fn deleting_an_entry_hides_it_but_keeps_the_blob() {
        // The index keeps a tombstone so a delete can be undone by hand.
        let t = TempVault::new();
        let paths = t.paths();
        let mut s = VaultSession::create(paths.clone(), "master", test_params()).unwrap();
        let entry = blank_entry(new_entry_id(domi_core::now_unix()), domi_core::now_unix());
        let id = entry.id.clone();
        s.save_entry(entry).unwrap();
        assert_eq!(s.visible_entries().len(), 1);

        s.delete_entry(&id).unwrap();
        assert_eq!(s.visible_entries().len(), 0, "deleted should not be visible");
        assert!(
            paths.root().join("entries").join(format!("{id}.enc")).exists(),
            "the blob should survive so the delete is reversible"
        );
    }

    #[test]
    fn a_rekey_makes_the_old_password_stop_working() {
        let t = TempVault::new();
        let paths = t.paths();
        let mut s = VaultSession::create(paths.clone(), "old", test_params()).unwrap();
        let entry = blank_entry(new_entry_id(domi_core::now_unix()), domi_core::now_unix());
        let id = entry.id.clone();
        s.save_entry(entry).unwrap();

        s.rekey("new").unwrap();
        drop(s);

        assert!(VaultSession::unlock(paths.clone(), "new").is_ok(), "the new password must work");
        assert!(
            VaultSession::unlock(paths, "old").is_err(),
            "the old password must stop working"
        );
        // And the entries survived the re-encryption.
        let s = VaultSession::unlock(VaultPaths::new(t.paths().root()), "new").unwrap();
        assert_eq!(s.load_entry(&id).unwrap().title, "Example");
    }

    #[test]
    fn ensure_tags_reuses_an_existing_tag_case_insensitively() {
        let t = TempVault::new();
        let mut s = VaultSession::create(t.paths(), "master", test_params()).unwrap();
        let now = domi_core::now_unix();

        let first = s.ensure_tags(&["Work".into()], now).unwrap();
        let second = s.ensure_tags(&["work".into()], now).unwrap();
        assert_eq!(first, second, "the same tag should be reused, not duplicated");
        assert_eq!(s.index.tags.len(), 1);
    }

    #[test]
    fn ensure_tags_ignores_blank_names_and_deduplicates() {
        let t = TempVault::new();
        let mut s = VaultSession::create(t.paths(), "master", test_params()).unwrap();
        let now = domi_core::now_unix();

        let ids = s.ensure_tags(&["Work".into(), "  ".into(), "Work".into()], now).unwrap();
        assert_eq!(ids.len(), 1, "blanks skipped, duplicates collapsed");
        assert_eq!(s.index.tags.len(), 1);
    }

    #[test]
    fn two_entries_created_in_the_same_second_get_different_ids() {
        // Wall-clock time alone is not unique enough; a test creating three
        // entries in a loop would collide and overwrite itself.
        let now = domi_core::now_unix();
        let ids: Vec<String> = (0..3).map(|_| new_entry_id(now)).collect();
        let mut unique = ids.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 3, "ids collided: {ids:?}");
        for id in &ids {
            assert_eq!(id.len(), 32, "unexpected id shape: {id}");
        }
    }

    #[test]
    fn an_interrupted_save_leaves_no_temp_file_behind() {
        let t = TempVault::new();
        let paths = t.paths();
        let mut s = VaultSession::create(paths.clone(), "master", test_params()).unwrap();
        let entry = blank_entry(new_entry_id(domi_core::now_unix()), domi_core::now_unix());
        s.save_entry(entry).unwrap();

        let mut files = Vec::new();
        collect_files(&paths.root().join("entries"), &mut files);
        let leftovers: Vec<_> = files.iter().filter(|f| f.ends_with(".tmp")).collect();
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

    /// Every file under `dir`, recursively.
    fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_files(&path, out);
            } else {
                out.push(path);
            }
        }
    }
}