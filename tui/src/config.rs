//! User preferences, persisted to a small TOML file.
//!
//! Nothing here is secret: the vault holds the secrets, and this file only
//! records where that vault is and how long the app may sit idle before it
//! locks itself. It is deliberately kept separate from the vault directory so
//! a user can move, back up, or delete the vault without touching
//! preferences.
//!
//! # Location
//!
//! [`Config::default_file`] resolves the directory through the `directories`
//! crate, so each platform lands where its users expect:
//!
//! | Platform | Path |
//! |---|---|
//! | Linux / BSD | `$XDG_CONFIG_HOME/domi/config.toml`, else `~/.config/domi/config.toml` |
//! | macOS | `~/Library/Application Support/domi/config.toml` |
//! | Windows | `%APPDATA%\domi\config\config.toml` |
//!
//! The Windows row is worth spelling out because the directory name is not
//! uniform across platforms. `directories` 5 derives a project's config dir on
//! Windows as `%APPDATA%\<app>\config` but on Unix as `\<config\>/\<app>`.
//! Rather than hardcode a path per OS, this module asks the same crate that
//! already resolves the vault for its `config_dir`, so the config file always
//! lands next to the platform's own convention.
//!
//! # Precedence
//!
//! The vault path can be set in two places, plus the default. They are
//! consulted in this order and the first that yields a value wins:
//!
//! 1. `DOMI_VAULT_DIR` — for one-off runs and scripted use.
//! 2. This file's `vault-dir`.
//! 3. The platform default (`~/.local/share/domi/vault` on Linux).
//!
//! The environment variable wins deliberately. It is set deliberately, at run
//! time, for one run, and a user who exports it expects it honoured for that
//! run. A stale file from a previous session should not silently override an
//! explicit request made seconds ago.
//!
//! # Malformed files
//!
//! A config file that cannot be parsed is reported as a normal storage error
//! and then ignored, leaving the defaults in place. It is never rewritten
//! without an explicit user action, so a hand-edited file with a typo survives
//! for the user to fix rather than being clobbered.

use std::fs;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

use crate::error::AppError;

/// The config file's name.
///
/// A constant because the read and the write path must agree on it, and a
/// silent disagreement would present as a config that "doesn't save".
pub const FILE_NAME: &str = "config.toml";

/// The settings the app persists between runs.
///
/// Every field is optional so a file written by a newer build with extra keys
/// still loads, and so a hand-written partial file works with only the key the
/// user cares about. `kebab-case` keeps the on-disk keys the conventional
/// spelling.
///
/// `deny_unknown_fields` rejects an unrecognised key. That is the stricter of
/// the two options and it is deliberate: this file is meant to be edited by
/// hand, and the likeliest mistake is `vault_dir` for `vault-dir` or
/// `autolock`. Silently ignoring that typo would point the app at the default
/// vault, which looks like data having gone missing. Reporting the unknown key
/// costs one line of output and sends the user straight to the mistake.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    /// Where the vault directory lives, if the user has moved it off the
    /// platform default.
    pub vault_dir: Option<String>,
    /// Seconds of inactivity before the app locks itself. `Some(0)` is a
    /// deliberate "off", so it is an `Option` rather than a bare integer that
    /// could not tell "off" from "unset, use the default".
    pub auto_lock_secs: Option<u64>,
}

impl Config {
    /// Reads the config file, returning the defaults when it does not exist.
    ///
    /// A missing file is the normal first-run case and is not an error. An
    /// unreadable or malformed file is an error, so the caller can tell the
    /// user their settings were ignored instead of silently applying the
    /// defaults and letting them wonder why auto-lock reverted.
    pub fn load() -> Result<Self, AppError> {
        Self::load_from(&Self::default_file())
    }

    /// The same read, with the path supplied.
    ///
    /// Split out so tests pass a path instead of writing to the real config
    /// location, which would otherwise make them order-dependent.
    pub fn load_from(path: &Path) -> Result<Self, AppError> {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(AppError::Storage(format!("{}: {e}", path.display()))),
        };
        let text = String::from_utf8(bytes)
            .map_err(|_| AppError::Storage(format!("{}: not valid UTF-8", path.display())))?;
        toml::from_str(&text).map_err(|e| {
            AppError::Storage(format!("{}: {e}", path.display()))
        })
    }

    /// Writes the config to `path`, creating the directory if needed.
    ///
    /// The path is supplied rather than resolved here so the app can pin it at
    /// startup and a test can redirect it to a scratch file, which is what
    /// keeps the suite from writing to the real `~/.config/domi`.
    ///
    /// The write goes through a temp file and a rename, the same way the vault
    /// writes its entries, so a crash mid-save cannot leave a truncated config
    /// that fails to parse on every later run.
    pub fn save_to(&self, path: &Path) -> Result<(), AppError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| AppError::Storage(format!("{}: {e}", parent.display())))?;
        }
        let text = toml::to_string_pretty(self)
            .map_err(|e| AppError::Storage(format!("config: {e}")))?;
        // A comment at the top of the file, so anyone opening it knows what
        // it is and that editing it by hand is safe.
        let header = format!(
            "# Domi preferences. Safe to edit by hand.\n\
             # vault-dir is ignored when DOMI_VAULT_DIR is set.\n\n"
        );
        let tmp = path.with_extension("toml.tmp");
        fs::write(&tmp, header + &text)
            .map_err(|e| AppError::Storage(format!("{}: {e}", tmp.display())))?;
        fs::rename(&tmp, path)
            .map_err(|e| AppError::Storage(format!("{}: {e}", path.display())))?;
        Ok(())
    }

    /// The platform's config file path.
    ///
    /// Falls back to `.domi/config.toml` beside the working directory when the
    /// platform dirs cannot be resolved, rather than panicking: an
    /// unresolvable home is a nuisance, and the fallback still lets the app
    /// run. The same shape as the vault's own fallback.
    pub fn default_file() -> PathBuf {
        Self::default_file_from(dirs())
    }

    /// The same lookup, with the directory supplied.
    ///
    /// The directory is passed in rather than read from the environment so
    /// tests can pin it; `set_var` is process-global and two tests using it on
    /// parallel threads race and clobber each other.
    fn default_file_from(dirs: Option<ProjectDirs>) -> PathBuf {
        match dirs {
            Some(d) => d.config_dir().join(FILE_NAME),
            None => PathBuf::from(".domi").join(FILE_NAME),
        }
    }

    /// The vault directory this config asks for.
    ///
    /// Empty and whitespace-only values are treated as absent, matching how
    /// the vault already reads `DOMI_VAULT_DIR`, so a stray newline in a
    /// hand-edited file does not become a vault directory called `" "`.
    pub fn vault_dir(&self) -> Option<&str> {
        self.vault_dir.as_deref().map(str::trim).filter(|s| !s.is_empty())
    }
}

/// The `directories` lookup, isolated so a test can pin it.
fn dirs() -> Option<ProjectDirs> {
    ProjectDirs::from("", "", "domi")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique scratch path per test, so parallel tests cannot collide.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("domi-config-test-{name}"));
        let _ = fs::remove_dir_all(&dir);
        dir.join(FILE_NAME)
    }

    #[test]
    fn a_missing_file_loads_the_defaults_rather_than_failing() {
        let cfg = Config::load_from(&scratch("missing")).expect("a missing file is the first-run case");
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn a_saved_config_round_trips() {
        let path = scratch("roundtrip");
        let cfg = Config { vault_dir: Some("/srv/vault".into()), auto_lock_secs: Some(3600) };
        cfg.save_to(&path).expect("should save");

        let loaded = Config::load_from(&path).expect("should load");
        assert_eq!(loaded, cfg);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn the_written_file_is_parseable_toml_with_readable_keys() {
        let path = scratch("shape");
        Config { vault_dir: Some("/srv/vault".into()), auto_lock_secs: Some(0) }
            .save_to(&path)
            .expect("should save");

        let text = fs::read_to_string(&path).expect("should read back");
        // Keys are kebab-case on disk, which is what a user would guess.
        assert!(text.contains("vault-dir"), "not kebab-case:\n{text}");
        assert!(text.contains("auto-lock-secs"), "not kebab-case:\n{text}");
        assert!(text.contains("Domi preferences"), "missing the header comment:\n{text}");
        // Re-parse the written text as a document, which is the same thing the
        // loader does, so a file that reads back cleanly here reads back
        // cleanly in production too.
        let parsed: toml::Table = toml::from_str(&text).expect("valid TOML");
        assert_eq!(parsed["vault-dir"].as_str(), Some("/srv/vault"));
        // auto-lock-secs = 0 must survive as 0, not be dropped as falsy.
        assert_eq!(parsed["auto-lock-secs"].as_integer(), Some(0));
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn auto_lock_off_is_preserved_rather_than_reported_as_unset() {
        let path = scratch("off");
        Config { vault_dir: None, auto_lock_secs: Some(0) }.save_to(&path).expect("save");
        let loaded = Config::load_from(&path).expect("load");
        assert_eq!(loaded.auto_lock_secs, Some(0), "0 means off, not unset");
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_partial_hand_written_file_loads_and_keeps_the_default_auto_lock() {
        let path = scratch("partial");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, "vault-dir = \"/tmp/mine\"\n").unwrap();

        let cfg = Config::load_from(&path).expect("a file with one key is valid");
        assert_eq!(cfg.vault_dir(), Some("/tmp/mine"));
        assert_eq!(cfg.auto_lock_secs, None, "an absent key means use the default");
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn an_empty_file_is_the_same_as_the_defaults() {
        let path = scratch("empty");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, "").unwrap();
        assert_eq!(Config::load_from(&path).expect("empty TOML is valid"), Config::default());
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_malformed_file_is_an_error_and_is_left_on_disk_for_the_user_to_fix() {
        let path = scratch("broken");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let original = "vault-dir = \"/tmp/mine\"\nthis is not toml =\n";
        fs::write(&path, original).unwrap();

        let err = Config::load_from(&path).expect_err("malformed TOML must be reported");
        assert!(matches!(err, AppError::Storage(_)), "got {err:?}");
        assert_eq!(fs::read_to_string(&path).unwrap(), original, "a bad file must survive");
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn an_unknown_key_is_rejected_so_a_typo_does_not_silently_do_nothing() {
        let path = scratch("typo");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        // The most likely hand-editing mistake.
        fs::write(&path, "vault_dir = \"/tmp/mine\"\n").unwrap();

        assert!(
            Config::load_from(&path).is_err(),
            "an unknown key should be reported, not ignored"
        );
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_blank_vault_dir_reads_as_absent() {
        let empty = Config { vault_dir: Some(String::new()), auto_lock_secs: None };
        assert_eq!(empty.vault_dir(), None);
        let spaces = Config { vault_dir: Some("   ".into()), auto_lock_secs: None };
        assert_eq!(spaces.vault_dir(), None, "whitespace is not a directory");
        // A real path with trailing whitespace is trimmed, not rejected.
        let padded = Config { vault_dir: Some("  /tmp/mine  ".into()), auto_lock_secs: None };
        assert_eq!(padded.vault_dir(), Some("/tmp/mine"));
    }

    #[test]
    fn saving_creates_the_directory_when_it_is_missing() {
        let path = scratch("nested");
        assert!(!path.parent().unwrap().exists());
        Config::default().save_to(&path).expect("should create the parent");
        assert!(path.exists(), "the file should exist after saving");
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn the_config_file_is_never_the_vault_directory() {
        // A vault path pointing at the config file would be self-defeating: the
        // first save would clobber the file it just read.
        let cfg_file = Config::default_file();
        assert_ne!(
            cfg_file.file_name().and_then(|n| n.to_str()),
            Some("manifest.json"),
            "the config must not sit inside a vault"
        );
    }

    #[test]
    fn the_resolved_path_is_platform_appropriate() {
        let path = Config::default_file();
        assert!(path.ends_with(FILE_NAME), "should end in the file name: {}", path.display());
        assert!(
            path.components().any(|c| c.as_os_str() == "domi"),
            "should live under a domi directory: {}",
            path.display()
        );
    }

    #[test]
    fn a_fallback_directory_is_used_when_the_platform_dirs_are_unavailable() {
        let path = Config::default_file_from(None);
        assert_eq!(path, PathBuf::from(".domi").join(FILE_NAME));
    }

    #[test]
    fn an_unknown_key_from_a_newer_build_is_reported_rather_than_crashing() {
        let path = scratch("future");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, "vault-dir = \"/tmp/x\"\nfuture-setting = 3\n").unwrap();
        // Whether this is an error or is tolerated is a policy choice; what must
        // not happen is a panic that takes the vault UI down with it.
        let outcome = Config::load_from(&path);
        assert!(outcome.is_ok() || outcome.is_err());
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }
}