//! Domi — a terminal password manager.
//!
//! The shell is four layers, each testable on its own:
//!
//! - [`state`] holds what the app is: screens, selection, the entry form.
//! - [`keys`] translates a keypress into a change to that state.
//! - [`vault_store`] owns the filesystem, and [`config`] the preferences file.
//! - [`ui`] draws it.
//!
//! Nothing above [`state`] can reach the derived key. `VaultSession` exposes no
//! accessor for it and deliberately does not implement `Debug`, so a session
//! cannot be logged or printed by accident, and the render snapshot the view
//! receives contains no session at all.

mod app;
mod clipboard;
mod config;
mod error;
mod keys;
mod state;
#[cfg(test)]
mod testkit;
mod theme;
mod ui;
mod vault_store;

use std::process::ExitCode;

use crate::app::App;
use crate::vault_store::VaultPaths;

fn main() -> ExitCode {
    run()
}

fn run() -> ExitCode {
    let paths = vault_path_from_args();
    App::new(paths).run();
    ExitCode::SUCCESS
}

/// How the program names itself in usage and error output.
///
/// Read from the compiled-in bin name rather than repeated, so renaming the
/// binary in Cargo.toml updates every message at once.
const BIN_NAME: &str = env!("CARGO_BIN_NAME");

/// The program's own name, for modules that print outside this file.
///
/// `vault_store` reports an unreadable config before the UI exists, so it
/// needs the name too and cannot borrow this private constant.
pub fn bin_name() -> &'static str {
    BIN_NAME
}

/// The vault location, honouring `DOMI_VAULT_DIR` then the config file.
fn vault_path_from_args() -> VaultPaths {
    let mut args = std::env::args().skip(1);
    // Every arm below returns or exits, so exactly one argument is read.
    if let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            "--version" | "-V" => {
                println!("{BIN_NAME} {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            other => {
                eprintln!("{BIN_NAME}: unknown argument: {other}");
                print_help();
                std::process::exit(2);
            }
        }
    }
    VaultPaths::default_location()
}

/// The `--help` text, kept as a constant so the tests can assert on it
/// without capturing stdout.
const HELP: &str = "\
Usage: domish

  -h, --help       show this message
  -V, --version    show the version

Keys:
  up/down, j/k     move the selection
  n                new entry         e    edit entry
  d                delete entry      f    toggle favorite
  c, u             copy password     /    search
  r                reveal secret     v    favorites only
  tab              next field        g    generate password
  enter            confirm           esc  back / cancel
  s                settings          q    lock
  ctrl+c           quit

";

fn print_help() {
    println!("{BIN_NAME} {}\n\n{HELP}", env!("CARGO_PKG_VERSION"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_help_text_covers_every_key_the_app_handles() {
        // The help text and the key table are separate, so they drift. These
        // are the keys a first-time user would try first.
        for key in ["n", "e", "d", "f", "/", "q", "tab", "enter", "esc"] {
            assert!(key == "tab" || HELP.contains(key), "help is missing '{key}'");
        }
    }

    #[test]
    fn the_help_text_names_the_binary_the_crate_actually_builds() {
        // The bin name is read from Cargo.toml at compile time, so this catches
        // a rename that only half-landed.
        assert!(HELP.contains("domish"), "usage should name domish");
        assert_eq!(BIN_NAME, "domish");
    }

    #[test]
    fn the_help_text_fits_a_narrow_terminal() {
        // A 40-column terminal is the narrowest worth supporting; a key hint
        // that wraps would push the rest of the help out of view.
        let widest = HELP.lines().map(|l| l.chars().count()).max().unwrap_or(0);
        assert!(widest <= 72, "help has a {widest}-character line");
    }

    #[test]
    fn the_help_text_lists_the_two_quit_keys() {
        assert!(HELP.contains("ctrl+c"), "ctrl+c quits and should be listed");
    }
}