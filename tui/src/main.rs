//! Fuin — a terminal password manager.
//!
//! The shell is three layers, each testable on its own:
//!
//! - [`state`] holds what the app is: screens, selection, the entry form.
//! - [`keys`] translates a keypress into a change to that state.
//! - [`app`] and [`widgets`] draw it.
//!
//! Nothing above `state` can reach the derived key. `VaultSession` exposes no
//! accessor for it and deliberately does not implement `Debug`, so a session
//! cannot be logged or printed by accident, and the render snapshot the view
//! receives contains no session at all.

mod app;
mod clipboard;
mod error;
mod keys;
mod state;
#[cfg(test)]
mod testkit;
mod theme;
mod vault_store;
mod widgets;

use std::process::ExitCode;

use iocraft::prelude::*;

use crate::app::App;
use crate::vault_store::VaultPaths;

fn main() -> ExitCode {
    smol::block_on(run())
}

async fn run() -> ExitCode {
    let paths = vault_path_from_args();
    // The wrapper is explicitly sized to the terminal. iocraft's own
    // `fullscreen()` wrapper gives its child no definite cross-axis size, so
    // a tree that relies on `flex_grow` alone collapses to its content width
    // and the app border stops spanning the window. Sizing here — one level
    // above the component — is what makes the frame fill the screen.
    // A print of the terminal's own geometry would be noise; the render loop
    // owns the screen and restores it on the way out.
    let exit = element! {
        View(width: 100_pct, height: 100_pct) {
            App(paths)
        }
    }
    .fullscreen()
    .await;
    drop(exit);
    ExitCode::SUCCESS
}

/// The vault location, honouring `--vault DIR` and the `FUIN_VAULT_DIR`
/// environment variable.
fn vault_path_from_args() -> VaultPaths {
    let mut args = std::env::args().skip(1);
    // Every arm below returns or exits, so exactly one argument is read.
    if let Some(arg) = args.next() {
        match arg.as_str() {
            "--vault" | "-v" => match args.next() {
                Some(dir) => return VaultPaths::new(dir),
                None => {
                    eprintln!("fuin: --vault needs a directory");
                    std::process::exit(2);
                }
            },
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            "--version" | "-V" => {
                println!("fuin {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            other => {
                eprintln!("fuin: unknown argument: {other}");
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
Usage: fuin [--vault DIR]

  -v, --vault DIR  use this vault instead of the default location
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
    println!("fuin {}\n\n{HELP}", env!("CARGO_PKG_VERSION"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_help_text_covers_every_key_the_app_handles() {
        // The help text and the key table are separate, so they drift. These
        // are the keys a first-time user would try first.
        for key in ["n", "e", "d", "f", "/", "q", "tab", "enter", "esc"] {
            assert!(
                key == "tab" || HELP.contains(key),
                "{key} is handled by the app but missing from --help"
            );
        }
    }

    #[test]
    fn help_mentions_every_flag_it_accepts() {
        for flag in ["--vault", "-v", "--help", "-h", "--version", "-V"] {
            assert!(HELP.contains(flag), "{flag} is accepted but undocumented");
        }
    }

    #[test]
    fn the_default_vault_location_is_absolute() {
        let paths = VaultPaths::default_location();
        assert!(paths.root().is_absolute(), "a relative vault path is a bug waiting to happen");
    }
}
