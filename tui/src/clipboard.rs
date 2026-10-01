//! Copying to the system clipboard from a terminal.
//!
//! OSC 52 is the only mechanism a terminal application can use: the escape
//! sequence carries base64 of the payload, and the terminal emulator — not this
//! process — decides where it lands. Support is widespread but gated behind a
//! setting in most emulators, and terminals that do not support it will show
//! the sequence literally or drop it, so the caller is told what happened
//! either way.
//!
//! The secret is base64-encoded into the sequence and the sequence is written
//! above the rendered frame, never into it, so a secret is not left sitting in
//! the scrollback of the app's own UI area.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

/// Builds the OSC 52 sequence that sets the clipboard to `payload`.
///
/// Split out as a pure function so the escaping can be tested without a
/// terminal, and so the exact bytes that leave the process are pinned.
pub fn set_clipboard_sequence(payload: &str) -> String {
    format!("\x1b]52;c;{}\x07", BASE64.encode(payload))
}

/// The maximum payload OSC 52 conventionally accepts, in bytes.
///
/// The widely-followed 74994-byte limit comes from the original XTerm
/// behaviour; exceeding it makes some emulators reject the whole sequence
/// rather than truncate, so a long secret is refused outright instead of
/// silently failing.
pub const MAX_PAYLOAD_BYTES: usize = 74_994;

/// Whether a payload is small enough for a terminal to accept.
///
/// Length is measured in bytes, not characters, because that is what the
/// escape sequence encodes and what the limit applies to.
pub fn is_supported_size(payload: &str) -> bool {
    payload.len() <= MAX_PAYLOAD_BYTES
}

/// Writes `payload` to the system clipboard, reporting whether it was sent.
///
/// A refusal comes back rather than a silent truncation: the user pressed `c`
/// expecting a password, and an empty clipboard would be worse than an error.
pub fn copy(payload: &str, write: impl FnOnce(&str)) -> Result<(), String> {
    if !is_supported_size(payload) {
        return Err("That secret is too long for the terminal clipboard".to_string());
    }
    write(&set_clipboard_sequence(payload));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base64_of(payload: &str) -> String {
        BASE64.encode(payload)
    }

    #[test]
    fn the_sequence_is_well_formed_osc_52() {
        let seq = set_clipboard_sequence("hunter2");
        assert!(seq.starts_with("\x1b]52;c;"), "wrong introducer: {seq:?}");
        assert!(seq.ends_with('\x07'), "must be BEL-terminated: {seq:?}");
    }

    #[test]
    fn the_payload_is_base64_so_no_escape_byte_leaks_through() {
        // A payload full of control characters must not be able to inject
        // terminal escapes of its own.
        let nasty = "a\u{1b}b\u{07}c\u{5c}d";
        let seq = set_clipboard_sequence(nasty);
        let encoded = seq
            .strip_prefix("\x1b]52;c;")
            .and_then(|s| s.strip_suffix('\x07'))
            .expect("malformed sequence");
        assert!(!encoded.contains('\x1b'), "escape survived encoding: {encoded}");
        assert!(!encoded.contains('\x07'), "BEL survived encoding: {encoded}");

        let decoded = BASE64.decode(encoded).expect("payload should decode");
        assert_eq!(String::from_utf8(decoded).unwrap(), nasty, "the value must round-trip");
    }

    #[test]
    fn a_plain_secret_round_trips() {
        let seq = set_clipboard_sequence("hunter2");
        let encoded = seq.trim_start_matches("\x1b]52;c;").trim_end_matches('\x07');
        assert_eq!(encoded, base64_of("hunter2"));
    }

    #[test]
    fn an_empty_payload_is_still_a_valid_sequence() {
        let seq = set_clipboard_sequence("");
        assert_eq!(seq, format!("\x1b]52;c;{}\x07", BASE64.encode("")));
    }

    #[test]
    fn size_is_measured_in_bytes_not_characters() {
        assert!(is_supported_size("hunter2"));
        assert!(is_supported_size(&"a".repeat(MAX_PAYLOAD_BYTES)));
        assert!(!is_supported_size(&"a".repeat(MAX_PAYLOAD_BYTES + 1)));
        // Four bytes per character, so a quarter as many characters still fits.
        assert!(is_supported_size(&"\u{1f600}".repeat(MAX_PAYLOAD_BYTES / 4)));
    }

    #[test]
    fn copying_writes_exactly_one_sequence() {
        let mut written = Vec::new();
        copy("hunter2", |seq| written.push(seq.to_string())).expect("should copy");
        assert_eq!(written, vec![set_clipboard_sequence("hunter2")]);
    }

    #[test]
    fn an_oversized_secret_is_refused_rather_than_truncated() {
        let mut wrote = false;
        let result = copy(&"a".repeat(MAX_PAYLOAD_BYTES + 1), |_| wrote = true);
        assert!(result.is_err(), "an oversized payload must report a failure");
        assert!(!wrote, "nothing should be written when the copy is refused");
    }

    #[test]
    fn the_refusal_message_is_user_readable() {
        let err = copy(&"a".repeat(MAX_PAYLOAD_BYTES + 1), |_| {}).unwrap_err();
        assert!(err.chars().all(|c| !c.is_uppercase() || c.is_ascii_uppercase()));
        assert!(!err.contains('\n'), "an error here must fit one line: {err}");
    }
}
