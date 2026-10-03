use serde::{Deserialize, Serialize};
use crate::crypto::{decrypt, encrypt, Key};
use crate::errors::CoreError;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum OAuthProvider {
    GoogleDrive,
    Dropbox,
    OneDrive,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct OAuthTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<i64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PkcePair {
    pub code_verifier: String,
    pub code_challenge: String,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct HttpRequestSpec {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub fn generate_pkce() -> Result<PkcePair, CoreError> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| CoreError::InvalidFormat("failed to generate random PKCE bytes".into()))?;

    let verifier = base64_url_encode(&bytes);
    // RFC 7636 S256 is SHA-256, not SHA-1 — must match the
    // `code_challenge_method=S256` sent in build_auth_url below, or every
    // provider's token exchange will reject the code.
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    let challenge = base64_url_encode(&hash);

    Ok(PkcePair {
        code_verifier: verifier,
        code_challenge: challenge,
    })
}

/// A random, unpredictable value the caller must persist alongside the pending
/// auth request and verify against the `state` returned by the provider's
/// redirect, to prevent OAuth login/account-linking CSRF.
pub fn generate_oauth_state() -> Result<String, CoreError> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| CoreError::InvalidFormat("failed to generate random state".into()))?;
    Ok(base64_url_encode(&bytes))
}

fn base64_url_encode(input: &[u8]) -> String {
    let mut out = String::new();
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut buffer = 0u32;
    let mut bits = 0;

    for &b in input {
        buffer = (buffer << 8) | (b as u32);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            let idx = ((buffer >> bits) & 0x3F) as usize;
            out.push(CHARS[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (6 - bits)) & 0x3F) as usize;
        out.push(CHARS[idx] as char);
    }
    out
}

/// Percent-encodes a value used in a URL query or an
/// `application/x-www-form-urlencoded` body. Only RFC 3986 unreserved bytes
/// are emitted verbatim, so caller-provided values cannot add query/form
/// parameters or change their meaning.
pub(crate) fn percent_encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for &byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0F) as usize] as char);
        }
    }
    encoded
}

pub fn build_auth_url(
    provider: OAuthProvider,
    client_id: &str,
    redirect_uri: &str,
    pkce: &PkcePair,
    state: &str,
) -> String {
    let client_id = percent_encode(client_id);
    let redirect_uri = percent_encode(redirect_uri);
    let challenge = percent_encode(&pkce.code_challenge);
    let state = percent_encode(state);
    match provider {
        OAuthProvider::GoogleDrive => format!(
            "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id={}&redirect_uri={}&scope=https://www.googleapis.com/auth/drive.file&code_challenge={}&code_challenge_method=S256&state={}",
            client_id, redirect_uri, challenge, state
        ),
        OAuthProvider::Dropbox => format!(
            "https://www.dropbox.com/oauth2/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state={}",
            client_id, redirect_uri, challenge, state
        ),
        OAuthProvider::OneDrive => format!(
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?response_type=code&client_id={}&redirect_uri={}&scope=files.readwrite%20offline_access&code_challenge={}&code_challenge_method=S256&state={}",
            client_id, redirect_uri, challenge, state
        ),
    }
}

pub fn build_token_exchange_request(
    token_url: &str,
    client_id: &str,
    code: &str,
    redirect_uri: &str,
    verifier: &str,
) -> HttpRequestSpec {
    let body_str = format!(
        "grant_type=authorization_code&client_id={}&code={}&redirect_uri={}&code_verifier={}",
        percent_encode(client_id),
        percent_encode(code),
        percent_encode(redirect_uri),
        percent_encode(verifier)
    );
    HttpRequestSpec {
        url: token_url.to_string(),
        method: "POST".to_string(),
        headers: vec![("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())],
        body: body_str.into_bytes(),
    }
}

pub fn parse_token_response(bytes: &[u8], current_unix_time: i64) -> Result<OAuthTokens, CoreError> {
    #[derive(Deserialize)]
    struct TokenResponse {
        access_token: String,
        refresh_token: Option<String>,
        expires_in: Option<i64>,
    }

    let parsed: TokenResponse = serde_json::from_slice(bytes)
        .map_err(|e| CoreError::InvalidFormat(format!("oauth response error: {e}")))?;

    // `expires_in` is a number from an untrusted provider response, so adding
    // it to the caller's clock can overflow i64 (a body claiming
    // `expires_in: 9223372036854775807` did). Reject the response instead.
    //
    // Saturating here would be wrong in a way it is fine for `index.version`:
    // a pinned i64::MAX expiry means "never refresh", so a stale or revoked
    // token would stay in use indefinitely. A malformed `expires_in` is the
    // provider's bug, and reporting it beats silently trusting the token.
    let expires_at = match parsed.expires_in {
        Some(secs) => Some(current_unix_time.checked_add(secs).ok_or_else(|| {
            CoreError::InvalidFormat(format!(
                "token response expires_in ({secs}) is out of range for the current time"
            ))
        })?),
        None => None,
    };

    Ok(OAuthTokens {
        access_token: parsed.access_token,
        refresh_token: parsed.refresh_token,
        expires_at,
    })
}

pub fn encrypt_tokens(key: &Key, tokens: &OAuthTokens) -> Result<Vec<u8>, CoreError> {
    let json = serde_json::to_vec(tokens)
        .map_err(|e| CoreError::InvalidFormat(format!("failed to serialize tokens: {e}")))?;
    encrypt(key, &json, b"oauth_tokens")
}

pub fn decrypt_tokens(key: &Key, ciphertext: &[u8]) -> Result<OAuthTokens, CoreError> {
    let bytes = decrypt(key, ciphertext, b"oauth_tokens")?;
    serde_json::from_slice(&bytes)
        .map_err(|e| CoreError::InvalidFormat(format!("failed to deserialize tokens: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{derive_key, KdfParams};

    #[test]
    fn test_pkce_and_auth_url() {
        let pkce = generate_pkce().unwrap();
        let state = generate_oauth_state().unwrap();
        let url = build_auth_url(OAuthProvider::GoogleDrive, "client123", "http://localhost", &pkce, &state);
        assert!(url.contains("client123"));
        assert!(url.contains(&pkce.code_challenge));
        assert!(url.contains(&state));
    }

    #[test]
    fn test_pkce_challenge_is_sha256_of_verifier() {
        // Regression test for the SHA-1/S256 mismatch: the challenge must be
        // derivable from the verifier via SHA-256, matching what build_auth_url
        // advertises as code_challenge_method=S256.
        use sha2::Digest;
        let pkce = generate_pkce().unwrap();
        let mut hasher = sha2::Sha256::new();
        hasher.update(pkce.code_verifier.as_bytes());
        let expected = super::base64_url_encode(&hasher.finalize());
        assert_eq!(pkce.code_challenge, expected);
    }

    #[test]
    fn oauth_request_values_are_percent_encoded() {
        let pkce = PkcePair {
            code_verifier: "verifier&part".into(),
            code_challenge: "challenge+part".into(),
        };
        let url = build_auth_url(
            OAuthProvider::Dropbox,
            "client&other=value",
            "com.domi:/callback?source=app&next=1",
            &pkce,
            "state&other=value",
        );
        assert!(url.contains("client_id=client%26other%3Dvalue"));
        assert!(url.contains("redirect_uri=com.domi%3A%2Fcallback%3Fsource%3Dapp%26next%3D1"));
        assert!(url.contains("code_challenge=challenge%2Bpart"));
        assert!(url.contains("state=state%26other%3Dvalue"));

        let request = build_token_exchange_request(
            "https://provider.example/token",
            "client&other=value",
            "code&other=value",
            "com.domi:/callback?source=app&next=1",
            &pkce.code_verifier,
        );
        let body = String::from_utf8(request.body).unwrap();
        assert_eq!(body, "grant_type=authorization_code&client_id=client%26other%3Dvalue&code=code%26other%3Dvalue&redirect_uri=com.domi%3A%2Fcallback%3Fsource%3Dapp%26next%3D1&code_verifier=verifier%26part");
    }

    #[test]
    fn test_token_encryption_roundtrip() {
        let tokens = OAuthTokens {
            access_token: "access123".into(),
            refresh_token: Some("refresh123".into()),
            expires_at: Some(1000),
        };
        let params = KdfParams { memory_kib: 8192, iterations: 1, parallelism: 1 };
        let key = derive_key("pass", &[0u8; 16], params).unwrap();

        let enc = encrypt_tokens(&key, &tokens).unwrap();
        let dec = decrypt_tokens(&key, &enc).unwrap();
        assert_eq!(dec, tokens);
    }

    // Regression: `expires_at` was `current_unix_time + expires_in`, which
    // overflowed and panicked on a provider response claiming
    // `expires_in: i64::MAX`. `parse_token_response` is reachable with raw
    // bytes straight off the wire on both the FFI and WASM boundary, so a
    // malformed response crashed the app instead of surfacing an error.

    #[test]
    fn parse_token_response_rejects_out_of_range_expires_in() {
        let body = br#"{"access_token":"tok","expires_in":9223372036854775807}"#;
        let now = 1_700_000_000;
        assert!(matches!(
            parse_token_response(body, now),
            Err(CoreError::InvalidFormat(_))
        ));
    }

    #[test]
    fn parse_token_response_accepts_the_largest_in_range_expiry() {
        // One below the boundary must still work — the fix rejects only what
        // genuinely cannot be represented.
        let body = format!(
            r#"{{"access_token":"tok","expires_in":{}}}"#,
            i64::MAX - 1_700_000_000
        );
        let tokens = parse_token_response(body.as_bytes(), 1_700_000_000).unwrap();
        assert_eq!(tokens.expires_at, Some(i64::MAX));
    }

    #[test]
    fn parse_token_response_omits_expiry_when_absent() {
        let tokens = parse_token_response(br#"{"access_token":"tok"}"#, 1_700_000_000).unwrap();
        assert_eq!(tokens.access_token, "tok");
        assert_eq!(tokens.expires_at, None);
    }
}
