use serde::{Deserialize, Serialize};
use crate::errors::CoreError;
use crate::oauth::{percent_encode, HttpRequestSpec};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum AliasProviderKind {
    AddyIo,
    SimpleLogin,
}

/// Provider-agnostic view of an alias, after parsing a provider's response.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AliasRecord {
    /// The alias's id on the provider's side (opaque, provider-specific format).
    pub provider_id: String,
    pub email: String,
    pub enabled: bool,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CreateAliasOptions {
    /// Custom local part (the bit before the `@`). `None` requests a
    /// provider-generated random one.
    pub local_part: Option<String>,
    /// Domain/hostname context for the alias. Addy.io: which of the user's
    /// alias domains to use. SimpleLogin: the site hostname the alias is
    /// being created for (used for suggestions), not an alias domain choice.
    pub domain: Option<String>,
    pub description: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct AliasAccountInfo {
    pub display_name: Option<String>,
    /// `None` when the provider doesn't expose a numeric quota (e.g. SimpleLogin).
    pub quota_remaining: Option<i64>,
}

/// Every alias provider the core supports implements this the same way, so
/// the vault's `Entry.alias_provider`/`alias_id`/`alias_email` fields and any
/// calling shell code stay provider-agnostic. Adding a new provider (Proton
/// Pass, Fastmail, iCloud Hide My Email, DuckDuckGo) only requires a new impl
/// of this trait — see the Core Expansion Plan's "Future Providers" section.
///
/// Every method returns/consumes plain data: build a request, get back raw
/// response bytes from the shell's HTTP client, parse them. Core never holds
/// a socket, a TLS session, or an async runtime.
pub trait AliasProvider {
    fn kind(&self) -> AliasProviderKind;

    fn create_alias_request(&self, api_key: &str, opts: &CreateAliasOptions) -> HttpRequestSpec;
    fn parse_alias_response(&self, bytes: &[u8]) -> Result<AliasRecord, CoreError>;

    fn delete_alias_request(&self, api_key: &str, provider_id: &str) -> HttpRequestSpec;

    fn enable_alias_request(&self, api_key: &str, provider_id: &str) -> HttpRequestSpec;
    fn disable_alias_request(&self, api_key: &str, provider_id: &str) -> HttpRequestSpec;

    fn list_aliases_request(&self, api_key: &str) -> HttpRequestSpec;
    fn parse_alias_list_response(&self, bytes: &[u8]) -> Result<Vec<AliasRecord>, CoreError>;

    fn account_info_request(&self, api_key: &str) -> HttpRequestSpec;
    fn parse_account_info_response(&self, bytes: &[u8]) -> Result<AliasAccountInfo, CoreError>;
}

/// Returns the provider implementation for a given kind, for callers that
/// only have the persisted `AliasProviderKind` (e.g. loaded from
/// `Entry.alias_provider`) and want the matching trait object.
pub fn provider_for(kind: AliasProviderKind) -> Box<dyn AliasProvider> {
    match kind {
        AliasProviderKind::AddyIo => Box::new(AddyIoProvider),
        AliasProviderKind::SimpleLogin => Box::new(SimpleLoginProvider),
    }
}

fn json_body_headers() -> Vec<(String, String)> {
    vec![("Content-Type".to_string(), "application/json".to_string())]
}

// ---------------------------------------------------------------------------
// Addy.io
// ---------------------------------------------------------------------------

/// Base URL and endpoint shapes per the [Addy.io API docs]. Addy.io uses
/// Laravel-style bearer-token auth and wraps resources in a `{"data": ...}`
/// envelope.
///
/// [Addy.io API docs]: https://app.addy.io/docs/
pub struct AddyIoProvider;

const ADDY_BASE: &str = "https://app.addy.io/api/v1";

fn addy_headers(api_key: &str) -> Vec<(String, String)> {
    let mut headers = json_body_headers();
    headers.push(("Authorization".to_string(), format!("Bearer {api_key}")));
    headers.push(("Accept".to_string(), "application/json".to_string()));
    headers.push(("X-Requested-With".to_string(), "XMLHttpRequest".to_string()));
    headers
}

#[derive(Deserialize)]
struct AddyAliasWire {
    id: String,
    email: String,
    active: bool,
    description: Option<String>,
}

impl From<AddyAliasWire> for AliasRecord {
    fn from(w: AddyAliasWire) -> Self {
        AliasRecord {
            provider_id: w.id,
            email: w.email,
            enabled: w.active,
            description: w.description,
        }
    }
}

#[derive(Deserialize)]
struct AddyAliasEnvelope {
    data: AddyAliasWire,
}

#[derive(Deserialize)]
struct AddyAliasListEnvelope {
    data: Vec<AddyAliasWire>,
}

#[derive(Deserialize)]
struct AddyAccountWire {
    username: Option<String>,
    bandwidth: Option<i64>,
    bandwidth_limit: Option<i64>,
}

#[derive(Deserialize)]
struct AddyAccountEnvelope {
    data: AddyAccountWire,
}

impl AliasProvider for AddyIoProvider {
    fn kind(&self) -> AliasProviderKind {
        AliasProviderKind::AddyIo
    }

    fn create_alias_request(&self, api_key: &str, opts: &CreateAliasOptions) -> HttpRequestSpec {
        let mut body = serde_json::Map::new();
        if let Some(domain) = &opts.domain {
            body.insert("domain".into(), serde_json::Value::String(domain.clone()));
        }
        let format = if opts.local_part.is_some() { "custom" } else { "random_characters" };
        body.insert("format".into(), serde_json::Value::String(format.to_string()));
        if let Some(local_part) = &opts.local_part {
            body.insert("local_part".into(), serde_json::Value::String(local_part.clone()));
        }
        if let Some(description) = &opts.description {
            body.insert("description".into(), serde_json::Value::String(description.clone()));
        }
        HttpRequestSpec {
            url: format!("{ADDY_BASE}/aliases"),
            method: "POST".to_string(),
            headers: addy_headers(api_key),
            body: serde_json::Value::Object(body).to_string().into_bytes(),
        }
    }

    fn parse_alias_response(&self, bytes: &[u8]) -> Result<AliasRecord, CoreError> {
        let parsed: AddyAliasEnvelope = serde_json::from_slice(bytes)
            .map_err(|e| CoreError::InvalidFormat(format!("addy.io alias response error: {e}")))?;
        Ok(parsed.data.into())
    }

    fn delete_alias_request(&self, api_key: &str, provider_id: &str) -> HttpRequestSpec {
        HttpRequestSpec {
            url: format!("{ADDY_BASE}/aliases/{}", percent_encode(provider_id)),
            method: "DELETE".to_string(),
            headers: addy_headers(api_key),
            body: Vec::new(),
        }
    }

    fn enable_alias_request(&self, api_key: &str, provider_id: &str) -> HttpRequestSpec {
        HttpRequestSpec {
            url: format!("{ADDY_BASE}/aliases/activate/bulk"),
            method: "POST".to_string(),
            headers: addy_headers(api_key),
            body: serde_json::json!({ "ids": [provider_id] }).to_string().into_bytes(),
        }
    }

    fn disable_alias_request(&self, api_key: &str, provider_id: &str) -> HttpRequestSpec {
        HttpRequestSpec {
            url: format!("{ADDY_BASE}/aliases/deactivate/bulk"),
            method: "POST".to_string(),
            headers: addy_headers(api_key),
            body: serde_json::json!({ "ids": [provider_id] }).to_string().into_bytes(),
        }
    }

    fn list_aliases_request(&self, api_key: &str) -> HttpRequestSpec {
        HttpRequestSpec {
            url: format!("{ADDY_BASE}/aliases"),
            method: "GET".to_string(),
            headers: addy_headers(api_key),
            body: Vec::new(),
        }
    }

    fn parse_alias_list_response(&self, bytes: &[u8]) -> Result<Vec<AliasRecord>, CoreError> {
        let parsed: AddyAliasListEnvelope = serde_json::from_slice(bytes)
            .map_err(|e| CoreError::InvalidFormat(format!("addy.io alias list response error: {e}")))?;
        Ok(parsed.data.into_iter().map(Into::into).collect())
    }

    fn account_info_request(&self, api_key: &str) -> HttpRequestSpec {
        HttpRequestSpec {
            url: format!("{ADDY_BASE}/account-details"),
            method: "GET".to_string(),
            headers: addy_headers(api_key),
            body: Vec::new(),
        }
    }

    fn parse_account_info_response(&self, bytes: &[u8]) -> Result<AliasAccountInfo, CoreError> {
        let parsed: AddyAccountEnvelope = serde_json::from_slice(bytes)
            .map_err(|e| CoreError::InvalidFormat(format!("addy.io account response error: {e}")))?;
        // Both fields come straight from an untrusted provider response, so
        // `limit - used` can overflow i64 (a body claiming
        // `bandwidth: -9223372036854775808` did). Quota is display-only, so an
        // out-of-range value degrades to "unknown quota" rather than erroring.
        let quota_remaining = match (parsed.data.bandwidth_limit, parsed.data.bandwidth) {
            (Some(limit), Some(used)) if limit > 0 => limit.checked_sub(used),
            _ => None,
        };
        Ok(AliasAccountInfo {
            display_name: parsed.data.username,
            quota_remaining,
        })
    }
}

// ---------------------------------------------------------------------------
// SimpleLogin
// ---------------------------------------------------------------------------

/// Base URL and endpoint shapes per SimpleLogin's `docs/api.md`. Unlike most
/// REST APIs, auth is via a custom `Authentication` header holding the raw
/// API key — not `Authorization: Bearer`.
pub struct SimpleLoginProvider;

const SIMPLELOGIN_BASE: &str = "https://app.simplelogin.io/api";

fn simplelogin_headers(api_key: &str) -> Vec<(String, String)> {
    let mut headers = json_body_headers();
    headers.push(("Authentication".to_string(), api_key.to_string()));
    headers
}

#[derive(Deserialize)]
struct SimpleLoginAliasWire {
    id: i64,
    alias: String,
    enabled: bool,
    note: Option<String>,
}

impl From<SimpleLoginAliasWire> for AliasRecord {
    fn from(w: SimpleLoginAliasWire) -> Self {
        AliasRecord {
            provider_id: w.id.to_string(),
            email: w.alias,
            enabled: w.enabled,
            description: w.note,
        }
    }
}

#[derive(Deserialize)]
struct SimpleLoginListWire {
    aliases: Vec<SimpleLoginAliasWire>,
}

#[derive(Deserialize)]
struct SimpleLoginUserInfoWire {
    name: Option<String>,
    email: Option<String>,
}

impl AliasProvider for SimpleLoginProvider {
    fn kind(&self) -> AliasProviderKind {
        AliasProviderKind::SimpleLogin
    }

    fn create_alias_request(&self, api_key: &str, opts: &CreateAliasOptions) -> HttpRequestSpec {
        // SimpleLogin's public API only exposes *random* alias creation
        // (`POST /alias/random/new`); custom local parts require the
        // dashboard-only `new_custom_alias` flow with a server-signed
        // suffix, which isn't part of the documented public API. `opts.
        // local_part` is intentionally ignored here — see docs/api.md.
        let mut body = serde_json::Map::new();
        if let Some(description) = &opts.description {
            body.insert("note".into(), serde_json::Value::String(description.clone()));
        }
        let query = opts
            .domain
            .as_ref()
            .map(|hostname| format!("?hostname={}", percent_encode(hostname)))
            .unwrap_or_default();
        HttpRequestSpec {
            url: format!("{SIMPLELOGIN_BASE}/alias/random/new{query}"),
            method: "POST".to_string(),
            headers: simplelogin_headers(api_key),
            body: serde_json::Value::Object(body).to_string().into_bytes(),
        }
    }

    fn parse_alias_response(&self, bytes: &[u8]) -> Result<AliasRecord, CoreError> {
        let parsed: SimpleLoginAliasWire = serde_json::from_slice(bytes)
            .map_err(|e| CoreError::InvalidFormat(format!("SimpleLogin alias response error: {e}")))?;
        Ok(parsed.into())
    }

    fn delete_alias_request(&self, api_key: &str, provider_id: &str) -> HttpRequestSpec {
        HttpRequestSpec {
            url: format!("{SIMPLELOGIN_BASE}/aliases/{}", percent_encode(provider_id)),
            method: "DELETE".to_string(),
            headers: simplelogin_headers(api_key),
            body: Vec::new(),
        }
    }

    fn enable_alias_request(&self, api_key: &str, provider_id: &str) -> HttpRequestSpec {
        // SimpleLogin exposes one `toggle` endpoint, not separate
        // enable/disable calls — see docs/api.md
        // (`POST /api/aliases/:alias_id/toggle`). Callers should check the
        // current `AliasRecord.enabled` before calling either of these two
        // methods, since calling the "wrong" one just flips it back.
        simplelogin_toggle_request(api_key, provider_id)
    }

    fn disable_alias_request(&self, api_key: &str, provider_id: &str) -> HttpRequestSpec {
        simplelogin_toggle_request(api_key, provider_id)
    }

    fn list_aliases_request(&self, api_key: &str) -> HttpRequestSpec {
        HttpRequestSpec {
            url: format!("{SIMPLELOGIN_BASE}/v2/aliases?page_id=0"),
            method: "GET".to_string(),
            headers: simplelogin_headers(api_key),
            body: Vec::new(),
        }
    }

    fn parse_alias_list_response(&self, bytes: &[u8]) -> Result<Vec<AliasRecord>, CoreError> {
        let parsed: SimpleLoginListWire = serde_json::from_slice(bytes)
            .map_err(|e| CoreError::InvalidFormat(format!("SimpleLogin alias list response error: {e}")))?;
        Ok(parsed.aliases.into_iter().map(Into::into).collect())
    }

    fn account_info_request(&self, api_key: &str) -> HttpRequestSpec {
        HttpRequestSpec {
            url: format!("{SIMPLELOGIN_BASE}/user_info"),
            method: "GET".to_string(),
            headers: simplelogin_headers(api_key),
            body: Vec::new(),
        }
    }

    fn parse_account_info_response(&self, bytes: &[u8]) -> Result<AliasAccountInfo, CoreError> {
        let parsed: SimpleLoginUserInfoWire = serde_json::from_slice(bytes)
            .map_err(|e| CoreError::InvalidFormat(format!("SimpleLogin account response error: {e}")))?;
        Ok(AliasAccountInfo {
            display_name: parsed.name.or(parsed.email),
            // SimpleLogin's user_info endpoint doesn't expose a numeric quota.
            quota_remaining: None,
        })
    }
}

fn simplelogin_toggle_request(api_key: &str, provider_id: &str) -> HttpRequestSpec {
    HttpRequestSpec {
        url: format!("{SIMPLELOGIN_BASE}/aliases/{}/toggle", percent_encode(provider_id)),
        method: "POST".to_string(),
        headers: simplelogin_headers(api_key),
        body: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addy_create_request_shape() {
        let provider = AddyIoProvider;
        let opts = CreateAliasOptions {
            local_part: Some("shopping".into()),
            domain: Some("anonaddy.me".into()),
            description: Some("For online shopping".into()),
        };
        let req = provider.create_alias_request("addy-token", &opts);
        assert_eq!(req.method, "POST");
        assert_eq!(req.url, "https://app.addy.io/api/v1/aliases");
        assert!(req.headers.contains(&("Authorization".to_string(), "Bearer addy-token".to_string())));
        let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
        assert_eq!(body["local_part"], "shopping");
        assert_eq!(body["format"], "custom");
        assert_eq!(body["domain"], "anonaddy.me");
    }

    #[test]
    fn addy_create_request_defaults_to_random_format_without_local_part() {
        let provider = AddyIoProvider;
        let req = provider.create_alias_request("token", &CreateAliasOptions::default());
        let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
        assert_eq!(body["format"], "random_characters");
        assert!(body.get("local_part").is_none());
    }

    #[test]
    fn addy_parses_alias_and_list_and_account_envelopes() {
        let provider = AddyIoProvider;
        let single = br#"{"data":{"id":"50c9e585-e7f5-41c4-9016-9014c15454bc","email":"shopping@anonaddy.me","active":true,"description":"For online shopping"}}"#;
        let record = provider.parse_alias_response(single).unwrap();
        assert_eq!(record.provider_id, "50c9e585-e7f5-41c4-9016-9014c15454bc");
        assert_eq!(record.email, "shopping@anonaddy.me");
        assert!(record.enabled);

        let list = br#"{"data":[{"id":"a1","email":"a@x.com","active":false,"description":null}]}"#;
        let records = provider.parse_alias_list_response(list).unwrap();
        assert_eq!(records.len(), 1);
        assert!(!records[0].enabled);

        let account = br#"{"data":{"username":"johndoe","bandwidth":1000,"bandwidth_limit":10000}}"#;
        let info = provider.parse_account_info_response(account).unwrap();
        assert_eq!(info.display_name.as_deref(), Some("johndoe"));
        assert_eq!(info.quota_remaining, Some(9000));
    }

    #[test]
    fn provider_id_is_percent_encoded_in_url_paths() {
        // Regression test: provider_id used to be interpolated into the URL
        // path unencoded, unlike every other caller-supplied value in this
        // codebase (oauth.rs percent-encodes client_id/redirect_uri/state).
        let addy = AddyIoProvider;
        let del = addy.delete_alias_request("k", "id/with space");
        assert_eq!(del.url, "https://app.addy.io/api/v1/aliases/id%2Fwith%20space");

        let sl = SimpleLoginProvider;
        let del = sl.delete_alias_request("k", "id/with space");
        assert_eq!(del.url, "https://app.simplelogin.io/api/aliases/id%2Fwith%20space");

        let toggle = sl.enable_alias_request("k", "id/with space");
        assert_eq!(toggle.url, "https://app.simplelogin.io/api/aliases/id%2Fwith%20space/toggle");
    }

    #[test]
    fn addy_delete_and_enable_disable_requests() {
        let provider = AddyIoProvider;
        let del = provider.delete_alias_request("k", "id-1");
        assert_eq!(del.method, "DELETE");
        assert_eq!(del.url, "https://app.addy.io/api/v1/aliases/id-1");

        let enable = provider.enable_alias_request("k", "id-1");
        assert_eq!(enable.method, "POST");
        assert_eq!(enable.url, "https://app.addy.io/api/v1/aliases/activate/bulk");
        assert_eq!(enable.body, br#"{"ids":["id-1"]}"#);

        let disable = provider.disable_alias_request("k", "id-1");
        assert_eq!(disable.method, "POST");
        assert_eq!(disable.url, "https://app.addy.io/api/v1/aliases/deactivate/bulk");
        assert_eq!(disable.body, br#"{"ids":["id-1"]}"#);
    }

    #[test]
    fn simplelogin_create_request_uses_authentication_header_and_hostname_query() {
        let provider = SimpleLoginProvider;
        let opts = CreateAliasOptions {
            local_part: None,
            domain: Some("example.com".into()),
            description: Some("signup alias".into()),
        };
        let req = provider.create_alias_request("sl-key", &opts);
        assert_eq!(req.method, "POST");
        assert_eq!(req.url, "https://app.simplelogin.io/api/alias/random/new?hostname=example.com");
        assert!(req.headers.contains(&("Authentication".to_string(), "sl-key".to_string())));
        assert!(!req.headers.iter().any(|(k, _)| k == "Authorization"));
        let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
        assert_eq!(body["note"], "signup alias");
    }

    #[test]
    fn simplelogin_hostname_is_percent_encoded() {
        let provider = SimpleLoginProvider;
        let opts = CreateAliasOptions {
            domain: Some("example.com&mode=uuid".into()),
            ..Default::default()
        };
        let req = provider.create_alias_request("sl-key", &opts);
        assert_eq!(req.url, "https://app.simplelogin.io/api/alias/random/new?hostname=example.com%26mode%3Duuid");
    }

    #[test]
    fn simplelogin_parses_alias_list_and_user_info() {
        let provider = SimpleLoginProvider;
        let single = br#"{"id":50001,"alias":"nederlanden_heatherington@example.com","enabled":true,"note":"test"}"#;
        let record = provider.parse_alias_response(single).unwrap();
        assert_eq!(record.provider_id, "50001");
        assert!(record.enabled);

        let list = br#"{"aliases":[{"id":1,"alias":"a@sl.local","enabled":false,"note":null}]}"#;
        let records = provider.parse_alias_list_response(list).unwrap();
        assert_eq!(records.len(), 1);
        assert!(!records[0].enabled);

        let user_info = br#"{"name":"Jane","email":"jane@example.com"}"#;
        let info = provider.parse_account_info_response(user_info).unwrap();
        assert_eq!(info.display_name.as_deref(), Some("Jane"));
        assert_eq!(info.quota_remaining, None);
    }

    #[test]
    fn simplelogin_enable_and_disable_both_hit_the_single_toggle_endpoint() {
        let provider = SimpleLoginProvider;
        let enable = provider.enable_alias_request("k", "42");
        let disable = provider.disable_alias_request("k", "42");
        assert_eq!(enable.url, disable.url);
        assert_eq!(enable.url, "https://app.simplelogin.io/api/aliases/42/toggle");
    }

    #[test]
    fn provider_for_returns_matching_kind() {
        assert_eq!(provider_for(AliasProviderKind::AddyIo).kind(), AliasProviderKind::AddyIo);
        assert_eq!(provider_for(AliasProviderKind::SimpleLogin).kind(), AliasProviderKind::SimpleLogin);
    }

    // Regression: the addy.io quota was `limit - used` on two untrusted i64
    // fields, which overflowed and panicked when `used` was near i64::MIN —
    // reachable straight from a provider response body.

    #[test]
    fn addy_quota_degrades_to_none_instead_of_overflowing() {
        let provider = AddyIoProvider;
        let body = br#"{"data":{"username":"u","bandwidth":-9223372036854775808,"bandwidth_limit":10000}}"#;
        let info = provider.parse_account_info_response(body).unwrap();
        assert_eq!(info.display_name.as_deref(), Some("u"));
        assert_eq!(info.quota_remaining, None, "unrepresentable quota reads as unknown");
    }

    #[test]
    fn addy_quota_still_computes_for_normal_and_negative_usage() {
        let provider = AddyIoProvider;
        // Ordinary over-quota usage: remaining clamps to a negative number,
        // same as before the fix.
        let body = br#"{"data":{"username":"u","bandwidth":15000,"bandwidth_limit":10000}}"#;
        let info = provider.parse_account_info_response(body).unwrap();
        assert_eq!(info.quota_remaining, Some(-5000));
    }
}
