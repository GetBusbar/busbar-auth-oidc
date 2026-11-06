// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MODULE FROM ITS SETTINGS: the engine's JSON config adapted into an [`OidcModule`]. The
//! door's `validate`, `open` and `refresh` ([`crate::door`]) build their instance here. Nothing is
//! fetched at `open`: the JWKS and, when a URL is not configured, the issuer's discovery document
//! are fetched at boot (`ready`), else by the first op that needs them.

use crate::{check_jwks_url, OidcConfig, OidcModule};

/// The settings, parsed: the check `validate` makes and the first step of `open`. Shape:
///
/// ```json
/// {
///   "issuer": "https://login.microsoftonline.com/<tenant-id>/v2.0",
///   "audience": "api://<client-id>",
///   "jwks_url": "https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys",
///   "role_claim": "groups"
/// }
/// ```
///
/// `jwks_url` is optional — when omitted it is discovered from the issuer's OIDC discovery document.
///
/// `issuer` and `audience` must not be blank: an empty one would load and then match no token (or
/// only a token claiming an empty one), so it is refused here, naming the key.
///
/// Optional string settings must be omitted rather than blank, and so must a `scopes` entry.
/// The issuer and the login endpoints are checked here, before an instance can retain the
/// settings or start an operation; `jwks_url`'s scheme is checked by `check_jwks_url` (called from
/// `module()` and the door's validate).
///
/// # Errors
/// Invalid settings, blank strings (a `scopes` entry included), an issuer with surrounding
/// whitespace, a zero refetch interval, or a disallowed endpoint scheme.
pub fn config(cfg: &str) -> Result<OidcConfig, String> {
    if cfg.trim().is_empty() {
        return Err(
            "settings: none provided; the oidc plugin requires issuer and audience".to_string(),
        );
    }
    let cfg: OidcConfig = serde_json::from_str(cfg)
        .map_err(busbar_contract::abi::sdk::auth_kit::json_error("settings"))?;
    for (key, value) in [("issuer", &cfg.issuer), ("audience", &cfg.audience)] {
        if value.trim().is_empty() {
            return Err(format!(
                "settings.{key}: is blank; it must name the token {key}"
            ));
        }
    }
    for (key, value) in [
        ("jwks_url", cfg.jwks_url.as_deref()),
        ("role_claim", Some(cfg.role_claim.as_str())),
        ("ca_cert_pem", cfg.ca_cert_pem.as_deref()),
        ("client_id", cfg.client_id.as_deref()),
        (
            "authorization_endpoint",
            cfg.authorization_endpoint.as_deref(),
        ),
        ("token_endpoint", cfg.token_endpoint.as_deref()),
    ] {
        if value.is_some_and(|v| v.trim().is_empty()) {
            return Err(format!(
                "settings.{key}: is blank; omit it or provide a non-blank value"
            ));
        }
    }
    if let Some(at) = cfg.scopes.iter().position(|s| s.trim().is_empty()) {
        return Err(format!(
            "settings.scopes[{at}]: is blank; a scope-token is never empty (RFC 6749 §3.3), so \
             omit the entry"
        ));
    }
    if cfg.jwks_min_refetch_secs == 0 {
        return Err("settings.jwks_min_refetch_secs: must be greater than zero".to_string());
    }
    configured_url("issuer", &cfg.issuer, false)?;
    if let Some(url) = &cfg.authorization_endpoint {
        configured_url("authorization_endpoint", url, false)?;
    }
    if let Some(url) = &cfg.token_endpoint {
        configured_url("token_endpoint", url, true)?;
    }
    Ok(cfg)
}

/// Keep the existing plaintext exceptions: local issuer/browser URLs, and private or loopback
/// token endpoints. Destination authorization remains the host's.
fn configured_url(key: &str, value: &str, token: bool) -> Result<(), String> {
    // The issuer is matched EXACTLY against every token's `iss`; `Url::parse` would accept a
    // padded one that then matches no token.
    if key == "issuer" && value.trim() != value {
        return Err(format!(
            "settings.{key}: has leading or trailing whitespace"
        ));
    }
    let parsed =
        url::Url::parse(value).map_err(|_| format!("settings.{key}: must be a valid URL"))?;
    if value.chars().any(char::is_control)
        || (key == "issuer" && (parsed.query().is_some() || parsed.fragment().is_some()))
        || (key == "authorization_endpoint" && parsed.fragment().is_some())
    {
        return Err(format!(
            "settings.{key}: contains a forbidden control character, query or fragment"
        ));
    }
    if parsed.scheme() == "https"
        || (parsed.scheme() == "http"
            && if token {
                crate::fetch::plaintext_allowed(crate::fetch::NEED_TOKEN, value)
            } else {
                crate::is_loopback_host(&parsed)
            })
    {
        return Ok(());
    }
    let exception = if token {
        "private or loopback"
    } else {
        "loopback"
    };
    Err(format!(
        "settings.{key}: must be an https URL (plain http only to a {exception} host)"
    ))
}

/// The module `open` builds from its parsed settings and HTTPS-only explicit JWKS URL.
pub(crate) fn module(cfg: &str) -> Result<OidcModule, String> {
    let cfg = config(cfg)?;
    check_jwks_url(&cfg)?;
    Ok(OidcModule::new(&cfg))
}

#[cfg(test)]
#[path = "tests/open_tests.rs"]
mod tests;
