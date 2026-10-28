// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MODULE FROM ITS SETTINGS: the engine's JSON config adapted into an [`OidcModule`]. The
//! door's `validate`, `open` and `refresh` ([`crate::door`]) build their instance here. Nothing is
//! fetched at `open`: it runs on no ticket and is handed no connector, so the JWKS and (when a URL
//! is not configured) the issuer's discovery document are fetched by the first op that needs them.

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
/// # Errors
/// No settings, settings that are not this module's config, or a blank `issuer`/`audience`.
pub fn config(cfg: &str) -> Result<OidcConfig, String> {
    if cfg.trim().is_empty() {
        return Err("oidc plugin requires config (issuer, audience); none provided".to_string());
    }
    let cfg: OidcConfig =
        serde_json::from_str(cfg).map_err(crate::json_err("invalid oidc plugin config"))?;
    for (key, value) in [("issuer", &cfg.issuer), ("audience", &cfg.audience)] {
        if value.trim().is_empty() {
            return Err(format!(
                "invalid oidc plugin config: `{key}` is blank; it must name the token {key}"
            ));
        }
    }
    Ok(cfg)
}

/// The module `open` builds from the settings: parsed, its explicit `jwks_url` https, or plain
/// http, which opens with a WARNING naming it ([`check_jwks_url`]).
pub(crate) fn module(cfg: &str) -> Result<OidcModule, String> {
    let cfg = config(cfg)?;
    if let Some(warning) = check_jwks_url(&cfg)? {
        tracing::warn!(module = "oidc", "{warning}");
    }
    Ok(OidcModule::new(&cfg))
}

#[cfg(test)]
#[path = "tests/open_tests.rs"]
mod tests;
