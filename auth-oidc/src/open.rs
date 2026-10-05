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
/// # Errors
/// No settings, or settings that are not this module's config.
pub fn config(cfg: &str) -> Result<OidcConfig, String> {
    if cfg.trim().is_empty() {
        return Err("oidc plugin requires config (issuer, audience); none provided".to_string());
    }
    serde_json::from_str(cfg).map_err(|e| format!("invalid oidc plugin config: {e}"))
}

/// The module `open` builds from the settings: parsed, its explicit `jwks_url` held to https.
pub(crate) fn module(cfg: &str) -> Result<OidcModule, String> {
    let cfg = config(cfg)?;
    check_jwks_url(&cfg)?;
    Ok(OidcModule::new(&cfg))
}

#[cfg(test)]
#[path = "tests/open_tests.rs"]
mod tests;
