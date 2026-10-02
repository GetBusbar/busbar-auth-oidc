// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MODULE FROM ITS SETTINGS: the engine's JSON config adapted into an [`OidcModule`], resolving
//! the JWKS url (explicit or via OIDC discovery) and the browser-login endpoints with a real HTTPS
//! fetcher. The door's `open` and `refresh` ([`crate::door`]) build their instance here.

use crate::{
    resolve_jwks_url, resolve_login_endpoints, JwksFetcher, OidcConfig, OidcModule, ReqwestFetcher,
};
use busbar_contract::auth::AuthPlugin;
use std::time::Duration;

/// The bound on a JWKS / discovery HTTP fetch. Generous enough for a cold DNS + TLS handshake to a
/// public IdP, short enough that a hung endpoint can't wedge boot or the (cached) auth path.
const JWKS_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Construct an OIDC auth module from the JSON config the engine passes through `open`. Shape:
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
pub fn open(cfg: &str) -> Result<Box<dyn AuthPlugin>, String> {
    open_parts(cfg).map(|(module, _)| module)
}

/// The settings, parsed: the check `validate` makes and the first step of `open`.
pub(crate) fn config(cfg: &str) -> Result<OidcConfig, String> {
    if cfg.trim().is_empty() {
        return Err("oidc plugin requires config (issuer, audience); none provided".to_string());
    }
    serde_json::from_str(cfg).map_err(|e| format!("invalid oidc plugin config: {e}"))
}

/// [`open`], keeping its discovery fetcher: the door's instance makes the login token exchange
/// through it ([`ReqwestFetcher::exchange`]).
pub(crate) fn open_parts(cfg: &str) -> Result<(Box<dyn AuthPlugin>, ReqwestFetcher), String> {
    let cfg = config(cfg)?;
    // The fetcher used both for discovery (if needed) and for JWKS refreshes.
    let fetcher = ReqwestFetcher::new(JWKS_FETCH_TIMEOUT, cfg.ca_cert_pem.as_deref())?;
    let module = open_with(cfg, &fetcher, |cfg| {
        // A SECOND fetcher instance for the live cache (the first was a borrow for discovery).
        let cache_fetcher = ReqwestFetcher::new(JWKS_FETCH_TIMEOUT, cfg.ca_cert_pem.as_deref())?;
        Ok(Box::new(cache_fetcher) as Box<dyn JwksFetcher>)
    })?;
    Ok((module, fetcher))
}

/// The body of [`open`] after the config is parsed, with the two fetchers injected: `discovery`
/// serves the discovery GETs made here, and `cache_fetcher` builds the fetcher the live JWKS cache
/// owns (called at the point `open` has always built it). Split out so the discovery merge is
/// testable without a network.
fn open_with(
    mut cfg: OidcConfig,
    discovery: &dyn JwksFetcher,
    cache_fetcher: impl FnOnce(&OidcConfig) -> Result<Box<dyn JwksFetcher>, String>,
) -> Result<Box<dyn AuthPlugin>, String> {
    // Resolve the JWKS url at construction (fail boot loudly if discovery can't find it), so the hot
    // path never does discovery.
    let jwks_url = resolve_jwks_url(&cfg, discovery)?;
    // Resolve the browser-login endpoints (authorize/token): explicit config wins, any absent one is
    // discovered from the issuer's openid-configuration. Filling them here is what makes
    // begin_login/complete_login live in production. UNLIKE the JWKS url above, a discovery FAILURE here
    // is NOT fatal to boot: login is an opt-in capability (auth ABI v2), so a verify-only deployment
    // that pins `jwks_url` and never reaches discovery must still boot — the endpoints simply stay
    // `None` and that half of login correctly fails closed. An endpoint that is neither configured nor
    // discoverable is left `None` for the same reason.
    // The failure is not fatal, but it is not silent either. Dropping the `Err` left an operator
    // with a plugin that loaded cleanly and a sign-in button that dead-ends, and no signal anywhere
    // naming the cause. That matters most in the case worth hearing about: `resolve_login_endpoints`
    // is where a discovery document whose `issuer` does not match the configured one is refused, so
    // a swallowed error here is exactly how a tampered discovery endpoint looks from the outside.
    match resolve_login_endpoints(&cfg, discovery) {
        Ok((authorization_endpoint, token_endpoint)) => {
            if cfg.authorization_endpoint.is_none() {
                cfg.authorization_endpoint = authorization_endpoint;
            }
            if cfg.token_endpoint.is_none() {
                cfg.token_endpoint = token_endpoint;
            }
        }
        Err(e) => {
            // Through `tracing` only: the door runs every slot under the SDK's per-call capture, so
            // this reaches the plugin instance's own log file, compiled in or dropped in alike (THE
            // DESIGN 11.2, "Plugin logging"; a plugin never writes stderr).
            let msg = login_discovery_failed_message(&e);
            tracing::warn!(module = "oidc", error = %e, "{}", msg);
        }
    }
    let cache_fetcher = cache_fetcher(&cfg)?;
    Ok(Box::new(OidcModule::new(&cfg, jwks_url, cache_fetcher)))
}

/// The operator message for a failed browser-login endpoint discovery at load. Discovery runs only
/// here, at load, and nothing retries it, so the message names the two ways out that actually
/// work: explicit endpoints, or a restart once the IdP's discovery endpoint is back.
fn login_discovery_failed_message(e: &str) -> String {
    format!(
        "busbar auth-oidc: browser-login endpoint discovery failed ({e}). The plugin is \
         loaded and token VERIFICATION is unaffected, but begin_login/complete_login will \
         refuse every attempt until `authorization_endpoint` and `token_endpoint` are \
         configured explicitly, or busbar is restarted after the IdP's discovery endpoint \
         recovers (discovery runs only at load)."
    )
}

#[cfg(test)]
#[path = "tests/open_tests.rs"]
mod tests;
