// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **OIDC auth module as a droppable busbar plugin** — a `cdylib` that exports the auth C ABI
//! ([`busbar_contract::abi::cold::auth`]). Build it, drop the resulting `.so`/`.dll`/`.dylib` into the engine's
//! plugins folder, define it once under `identity-providers:` (`module: oidc` plus its `settings:`),
//! and reference that name from `auth.chain`; the engine loads it in-process at boot over the auth
//! ABI.
//!
//! All the OIDC logic (JWKS, JWT verification on `ring`, claim policy) lives in the `busbar-auth-oidc`
//! `lib` crate (which a custom build can also link statically). Here we only adapt the engine's JSON
//! config into an `OidcModule` — resolving the JWKS url (explicit or via OIDC discovery) with a real
//! HTTPS fetcher — and hand the trait object to the SDK, which emits the six extern-C symbols the
//! loader resolves (`busbar_abi`, `busbar_plugin_kind`, `busbar_open`, `busbar_call`, `busbar_free`,
//! `busbar_close`).

use busbar_auth_oidc::{
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
///
/// PUBLIC because it is the COMPILED-IN constructor (DECISIONS #2): a build that links this crate
/// opens the module through this function and drives it through the `dispatch_compiled_in` twin the
/// export macro emits — the same op-dispatch the cdylib's `busbar_call` runs.
pub fn open(cfg: &str) -> Result<Box<dyn AuthPlugin>, String> {
    let cfg: OidcConfig = if cfg.trim().is_empty() {
        return Err("oidc plugin requires config (issuer, audience); none provided".to_string());
    } else {
        serde_json::from_str(cfg).map_err(|e| format!("invalid oidc plugin config: {e}"))?
    };

    // The fetcher used both for discovery (if needed) and for JWKS refreshes.
    let fetcher = ReqwestFetcher::new(JWKS_FETCH_TIMEOUT, cfg.ca_cert_pem.as_deref())?;
    open_with(cfg, &fetcher, |cfg| {
        // A SECOND fetcher instance for the live cache (the first was a borrow for discovery).
        let cache_fetcher = ReqwestFetcher::new(JWKS_FETCH_TIMEOUT, cfg.ca_cert_pem.as_deref())?;
        Ok(Box::new(cache_fetcher) as Box<dyn JwksFetcher>)
    })
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
            let msg = login_discovery_failed_message(&e);
            // STDERR, not only `tracing`. This crate ships as a `cdylib`, which statically links its
            // own copy of `tracing-core` and therefore its own global dispatcher. The host installs
            // a subscriber on ITS copy, and nothing in the plugin SDK or ABI bridges the two, so a
            // `tracing` event raised in here is evaluated against a dispatcher that has no
            // subscriber and is discarded. The plugin runs in the host's process, so its stderr IS
            // the operator's stderr, which makes it the one channel that actually arrives.
            eprintln!("{msg}");
            // Also emitted through `tracing`, which is NOT redundant: this crate is advertised as
            // linkable statically, and in that build there is a single dispatcher and the host's
            // subscriber does see it, structured.
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

busbar_contract::export_login_plugin!(open);

#[cfg(test)]
mod tests;
