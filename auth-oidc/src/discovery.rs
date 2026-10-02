// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ISSUER'S DISCOVERY DOCUMENT (`<issuer>/.well-known/openid-configuration`), fetched once, on
//! the first op that needs it, sans-IO single-flight like the JWKS ([`crate::cache`]): the claimer's
//! op pends on its exchange, a caller arriving meanwhile waits, and every later op reads the
//! resolved document. It names the JWKS url when `jwks_url` is not configured, and whichever login
//! endpoint is not. A failed fetch is remembered with its error for `jwks_min_refetch_secs`, so an
//! unreachable issuer is asked again at the JWKS cache's own retry bound, never per request.
//!
//! RFC 8414 §3.3 / OIDC Discovery 1.0 §4.3: the document's own `issuer` MUST equal the issuer it
//! was requested from. Without this check, one poisoned discovery response repoints `jwks_uri` (and
//! the login endpoints) — and therefore every future signature verification — at an
//! attacker-controlled key set. Callers whose URLs are configured explicitly never fetch it.

use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::{Duration, Instant};

use busbar_contract::abi::sdk::conn::ConnFailure;
use serde_json::Value;

use crate::fetch::{failed, Doc, Fetch};
use crate::flight::{Flight, Step};
use crate::OidcConfig;

/// Where the discovery document of `cfg`'s issuer is served.
pub fn discovery_url(cfg: &OidcConfig) -> String {
    format!(
        "{}/.well-known/openid-configuration",
        cfg.issuer.trim_end_matches('/')
    )
}

/// The discovery document `fetched` from `url`, validated against `cfg`'s issuer.
///
/// # Errors
/// 1.5.5's texts: the fetch failed, the body is not JSON, the document names another issuer (the
/// remote value escaped: it is untrusted input an operator reads) or none.
pub fn check_document(
    cfg: &OidcConfig,
    url: &str,
    fetched: Result<String, String>,
) -> Result<Value, String> {
    let body = fetched.map_err(|e| {
        format!("OIDC discovery fetch failed ({url}): {e}; set jwks_url explicitly")
    })?;
    let doc: Value = serde_json::from_str(&body)
        .map_err(|e| format!("OIDC discovery document is not JSON: {e}"))?;
    match doc.get("issuer").and_then(Value::as_str) {
        Some(doc_issuer) if doc_issuer == cfg.issuer => Ok(doc),
        Some(other) => Err(format!(
            "OIDC discovery document's issuer '{}' does not match the configured issuer '{}' \
             ({url}); refusing to trust its jwks_uri",
            other.escape_debug(),
            cfg.issuer
        )),
        None => Err(format!(
            "OIDC discovery document has no 'issuer' ({url}); refusing to trust its jwks_uri"
        )),
    }
}

/// Where the document stands.
enum State {
    /// Never fetched.
    Idle,
    /// A caller's fetch is in flight.
    Flight(Flight),
    /// Fetched and valid.
    Done(Arc<Value>),
    /// The last fetch failed at `at`, with `error`.
    Failed { error: String, at: Instant },
}

/// The issuer's discovery document, single-flight.
pub struct Discovery {
    /// How long a failure is answered before the issuer is asked again.
    retry: Duration,
    state: Mutex<State>,
}

impl Discovery {
    /// A document not yet fetched, a failure answered for `retry`.
    pub fn new(retry: Duration) -> Self {
        Self {
            retry,
            state: Mutex::new(State::Idle),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The validated document of `cfg`'s issuer, fetched through `io` when nobody has yet: PENDING
    /// while this caller's fetch is in flight, WAIT while another's is.
    pub fn document(
        &self,
        cfg: &OidcConfig,
        now: Instant,
        io: &mut dyn Fetch,
    ) -> Step<Result<Arc<Value>, String>> {
        let url = discovery_url(cfg);
        let me = io.caller();
        {
            let mut state = self.lock();
            match &*state {
                State::Done(doc) => return Step::Ready(Ok(Arc::clone(doc))),
                State::Flight(fl) if fl.mine(me) => {}
                State::Flight(fl) if fl.held_against(me, now) => {
                    if me.is_none() {
                        return Step::Ready(
                            check_document(cfg, &url, Err(failed(&url, ConnFailure::NoTicket)))
                                .map(Arc::new),
                        );
                    }
                    return Step::Wait;
                }
                State::Failed { error, at } if now.saturating_duration_since(*at) < self.retry => {
                    return Step::Ready(Err(error.clone()));
                }
                _ => {
                    let Some(owner) = me else {
                        return Step::Ready(
                            check_document(cfg, &url, Err(failed(&url, ConnFailure::NoTicket)))
                                .map(Arc::new),
                        );
                    };
                    *state = State::Flight(Flight { owner, at: now });
                }
            }
        }
        let fetched = match io.get(Doc::Discovery, &url) {
            Poll::Pending => return Step::Pending,
            Poll::Ready(r) => r,
        };
        let checked = check_document(cfg, &url, fetched).map(Arc::new);
        let mut state = self.lock();
        // A late answer never undoes a document another caller has since resolved.
        if !matches!(&*state, State::Done(_)) {
            *state = match &checked {
                Ok(doc) => State::Done(Arc::clone(doc)),
                Err(error) => State::Failed {
                    error: error.clone(),
                    at: now,
                },
            };
        }
        Step::Ready(checked)
    }
}
