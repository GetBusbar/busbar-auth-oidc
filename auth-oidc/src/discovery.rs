// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ISSUER'S DISCOVERY DOCUMENT (`<issuer>/.well-known/openid-configuration`), fetched on the
//! first op that needs it and again a day later ([`REDISCOVER`]) or after a `refresh`, sans-IO
//! single-flight like the JWKS ([`crate::cache`]): the claimer's op pends on its exchange, a caller
//! arriving meanwhile waits (or, during a re-discovery, is served the previous document) and is
//! woken when the document is resolved ([`Fetch::wake`]), and every later op reads the resolved
//! document. It names the JWKS url when `jwks_url` is not configured, and whichever login
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

use busbar_contract::abi::mechanism::ticket::Ticket;
use serde_json::Value;

use crate::fetch::{Doc, Fetch};
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
/// The fetch failed, the body is not JSON, the document names another issuer (the
/// remote value escaped: it is untrusted input an operator reads) or none.
pub fn check_document(
    cfg: &OidcConfig,
    url: &str,
    fetched: Result<String, String>,
) -> Result<Value, String> {
    let url = &crate::fetch::shown(url);
    let body = fetched.map_err(|e| {
        format!("OIDC discovery fetch failed ({url}): {e}; set jwks_url explicitly")
    })?;
    let doc: Value = serde_json::from_str(&body).map_err(
        busbar_contract::abi::sdk::auth_kit::json_error("OIDC discovery document is not JSON"),
    )?;
    match doc.get("issuer").and_then(Value::as_str) {
        Some(doc_issuer) if doc_issuer == cfg.issuer => Ok(doc),
        Some(other) => Err(format!(
            "OIDC discovery document's issuer '{}' does not match the configured issuer '{}' \
             ({url}); refusing to trust its jwks_uri",
            crate::untrusted(other),
            cfg.issuer
        )),
        None => Err(format!(
            "OIDC discovery document has no 'issuer' ({url}); refusing to trust its jwks_uri"
        )),
    }
}

/// How long a fetched document is held before the issuer is asked again: an IdP that moves its
/// keys or endpoints is followed within a day.
pub const REDISCOVER: Duration = Duration::from_secs(24 * 3600);

/// Where the document stands.
enum State {
    /// Never fetched.
    Idle,
    /// A caller's fetch is in flight, and the document it re-discovers (served meanwhile), if any.
    Flight(Flight, Option<Arc<Value>>),
    /// Fetched and valid; asked for again at `due` (`None`: at its next use, after a `refresh`).
    Done {
        doc: Arc<Value>,
        due: Option<Instant>,
    },
    /// The last fetch failed at `at`, with `error`, and there was no document to keep.
    Failed { error: String, at: Instant },
}

/// The issuer's discovery document, single-flight.
pub struct Discovery {
    /// How long a failure is answered before the issuer is asked again.
    retry: Duration,
    /// Where the document stands, and the ops waiting on its fetch (woken when it resolves).
    state: Mutex<(State, Vec<Ticket>)>,
}

impl Discovery {
    /// A document not yet fetched, a failure answered for `retry`.
    pub fn new(retry: Duration) -> Self {
        Self {
            retry,
            state: Mutex::new((State::Idle, Vec::new())),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, (State, Vec<Ticket>)> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Have the document asked for again at its next use (a `refresh`), the one held serving
    /// until then and meanwhile.
    pub fn expire(&self) {
        if let State::Done { due, .. } = &mut self.lock().0 {
            *due = None;
        }
    }

    /// The validated document of `cfg`'s issuer, fetched through `io` when nobody has yet, or
    /// again once it is due ([`REDISCOVER`], [`Self::expire`]): PENDING while this caller's fetch
    /// is in flight, WAIT while another's is and there is no document to serve meanwhile.
    pub fn document(
        &self,
        cfg: &OidcConfig,
        now: Instant,
        io: &mut dyn Fetch,
    ) -> Step<Result<Arc<Value>, String>> {
        let url = discovery_url(cfg);
        let me = io.caller();
        {
            let mut guard = self.lock();
            let (state, waiters) = &mut *guard;
            match &*state {
                State::Done { doc, due } if due.is_some_and(|d| now < d) => {
                    return Step::Ready(Ok(Arc::clone(doc)));
                }
                State::Flight(fl, _) if fl.mine(me) => {}
                State::Flight(fl, Some(prev)) if fl.held_against(me, now) => {
                    return Step::Ready(Ok(Arc::clone(prev)));
                }
                State::Flight(fl, None) if fl.held_against(me, now) => {
                    let Some(me) = me else {
                        return Step::Ready(
                            check_document(cfg, &url, Err(io.cannot_pend(&url))).map(Arc::new),
                        );
                    };
                    if !waiters.contains(&me) {
                        waiters.push(me);
                    }
                    return Step::Wait;
                }
                State::Failed { error, at } if now.saturating_duration_since(*at) < self.retry => {
                    return Step::Ready(Err(error.clone()));
                }
                _ => {
                    let prev = match &*state {
                        State::Done { doc, .. } | State::Flight(_, Some(doc)) => {
                            Some(Arc::clone(doc))
                        }
                        _ => None,
                    };
                    let Some(owner) = me else {
                        // A call on no ticket may not fetch; a document held is still served.
                        if let Some(prev) = prev {
                            return Step::Ready(Ok(prev));
                        }
                        return Step::Ready(
                            check_document(cfg, &url, Err(io.cannot_pend(&url))).map(Arc::new),
                        );
                    };
                    *state = State::Flight(Flight { owner, at: now }, prev);
                }
            }
        }
        let fetched = match io.get(Doc::Discovery, &url) {
            Poll::Pending => return Step::Pending,
            Poll::Ready(r) => r,
        };
        let checked = check_document(cfg, &url, fetched).map(Arc::new);
        let mut guard = self.lock();
        let (state, waiters) = &mut *guard;
        // A document resolves whenever another caller's has not already (any valid
        // issuer-matched one is good). A failure ends only this caller's own flight: a late error
        // from an abandoned flight must not overwrite the one another caller has since taken
        // over. A failed RE-discovery keeps the document it would have replaced, and asks again
        // after the retry bound.
        let mut failed = None;
        let mut kept = None;
        let (answer, waiters) = match (checked, &*state) {
            (Ok(_), State::Done { doc, due }) if due.is_some_and(|d| now < d) => {
                (Ok(Arc::clone(doc)), Vec::new())
            }
            (Ok(doc), _) => {
                *state = State::Done {
                    doc: Arc::clone(&doc),
                    due: Some(now + REDISCOVER),
                };
                (Ok(doc), std::mem::take(waiters))
            }
            (Err(error), State::Flight(fl, prev)) if fl.mine(me) => {
                let answer = match prev.clone() {
                    Some(prev) => {
                        kept = Some(error.clone());
                        *state = State::Done {
                            doc: Arc::clone(&prev),
                            due: Some(now + self.retry),
                        };
                        Ok(prev)
                    }
                    None => {
                        failed = Some(error.clone());
                        *state = State::Failed {
                            error: error.clone(),
                            at: now,
                        };
                        Err(error)
                    }
                };
                (answer, std::mem::take(waiters))
            }
            (Err(error), _) => (Err(error), Vec::new()),
        };
        drop(guard);
        if let Some(e) = failed {
            // The tick discards a discovery failure, so say it here, once per attempt.
            tracing::warn!(module = "oidc", url = %crate::fetch::shown(&url), error = %e, "OIDC discovery failed");
        }
        if let Some(e) = kept {
            tracing::warn!(module = "oidc", url = %crate::fetch::shown(&url), error = %e, "OIDC re-discovery failed; serving the previous document");
        }
        // The waiters re-enter on this wake and read the document (or its failure).
        if !waiters.is_empty() {
            io.wake(&waiters);
        }
        Step::Ready(answer)
    }
}

#[cfg(test)]
#[path = "tests/discovery_tests.rs"]
mod tests;
