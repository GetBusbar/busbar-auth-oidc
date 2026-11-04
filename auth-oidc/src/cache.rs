// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The JWKS cache: fetch-on-demand, TTL refresh, and a BOUNDED refetch — when a token names a `kid`

use crate::fetch::{Doc, Fetch};
use crate::flight::{Flight, Step};
use crate::jwks::{Jwk, JwkSet};
use busbar_contract::abi::mechanism::ticket::Ticket;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::{Duration, Instant};

/// Where in a [`JwksCache::with_key`] call its fetch was claimed: the cold/stale refresh before the
/// first lookup, or the bounded rotation refetch after a miss. A caller re-entering its own fetch
/// carries on from there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Point {
    Refresh,
    Rotation,
}

/// Why [`JwksCache::with_key`] could not answer `f`'s result: the KEY SET could not be had (an
/// IdP outage: a fetch that failed, the rate limit holding off the retry after one, a set past its
/// staleness ceiling, a rotation refetch that failed), or it was had and no key in it verifies the
/// token (a bad signature, an alg/key mismatch, a kid absent from the set the IdP last answered).
/// An IdP outage is never a 401, so the two are answered apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// The key set cannot be had: an outage, never the token's fault.
    Unavailable(String),
    /// The key set is had and no key in it verifies the token.
    Mismatch(String),
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl KeyError {
    /// The words of the error, whichever it is.
    pub fn message(&self) -> &str {
        match self {
            Self::Unavailable(m) | Self::Mismatch(m) => m,
        }
    }
}

/// THE STALENESS CEILING (how long a key set keeps serving while every refetch fails): this many
/// TTLs, and never less than [`MAX_STALE_FLOOR`].
const MAX_STALE_TTLS: u32 = 24;
/// The staleness ceiling's floor: a day.
const MAX_STALE_FLOOR: Duration = Duration::from_secs(24 * 3600);

/// A JWKS cache. Holds the last-fetched key set, the timestamps that bound refresh and the fetch in
pub struct JwksCache {
    /// Minimum gap between fetch ATTEMPTS — the bound on every refetch trigger (cold, TTL-stale,
    min_refetch_interval: Duration,
    /// TTL after which the cached set is considered stale and proactively refetched on next use.
    ttl: Duration,
    /// Absolute ceiling on how long a cached key set may keep serving while every refetch attempt
    max_stale: Duration,
    /// The cached data. Held for microseconds only — NEVER across a fetch or a signature verify.
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    /// The current key set, behind an `Arc` so callers snapshot it and verify with no lock held.
    keys: Option<Arc<JwkSet>>,
    /// When the current `keys` were fetched (advanced on SUCCESS only).
    fetched_at: Option<Instant>,
    /// When the last fetch ATTEMPT started (success or failure) — the rate-limit anchor.
    last_attempt: Option<Instant>,
    /// THE SINGLE FLIGHT: the fetch in progress, and where its caller claimed it.
    flight: Option<(Flight, Point)>,
    /// The ops waiting on the flight ([`Step::Wait`]): woken when it settles.
    waiters: Vec<Ticket>,
    /// Whether the latest settled fetch FAILED: a kid missing from the set in hand is then not the
    /// token's fault, since the IdP's current set could not be had.
    failing: bool,
}

impl JwksCache {
    /// A cache with the given rate limit and TTL.
    pub fn new(min_refetch_interval: Duration, ttl: Duration) -> Self {
        let max_stale = std::cmp::max(ttl.saturating_mul(MAX_STALE_TTLS), MAX_STALE_FLOOR);
        Self {
            min_refetch_interval,
            ttl,
            max_stale,
            inner: Mutex::default(),
        }
    }

    /// Run `f` against the key matching `kid`, the JWKS fetched from `url` through `io`. If the
    pub fn with_key<T>(
        &self,
        url: &str,
        kid: &str,
        now: Instant,
        io: &mut dyn Fetch,
        f: impl Fn(&Jwk) -> Result<T, String>,
    ) -> Step<Result<T, KeyError>> {
        self.with_key_for(url, kid, None, now, io, f)
    }

    /// [`Self::with_key`] for a token signed with `alg`: a token naming NO kid (`kid` empty) is
    pub fn with_key_for<T>(
        &self,
        url: &str,
        kid: &str,
        alg: Option<&str>,
        now: Instant,
        io: &mut dyn Fetch,
        f: impl Fn(&Jwk) -> Result<T, String>,
    ) -> Step<Result<T, KeyError>> {
        let (mine, snapshot) = {
            let inner = self.lock();
            let mine = inner.flight.filter(|(fl, _)| fl.mine(io.caller()));
            (mine, self.snapshot_of(&inner, now))
        };
        let (keys, now) = match mine {
            Some((flight, point)) => {
                let keys = match step!(self.land(io, url, flight.at)) {
                    Ok(keys) => keys,
                    Err(e) => return Step::Ready(Err(KeyError::Unavailable(e))),
                };
                if point == Point::Rotation {
                    return Step::Ready(self.after_rotation(keys.as_deref(), url, kid, alg, &f));
                }
                (keys, flight.at)
            }
            None => {
                let (mut keys, stale, expired) = snapshot;

                if expired {
                    keys = None;
                }

                if keys.is_none() || stale {
                    let wait = keys.is_none();
                    keys = match step!(self.refresh(io, url, now, wait, Point::Refresh)) {
                        Ok(keys) => keys,
                        Err(e) => return Step::Ready(Err(KeyError::Unavailable(e))),
                    };
                }
                (keys, now)
            }
        };

        let Some(set) = keys else {
            return Step::Ready(Err(KeyError::Unavailable(format!(
                "no JWKS has been fetched from {} yet (the last fetch attempt failed and the \
                 refetch rate limit is holding off the next one); cannot verify any token",
                crate::fetch::shown(url)
            ))));
        };

        if let Some(result) = Self::try_all(&set, kid, alg, &f) {
            return Step::Ready(result.map_err(KeyError::Mismatch));
        }

        let keys = match step!(self.refresh(io, url, now, false, Point::Rotation)) {
            Ok(keys) => keys,
            Err(e) => return Step::Ready(Err(KeyError::Unavailable(e))),
        };
        Step::Ready(self.after_rotation(keys.as_deref(), url, kid, alg, &f))
    }

    /// THE WARM-UP (`ready`, at boot): fetch the key set once when the cache holds none, so the
    pub fn warm(&self, url: &str, now: Instant, io: &mut dyn Fetch) -> Step<Result<(), String>> {
        let mine = self.lock().flight.filter(|(fl, _)| fl.mine(io.caller()));
        if let Some((flight, _)) = mine {
            let _ = step_ok!(self.land(io, url, flight.at));
            return Step::Ready(Ok(()));
        }
        let (keys, _, expired) = self.snapshot(now);
        if keys.is_some() && !expired {
            return Step::Ready(Ok(()));
        }
        let _ = step_ok!(self.refresh(io, url, now, true, Point::Refresh));
        Step::Ready(Ok(()))
    }

    /// THE TICK'S REFRESH AHEAD OF THE TTL: when the set is due (none yet, or within `lead` of its
    pub fn refresh_ahead(
        &self,
        url: &str,
        lead: Duration,
        now: Instant,
        io: &mut dyn Fetch,
    ) -> Step<Result<(), String>> {
        let mine = self.lock().flight.filter(|(fl, _)| fl.mine(io.caller()));
        if let Some((flight, _)) = mine {
            let _ = step_ok!(self.land(io, url, flight.at));
            return Step::Ready(Ok(()));
        }
        if !self.due(now, lead) {
            return Step::Ready(Ok(()));
        }
        match self.refresh(io, url, now, false, Point::Refresh) {
            Step::Pending => Step::Pending,
            Step::Ready(r) => Step::Ready(r.map(|_| ())),
            Step::Wait => Step::Ready(Ok(())),
        }
    }

    /// Whether the set is due for its refresh at `now`: none fetched, or `lead` or less short of
    fn due(&self, now: Instant, lead: Duration) -> bool {
        self.lock()
            .fetched_at
            .is_none_or(|t| now.saturating_duration_since(t) >= self.ttl.saturating_sub(lead))
    }

    /// The lookup after the bounded rotation refetch: a match, or the unknown-`kid` error — a
    fn after_rotation<T>(
        &self,
        keys: Option<&JwkSet>,
        url: &str,
        kid: &str,
        alg: Option<&str>,
        f: &impl Fn(&Jwk) -> Result<T, String>,
    ) -> Result<T, KeyError> {
        if let Some(result) = keys.and_then(|set| Self::try_all(set, kid, alg, f)) {
            return result.map_err(KeyError::Mismatch);
        }
        if self.lock().failing {
            return Err(KeyError::Unavailable(format!(
                "no cached JWKS key matches the token's kid '{}' and the latest fetch of the key \
                 set from {} failed, so the token cannot be judged",
                crate::untrusted(kid),
                crate::fetch::shown(url)
            )));
        }

        if kid.is_empty() {
            return Err(KeyError::Mismatch(
                "the token has no kid and the JWKS does not select exactly one usable signing key"
                    .to_string(),
            ));
        }
        Err(KeyError::Mismatch(format!(
            "no JWKS key matches the token's kid '{}' (a rotation refetch is bounded by \
             jwks_min_refetch_secs, so the key set may not have been refetched for this token); the \
             signing key is unknown to the provider's key set",
            crate::untrusted(kid)
        )))
    }

    /// Try `f` against every key in `set` selected for `kid` and `alg` ([`JwkSet::select`]),
    fn try_all<T>(
        set: &JwkSet,
        kid: &str,
        alg: Option<&str>,
        f: &impl Fn(&Jwk) -> Result<T, String>,
    ) -> Option<Result<T, String>> {
        let mut last_err = None;
        for k in set.select(kid, alg) {
            match f(k) {
                Ok(v) => return Some(Ok(v)),
                Err(e) => last_err = Some(e),
            }
        }
        last_err.map(Err)
    }

    /// Snapshot the cached set, whether it is past TTL, and whether it is past the absolute staleness
    fn snapshot(&self, now: Instant) -> (Option<Arc<JwkSet>>, bool, bool) {
        self.snapshot_of(&self.lock(), now)
    }

    /// [`Self::snapshot`] under a lock the caller holds.
    fn snapshot_of(&self, inner: &Inner, now: Instant) -> (Option<Arc<JwkSet>>, bool, bool) {
        let stale = match inner.fetched_at {
            None => true,
            Some(t) => now.saturating_duration_since(t) >= self.ttl,
        };
        (inner.keys.clone(), stale, self.past_ceiling(inner, now))
    }

    /// Bring the cache up to date if the rate limit allows, and answer the current key set.
    fn refresh(
        &self,
        io: &mut dyn Fetch,
        url: &str,
        now: Instant,
        wait: bool,
        point: Point,
    ) -> Step<Result<Option<Arc<JwkSet>>, String>> {
        let me = io.caller();
        {
            let mut inner = self.lock();

            let desperate = wait && (inner.keys.is_none() || self.past_ceiling(&inner, now));

            if !desperate && !self.permits_attempt(&inner, now) {
                return Step::Ready(self.serve_within_ceiling(&inner, url, now));
            }

            if inner.flight.is_some_and(|(fl, _)| fl.held_against(me, now)) {
                if !desperate {
                    return Step::Ready(self.serve_within_ceiling(&inner, url, now));
                }
                let Some(me) = me else {
                    return Step::Ready(Err(io.cannot_pend(url)));
                };
                if !inner.waiters.contains(&me) {
                    inner.waiters.push(me);
                }
                return Step::Wait;
            }

            if inner.flight.is_none() && !self.permits_attempt(&inner, now) {
                return Step::Ready(self.serve_within_ceiling(&inner, url, now));
            }

            let Some(owner) = me else {
                return Step::Ready(Err(io.cannot_pend(url)));
            };

            inner.last_attempt = Some(now);
            inner.flight = Some((Flight { owner, at: now }, point));
        }

        self.land(io, url, now)
    }

    /// Drive this caller's JWKS fetch one step: PENDING until the host answers, then settle it.
    fn land(
        &self,
        io: &mut dyn Fetch,
        url: &str,
        at: Instant,
    ) -> Step<Result<Option<Arc<JwkSet>>, String>> {
        match io.get(Doc::Jwks, url) {
            Poll::Pending => Step::Pending,
            Poll::Ready(fetched) => Step::Ready(self.settle(io, url, at, fetched)),
        }
    }

    /// The fetch claimed at `at` answered `fetched`: install a parsed set, or keep the previous keys
    fn settle(
        &self,
        io: &dyn Fetch,
        url: &str,
        at: Instant,
        fetched: Result<String, String>,
    ) -> Result<Option<Arc<JwkSet>>, String> {
        let fetched = fetched.and_then(|body| JwkSet::parse(&body));
        let mut inner = self.lock();
        let waiters = if inner.flight.is_some_and(|(fl, _)| fl.mine(io.caller())) {
            inner.flight = None;
            std::mem::take(&mut inner.waiters)
        } else {
            Vec::new()
        };
        let mut kept_through: Option<String> = None;
        let mut nothing_kept: Option<String> = None;
        let settled = match fetched {
            Ok(set) if inner.fetched_at.is_none_or(|t| t <= at) => {
                inner.keys = Some(Arc::new(set));
                inner.fetched_at = Some(at);
                inner.failing = false;
                Ok(inner.keys.clone())
            }
            Ok(_) => Ok(inner.keys.clone()),
            Err(e) => {
                if inner.fetched_at.is_none_or(|t| t <= at) {
                    inner.failing = true;
                }
                let too_stale = self.past_ceiling(&inner, at);
                match inner.keys.clone() {
                    Some(keys) if !too_stale => {
                        kept_through = Some(e);
                        Ok(Some(keys))
                    }
                    _ => {
                        nothing_kept = Some(e.clone());
                        Err(e)
                    }
                }
            }
        };
        drop(inner);
        if let Some(e) = kept_through {
            tracing::warn!(
                module = "oidc",
                url = %crate::fetch::shown(url),
                error = %e,
                "JWKS refresh failed; serving the previous key set"
            );
        }
        if let Some(e) = nothing_kept {
            tracing::warn!(
                module = "oidc",
                url = %crate::fetch::shown(url),
                error = %e,
                "JWKS fetch failed; no key set to serve"
            );
        }

        if !waiters.is_empty() {
            io.wake(&waiters);
        }
        settled
    }

    /// Whether a fetch ATTEMPT is allowed now. Anchored on the last attempt (not the last success),
    fn permits_attempt(&self, inner: &Inner, now: Instant) -> bool {
        match inner.last_attempt {
            None => true,
            Some(t) => now.saturating_duration_since(t) >= self.min_refetch_interval,
        }
    }

    /// Whether the cached keys are past the absolute staleness ceiling (`max_stale`) at `now`.
    fn past_ceiling(&self, inner: &Inner, now: Instant) -> bool {
        inner
            .fetched_at
            .is_some_and(|t| now.saturating_duration_since(t) >= self.max_stale)
    }

    /// Return the currently cached keys, but ONLY if they are within the absolute staleness ceiling
    fn serve_within_ceiling(
        &self,
        inner: &Inner,
        url: &str,
        now: Instant,
    ) -> Result<Option<Arc<JwkSet>>, String> {
        if self.past_ceiling(inner, now) {
            Err(format!(
                "cached JWKS from {} is past the absolute staleness ceiling ({:?}) while every \
                 refetch attempt is failing or rate-limited; refusing to verify against a key set \
                 the provider may have rotated out because it was compromised",
                crate::fetch::shown(url),
                self.max_stale
            ))
        } else {
            Ok(inner.keys.clone())
        }
    }

    /// Take the data lock, recovering from poisoning rather than failing auth: the guarded data is a
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[cfg(test)]
#[path = "tests/cache_tests.rs"]
mod tests;
