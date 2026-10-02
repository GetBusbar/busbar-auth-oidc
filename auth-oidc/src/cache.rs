// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The JWKS cache: fetch-on-demand, TTL refresh, and a BOUNDED refetch — when a token names a `kid`
//! absent from the cached set (the provider rotated its signing key), refetch once, rate-limited,
//! and retry. Guards against a bogus-`kid` flood turning into a fetch storm.
//!
//! ## Sans-IO single-flight (THE DESIGN, auth)
//!
//! The cache never blocks and never dials: its fetch is the caller's [`Fetch`], which answers
//! PENDING while the caller's own exchange is in flight. A cold key id pends `verify`; ONE caller
//! claims the fetch (the [`Flight`]) and its op re-enters on its exchange's wake; every other caller
//! with nothing to serve answers [`Step::Wait`] and asks again shortly, taking the winner's keys once
//! they land. A caller that already holds a usable key set never waits on another's fetch: it serves
//! from what it has while the winner refreshes. The cache's lock is held for the microseconds it
//! takes to clone an `Arc` or write one back — never across a fetch, never across a signature
//! verification (`f` runs on a snapshot with nothing held).
//!
//! ## Why every fetch trigger is rate-limited
//!
//! Every trigger — cold start, TTL-stale, and unknown-`kid` rotation alike — goes through the same
//! `min_refetch_interval` rate limit anchored on the last fetch ATTEMPT (failures included).
//! Bounding the rotation path alone is not enough: because `fetched_at` advances only on success, an
//! unreachable IdP would leave the set permanently TTL-stale and every single request would issue its
//! own fresh GET — an unbounded fetch storm against the provider.

use crate::fetch::{failed, Doc, Fetch};
use crate::flight::{Flight, Step};
use crate::jwks::{Jwk, JwkSet};
use busbar_contract::abi::sdk::conn::ConnFailure;
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

/// A JWKS cache. Holds the last-fetched key set, the timestamps that bound refresh and the fetch in
/// flight.
pub struct JwksCache {
    /// Minimum gap between fetch ATTEMPTS — the bound on every refetch trigger (cold, TTL-stale,
    /// kid-rotation), so no flood of requests can turn into a fetch storm.
    min_refetch_interval: Duration,
    /// TTL after which the cached set is considered stale and proactively refetched on next use.
    ttl: Duration,
    /// Absolute ceiling on how long a cached key set may keep serving while every refetch attempt
    /// fails. `ttl`-staleness alone has no upper bound — a transient blip correctly keeps serving the
    /// last-known-good keys (see `settle`), but with no ceiling an IdP outage of days would keep
    /// validating signatures against a key the provider may have rotated out BECAUSE it was
    /// compromised. Derived from `ttl` (not a new config field): `max(ttl * 24, 24h)`, so a short-TTL
    /// deployment gets a generous-but-bounded window and a long-TTL one still has SOME bound.
    max_stale: Duration,
    /// The cached data. Held for microseconds only — NEVER across a fetch or a signature verify.
    inner: Mutex<Inner>,
}

struct Inner {
    /// The current key set, behind an `Arc` so callers snapshot it and verify with no lock held.
    keys: Option<Arc<JwkSet>>,
    /// When the current `keys` were fetched (advanced on SUCCESS only).
    fetched_at: Option<Instant>,
    /// When the last fetch ATTEMPT started (success or failure) — the rate-limit anchor.
    last_attempt: Option<Instant>,
    /// THE SINGLE FLIGHT: the fetch in progress, and where its caller claimed it.
    flight: Option<(Flight, Point)>,
}

impl JwksCache {
    /// A cache with the given rate limit and TTL.
    pub fn new(min_refetch_interval: Duration, ttl: Duration) -> Self {
        let max_stale = std::cmp::max(ttl.saturating_mul(24), Duration::from_secs(24 * 3600));
        Self {
            min_refetch_interval,
            ttl,
            max_stale,
            inner: Mutex::new(Inner {
                keys: None,
                fetched_at: None,
                last_attempt: None,
                flight: None,
            }),
        }
    }

    /// Run `f` against the key matching `kid`, the JWKS fetched from `url` through `io`. If the
    /// cache is empty or stale, fetch first. If `kid` still misses after that (key ROTATION),
    /// refetch ONCE — rate-limited by `min_refetch_interval` — and retry. `f` receives the found
    /// key; a miss after the bounded refetch is a precise error.
    ///
    /// PENDING while this caller's fetch is in flight (re-enter with the same `io` state: the call
    /// carries on from where it fetched, at the instant it claimed the fetch); WAIT while another
    /// caller's is and this one has nothing to serve.
    pub fn with_key<T>(
        &self,
        url: &str,
        kid: &str,
        now: Instant,
        io: &mut dyn Fetch,
        f: impl Fn(&Jwk) -> Result<T, String>,
    ) -> Step<Result<T, String>> {
        // RESUME: this caller's own fetch, then on from the point it claimed it.
        let mine = self.lock().flight.filter(|(fl, _)| fl.mine(io.caller()));
        let (keys, now) = match mine {
            Some((flight, point)) => {
                let fetched = match io.get(Doc::Jwks, url) {
                    Poll::Pending => return Step::Pending,
                    Poll::Ready(r) => r,
                };
                let keys = match self.settle(io, url, flight.at, fetched) {
                    Ok(keys) => keys,
                    Err(e) => return Step::Ready(Err(e)),
                };
                if point == Point::Rotation {
                    return Step::Ready(Self::after_rotation(keys.as_deref(), kid, &f));
                }
                (keys, flight.at)
            }
            None => {
                let (mut keys, stale, expired) = self.snapshot(now);
                // Past the absolute staleness ceiling: treat exactly like a cold cache. `settle`
                // itself refuses to fall back to these same keys once they are this old, so forcing
                // the "nothing to serve" path here — rather than trying `keys` first — means an
                // outage this long surfaces the honest "cannot verify" error instead of silently
                // keeping a possibly-revoked key alive.
                if expired {
                    keys = None;
                }
                // Ensure we have a (fresh enough) key set. A cold cache has nothing to serve, so it
                // WAITS for the in-flight fetch; a merely TTL-stale one does not — stale keys still
                // verify tokens, and waiting on the refresh is what turns a slow IdP into an outage.
                if keys.is_none() || stale {
                    let wait = keys.is_none();
                    keys = step_ok!(self.refresh(io, url, now, wait, Point::Refresh));
                }
                (keys, now)
            }
        };
        // Still nothing: the provider is unreachable AND we are inside the retry bound, so we are
        // deliberately not asking again yet. Say that, rather than the "unknown kid" error below —
        // which would blame the token for the provider being down.
        let Some(set) = keys else {
            return Step::Ready(Err(format!(
                "no JWKS has been fetched from {url} yet (the last fetch attempt failed and the \
                 refetch rate limit is holding off the next one); cannot verify any token"
            )));
        };
        // First lookup. More than one key can share `kid` (RFC 7517 §4.5 — e.g. an RSA and an EC key
        // coexisting under one `kid` during an algorithm migration), so try every match and return
        // the first that verifies; keep the last error if none do.
        if let Some(result) = Self::try_all(&set, kid, &f) {
            return Step::Ready(result);
        }
        // Miss ⇒ possible key rotation. Refetch ONCE if the rate limit permits, then retry. Never
        // waits: a caller in this branch is about to reject the token anyway.
        let keys = step_ok!(self.refresh(io, url, now, false, Point::Rotation));
        Step::Ready(Self::after_rotation(keys.as_deref(), kid, &f))
    }

    /// The lookup after the bounded rotation refetch: a match, or the unknown-`kid` error.
    fn after_rotation<T>(
        keys: Option<&JwkSet>,
        kid: &str,
        f: &impl Fn(&Jwk) -> Result<T, String>,
    ) -> Result<T, String> {
        if let Some(result) = keys.and_then(|set| Self::try_all(set, kid, f)) {
            return result;
        }
        // `kid` comes from the UNSIGNED header of an untrusted bearer and this error reaches a
        // warn log before any signature has been accepted, so it is escaped: a kid carrying a
        // newline or a terminal escape must not forge or colour log records. Printable kids are
        // byte-identical.
        Err(format!(
            "no JWKS key matches the token's kid '{}' (after a bounded rotation refetch); the \
             signing key is unknown to the configured jwks_url",
            kid.escape_debug()
        ))
    }

    /// Try `f` against every key in `set` matching `kid`, returning the first `Ok`. If at least one
    /// key matched but all errored, returns the LAST error. Returns `None` when zero keys matched
    /// `kid` at all, so the caller can distinguish "no key with this kid" from "keys existed but none
    /// verified".
    fn try_all<T>(
        set: &JwkSet,
        kid: &str,
        f: &impl Fn(&Jwk) -> Result<T, String>,
    ) -> Option<Result<T, String>> {
        let mut last_err = None;
        for k in set.find_all(kid) {
            match f(k) {
                Ok(v) => return Some(Ok(v)),
                Err(e) => last_err = Some(e),
            }
        }
        last_err.map(Err)
    }

    /// Snapshot the cached set, whether it is past TTL, and whether it is past the absolute staleness
    /// ceiling (`max_stale`). Holds the lock for an `Arc` clone.
    fn snapshot(&self, now: Instant) -> (Option<Arc<JwkSet>>, bool, bool) {
        let inner = self.lock();
        let stale = match inner.fetched_at {
            None => true,
            Some(t) => now.saturating_duration_since(t) >= self.ttl,
        };
        (inner.keys.clone(), stale, self.past_ceiling(&inner, now))
    }

    /// Bring the cache up to date if the rate limit allows, and answer the current key set.
    ///
    /// Never fails on a fetch error when the cache already holds keys: a transient provider blip
    /// must not stop tokens signed by keys we already have from verifying. A cold cache DOES
    /// propagate the error, because there is nothing to fall back to and the caller needs the
    /// reason.
    ///
    /// `wait` distinguishes the two single-flight behaviours: `false` (the common case) means "if
    /// someone else is already fetching, don't wait — use what we have"; `true` means "we have
    /// nothing to serve, so wait for the in-flight fetch and take its result".
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
            // DESPERATE = the caller has nothing at all to serve: no keys, or only keys past the
            // staleness ceiling. Such a caller must wait for the in-flight fetch rather than be
            // turned away by the rate limit — being rate-limited out of a fetch that is happening
            // right now would fail the very first requests after boot.
            let desperate = wait && (inner.keys.is_none() || self.past_ceiling(&inner, now));
            // RATE LIMIT, checked before the flight so a rate-limited caller never waits.
            if !desperate && !self.permits_attempt(&inner, now) {
                return Step::Ready(self.serve_within_ceiling(&inner, url, now));
            }
            // SINGLE-FLIGHT. A caller with usable keys serves them rather than waiting on a fetch
            // it does not need; a desperate one waits for it.
            if inner.flight.is_some_and(|(fl, _)| fl.held_against(me, now)) {
                if !desperate {
                    return Step::Ready(self.serve_within_ceiling(&inner, url, now));
                }
                if me.is_none() {
                    return Step::Ready(Err(failed(url, ConnFailure::NoTicket)));
                }
                return Step::Wait;
            }
            // Re-check the rate limit for the desperate caller: the fetch it would have waited for
            // has already been made, and re-fetching immediately would defeat the bound.
            if !self.permits_attempt(&inner, now) {
                return Step::Ready(self.serve_within_ceiling(&inner, url, now));
            }
            // A call on no ticket may not pend, so it may not claim a fetch either: it would hold
            // the rate-limit window without ever asking.
            let Some(owner) = me else {
                return Step::Ready(Err(failed(url, ConnFailure::NoTicket)));
            };
            // Claim the window BEFORE the fetch so concurrent callers see it and back off. This is
            // also what makes the rate limit apply to FAILURES — the anchor advances either way.
            inner.last_attempt = Some(now);
            inner.flight = Some((Flight { owner, at: now }, point));
        }
        // THE FETCH — no lock held.
        match io.get(Doc::Jwks, url) {
            Poll::Pending => Step::Pending,
            Poll::Ready(fetched) => Step::Ready(self.settle(io, url, now, fetched)),
        }
    }

    /// The fetch claimed at `at` answered `fetched`: install a parsed set, or keep the previous keys
    /// (a transient provider blip must not blow away a working key set) — UNLESS those are already
    /// past the absolute staleness ceiling, in which case a days-long outage must not keep
    /// validating signatures against keys the provider may have rotated out specifically because
    /// they were compromised. Ends the caller's flight.
    fn settle(
        &self,
        io: &dyn Fetch,
        url: &str,
        at: Instant,
        fetched: Result<String, String>,
    ) -> Result<Option<Arc<JwkSet>>, String> {
        let fetched = fetched.and_then(|body| JwkSet::parse(&body));
        let mut inner = self.lock();
        if inner.flight.is_some_and(|(fl, _)| fl.mine(io.caller())) {
            inner.flight = None;
        }
        match fetched {
            // A late answer to a flight another caller has since taken over never replaces keys
            // fetched after it was claimed.
            Ok(set) if inner.fetched_at.is_none_or(|t| t <= at) => {
                inner.keys = Some(Arc::new(set));
                inner.fetched_at = Some(at);
                Ok(inner.keys.clone())
            }
            Ok(_) => Ok(inner.keys.clone()),
            Err(e) => {
                let too_stale = self.past_ceiling(&inner, at);
                let previous = inner.keys.clone();
                drop(inner);
                match previous {
                    Some(keys) if !too_stale => {
                        // The fallback hides the failure from every caller, so it is logged here:
                        // otherwise an IdP serving 5xx, a TLS failure or an empty key set leaves no
                        // trace until a rotated-key token is rejected as "unknown kid". The attempt
                        // window rate-limits this. The error names the URL and the cause only.
                        tracing::warn!(
                            module = "oidc",
                            url = %url,
                            error = %e,
                            "JWKS refresh failed; serving the previous key set"
                        );
                        Ok(Some(keys))
                    }
                    _ => Err(e),
                }
            }
        }
    }

    /// Whether a fetch ATTEMPT is allowed now. Anchored on the last attempt (not the last success),
    /// so failures are rate-limited exactly like successes and an unreachable provider cannot be
    /// turned into a per-request fetch storm.
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
    /// (`max_stale`). Every early return in [`Self::refresh`] that would otherwise serve the cached
    /// set routes through here, so `max_stale` is enforced UNIFORMLY, not only on the fetch-failure
    /// branch. Without this, a sustained IdP outage under traffic (where nearly every request takes
    /// one of those early returns) would keep verifying tokens against a key set old enough that the
    /// provider may have rotated it out precisely because it was compromised. Past the ceiling it
    /// fails closed with the same "cannot verify" posture the fetch-failure path uses.
    fn serve_within_ceiling(
        &self,
        inner: &Inner,
        url: &str,
        now: Instant,
    ) -> Result<Option<Arc<JwkSet>>, String> {
        if self.past_ceiling(inner, now) {
            Err(format!(
                "cached JWKS from {url} is past the absolute staleness ceiling ({:?}) while every \
                 refetch attempt is failing or rate-limited; refusing to verify against a key set \
                 the provider may have rotated out because it was compromised",
                self.max_stale
            ))
        } else {
            Ok(inner.keys.clone())
        }
    }

    /// Take the data lock, recovering from poisoning rather than failing auth: the guarded data is a
    /// public key cache, and a panic elsewhere leaves it structurally intact.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[cfg(test)]
#[path = "tests/cache_tests.rs"]
mod tests;
