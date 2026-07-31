// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The JWKS cache: fetch-on-demand, TTL refresh, and a BOUNDED refetch — when a token names a `kid`
//! absent from the cached set (the provider rotated its signing key), refetch once, rate-limited,
//! and retry. Guards against a bogus-`kid` flood turning into a fetch storm.
//!
//! ## What the locking here is for, and what it must never do
//!
//! `with_key` is called on EVERY OIDC-authenticated request, synchronously, from the engine's auth
//! middleware — which is an `async fn` on a Tokio worker thread. Two things therefore must not
//! happen under this cache's lock, and the whole shape of this file is that constraint:
//!
//! * **The HTTPS fetch must not run under the lock.** It is `reqwest::blocking` with a 10s timeout,
//!   so a slow IdP would otherwise park one worker for 10s *and* every other request behind a
//!   `std::sync::Mutex::lock()` — which, unlike an `.await`, cannot yield. `/healthz` is exempt from
//!   the auth chain but still needs a worker thread to be polled, so the node fails its liveness
//!   probe and gets killed. A slow identity provider must not take down traffic that never presented
//!   an OIDC token.
//! * **Signature verification must not run under the lock.** `f` is RSA/ECDSA verification, pure
//!   CPU. Holding the cache lock across it caps OIDC auth throughput at one signature at a time
//!   PROCESS-WIDE, on reactor threads.
//!
//! So the mutex protects only the cached *data*, held for the microseconds it takes to clone an
//! `Arc` or write one back. The key set is an `Arc<JwkSet>` precisely so a caller can take a
//! snapshot and then verify against it with nothing held.
//!
//! ## Single-flight, and why every fetch trigger is rate-limited
//!
//! Fetches are coordinated by a separate gate so that N concurrent requests that all need a refresh
//! produce ONE fetch, not N serial 10-second ones. A caller that already holds a usable key set
//! never waits on that gate at all — it serves from what it has and lets the winner refresh in the
//! background. Only a caller with NOTHING to serve (a cold cache) waits, and then only for the one
//! in-flight fetch.
//!
//! Every trigger — cold start, TTL-stale, and unknown-`kid` rotation alike — goes through the same
//! `min_refetch_interval` rate limit anchored on the last fetch ATTEMPT (failures included).
//! Previously only the rotation path was bounded: because `fetched_at` advances only on success, an
//! unreachable IdP left the set permanently TTL-stale and every single request issued its own fresh
//! GET — an unbounded fetch storm against the provider, each request stalling for the full timeout.

use crate::jwks::JwkSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How a JWKS is fetched. A trait so the verification logic is testable WITHOUT network: the plugin
/// wires an HTTPS-fetching implementor; tests wire a fixture.
pub trait JwksFetcher: Send + Sync {
    /// GET the JWKS document body from the configured `jwks_uri`. Returns the raw JSON text or an
    /// error message. MUST be bounded both in TIME (a timeout — a hung provider must not hang auth)
    /// and in BODY SIZE (the real implementation caps at `reqwest_fetcher::MAX_JWKS_BYTES`, since
    /// the fetch also runs under this cache's single-flight gate and would otherwise park every
    /// cold-cache caller behind one unbounded read).
    fn fetch(&self, url: &str) -> Result<String, String>;
}

/// A JWKS cache over a fetcher. Holds the last-fetched key set and the timestamps that bound refresh.
pub struct JwksCache {
    url: String,
    fetcher: Box<dyn JwksFetcher>,
    /// Minimum gap between fetch ATTEMPTS — the bound on every refetch trigger (cold, TTL-stale,
    /// kid-rotation), so no flood of requests can turn into a fetch storm.
    min_refetch_interval: Duration,
    /// TTL after which the cached set is considered stale and proactively refetched on next use.
    ttl: Duration,
    /// Absolute ceiling on how long a cached key set may keep serving while every refetch attempt
    /// fails. `ttl`-staleness alone has no upper bound — a transient blip correctly keeps serving the
    /// last-known-good keys (see `refresh`'s doc comment), but with no ceiling an IdP outage of days
    /// would keep validating signatures against a key the provider may have rotated out BECAUSE it was
    /// compromised. Derived from `ttl` (not a new config field): `max(ttl * 24, 24h)`, so a short-TTL
    /// deployment gets a generous-but-bounded window and a long-TTL one still has SOME bound.
    max_stale: Duration,
    /// The cached data. Held for microseconds only — NEVER across a fetch or a signature verify.
    inner: Mutex<Inner>,
    /// The SINGLE-FLIGHT gate. Held by whichever caller is performing a fetch, for the duration of
    /// that fetch. Deliberately separate from `inner` so a fetch in progress blocks neither a cache
    /// read nor a verification. Nothing but the fetch itself is done under it.
    fetch_gate: Mutex<()>,
}

struct Inner {
    /// The current key set, behind an `Arc` so callers snapshot it and verify with no lock held.
    keys: Option<Arc<JwkSet>>,
    /// When the current `keys` were fetched (advanced on SUCCESS only).
    fetched_at: Option<Instant>,
    /// When the last fetch ATTEMPT started (success or failure) — the rate-limit anchor.
    last_attempt: Option<Instant>,
}

impl JwksCache {
    /// A cache for `url` over `fetcher`, with the given rate limit and TTL.
    pub fn new(
        url: impl Into<String>,
        fetcher: Box<dyn JwksFetcher>,
        min_refetch_interval: Duration,
        ttl: Duration,
    ) -> Self {
        let max_stale = std::cmp::max(ttl.saturating_mul(24), Duration::from_secs(24 * 3600));
        Self {
            url: url.into(),
            fetcher,
            min_refetch_interval,
            ttl,
            max_stale,
            inner: Mutex::new(Inner {
                keys: None,
                fetched_at: None,
                last_attempt: None,
            }),
            fetch_gate: Mutex::new(()),
        }
    }

    /// Run `f` against the key matching `kid`. If the cache is empty or stale, fetch first. If `kid`
    /// still misses after that (key ROTATION), refetch ONCE — rate-limited by `min_refetch_interval`
    /// — and retry. `f` receives the found key; a miss after the bounded refetch is a precise error.
    ///
    /// `f` is invoked with NO cache lock held (see the module docs): concurrent verifications run
    /// concurrently, and a fetch in flight never blocks one.
    pub fn with_key<T>(
        &self,
        kid: &str,
        now: Instant,
        f: impl Fn(&crate::jwks::Jwk) -> Result<T, String>,
    ) -> Result<T, String> {
        let (mut keys, stale, expired) = self.snapshot(now);
        // Past the absolute staleness ceiling: treat exactly like a cold cache. `refresh` itself
        // refuses to fall back to these same keys once they are this old (see its Err branch), so
        // forcing the "nothing to serve" path here — rather than trying `keys` first — means an
        // outage this long surfaces the honest "cannot verify" error instead of silently keeping a
        // possibly-revoked key alive.
        if expired {
            keys = None;
        }

        // Ensure we have a (fresh enough) key set. A cold cache has nothing to serve, so it WAITS
        // for the in-flight fetch; a merely TTL-stale one does not — stale keys still verify tokens,
        // and blocking on the refresh is the behaviour that turns a slow IdP into an outage.
        if keys.is_none() || stale {
            keys = self.refresh(now, /* wait = */ keys.is_none())?;
        }
        // Still nothing: the provider is unreachable AND we are inside the retry bound, so we are
        // deliberately not asking again yet. Say that, rather than the "unknown kid" error below —
        // which would blame the token for the provider being down. Also the path a caller past the
        // staleness ceiling lands on if the refetch still could not produce a fresh set.
        if keys.is_none() {
            return Err(format!(
                "no JWKS has been fetched from {} yet (the last fetch attempt failed and the \
                 refetch rate limit is holding off the next one); cannot verify any token",
                self.url
            ));
        }

        // First lookup. More than one key can share `kid` (RFC 7517 §4.5 — e.g. an RSA and an EC key
        // coexisting under one `kid` during an algorithm migration), so try every match and return the
        // first that verifies; keep the last error if none do.
        if let Some(set) = &keys {
            if let Some(result) = Self::try_all(set, kid, &f) {
                return result;
            }
        }

        // Miss ⇒ possible key rotation. Refetch ONCE if the rate limit permits, then retry. Never
        // waits: a caller in this branch is about to reject the token anyway, and making it queue
        // behind another caller's fetch only converts one bad token into a stalled worker.
        let keys = self.refresh(now, /* wait = */ false)?;
        if let Some(set) = &keys {
            if let Some(result) = Self::try_all(set, kid, &f) {
                return result;
            }
        }

        Err(format!(
            "no JWKS key matches the token's kid '{kid}' (after a bounded rotation refetch); the \
             signing key is unknown to the configured jwks_url"
        ))
    }

    /// Try `f` against every key in `set` matching `kid`, returning the first `Ok`. If at least one
    /// key matched but all errored, returns the LAST error. Returns `None` when zero keys matched
    /// `kid` at all, so the caller can distinguish "no key with this kid" from "keys existed but none
    /// verified" (the latter is a real verification failure worth reporting precisely; the former
    /// falls through to the caller's own "no JWKS key matches" message).
    fn try_all<T>(
        set: &JwkSet,
        kid: &str,
        f: &impl Fn(&crate::jwks::Jwk) -> Result<T, String>,
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
        let expired = match inner.fetched_at {
            None => false,
            Some(t) => now.saturating_duration_since(t) >= self.max_stale,
        };
        (inner.keys.clone(), stale, expired)
    }

    /// Bring the cache up to date if the rate limit allows, and return the current key set.
    ///
    /// Never fails on a fetch error when the cache already holds keys: a transient provider blip
    /// must not stop tokens signed by keys we already have from verifying. A cold cache DOES
    /// propagate the error, because there is nothing to fall back to and the caller needs the
    /// reason.
    ///
    /// `wait` distinguishes the two single-flight behaviours: `false` (the common case) means "if
    /// someone else is already fetching, don't queue — use what we have"; `true` means "we have
    /// nothing to serve, so wait for the in-flight fetch and take its result".
    fn refresh(&self, now: Instant, wait: bool) -> Result<Option<Arc<JwkSet>>, String> {
        // DESPERATE = the caller has nothing at all to serve. Such a caller must join the in-flight
        // fetch rather than be turned away by the rate limit — being rate-limited out of a fetch
        // that is happening right now would fail the very first requests after boot.
        let desperate = {
            let inner = self.lock();
            let desperate = wait && inner.keys.is_none();
            // RATE LIMIT, checked before taking the gate so a rate-limited caller never queues.
            if !desperate && !self.permits_attempt(&inner, now) {
                return Ok(inner.keys.clone());
            }
            desperate
        };

        // SINGLE-FLIGHT. The winner fetches; a loser with usable keys returns immediately rather
        // than queueing behind a fetch it does not need.
        let _gate = match self.fetch_gate.try_lock() {
            Ok(g) => g,
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) if !desperate => {
                return Ok(self.lock().keys.clone());
            }
            // Cold cache: wait for the ONE in-flight fetch rather than failing, and rather than
            // starting a second one.
            Err(std::sync::TryLockError::WouldBlock) => {
                self.fetch_gate.lock().unwrap_or_else(|p| p.into_inner())
            }
        };

        // Gate acquired — but the fetch we queued behind may already have satisfied us.
        {
            let mut inner = self.lock();
            if desperate && inner.keys.is_some() {
                return Ok(inner.keys.clone());
            }
            // Re-check the rate limit under the gate: the caller we queued behind has advanced it,
            // and re-fetching immediately would defeat the bound.
            if !self.permits_attempt(&inner, now) {
                return Ok(inner.keys.clone());
            }
            // Claim the window BEFORE the fetch so concurrent callers see it and back off. This is
            // also what makes the rate limit apply to FAILURES — the anchor advances either way.
            inner.last_attempt = Some(now);
        }

        // THE FETCH — no `inner` lock held, only the single-flight gate.
        let fetched = self
            .fetcher
            .fetch(&self.url)
            .and_then(|body| JwkSet::parse(&body));

        let mut inner = self.lock();
        match fetched {
            Ok(set) => {
                inner.keys = Some(Arc::new(set));
                inner.fetched_at = Some(now);
                Ok(inner.keys.clone())
            }
            // Keep the previous keys (a transient provider blip must not blow away a working key
            // set) and keep serving from them; surface the error only when there is nothing else —
            // UNLESS those previous keys are already past the absolute staleness ceiling, in which
            // case a days-long outage must not keep validating signatures against keys the provider
            // may have rotated out specifically because they were compromised.
            Err(e) => {
                let too_stale = inner
                    .fetched_at
                    .is_some_and(|t| now.saturating_duration_since(t) >= self.max_stale);
                match inner.keys.clone() {
                    Some(keys) if !too_stale => Ok(Some(keys)),
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

    /// Take the data lock, recovering from poisoning rather than failing auth: the guarded data is a
    /// public key cache, and a panic elsewhere leaves it structurally intact.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Barrier;

    /// A minimal but real JWKS document. These tests exercise the CACHE's concurrency contract, not
    /// the crypto — `f` is whatever the test needs it to be — so the key material only has to parse.
    fn jwks(kid: &str) -> String {
        format!(r#"{{"keys":[{{"kty":"EC","crv":"P-256","kid":"{kid}","x":"AAAA","y":"BBBB"}}]}}"#)
    }

    /// A fetcher that counts its calls and can be made arbitrarily slow or broken — a stand-in for
    /// the IdP having a bad day, which is the whole failure mode under test.
    struct TestFetcher {
        body: Result<String, String>,
        delay: Duration,
        calls: Arc<AtomicUsize>,
    }
    impl JwksFetcher for TestFetcher {
        fn fetch(&self, _url: &str) -> Result<String, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(self.delay);
            self.body.clone()
        }
    }

    fn cache(
        body: Result<String, String>,
        delay: Duration,
        ttl: Duration,
    ) -> (JwksCache, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = JwksCache::new(
            "https://idp.example/jwks",
            Box::new(TestFetcher {
                body,
                delay,
                calls: calls.clone(),
            }),
            Duration::from_secs(60),
            ttl,
        );
        (c, calls)
    }

    /// THE CLASS TEST, half 1: signature verification must not be serialised.
    ///
    /// `f` is RSA/ECDSA verification, and it used to run WITH the cache mutex held — so every OIDC
    /// request in the process verified one at a time, on Tokio worker threads. The property is
    /// concurrency, so the test measures it directly: `f` records how many callers are inside it at
    /// once.
    ///
    /// RED (lock held across `f`): observed concurrency is exactly 1.
    /// GREEN: several verifications overlap.
    #[test]
    fn concurrent_verifications_are_not_serialised() {
        let (c, _calls) = cache(Ok(jwks("k1")), Duration::ZERO, Duration::from_secs(3600));
        // Prime the cache so the fetch is out of the picture and only `f`'s locking is measured.
        c.with_key("k1", Instant::now(), |_| Ok(())).expect("prime");

        const N: usize = 8;
        let inside = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let start = Arc::new(Barrier::new(N));
        let now = Instant::now();

        std::thread::scope(|s| {
            for _ in 0..N {
                let (c, inside, peak, start) = (&c, inside.clone(), peak.clone(), start.clone());
                s.spawn(move || {
                    start.wait();
                    c.with_key("k1", now, |_| {
                        let here = inside.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(here, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(80));
                        inside.fetch_sub(1, Ordering::SeqCst);
                        Ok(())
                    })
                    .expect("verify");
                });
            }
        });

        assert!(
            peak.load(Ordering::SeqCst) > 1,
            "OIDC signature verification is serialised process-wide: {} of {N} concurrent \
             verifications ever overlapped. The cache lock must not be held across `f`.",
            peak.load(Ordering::SeqCst)
        );
    }

    /// THE CLASS TEST, half 2: a slow JWKS endpoint must not stall callers that have a usable key.
    ///
    /// This is the liveness failure. One request triggers a TTL-stale refetch against an IdP that
    /// takes seconds; every other request — including ones whose token is signed by a key already
    /// cached — used to block on `lock()`, which cannot yield, parking worker threads until
    /// `/healthz` could not be polled and the orchestrator killed the node.
    ///
    /// RED (fetch under the lock): the second caller waits out the full fetch.
    /// GREEN: it serves from the cached key set immediately.
    #[test]
    fn a_slow_jwks_fetch_does_not_stall_a_caller_that_already_has_the_key() {
        const FETCH: Duration = Duration::from_millis(1500);
        let (c, _calls) = cache(Ok(jwks("k1")), FETCH, Duration::from_millis(1));
        let t0 = Instant::now();
        c.with_key("k1", t0, |_| Ok(())).expect("prime");

        // Past TTL, so the next caller triggers a refetch against the slow provider.
        let now = t0 + Duration::from_secs(10);
        let ready = Arc::new(Barrier::new(2));

        std::thread::scope(|s| {
            let slow = {
                let (c, ready) = (&c, ready.clone());
                s.spawn(move || {
                    ready.wait();
                    c.with_key("k1", now, |_| Ok(()))
                        .expect("refetching caller")
                })
            };
            ready.wait();
            // Give the refetcher a moment to be inside the fetch.
            std::thread::sleep(Duration::from_millis(100));

            let began = Instant::now();
            c.with_key("k1", now, |_| Ok(())).expect("unblocked caller");
            let waited = began.elapsed();
            assert!(
                waited < FETCH / 3,
                "a caller holding a usable cached key waited {waited:?} on another caller's JWKS \
                 fetch (fetch takes {FETCH:?}); a slow IdP must not stall requests it has nothing \
                 to do with"
            );
            slow.join().unwrap();
        });
    }

    /// SINGLE-FLIGHT on a cold cache: N concurrent first-requests must produce ONE fetch, not N
    /// serial ones. Without it, N unknown-kid or cold requests each pay the full 10s timeout in
    /// turn — the "one 10s stall each" behaviour that made a slow IdP compound.
    #[test]
    fn concurrent_cold_starts_produce_exactly_one_fetch() {
        let (c, calls) = cache(
            Ok(jwks("k1")),
            Duration::from_millis(300),
            Duration::from_secs(3600),
        );
        const N: usize = 6;
        let start = Arc::new(Barrier::new(N));
        let now = Instant::now();
        let began = Instant::now();

        std::thread::scope(|s| {
            for _ in 0..N {
                let (c, start) = (&c, start.clone());
                s.spawn(move || {
                    start.wait();
                    c.with_key("k1", now, |_| Ok(())).expect("cold caller");
                });
            }
        });

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a cold cache must single-flight: {N} concurrent callers issued {} fetches",
            calls.load(Ordering::SeqCst)
        );
        assert!(
            began.elapsed() < Duration::from_millis(300) * 3,
            "cold-start callers serialised behind one another's fetches ({:?})",
            began.elapsed()
        );
    }

    /// The TTL-stale path must obey the SAME rate limit the kid-rotation path already did. Because
    /// `fetched_at` only advances on success, an unreachable IdP leaves the set permanently stale —
    /// so without this bound every single request issues its own GET, forever.
    ///
    /// RED (only the rotation path rate-limited): one fetch per request.
    /// GREEN: one fetch per `min_refetch_interval`.
    #[test]
    fn a_failing_provider_does_not_produce_a_fetch_storm() {
        // Fetch #1 primes the cache; after that the provider is unreachable. Simulated by a TTL of
        // ~0 (always stale) plus a fetcher that fails — the second and later calls all fail.
        let calls = Arc::new(AtomicUsize::new(0));
        let c = JwksCache::new(
            "https://idp.example/jwks",
            Box::new(TestFetcher {
                body: Err("connection timed out".into()),
                delay: Duration::ZERO,
                calls: calls.clone(),
            }),
            Duration::from_secs(60),
            Duration::from_millis(1),
        );
        let t0 = Instant::now();
        // Cold + failing ⇒ the error surfaces (nothing to fall back to), and it counts as ONE
        // attempt.
        assert!(c.with_key("k1", t0, |_| Ok(())).is_err());
        for i in 0..100u64 {
            let _ = c.with_key("k1", t0 + Duration::from_millis(i), |_| Ok(()));
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "an unreachable IdP must be retried once per min_refetch_interval, not once per \
             request: {} GETs for 101 requests",
            calls.load(Ordering::SeqCst)
        );

        // Past the rate limit: exactly one more attempt, then quiet again.
        let later = t0 + Duration::from_secs(61);
        for i in 0..50u64 {
            let _ = c.with_key("k1", later + Duration::from_millis(i), |_| Ok(()));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2, "one retry per interval");
    }

    /// A transient provider failure must not blow away a working key set: tokens signed by keys we
    /// already hold keep verifying while the IdP is down.
    #[test]
    fn a_fetch_failure_keeps_serving_the_previously_fetched_keys() {
        let calls = Arc::new(AtomicUsize::new(0));
        struct Flaky {
            first: Mutex<bool>,
            body: String,
            calls: Arc<AtomicUsize>,
        }
        impl JwksFetcher for Flaky {
            fn fetch(&self, _url: &str) -> Result<String, String> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let mut first = self.first.lock().unwrap();
                if *first {
                    *first = false;
                    return Ok(self.body.clone());
                }
                Err("provider unreachable".into())
            }
        }
        let c = JwksCache::new(
            "https://idp.example/jwks",
            Box::new(Flaky {
                first: Mutex::new(true),
                body: jwks("k1"),
                calls: calls.clone(),
            }),
            Duration::from_millis(1),
            Duration::from_millis(1),
        );
        let t0 = Instant::now();
        c.with_key("k1", t0, |_| Ok(())).expect("prime");

        // Stale, and every refetch from here fails — the cached key must still verify.
        c.with_key("k1", t0 + Duration::from_secs(10), |_| Ok(()))
            .expect("a fetch failure must not invalidate keys we already hold");
        assert!(
            calls.load(Ordering::SeqCst) >= 2,
            "the refetch was attempted"
        );
    }

    /// Two keys sharing a `kid` with different `kty` (RFC 7517 §4.5 — e.g. an RSA/EC pair
    /// coexisting during an algorithm migration). The first key in the set is the WRONG `kty` for
    /// what `f` needs; only the second matches. `with_key` must try both, not just the first found.
    ///
    /// RED (single-key `find`, `FnOnce` closure): only the first (RSA) key is ever tried, so `f`
    /// (which only succeeds for an EC key) always fails, and `with_key` returns
    /// "no JWKS key matches" even though a matching key is right there in the cache.
    /// GREEN: `with_key` tries every same-`kid` key and succeeds on the second.
    #[test]
    fn with_key_tries_every_key_sharing_a_kid_until_one_verifies() {
        let body = r#"{"keys":[
            {"kty":"RSA","kid":"shared","n":"AAAA","e":"AQAB"},
            {"kty":"EC","kid":"shared","crv":"P-256","x":"AAAA","y":"BBBB"}
        ]}"#
        .to_string();
        let (c, _calls) = cache(Ok(body), Duration::ZERO, Duration::from_secs(3600));

        let result = c.with_key("shared", Instant::now(), |key| {
            if key.kty == "EC" {
                Ok("verified with the EC key")
            } else {
                Err(format!("wrong kty for this token: {}", key.kty))
            }
        });

        assert_eq!(
            result,
            Ok("verified with the EC key"),
            "with_key must try every key sharing a kid, not just the first match"
        );
    }

    /// All keys sharing a `kid` fail `f`: the LAST error must surface (not silently "no key found").
    #[test]
    fn with_key_reports_the_last_error_when_no_key_sharing_a_kid_verifies() {
        let body = r#"{"keys":[
            {"kty":"RSA","kid":"shared","n":"AAAA","e":"AQAB"},
            {"kty":"EC","kid":"shared","crv":"P-256","x":"AAAA","y":"BBBB"}
        ]}"#
        .to_string();
        let (c, _calls) = cache(Ok(body), Duration::ZERO, Duration::from_secs(3600));

        let err = c
            .with_key("shared", Instant::now(), |key| {
                Err::<(), _>(format!("rejected: {}", key.kty))
            })
            .unwrap_err();

        assert_eq!(
            err, "rejected: EC",
            "when every same-kid key fails, the error from the LAST one tried should surface"
        );
    }

    /// The absolute staleness ceiling: once every refetch has failed for longer than `max_stale`
    /// (derived from `ttl`), the cache must stop serving the ancient key set — a days-long IdP outage
    /// must not keep validating signatures against a key the provider may have rotated out because it
    /// was compromised.
    ///
    /// RED (no ceiling): `with_key` keeps succeeding forever off the primed keys.
    /// GREEN: once `now` passes the ceiling, `with_key` returns the "cannot verify" error instead.
    #[test]
    fn a_permanently_unreachable_provider_stops_serving_keys_past_the_staleness_ceiling() {
        let ttl = Duration::from_millis(1);

        // A fetcher that succeeds exactly once (priming the cache) and fails on every attempt after
        // — standing in for an IdP that goes down and stays down.
        struct FailAfterFirst {
            first: Mutex<bool>,
            body: String,
            calls: Arc<AtomicUsize>,
        }
        impl JwksFetcher for FailAfterFirst {
            fn fetch(&self, _url: &str) -> Result<String, String> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let mut first = self.first.lock().unwrap();
                if *first {
                    *first = false;
                    return Ok(self.body.clone());
                }
                Err("provider unreachable".into())
            }
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let c = JwksCache::new(
            "https://idp.example/jwks",
            Box::new(FailAfterFirst {
                first: Mutex::new(true),
                body: jwks("k1"),
                calls: calls.clone(),
            }),
            Duration::from_millis(1),
            ttl,
        );
        let t0 = Instant::now();
        c.with_key("k1", t0, |_| Ok(())).expect("prime");

        // Still within the ceiling (max_stale = max(ttl*24, 24h) = 24h here): stale keys keep serving.
        let still_within = t0 + Duration::from_secs(3600);
        c.with_key("k1", still_within, |_| Ok(()))
            .expect("within the ceiling, a transient-looking outage must keep serving cached keys");

        // Past the 24h ceiling, with every refetch attempt still failing: must now error out rather
        // than silently keep validating against a key that old.
        let past_ceiling = t0 + Duration::from_secs(25 * 3600);
        let err = c.with_key("k1", past_ceiling, |_| Ok(()));
        assert!(
            err.is_err(),
            "a key set this stale (>24h with every refetch failing) must stop being served, got {err:?}"
        );
    }
}
