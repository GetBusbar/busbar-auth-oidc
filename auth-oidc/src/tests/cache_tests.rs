// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The JWKS cache's contract, sans-IO: single-flight (a cold kid pends ONE fetch, every waiter takes
//! its keys), a caller with usable keys never waits on another's fetch, every trigger rate-limited,
//! failures fall back to the previous keys up to the staleness ceiling, and 1.5.5's timings. The
//! IdP is the scripted one (`crate::script`): an op that pends answers its first ask `Pending` and
//! the re-ask on its re-entry `Ready`.

use super::*;
use crate::script::{ready, ticket, Idp, ME};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Barrier;

const URL: &str = "https://idp.example/jwks";

/// A minimal but real JWKS document. These tests exercise the CACHE's contract, not the crypto —
/// `f` is whatever the test needs it to be — so the key material only has to parse.
fn jwks(kid: &str) -> String {
    format!(r#"{{"keys":[{{"kty":"EC","crv":"P-256","kid":"{kid}","x":"AAAA","y":"BBBB"}}]}}"#)
}

/// `with_key` for kid `k1` on one op that answers at once.
fn serve(c: &JwksCache, idp: &Idp, now: Instant) -> Result<(), String> {
    ready(c.with_key(URL, "k1", now, &mut idp.at_once(Some(ME)), |_| Ok(())))
}

/// THE CLASS TEST: signature verification must not be serialised. `f` runs on a snapshot with no
/// lock held, so concurrent verifications overlap; with the lock held across `f` the observed
/// concurrency would be exactly 1.
#[test]
fn concurrent_verifications_are_not_serialised() {
    let c = JwksCache::new(Duration::from_secs(60), Duration::from_secs(3600));
    let idp = Idp::new(jwks("k1"));
    let now = Instant::now();
    serve(&c, &idp, now).expect("prime");

    const N: usize = 8;
    let inside = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let start = Arc::new(Barrier::new(N));
    std::thread::scope(|s| {
        for n in 0..N {
            let (c, idp) = (&c, &idp);
            let (inside, peak, start) = (inside.clone(), peak.clone(), start.clone());
            s.spawn(move || {
                start.wait();
                let mut io = idp.at_once(Some(ticket(n as u32 + 2)));
                ready(c.with_key(URL, "k1", now, &mut io, |_| {
                    let here = inside.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(here, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(80));
                    inside.fetch_sub(1, Ordering::SeqCst);
                    Ok(())
                }))
                .expect("verify");
            });
        }
    });
    assert!(
        peak.load(Ordering::SeqCst) > 1,
        "OIDC signature verification is serialised: {} of {N} concurrent verifications ever \
         overlapped. The cache lock must not be held across `f`.",
        peak.load(Ordering::SeqCst)
    );
}

/// THE SPEC'S SINGLE FLIGHT: a cold kid pends verify, ONE exchange fetches, every waiter wakes and
/// takes its keys. Three cold callers: the first claims the fetch and pends on it, the other two
/// WAIT (they fetch nothing), and once the first re-enters with the answer both are served the
/// same keys.
#[test]
fn a_cold_kid_pends_one_fetch_and_every_waiter_takes_its_keys() {
    let c = JwksCache::new(Duration::from_secs(60), Duration::from_secs(3600));
    let idp = Idp::new(jwks("k1"));
    let t0 = Instant::now();
    let (mut a, mut b, mut d) = (
        idp.pending(ticket(1)),
        idp.pending(ticket(2)),
        idp.pending(ticket(3)),
    );
    let f = |_: &Jwk| Ok::<_, String>("verified");

    assert_eq!(c.with_key(URL, "k1", t0, &mut a, f), Step::Pending);
    assert_eq!(c.with_key(URL, "k1", t0, &mut b, f), Step::Wait);
    assert_eq!(c.with_key(URL, "k1", t0, &mut d, f), Step::Wait);
    assert_eq!(idp.calls(), 1, "one fetch for three cold callers");

    // The claimer re-enters on its exchange's wake: its answer lands.
    assert_eq!(
        c.with_key(URL, "k1", t0, &mut a, f),
        Step::Ready(Ok("verified"))
    );
    // The waiters re-enter: the keys are there.
    let later = t0 + Duration::from_millis(25);
    assert_eq!(
        c.with_key(URL, "k1", later, &mut b, f),
        Step::Ready(Ok("verified"))
    );
    assert_eq!(
        c.with_key(URL, "k1", later, &mut d, f),
        Step::Ready(Ok("verified"))
    );
    assert_eq!(idp.calls(), 1, "the waiters fetched nothing");
}

/// THE LIVENESS RULE: a slow JWKS endpoint must not stall a caller that already has a usable key.
/// While one caller's TTL refresh is in flight, another holding the (stale) cached set serves it at
/// once — whether the rate limit turns it away or it finds the flight taken.
#[test]
fn a_fetch_in_flight_does_not_stall_a_caller_that_already_has_the_key() {
    for min_refetch in [Duration::from_secs(60), Duration::ZERO] {
        let c = JwksCache::new(min_refetch, Duration::from_millis(1));
        let idp = Idp::new(jwks("k1"));
        let t0 = Instant::now();
        serve(&c, &idp, t0).expect("prime");

        // Past the TTL and past the rate limit: the next caller refreshes.
        let now = t0 + Duration::from_secs(61);
        let mut winner = idp.pending(ticket(1));
        assert_eq!(
            c.with_key(URL, "k1", now, &mut winner, |_| Ok(())),
            Step::Pending
        );
        assert_eq!(idp.calls(), 2);

        // Another caller with the stale set serves it at once and fetches nothing.
        let mut other = idp.pending(ticket(2));
        assert_eq!(
            c.with_key(URL, "k1", now, &mut other, |_| Ok(())),
            Step::Ready(Ok(())),
            "min_refetch {min_refetch:?}"
        );
        assert_eq!(idp.calls(), 2, "the caller with keys never joins the fetch");
        assert_eq!(
            c.with_key(URL, "k1", now, &mut winner, |_| Ok(())),
            Step::Ready(Ok(()))
        );
    }
}

/// The TTL-stale path obeys the SAME rate limit as the kid-rotation path: an unreachable IdP is
/// retried once per `min_refetch_interval`, not once per request.
#[test]
fn a_failing_provider_does_not_produce_a_fetch_storm() {
    let c = JwksCache::new(Duration::from_secs(60), Duration::from_millis(1));
    let idp = Idp::answering(Err("connection timed out".into()));
    let t0 = Instant::now();
    assert_eq!(
        serve(&c, &idp, t0),
        Err("connection timed out".to_string()),
        "a cold cache surfaces the fetch error"
    );
    for i in 0..100u64 {
        let _ = serve(&c, &idp, t0 + Duration::from_millis(i));
    }
    assert_eq!(
        idp.calls(),
        1,
        "an unreachable IdP must be retried once per min_refetch_interval, not once per request"
    );
    let later = t0 + Duration::from_secs(61);
    for i in 0..50u64 {
        let _ = serve(&c, &idp, later + Duration::from_millis(i));
    }
    assert_eq!(idp.calls(), 2, "one retry per interval");
}

/// A transient provider failure must not blow away a working key set.
#[test]
fn a_fetch_failure_keeps_serving_the_previously_fetched_keys() {
    let c = JwksCache::new(Duration::from_millis(1), Duration::from_millis(1));
    let idp = Idp::new(jwks("k1"));
    let t0 = Instant::now();
    serve(&c, &idp, t0).expect("prime");
    idp.set_answer(Err("provider unreachable".into()));
    serve(&c, &idp, t0 + Duration::from_secs(10))
        .expect("a fetch failure must not invalidate keys we already hold");
    assert_eq!(idp.calls(), 2, "the refetch was attempted");
}

/// OIDC-8: a failed refresh that falls back to the previous keys logs a warn carrying the fetch
/// error, so an IdP outage is visible before the first rotated-key token is rejected.
#[test]
fn a_failed_refresh_that_keeps_the_previous_keys_logs_a_warn_with_the_error() {
    let c = JwksCache::new(Duration::from_millis(1), Duration::from_millis(1));
    let idp = Idp::new(jwks("k1"));
    let t0 = Instant::now();
    let cap = busbar_contract::testkit::WarnCapture::default();
    tracing::subscriber::with_default(cap.clone(), || {
        serve(&c, &idp, t0).expect("prime");
        idp.set_answer(Err("provider unreachable".into()));
        serve(&c, &idp, t0 + Duration::from_secs(10)).expect("the previous keys still serve");
    });
    assert_eq!(idp.calls(), 2, "the refetch was attempted");
    assert_eq!(
        cap.count("JWKS refresh failed; serving the previous key set"),
        1,
        "one warn for the one failed refresh: {:?}",
        cap.messages()
    );
    assert!(
        cap.contains("provider unreachable") && cap.contains(URL),
        "the warn names the fetch error and the URL: {:?}",
        cap.messages()
    );
}

/// Two keys sharing a `kid` with different `kty` (RFC 7517 §4.5): `with_key` tries both.
#[test]
fn with_key_tries_every_key_sharing_a_kid_until_one_verifies() {
    let body = r#"{"keys":[
        {"kty":"RSA","kid":"shared","n":"AAAA","e":"AQAB"},
        {"kty":"EC","kid":"shared","crv":"P-256","x":"AAAA","y":"BBBB"}
    ]}"#;
    let c = JwksCache::new(Duration::ZERO, Duration::from_secs(3600));
    let idp = Idp::new(body.to_string());
    let result = ready(c.with_key(
        URL,
        "shared",
        Instant::now(),
        &mut idp.at_once(Some(ME)),
        |key| {
            if key.kty == "EC" {
                Ok("verified with the EC key")
            } else {
                Err(format!("wrong kty for this token: {}", key.kty))
            }
        },
    ));
    assert_eq!(result, Ok("verified with the EC key"));
}

/// All keys sharing a `kid` fail `f`: the LAST error surfaces (not silently "no key found").
#[test]
fn with_key_reports_the_last_error_when_no_key_sharing_a_kid_verifies() {
    let body = r#"{"keys":[
        {"kty":"RSA","kid":"shared","n":"AAAA","e":"AQAB"},
        {"kty":"EC","kid":"shared","crv":"P-256","x":"AAAA","y":"BBBB"}
    ]}"#;
    let c = JwksCache::new(Duration::ZERO, Duration::from_secs(3600));
    let idp = Idp::new(body.to_string());
    let err = ready(c.with_key(
        URL,
        "shared",
        Instant::now(),
        &mut idp.at_once(Some(ME)),
        |key| Err::<(), _>(format!("rejected: {}", key.kty)),
    ))
    .unwrap_err();
    assert_eq!(err, "rejected: EC");
}

/// KEY ROTATION: a kid absent from a fresh set refetches ONCE (rate-limited), pending on that
/// fetch, and the call carries on from the rotation point when it re-enters.
#[test]
fn an_unknown_kid_pends_one_rotation_refetch_and_carries_on_from_it() {
    let c = JwksCache::new(Duration::from_secs(60), Duration::from_secs(3600));
    let idp = Idp::new(jwks("old"));
    let t0 = Instant::now();
    ready(c.with_key(URL, "old", t0, &mut idp.at_once(Some(ME)), |_| Ok(()))).expect("prime");
    idp.set_body(jwks("new"));

    let now = t0 + Duration::from_secs(61);
    let mut op = idp.pending(ticket(2));
    assert_eq!(
        c.with_key(URL, "new", now, &mut op, |_| Ok(())),
        Step::Pending
    );
    assert_eq!(
        c.with_key(URL, "new", now, &mut op, |_| Ok(())),
        Step::Ready(Ok(()))
    );
    assert_eq!(idp.calls(), 2, "exactly one refetch for the rotation");

    // Inside the rate-limit window a third, unknown kid is refused off the set in hand.
    let err = ready(c.with_key(
        URL,
        "ghost",
        now + Duration::from_secs(1),
        &mut idp.at_once(Some(ME)),
        |_| Ok(()),
    ))
    .unwrap_err();
    assert!(
        err.contains("no JWKS key matches the token's kid 'ghost'"),
        "{err}"
    );
    assert_eq!(idp.calls(), 2, "the rate limit held off a second refetch");
}

/// The absolute staleness ceiling: once every refetch has failed for longer than `max_stale`
/// (derived from `ttl`), the cache stops serving the ancient key set.
#[test]
fn a_permanently_unreachable_provider_stops_serving_keys_past_the_staleness_ceiling() {
    let c = JwksCache::new(Duration::from_millis(1), Duration::from_millis(1));
    let idp = Idp::new(jwks("k1"));
    let t0 = Instant::now();
    serve(&c, &idp, t0).expect("prime");
    idp.set_answer(Err("provider unreachable".into()));
    serve(&c, &idp, t0 + Duration::from_secs(3600))
        .expect("within the ceiling (24h here), the cached keys keep serving");
    assert!(
        serve(&c, &idp, t0 + Duration::from_secs(25 * 3600)).is_err(),
        "a key set this stale (>24h with every refetch failing) must stop being served"
    );
}

/// The ceiling on the RATE-LIMITED EARLY RETURN: once a request past the ceiling has triggered (and
/// failed) a fetch, the next one inside the rate-limit window fails closed with the ceiling error
/// rather than serving the ancient keys.
#[test]
fn the_rate_limited_early_return_also_enforces_the_staleness_ceiling() {
    let c = JwksCache::new(Duration::from_secs(60), Duration::from_millis(1));
    let idp = Idp::new(jwks("k1"));
    let t0 = Instant::now();
    serve(&c, &idp, t0).expect("prime");
    idp.set_answer(Err("provider unreachable".into()));

    let past = t0 + Duration::from_secs(25 * 3600);
    assert!(serve(&c, &idp, past).is_err());
    let err = serve(&c, &idp, past + Duration::from_millis(1))
        .expect_err("a rate-limited call past max_stale must fail closed");
    assert!(err.contains("staleness ceiling"), "{err}");
    assert_eq!(idp.calls(), 2, "the second call was rate-limited");
}

/// `snapshot`'s `expired` flag at its exact boundary: `ttl = 3600s` makes `max_stale = 86400s`.
#[test]
fn snapshot_expired_flag_is_true_at_the_exact_max_stale_boundary() {
    let c = JwksCache::new(Duration::ZERO, Duration::from_secs(3600));
    let idp = Idp::new(jwks("k1"));
    let t0 = Instant::now();
    serve(&c, &idp, t0).expect("prime");
    assert!(!c.snapshot(t0 + Duration::from_secs(86400 - 1)).2);
    assert!(c.snapshot(t0 + Duration::from_secs(86400)).2);
}

/// The `ttl * 24` term of `max_stale` (OIDC-22): with `ttl = 7200s` the ceiling is 48h.
#[test]
fn max_stale_scales_with_a_long_ttl() {
    let c = JwksCache::new(Duration::from_millis(1), Duration::from_secs(7200));
    let idp = Idp::new(jwks("k1"));
    let t0 = Instant::now();
    serve(&c, &idp, t0).expect("prime");
    idp.set_answer(Err("provider unreachable".into()));
    serve(&c, &idp, t0 + Duration::from_secs(47 * 3600)).expect("+47h still serves");
    assert!(serve(&c, &idp, t0 + Duration::from_secs(48 * 3600)).is_err());
}

/// OIDC-7: a caller whose cached keys are past `max_stale` is treated as a COLD cache: while a
/// recovery fetch is in flight it waits for it and then serves its fresh keys, rather than being
/// rejected with the ceiling error.
#[test]
fn a_caller_past_the_ceiling_waits_for_the_in_flight_recovery_fetch() {
    let c = JwksCache::new(Duration::from_secs(60), Duration::from_millis(1));
    let idp = Idp::new(jwks("k1"));
    let t0 = Instant::now();
    serve(&c, &idp, t0).expect("prime");

    let now = t0 + Duration::from_secs(25 * 3600);
    let (mut winner, mut late) = (idp.pending(ticket(1)), idp.pending(ticket(2)));
    assert_eq!(
        c.with_key(URL, "k1", now, &mut winner, |_| Ok(())),
        Step::Pending
    );
    assert_eq!(
        c.with_key(URL, "k1", now, &mut late, |_| Ok(())),
        Step::Wait
    );
    assert_eq!(
        c.with_key(URL, "k1", now, &mut winner, |_| Ok(())),
        Step::Ready(Ok(()))
    );
    assert_eq!(
        c.with_key(URL, "k1", now, &mut late, |_| Ok(())),
        Step::Ready(Ok(()))
    );
    assert_eq!(idp.calls(), 2, "the waiting caller takes the winner's keys");
}

/// A caller past the ceiling never serves keys past it: when the flight it would wait on is older
/// than a fetch may take (abandoned), it makes its own recovery fetch, and when that fails it fails
/// closed — never the winner's set, never the ancient one.
#[test]
fn a_caller_past_the_ceiling_never_serves_keys_past_the_ceiling() {
    let c = JwksCache::new(Duration::ZERO, Duration::from_millis(1));
    let idp = Idp::new(jwks("k1"));
    let t0 = Instant::now();
    serve(&c, &idp, t0).expect("prime");

    let mut winner = idp.pending(ticket(1));
    let within = t0 + Duration::from_secs(1);
    assert_eq!(
        c.with_key(URL, "k1", within, &mut winner, |_| Ok(())),
        Step::Pending
    );

    idp.set_answer(Err("provider unreachable".into()));
    let past = t0 + Duration::from_secs(25 * 3600);
    assert!(
        ready(
            c.with_key(URL, "k1", past, &mut idp.at_once(Some(ticket(2))), |_| Ok(
                ()
            ))
        )
        .is_err(),
        "a caller past max_stale must fail closed"
    );
    idp.set_answer(Ok(jwks("k1")));
    assert_eq!(
        c.with_key(URL, "k1", within, &mut winner, |_| Ok(())),
        Step::Ready(Ok(()))
    );
    assert_eq!(
        idp.calls(),
        3,
        "prime, the winner's refresh, the late caller's recovery"
    );
}

/// A cold caller that waited on a fetch which then FAILED re-checks the rate limit when it
/// re-enters: inside the window it does not start a second immediate fetch, and it fails closed
/// with the honest "cannot verify" error.
#[test]
fn a_waiter_whose_fetch_failed_fails_closed_inside_the_rate_limit() {
    let c = JwksCache::new(Duration::from_secs(60), Duration::from_millis(1));
    let idp = Idp::answering(Err("provider unreachable".into()));
    let t0 = Instant::now();
    let (mut winner, mut waiter) = (idp.pending(ticket(1)), idp.pending(ticket(2)));
    assert_eq!(
        c.with_key(URL, "k1", t0, &mut winner, |_| Ok(())),
        Step::Pending
    );
    assert_eq!(
        c.with_key(URL, "k1", t0, &mut waiter, |_| Ok(())),
        Step::Wait
    );
    assert_eq!(
        c.with_key(URL, "k1", t0, &mut winner, |_| Ok(())),
        Step::Ready(Err("provider unreachable".to_string()))
    );
    let err = ready(c.with_key(URL, "k1", t0, &mut waiter, |_| Ok(()))).unwrap_err();
    assert!(err.contains("cannot verify any token"), "{err}");
    assert_eq!(idp.calls(), 1);
}

/// A flight whose op never came back (cancelled, faulted) is abandoned after 1.5.5's fetch bound:
/// a cold caller waits on it until then, and takes it over after.
#[test]
fn an_abandoned_flight_is_taken_over_after_the_fetch_bound() {
    let c = JwksCache::new(Duration::from_millis(1), Duration::from_secs(3600));
    let idp = Idp::new(jwks("k1"));
    let t0 = Instant::now();
    let mut gone = idp.pending(ticket(1));
    assert_eq!(
        c.with_key(URL, "k1", t0, &mut gone, |_| Ok(())),
        Step::Pending
    );

    let mut cold = idp.pending(ticket(2));
    let within = t0 + crate::flight::FLIGHT_MAX - Duration::from_millis(1);
    assert_eq!(
        c.with_key(URL, "k1", within, &mut cold, |_| Ok(())),
        Step::Wait
    );
    let past = t0 + crate::flight::FLIGHT_MAX;
    assert_eq!(
        c.with_key(URL, "k1", past, &mut cold, |_| Ok(())),
        Step::Pending
    );
    assert_eq!(
        c.with_key(URL, "k1", past, &mut cold, |_| Ok(())),
        Step::Ready(Ok(()))
    );
    assert_eq!(idp.calls(), 2);
}

/// A call on no ticket may not pend: it neither claims a fetch (which would hold the rate-limit
/// window without ever asking) nor waits. It fails at once, and the next ticketed caller fetches.
#[test]
fn a_ticketless_caller_never_claims_or_waits() {
    let c = JwksCache::new(Duration::from_secs(60), Duration::from_secs(3600));
    let idp = Idp::new(jwks("k1"));
    let t0 = Instant::now();
    let err = ready(c.with_key(URL, "k1", t0, &mut idp.at_once(None), |_| Ok(()))).unwrap_err();
    assert_eq!(
        err,
        "request to https://idp.example/jwks failed: the call runs on no ticket and cannot pend"
    );
    assert_eq!(idp.calls(), 0);

    let mut claimer = idp.pending(ticket(1));
    assert_eq!(
        c.with_key(URL, "k1", t0, &mut claimer, |_| Ok(())),
        Step::Pending
    );
    assert!(
        ready(c.with_key(URL, "k1", t0, &mut idp.at_once(None), |_| Ok(()))).is_err(),
        "a ticketless cold caller cannot wait either"
    );
    assert_eq!(
        c.with_key(URL, "k1", t0, &mut claimer, |_| Ok(())),
        Step::Ready(Ok(()))
    );
    assert_eq!(serve(&c, &idp, t0), Ok(()), "warm: no ticket needed");
    assert_eq!(idp.calls(), 1);
}
