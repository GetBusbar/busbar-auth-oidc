// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The discovery document's single flight: the claimer pends on ONE fetch, a caller arriving
//! meanwhile waits and takes the claimer's document, and the boot-time `ready` resolution runs it
//! (an explicit `jwks_url` skips it).

use super::*;
use crate::script::{ready, ticket, Idp, ME};
use crate::{OidcModule, Step};

const ISSUER: &str = "https://idp.example/v2.0";

fn cfg(jwks_url: Option<&str>) -> OidcConfig {
    serde_json::from_value(serde_json::json!({
        "issuer": ISSUER,
        "audience": "api://a",
        "jwks_url": jwks_url,
    }))
    .unwrap()
}

fn doc() -> String {
    serde_json::json!({ "issuer": ISSUER, "jwks_uri": "https://idp.example/keys" }).to_string()
}

#[test]
fn a_caller_arriving_during_the_fetch_waits_and_takes_the_claimer_s_document() {
    let (c, d) = (cfg(None), Discovery::new(Duration::from_secs(60)));
    let idp = Idp::new(doc());
    let now = Instant::now();
    let (mut a, mut b) = (idp.pending(ticket(1)), idp.pending(ticket(2)));
    assert_eq!(d.document(&c, now, &mut a), Step::Pending);
    assert_eq!(d.document(&c, now, &mut b), Step::Wait);
    assert!(idp.woken().is_empty());
    assert!(matches!(d.document(&c, now, &mut a), Step::Ready(Ok(_))));
    assert_eq!(
        idp.woken(),
        vec![ticket(2)],
        "the waiter is woken when it lands"
    );
    assert!(matches!(d.document(&c, now, &mut b), Step::Ready(Ok(_))));
    assert_eq!(idp.calls(), 1, "one discovery fetch for two callers");
}

#[test]
fn ready_resolves_the_jwks_url_at_boot_and_an_explicit_one_skips_it() {
    let idp = Idp::new(doc());
    let now = Instant::now();
    let m = OidcModule::new(&cfg(Some("https://idp.example/explicit")));
    assert_eq!(ready(m.ready(now, &mut idp.at_once(Some(ME)))), Ok(()));
    assert_eq!(
        idp.calls(),
        1,
        "an explicit jwks_url never fetches discovery: the one request is the key set's warm-up"
    );

    let m = OidcModule::new(&cfg(None));
    let before = idp.calls();
    assert_eq!(ready(m.ready(now, &mut idp.at_once(Some(ME)))), Ok(()));
    assert_eq!(
        idp.calls() - before,
        2,
        "discovery, then the key set's warm-up"
    );

    let down = Idp::answering(Err("connection refused".into()));
    let m = OidcModule::new(&cfg(None));
    let err = ready(m.ready(now, &mut down.at_once(Some(ME)))).unwrap_err();
    assert!(
        err.starts_with("OIDC discovery fetch failed"),
        "1.5.5's boot refusal: {err}"
    );
}

/// An op whose fetch answers `Err`, but only after another op has taken over its abandoned flight:
/// the interleaving a late answer from a flight past `FLIGHT_MAX` produces.
struct TakenOver<'a> {
    a: crate::script::Caller<'a>,
    b: crate::script::Caller<'a>,
    d: &'a Discovery,
    c: &'a OidcConfig,
    at: Instant,
    taken: bool,
}

impl Fetch for TakenOver<'_> {
    fn caller(&self) -> Option<busbar_contract::abi::mechanism::ticket::Ticket> {
        self.a.caller()
    }

    fn get(&mut self, _: Doc, _: &str) -> Poll<Result<String, String>> {
        if !self.taken {
            self.taken = true;
            assert_eq!(self.d.document(self.c, self.at, &mut self.b), Step::Pending);
        }
        Poll::Ready(Err("connection reset".into()))
    }

    fn post(
        &mut self,
        url: &str,
        form: &busbar_contract::abi::sdk::cred::FormBody,
    ) -> Poll<Result<busbar_contract::auth::LoginHttpResponse, String>> {
        self.a.post(url, form)
    }
}

#[test]
fn a_late_failure_from_an_abandoned_flight_does_not_overwrite_the_live_one() {
    let (c, d) = (cfg(None), Discovery::new(Duration::from_secs(60)));
    let idp = Idp::new(doc());
    let t0 = Instant::now();
    let late = t0 + crate::flight::FLIGHT_MAX + Duration::from_secs(1);
    let mut a = idp.pending(ticket(1));
    assert_eq!(d.document(&c, t0, &mut a), Step::Pending);
    // A re-enters past FLIGHT_MAX; while its fetch answers, B takes over the abandoned flight.
    let mut a = TakenOver {
        a,
        b: idp.pending(ticket(2)),
        d: &d,
        c: &c,
        at: late,
        taken: false,
    };
    let b_caller_err = ready(d.document(&c, late, &mut a));
    assert!(b_caller_err.is_err(), "A's own answer is its error");
    let mut b = a.b;
    let got = ready(d.document(&c, late, &mut b));
    assert!(
        got.is_ok(),
        "B must get its own document, not A's late error: {got:?}"
    );
}

#[test]
fn a_failed_discovery_logs_one_warn_with_the_error() {
    let (c, d) = (cfg(None), Discovery::new(Duration::from_secs(60)));
    let idp = Idp::answering(Err("connection refused".into()));
    let cap = busbar_test_kit::warn_capture::WarnCapture::default();
    tracing::subscriber::with_default(cap.clone(), || {
        let now = Instant::now();
        assert!(ready(d.document(&c, now, &mut idp.at_once(Some(ME)))).is_err());
        assert!(ready(d.document(&c, now, &mut idp.at_once(Some(ME)))).is_err());
    });
    assert_eq!(
        cap.count("OIDC discovery failed"),
        1,
        "one warn per attempt; the retry window answers the second silently: {:?}",
        cap.messages()
    );
    assert!(
        cap.contains("connection refused") && cap.contains(ISSUER),
        "{:?}",
        cap.messages()
    );
}

/// L15: the discovery document is not held for the module's life: 24 h after it was fetched the
/// issuer is asked again (an IdP that moved its keys or endpoints is followed), and while that
/// re-discovery is in flight or has failed, the previous document keeps serving (a re-discovery
/// that fails is asked again after the retry bound, not a day later).
#[test]
fn the_document_is_rediscovered_after_a_day_serving_the_previous_one_meanwhile() {
    let (c, d) = (cfg(None), Discovery::new(Duration::from_secs(60)));
    let idp = Idp::new(doc());
    let t0 = Instant::now();
    assert!(matches!(ready(d.document(&c, t0, &mut idp.at_once(Some(ME)))), Ok(_)));
    let within = t0 + Duration::from_secs(24 * 3600 - 1);
    assert!(matches!(ready(d.document(&c, within, &mut idp.at_once(Some(ME)))), Ok(_)));
    assert_eq!(idp.calls(), 1, "held within the day");

    let day = t0 + Duration::from_secs(24 * 3600);
    let mut claimer = idp.pending(ticket(1));
    assert_eq!(d.document(&c, day, &mut claimer), Step::Pending, "asked again");
    assert!(
        matches!(ready(d.document(&c, day, &mut idp.at_once(Some(ticket(2))))), Ok(_)),
        "another caller is served the previous document meanwhile"
    );
    idp.set_answer(Err("down".to_string()));
    assert!(
        matches!(ready(d.document(&c, day, &mut claimer)), Ok(_)),
        "a failed re-discovery keeps the previous document"
    );
    assert_eq!(idp.calls(), 2);
    let retry = day + Duration::from_secs(60);
    let _ = ready(d.document(&c, retry, &mut idp.at_once(Some(ME))));
    assert_eq!(idp.calls(), 3, "asked again after the retry bound");
}
