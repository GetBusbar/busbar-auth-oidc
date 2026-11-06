// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The discovery document's single flight: the claimer pends on ONE fetch, a caller arriving

use super::*;
use crate::script::{ready, ticket, Idp, ME};
use crate::{OidcModule, Step};
use busbar_contract::abi::sdk::cred::FormBody;
use busbar_contract::auth::LoginHttpResponse;

const ISSUER: &str = "https://idp.example/v2.0";

#[test]
fn present_but_nonstring_discovery_endpoints_are_errors() {
    for field in ["jwks_uri", "authorization_endpoint", "token_endpoint"] {
        for value in [
            serde_json::json!(123),
            serde_json::json!({"SecretEndpoint":true}),
            serde_json::Value::Null,
        ] {
            let mut document =
                serde_json::json!({"issuer":ISSUER,"jwks_uri":"https://idp.example/keys"});
            document[field] = value;
            let idp = Idp::new(document.to_string());
            let module = OidcModule::new(&cfg(None));
            let mut io = idp.at_once(Some(ME));
            let error = match field {
                "jwks_uri" => ready(module.jwks_url(Instant::now(), &mut io)).map(|_| ()),
                "authorization_endpoint" => {
                    ready(module.authorization_endpoint(Instant::now(), &mut io)).map(|_| ())
                }
                _ => ready(module.token_endpoint(Instant::now(), &mut io)).map(|_| ()),
            }
            .expect_err("a malformed endpoint is not absent");
            assert!(error.contains(field));
            assert!(!error.contains("SecretEndpoint"));
        }
    }
}

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

/// A `ready` meeting another op's key-set warm-up in flight waits for it (that fetch's settle wakes
/// it) rather than declaring the boot ready with no key set held.
#[test]
fn ready_meeting_another_op_s_key_set_fetch_waits_for_it() {
    let idp = Idp::new(
        r#"{"keys":[{"kty":"EC","kid":"a","crv":"P-256","x":"AAAA","y":"BBBB"}]}"#.to_string(),
    );
    let now = Instant::now();
    let m = OidcModule::new(&cfg(Some("https://idp.example/explicit")));
    let mut first = idp.pending(ticket(1));
    assert_eq!(m.ready(now, &mut first), Step::Pending);
    assert_eq!(
        m.ready(now, &mut idp.pending(ticket(2))),
        Step::Wait,
        "the second ready waits on the warm-up in flight"
    );
    assert_eq!(ready(m.ready(now, &mut first)), Ok(()));
    assert_eq!(idp.woken(), vec![ticket(2)], "its settle wakes the waiter");
    assert_eq!(idp.calls(), 1, "one key-set fetch");
}

/// A late failure of an op whose flight was taken over still serves the document held: the
/// previous one stays available whichever op's re-discovery fails.
#[test]
fn a_late_failure_after_a_takeover_serves_the_held_document() {
    let (c, d) = (cfg(None), Discovery::new(Duration::from_secs(60)));
    let idp = Idp::new(doc());
    let t0 = Instant::now();
    let previous = ready(d.document(&c, t0, &mut idp.at_once(Some(ME)))).expect("discovered");
    d.expire();
    let late = t0 + crate::flight::FLIGHT_MAX + Duration::from_secs(1);
    let mut a = idp.pending(ticket(1));
    assert_eq!(d.document(&c, t0, &mut a), Step::Pending, "re-discovery");
    let mut a = TakenOver {
        a,
        b: idp.pending(ticket(2)),
        d: &d,
        c: &c,
        at: late,
        taken: false,
    };
    let served = ready(d.document(&c, late, &mut a)).expect("the held document serves");
    assert!(Arc::ptr_eq(&previous, &served));
}

/// A `refresh` asks again after a failed FIRST discovery too: the failure is not held over it for
/// the rest of its retry interval.
#[test]
fn a_refresh_drops_a_held_discovery_failure() {
    let (c, d) = (cfg(None), Discovery::new(Duration::from_secs(3600)));
    let idp = Idp::answering(Err("connection refused".into()));
    let t0 = Instant::now();
    assert!(ready(d.document(&c, t0, &mut idp.at_once(Some(ME)))).is_err());
    idp.set_body(doc());
    let later = t0 + Duration::from_secs(1);
    assert!(
        ready(d.document(&c, later, &mut idp.at_once(Some(ME)))).is_err(),
        "within the retry interval the failure is answered"
    );
    assert_eq!(idp.calls(), 1);
    d.expire();
    assert!(ready(d.document(&c, later, &mut idp.at_once(Some(ME)))).is_ok());
    assert_eq!(idp.calls(), 2, "the refresh had the issuer asked again");
}

#[test]
fn a_failed_discovery_logs_one_warn_with_the_error() {
    let (c, d) = (cfg(None), Discovery::new(Duration::from_secs(60)));
    let idp = Idp::answering(Err("connection refused".into()));
    let cap = crate::tests::diagnostics::WarnCapture::default();
    tracing::subscriber::with_default(cap.subscriber(), || {
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

#[test]
fn the_document_is_rediscovered_after_a_day_serving_the_previous_one_meanwhile() {
    let (c, d) = (cfg(None), Discovery::new(Duration::from_secs(60)));
    let idp = Idp::new(doc());
    let t0 = Instant::now();
    assert!(ready(d.document(&c, t0, &mut idp.at_once(Some(ME)))).is_ok());
    let within = t0 + Duration::from_secs(24 * 3600 - 1);
    assert!(ready(d.document(&c, within, &mut idp.at_once(Some(ME)))).is_ok());
    assert_eq!(idp.calls(), 1, "held within the day");

    let day = t0 + Duration::from_secs(24 * 3600);
    let mut claimer = idp.pending(ticket(1));
    assert_eq!(
        d.document(&c, day, &mut claimer),
        Step::Pending,
        "asked again"
    );
    assert!(
        ready(d.document(&c, day, &mut idp.at_once(Some(ticket(2))))).is_ok(),
        "another caller is served the previous document meanwhile"
    );
    idp.set_answer(Err("down".to_string()));
    assert!(
        ready(d.document(&c, day, &mut claimer)).is_ok(),
        "a failed re-discovery keeps the previous document"
    );
    assert_eq!(idp.calls(), 2);
    let retry = day + Duration::from_secs(60);
    let _ = ready(d.document(&c, retry, &mut idp.at_once(Some(ME))));
    assert_eq!(idp.calls(), 3, "asked again after the retry bound");
}

#[test]
fn a_failed_rediscovery_keeps_the_previous_document_for_the_full_retry_interval() {
    for seconds in [1, 60, u64::MAX] {
        let settings = serde_json::json!({
            "issuer": ISSUER,
            "audience": "api://a",
            "jwks_min_refetch_secs": seconds,
        })
        .to_string();
        assert!(
            <crate::door::Oidc as busbar_contract::abi::sdk::life::Life>::validate(
                settings.as_bytes()
            )
            .is_ok()
        );
        let mut c = cfg(None);
        c.jwks_min_refetch_secs = seconds;
        let d = Discovery::new(Duration::from_secs(c.jwks_min_refetch_secs));
        let idp = Idp::new(doc());
        let t0 = Instant::now();
        let previous = ready(d.document(&c, t0, &mut idp.at_once(Some(ME)))).unwrap();
        let failed_at = t0 + REDISCOVER;
        idp.set_answer(Err("rediscovery unavailable".into()));
        let retained = ready(d.document(&c, failed_at, &mut idp.at_once(Some(ME)))).unwrap();
        assert!(Arc::ptr_eq(&previous, &retained));
        assert_eq!(idp.calls(), 2);
        let before_retry = failed_at + Duration::from_millis(999);
        let retained = ready(d.document(&c, before_retry, &mut idp.at_once(Some(ME)))).unwrap();
        assert!(Arc::ptr_eq(&previous, &retained));
        assert_eq!(
            idp.calls(),
            2,
            "no immediate retry, including an overflowing interval"
        );
        if let Some(due) = failed_at.checked_add(Duration::from_secs(seconds)) {
            let just_before = due.checked_sub(Duration::from_nanos(1)).unwrap();
            let _ = ready(d.document(&c, just_before, &mut idp.at_once(Some(ME))));
            assert_eq!(
                idp.calls(),
                2,
                "still retained just before the retry boundary"
            );
            let _ = ready(d.document(&c, due, &mut idp.at_once(Some(ME))));
            assert_eq!(idp.calls(), 3, "retry at the exact boundary");
        } else {
            let later = failed_at + REDISCOVER;
            assert!(ready(d.document(&c, later, &mut idp.at_once(Some(ME)))).is_ok());
            assert_eq!(idp.calls(), 2, "the large interval is not shortened");
        }
        let before_expire = idp.calls();
        d.expire();
        let _ = ready(d.document(&c, failed_at, &mut idp.at_once(Some(ME))));
        assert_eq!(
            idp.calls(),
            before_expire + 1,
            "explicit refresh still retries"
        );
    }
}

#[test]
fn a_discovered_jwks_failure_scrubs_userinfo_without_changing_the_fetch_url() {
    struct FailingKeys<'a> {
        url: &'a str,
        asked: Vec<(crate::fetch::Doc, String)>,
    }
    impl Fetch for FailingKeys<'_> {
        fn caller(&self) -> Option<busbar_contract::abi::mechanism::ticket::Ticket> {
            Some(ME)
        }
        fn get(&mut self, doc: crate::fetch::Doc, url: &str) -> Poll<Result<String, String>> {
            self.asked.push((doc, url.to_string()));
            Poll::Ready(match doc {
                crate::fetch::Doc::Discovery => Ok(serde_json::json!({
                    "issuer": ISSUER, "jwks_uri": self.url,
                })
                .to_string()),
                crate::fetch::Doc::Jwks => Err("transport unavailable".to_string()),
            })
        }
        fn post(
            &mut self,
            _: &str,
            _: &busbar_contract::abi::sdk::cred::FormBody,
        ) -> Poll<Result<busbar_contract::auth::LoginHttpResponse, String>> {
            panic!("JWKS warm-up never posts credentials")
        }
    }

    for url in [
        "https://idp.example/keys?set=1",
        "https://user:OidcPassCanary@idp.example/keys?set=1",
    ] {
        let module = OidcModule::new(&cfg(None));
        let mut io = FailingKeys {
            url,
            asked: Vec::new(),
        };
        let capture = crate::tests::diagnostics::WarnCapture::default();
        tracing::subscriber::with_default(capture.subscriber(), || {
            assert_eq!(ready(module.ready(Instant::now(), &mut io)), Ok(()));
        });
        assert_eq!(io.asked.len(), 2, "discovery then the discovered JWKS");
        assert_eq!(
            io.asked[1],
            (crate::fetch::Doc::Jwks, url.to_string()),
            "display escaping must not rewrite the destination handed to the fetcher"
        );
        let messages = capture.messages();
        assert_eq!(messages.len(), 1, "{messages:?}");
        let logged = &messages[0];
        assert!(
            logged.contains("JWKS fetch failed; no key set to serve"),
            "{logged:?}"
        );
        assert!(logged.contains("transport unavailable"), "{logged:?}");
        assert!(!logged.chars().any(char::is_control), "{logged:?}");
        assert!(
            !logged.contains("user:") && !logged.contains("OidcPassCanary"),
            "{logged:?}"
        );
        if !url.contains('@') {
            assert!(logged.contains("keys?set=1"), "{logged:?}");
        }
    }
}

/// A scripted op whose `busy_elsewhere` answer is settable.
struct Busy<'a>(crate::script::Caller<'a>, bool);

impl Fetch for Busy<'_> {
    fn caller(&self) -> Option<Ticket> {
        self.0.caller()
    }
    fn get(&mut self, doc: Doc, url: &str) -> Poll<Result<String, String>> {
        self.0.get(doc, url)
    }
    fn post(&mut self, url: &str, form: &FormBody) -> Poll<Result<LoginHttpResponse, String>> {
        self.0.post(url, form)
    }
    fn busy_elsewhere(&self, _: &str) -> bool {
        self.1
    }
}

#[test]
fn an_op_with_its_own_exchange_in_flight_is_not_made_to_refetch_discovery() {
    let (c, d) = (cfg(None), Discovery::new(Duration::from_secs(60)));
    let idp = Idp::new(doc());
    let now = Instant::now();
    assert!(ready(d.document(&c, now, &mut idp.at_once(Some(ME)))).is_ok());
    d.expire();
    assert_eq!(idp.calls(), 1);

    let mut busy = Busy(idp.at_once(Some(ticket(1))), true);
    assert!(
        ready(d.document(&c, now, &mut busy)).is_ok(),
        "the previous document is answered"
    );
    assert_eq!(
        idp.calls(),
        1,
        "and no request is made over its own exchange"
    );

    let mut free = Busy(idp.at_once(Some(ticket(1))), false);
    assert!(ready(d.document(&c, now, &mut free)).is_ok());
    assert_eq!(idp.calls(), 2, "an op with nothing in flight refetches");
}

#[test]
fn a_document_without_a_usable_jwks_uri_is_refused_unless_jwks_url_is_configured() {
    let bare = serde_json::json!({ "issuer": ISSUER }).to_string();
    let url = discovery_url(&cfg(None));
    let err = check_document(&cfg(None), &url, Ok(bare.clone())).expect_err("no jwks_uri");
    assert!(err.contains("no jwks_uri"), "{err}");
    let numeric = serde_json::json!({ "issuer": ISSUER, "jwks_uri": 5 }).to_string();
    assert!(check_document(&cfg(None), &url, Ok(numeric)).is_err());
    assert!(check_document(&cfg(Some("https://idp.example/k")), &url, Ok(bare)).is_ok());
}

#[test]
fn a_rediscovered_document_without_jwks_uri_keeps_the_previous_good_one() {
    let (c, d) = (cfg(None), Discovery::new(Duration::from_secs(60)));
    let idp = Idp::new(doc());
    let now = Instant::now();
    assert!(ready(d.document(&c, now, &mut idp.at_once(Some(ME)))).is_ok());
    d.expire();
    idp.set_body(serde_json::json!({ "issuer": ISSUER }).to_string());
    let got = ready(d.document(&c, now, &mut idp.at_once(Some(ME)))).expect("previous kept");
    assert_eq!(got["jwks_uri"], "https://idp.example/keys");
}

/// An op whose discovery answer is `body`, delivered only after another op has taken over its
/// abandoned flight and finished its own fetch.
struct LateSuccess<'a> {
    a: crate::script::Caller<'a>,
    b: crate::script::Caller<'a>,
    d: &'a Discovery,
    c: &'a OidcConfig,
    at: Instant,
    body: String,
    taken: bool,
}

impl Fetch for LateSuccess<'_> {
    fn caller(&self) -> Option<Ticket> {
        self.a.caller()
    }

    fn get(&mut self, _: Doc, _: &str) -> Poll<Result<String, String>> {
        if !self.taken {
            self.taken = true;
            assert_eq!(self.d.document(self.c, self.at, &mut self.b), Step::Pending);
            assert!(matches!(
                self.d.document(self.c, self.at, &mut self.b),
                Step::Ready(Ok(_))
            ));
        }
        Poll::Ready(Ok(self.body.clone()))
    }

    fn post(&mut self, url: &str, form: &FormBody) -> Poll<Result<LoginHttpResponse, String>> {
        self.a.post(url, form)
    }
}

#[test]
fn a_late_success_from_an_abandoned_flight_does_not_replace_the_live_document() {
    let (c, d) = (cfg(None), Discovery::new(Duration::from_secs(60)));
    let idp = Idp::new(doc());
    let t0 = Instant::now();
    let late = t0 + crate::flight::FLIGHT_MAX + Duration::from_secs(1);
    let mut a = idp.pending(ticket(1));
    assert_eq!(d.document(&c, t0, &mut a), Step::Pending);
    let stale = serde_json::json!({ "issuer": ISSUER, "jwks_uri": "https://idp.example/stale" });
    let mut a = LateSuccess {
        a,
        b: idp.pending(ticket(2)),
        d: &d,
        c: &c,
        at: late,
        body: stale.to_string(),
        taken: false,
    };
    let got = ready(d.document(&c, late, &mut a)).expect("a document");
    assert_eq!(
        got["jwks_uri"], "https://idp.example/keys",
        "the taker's fresh document wins over the late answer"
    );
    let held = ready(d.document(&c, late, &mut idp.at_once(Some(ME)))).expect("held");
    assert_eq!(held["jwks_uri"], "https://idp.example/keys");
}

#[test]
fn a_ticketless_caller_meeting_another_op_s_first_discovery_cannot_wait() {
    let (c, d) = (cfg(None), Discovery::new(Duration::from_secs(60)));
    let idp = Idp::new(doc());
    let now = Instant::now();
    assert_eq!(
        d.document(&c, now, &mut idp.pending(ticket(1))),
        Step::Pending
    );
    let err = ready(d.document(&c, now, &mut idp.at_once(None))).unwrap_err();
    assert!(err.contains("cannot pend"), "{err}");
    assert_eq!(idp.calls(), 1, "it made no request of its own");
}

#[test]
fn a_ticketless_caller_is_served_the_previous_document_when_rediscovery_is_due() {
    let (c, d) = (cfg(None), Discovery::new(Duration::from_secs(60)));
    let idp = Idp::new(doc());
    let now = Instant::now();
    let previous = ready(d.document(&c, now, &mut idp.at_once(Some(ME)))).expect("discovered");
    d.expire();
    let served = ready(d.document(&c, now, &mut idp.at_once(None))).expect("previous served");
    assert!(Arc::ptr_eq(&previous, &served));
    assert_eq!(idp.calls(), 1, "a ticketless caller cannot claim a refetch");
}

#[test]
fn a_cold_op_busy_with_its_own_exchange_still_discovers() {
    let (c, d) = (cfg(None), Discovery::new(Duration::from_secs(60)));
    let idp = Idp::new(doc());
    let now = Instant::now();
    let mut busy = Busy(idp.pending(ticket(1)), true);
    assert_eq!(
        d.document(&c, now, &mut busy),
        Step::Pending,
        "with no previous document to serve it must fetch"
    );
    assert_eq!(idp.calls(), 1);
}
