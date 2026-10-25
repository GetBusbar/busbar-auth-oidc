// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The instance's `refresh`, as the host calls it: the admin cache flush (unchanged settings) drops
//! the verdict cache and reports how many entries it held, and keeps the module and its key set —
//! for a verify-only instance too, whose secret the host lends as one EMPTY entry.

use super::*;
use crate::script::{ready, Idp, ME};
use crate::tests::{base_claims, TestKey, AUDIENCE, ISSUER};

fn settings() -> Vec<u8> {
    serde_json::json!({
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "jwks_url": "https://jwks.test/keys",
    })
    .to_string()
    .into_bytes()
}

/// The secrets the host lends: one entry, `secret`.
fn lent(secret: &[u8]) -> [&[u8]; 1] {
    [secret]
}

/// A verify of `token` on the instance's current module.
fn verify(oidc: &Oidc, idp: &Idp, token: &str) -> AuthVerdict {
    let now = crate::now_unix();
    ready(
        oidc.now()
            .module
            .verify(Some(token), now, Instant::now(), &mut idp.at_once(Some(ME))),
    )
    .expect("the jwks_url is configured")
}

/// The host lends one entry per secret reference, a missing one as EMPTY bytes (plugin-loader
/// `auth_door.rs`). A refresh with the same settings and that same empty entry keeps the opened
/// module and its key set, as the door's contract says, rather than re-opening it cold.
#[test]
fn an_empty_lent_secret_refresh_keeps_the_module_and_its_key_set() {
    let key = TestKey::generate("k1");
    let idp = Idp::new(key.jwks());
    let oidc = Oidc::open(&settings(), &lent(b""), 1).expect("opens");
    let before = oidc.now();
    let now = crate::now_unix();
    let token = key.mint(&base_claims(now));
    assert!(matches!(
        verify(&oidc, &idp, &token),
        AuthVerdict::Identify(_)
    ));
    assert_eq!(idp.calls(), 1, "the key set is fetched once");

    oidc.refresh(&settings(), &lent(b""), 2).expect("refreshes");
    assert!(
        Arc::ptr_eq(&before, &oidc.now()),
        "the same settings and no secret keep the opened module"
    );
    let mut other = base_claims(now);
    other["sub"] = serde_json::json!("another-subject");
    assert!(matches!(
        verify(&oidc, &idp, &key.mint(&other)),
        AuthVerdict::Identify(_)
    ));
    assert_eq!(idp.calls(), 1, "its key set survives: no refetch");

    // A secret that changes re-opens it.
    oidc.refresh(&settings(), &lent(b"a-client-secret"), 3)
        .expect("refreshes");
    assert!(!Arc::ptr_eq(&before, &oidc.now()), "a new secret re-opens");
}

/// `abi::auth`: "an auth plugin DROPS its inbound cache on every `refresh`" and reports how many
/// entries under the `busbar_auth_cache_flushed_total` family, which the host sums into the admin
/// flush's `{"flushed": N}` (1.5.5's count).
#[test]
fn refresh_drops_the_verdict_cache_and_reports_its_count() {
    let key = TestKey::generate("k1");
    let idp = Idp::new(key.jwks());
    let oidc = Oidc::open(&settings(), &lent(b""), 1).expect("opens");
    let token = key.mint(&base_claims(crate::now_unix()));
    assert!(matches!(
        verify(&oidc, &idp, &token),
        AuthVerdict::Identify(_)
    ));

    let flushed = |value| Some(busbar_contract::abi::sdk::life::Counted { family: 0, value });
    let refreshed = oidc.refresh(&settings(), &lent(b""), 2).expect("refreshes");
    assert_eq!(refreshed.counted, flushed(1.0), "the one cached identity");
    let refreshed = oidc.refresh(&settings(), &lent(b""), 3).expect("refreshes");
    assert_eq!(refreshed.counted, flushed(0.0), "nothing left to drop");

    // Settings that change drop the running module's cache too.
    assert!(matches!(
        verify(&oidc, &idp, &token),
        AuthVerdict::Identify(_)
    ));
    let mut changed: serde_json::Value = serde_json::from_slice(&settings()).unwrap();
    changed["role_claim"] = serde_json::json!("roles");
    let refreshed = oidc
        .refresh(changed.to_string().as_bytes(), &lent(b""), 4)
        .expect("refreshes");
    assert_eq!(refreshed.counted, flushed(1.0));
}

/// `validate` HOLDS `jwks_url` TO HTTPS AS `open` DOES (Q128 auth-oidc LOW, reader r82 on 59293c0):
/// a config `--validate` accepts is one boot opens. RED before the fix: validate parsed the config
/// and skipped the https check `open` applies.
#[test]
fn validate_refuses_a_plaintext_jwks_url_as_open_does() {
    let plaintext = serde_json::json!({
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "jwks_url": "http://jwks.test/keys",
    })
    .to_string();
    let refused = <Oidc as Life>::validate(plaintext.as_bytes());
    assert!(refused.is_err(), "validate accepted what open refuses");
    assert!(<Oidc as Life>::validate(&settings()).is_ok());
}

/// A nonce mismatch answers the security-check verdict AND says so in the plugin's log, with no
/// nonce value in it.
#[test]
fn a_nonce_mismatch_is_logged() {
    use base64::Engine as _;
    let oidc = Oidc::open(&settings(), &lent(b""), 1).expect("opens");
    let id_token = format!(
        "h.{}.s",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"nonce":"THEIRS-SECRET"}"#)
    );
    let mut answer = Some(LoginHttpResponse {
        status: 200,
        body: serde_json::json!({ "id_token": id_token }).to_string(),
    });
    let mut io = HostIo::new(None, Ticket::NONE, IoState::default(), false);
    let cap = busbar_contract::testkit::WarnCapture::default();
    let login = tracing::subscriber::with_default(cap.clone(), || {
        oidc.now()
            .login(None, None, None, "MINE-SECRET", &mut answer, &mut io)
    });
    assert!(matches!(login, Step::Ready(Login::SecurityCheck)));
    let logged = cap.messages().join("\n");
    assert!(
        logged.contains("does not carry this login's nonce"),
        "{logged:?}"
    );
    assert!(!logged.contains("SECRET"), "a nonce leaked: {logged:?}");
}

fn ticket(n: u32) -> Ticket {
    Ticket {
        slot: n,
        generation: 1,
    }
}

fn kept_for(n: u32, at: Instant) -> Reached {
    Reached {
        at,
        state: format!("s{n}").into_bytes(),
        code: Zeroizing::new(format!("c{n}").into_bytes()),
        principal: Principal::from_id(format!("u{n}")),
    }
}

/// A full short-answer map makes room by dropping its OLDEST entry only: every other identity a
/// short buffer reached still waits for its re-call (clearing the map would refuse them all).
#[test]
fn a_full_reached_map_evicts_only_the_oldest() {
    let t0 = Instant::now();
    let at = |n: u32| t0 + std::time::Duration::from_millis(u64::from(n));
    let mut map = HashMap::new();
    let max = u32::try_from(REACHED_MAX).expect("fits");
    for n in 1..=max {
        keep(&mut map, REACHED_MAX, ticket(n), kept_for(n, at(n)));
    }
    keep(&mut map, REACHED_MAX, ticket(max + 1), kept_for(max + 1, at(max + 1)));
    assert_eq!(map.len(), REACHED_MAX);
    assert!(!map.contains_key(&ticket(1)), "the oldest is evicted");
    let earlier = map.get(&ticket(2)).expect("an earlier ticket's re-call is still served");
    assert_eq!(earlier.principal.id, "u2");
    assert!(map.contains_key(&ticket(max + 1)));
}

/// A ticket kept again replaces its own entry and evicts no other.
#[test]
fn a_ticket_kept_again_does_not_evict() {
    let t0 = Instant::now();
    let mut map = HashMap::new();
    keep(&mut map, 2, ticket(1), kept_for(1, t0));
    keep(&mut map, 2, ticket(2), kept_for(2, t0));
    keep(&mut map, 2, ticket(2), kept_for(2, t0));
    assert_eq!(map.len(), 2);
    assert!(map.contains_key(&ticket(1)));
}

/// A blank `issuer` or `audience` is REFUSED at `validate` and at `open`, FAILED and naming the
/// key: an empty issuer/audience would load and then match no token (or a token claiming an empty
/// one), so it is refused rather than opened.
#[test]
fn a_blank_issuer_or_audience_is_refused_naming_the_key() {
    for (key, blank) in [("issuer", ""), ("issuer", "  "), ("audience", ""), ("audience", " \t")] {
        let mut cfg = serde_json::json!({
            "issuer": ISSUER,
            "audience": AUDIENCE,
            "jwks_url": "https://jwks.test/keys",
        });
        cfg[key] = serde_json::Value::from(blank);
        let cfg = cfg.to_string();
        let refused = <Oidc as Life>::validate(cfg.as_bytes()).expect_err("validate refuses");
        assert_eq!(refused.outcome(), Outcome::Failed);
        let text = refused.text().unwrap_or_default();
        assert!(text.contains(key), "validate names `{key}`: {text}");
        let refused = Oidc::open(cfg.as_bytes(), &lent(b""), 1).expect_err("open refuses");
        assert_eq!(refused.outcome(), Outcome::Failed);
        let text = refused.text().unwrap_or_default();
        assert!(text.contains(key), "open names `{key}`: {text}");
    }
}
