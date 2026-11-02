// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The instance's `refresh`, as the host calls it: the admin cache flush (unchanged settings) drops

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

    oidc.refresh(&settings(), &lent(b"a-client-secret"), 3)
        .expect("refreshes");
    assert!(!Arc::ptr_eq(&before, &oidc.now()), "a new secret re-opens");
}

/// `abi::auth`: "an auth plugin DROPS its inbound cache on every `refresh`" and reports how many
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

#[test]
fn a_refused_refresh_keeps_the_module_and_cached_verdict() {
    let key = TestKey::generate("k1");
    let idp = Idp::new(key.jwks());
    let current = settings();
    for (next, secret) in [
        (b"{}".as_slice(), b"".as_slice()),
        (current.as_slice(), b"\xff".as_slice()),
    ] {
        let oidc = Oidc::open(&settings(), &lent(b""), 1).expect("opens");
        let before = oidc.now();
        let token = key.mint(&base_claims(crate::now_unix()));
        assert!(matches!(
            verify(&oidc, &idp, &token),
            AuthVerdict::Identify(_)
        ));
        assert!(oidc.refresh(next, &lent(secret), 2).is_err());
        assert!(Arc::ptr_eq(&before, &oidc.now()));
        assert_eq!(
            oidc.refresh(&settings(), &lent(b""), 3).unwrap().counted,
            Some(Counted {
                family: CACHE_FAMILY,
                value: 1.0
            }),
            "the refused refresh did not flush"
        );
    }
}

#[test]
fn validate_answers_a_jwks_url_as_open_does() {
    let plaintext = serde_json::json!({
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "jwks_url": "http://jwks.test/keys",
    })
    .to_string();
    assert!(<Oidc as Life>::validate(plaintext.as_bytes()).is_err());
    assert!(Oidc::open(plaintext.as_bytes(), &lent(b""), 1).is_err());
    let other = serde_json::json!({
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "jwks_url": "ftp://jwks.test/keys",
    })
    .to_string();
    assert!(<Oidc as Life>::validate(other.as_bytes()).is_err());
    assert!(Oidc::open(other.as_bytes(), &lent(b""), 1).is_err());
    assert!(<Oidc as Life>::validate(&settings()).is_ok());
}

/// `validate` accepts a loopback http `jwks_url` as `open` does: a config `--validate` passes is
#[test]
fn validate_accepts_a_loopback_http_jwks_url_as_open_does() {
    let loopback = serde_json::json!({
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "jwks_url": "http://127.0.0.1:8080/jwks",
    })
    .to_string();
    assert!(<Oidc as Life>::validate(loopback.as_bytes()).is_ok());
    assert!(Oidc::open(loopback.as_bytes(), &lent(b""), 1).is_ok());
}

/// A nonce mismatch answers the security-check verdict AND says so in the plugin's log, with no
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
    let cap = crate::tests::diagnostics::WarnCapture::default();
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

fn kept_for(n: u32, at: u64) -> Reached {
    Reached {
        at,
        state: busbar_contract::abi::sdk::cred::Held::new(format!("s{n}").into_bytes()),
        code: busbar_contract::abi::sdk::cred::Held::new(format!("c{n}").into_bytes()),
        principal: Principal::from_id(format!("u{n}")),
    }
}

#[test]
fn a_kept_identity_serves_only_its_own_state_and_code() {
    let kept = kept_for(1, 0);
    assert!(kept.serves(b"s1", b"c1"), "its own callback");
    for (state, code) in [
        (&b"s2"[..], &b"c1"[..]),
        (b"s1", b"c2"),
        (b"s2", b"c2"),
        (b"", b""),
        (b"s1", b""),
        (b"s", b"c1"),
    ] {
        assert!(
            !kept.serves(state, code),
            "{:?}/{:?} is another callback",
            String::from_utf8_lossy(state),
            String::from_utf8_lossy(code)
        );
    }
}

/// A full short-answer map makes room by dropping its OLDEST entry only: every other identity a
#[test]
fn a_full_reached_map_evicts_only_the_oldest() {
    let at = |n: u32| u64::from(n) * 1_000_000;
    let mut map = HashMap::new();
    let max = u32::try_from(REACHED_MAX).expect("fits");
    for n in 1..=max {
        keep(&mut map, REACHED_MAX, ticket(n), kept_for(n, at(n)));
    }
    keep(
        &mut map,
        REACHED_MAX,
        ticket(max + 1),
        kept_for(max + 1, at(max + 1)),
    );
    assert_eq!(map.len(), REACHED_MAX);
    assert!(!map.contains_key(&ticket(1)), "the oldest is evicted");
    let earlier = map
        .get(&ticket(2))
        .expect("an earlier ticket's re-call is still served");
    assert_eq!(earlier.principal.id, "u2");
    assert!(map.contains_key(&ticket(max + 1)));
}

/// A ticket kept again replaces its own entry and evicts no other.
#[test]
fn a_ticket_kept_again_does_not_evict() {
    let t0 = 0;
    let mut map = HashMap::new();
    keep(&mut map, 2, ticket(1), kept_for(1, t0));
    keep(&mut map, 2, ticket(2), kept_for(2, t0));
    keep(&mut map, 2, ticket(2), kept_for(2, t0));
    assert_eq!(map.len(), 2);
    assert!(map.contains_key(&ticket(1)));
}

#[test]
fn a_kept_identity_older_than_ten_minutes_goes() {
    let t0 = 0;
    let mut map = HashMap::new();
    keep(&mut map, REACHED_MAX, ticket(1), kept_for(1, t0));
    keep(
        &mut map,
        REACHED_MAX,
        ticket(2),
        kept_for(2, t0 + 9 * 60 * 1_000_000_000),
    );
    keep(
        &mut map,
        REACHED_MAX,
        ticket(3),
        kept_for(3, t0 + (10 * 60 + 1) * 1_000_000_000),
    );
    assert!(!map.contains_key(&ticket(1)), "older than 10 minutes: gone");
    assert!(map.contains_key(&ticket(2)) && map.contains_key(&ticket(3)));
}

/// A blank `issuer` or `audience` is REFUSED at `validate` and at `open`, FAILED and naming the
#[test]
fn a_blank_issuer_or_audience_is_refused_naming_the_key() {
    for (key, blank) in [
        ("issuer", ""),
        ("issuer", "  "),
        ("audience", ""),
        ("audience", " \t"),
    ] {
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

/// BIND-AUDIT: a plain http `jwks_url` raises the diagnostic the Statement declares,
#[test]
fn a_plain_http_jwks_url_raises_its_declared_diagnostic() {
    let plain = serde_json::json!({
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "jwks_url": "http://127.0.0.1:8080/jwks",
    })
    .to_string();
    let oidc = Oidc::open(plain.as_bytes(), &lent(b""), 1).expect("a plain http jwks_url opens");
    let flag = oidc.flagged().expect("it raises its warning");
    assert_eq!(DIAG_NAMES[flag.id_idx as usize], "BUSBAR-4032");
    assert_eq!(
        DIAG_IDS.len(),
        DIAG_NAMES.len(),
        "the Statement declares it"
    );
    assert_eq!(
        flag.severity,
        busbar_contract::abi::mechanism::call::SEVERITY_WARN
    );
    let logged = crate::check_jwks_url(&config(&plain).expect("parses"))
        .expect("checks")
        .expect("a warning");
    assert_eq!(flag.text, logged, "the words the log line says");

    let https = Oidc::open(&settings(), &lent(b""), 1).expect("opens");
    assert!(
        https.flagged().is_none(),
        "an https jwks_url raises nothing"
    );
    oidc.refresh(&settings(), &lent(b""), 2).expect("refreshes");
    assert!(
        oidc.flagged().is_none(),
        "a refresh to https stops raising it"
    );
}

#[test]
fn bad_settings_are_refused_in_the_contracts_settings_line_form() {
    use busbar_contract::abi::mechanism::lifecycle::{check_validate_refusal, refusal_lines};
    for (cfg, lead) in [
        ("", "settings: "),
        ("{ not json", "settings: "),
        (r#"{"audience":"a"}"#, "settings: missing field `issuer`"),
        (
            r#"{"issuer":"https://i.test","audience":"a","bogus":1}"#,
            "settings: unknown field `bogus`",
        ),
        (r#"{"issuer":" ","audience":"a"}"#, "settings.issuer: "),
        (
            r#"{"issuer":"https://i.test","audience":""}"#,
            "settings.audience: ",
        ),
    ] {
        for refused in [
            <Oidc as Life>::validate(cfg.as_bytes()).expect_err("validate refuses"),
            Oidc::open(cfg.as_bytes(), &lent(b""), 1).expect_err("open refuses"),
        ] {
            assert_eq!(refused.outcome(), Outcome::Failed);
            let text = refused.text().unwrap_or_default().to_string();
            assert!(text.starts_with(lead), "{cfg:?}: {text}");
            check_validate_refusal(text.as_bytes()).expect("a well-formed refusal");
            let rendered = refusal_lines("identity-providers", "corp", &text);
            assert!(
                rendered[0].starts_with("identity-providers.corp.settings"),
                "{rendered:?}"
            );
        }
    }
    let refused = <Oidc as Life>::validate(&[0xff]).expect_err("not UTF-8");
    assert!(
        refused.text().unwrap_or_default().starts_with("settings: "),
        "{:?}",
        refused.text()
    );
    let refused = Oidc::open(&settings(), &lent(&[0xff, 0xfe]), 1).expect_err("not text");
    assert_eq!(refused.outcome(), Outcome::Failed);
    assert_eq!(
        refused.text().unwrap_or_default(),
        "secrets: `client_secret` is not UTF-8"
    );
}

#[test]
fn present_blank_optional_settings_are_refused_by_validate_and_open() {
    for key in [
        "jwks_url",
        "role_claim",
        "ca_cert_pem",
        "client_id",
        "authorization_endpoint",
        "token_endpoint",
    ] {
        for blank in ["", " \n\t "] {
            let mut cfg: serde_json::Value = serde_json::from_slice(&settings()).unwrap();
            cfg[key] = serde_json::json!(blank);
            let cfg = cfg.to_string();
            for refused in [
                <Oidc as Life>::validate(cfg.as_bytes()).expect_err("validate refuses blank"),
                Oidc::open(cfg.as_bytes(), &lent(b""), 1).expect_err("open refuses blank"),
            ] {
                let text = refused.text().unwrap_or_default();
                assert!(text.starts_with(&format!("settings.{key}: ")), "{text}");
                assert!(text.contains("blank"), "{text}");
                busbar_contract::abi::mechanism::lifecycle::check_validate_refusal(text.as_bytes())
                    .expect("a well-formed settings refusal");
            }
        }
    }

    let cfg = serde_json::json!({ "issuer": ISSUER, "audience": AUDIENCE }).to_string();
    assert!(<Oidc as Life>::validate(cfg.as_bytes()).is_ok());
    assert!(Oidc::open(cfg.as_bytes(), &lent(b""), 1).is_ok());
}

#[test]
fn zero_refetch_interval_is_refused_and_positive_intervals_remain_valid() {
    for secs in [0, 1, 60, u64::MAX] {
        let mut cfg: serde_json::Value = serde_json::from_slice(&settings()).unwrap();
        cfg["jwks_min_refetch_secs"] = serde_json::json!(secs);
        let cfg = cfg.to_string();
        let validated = <Oidc as Life>::validate(cfg.as_bytes());
        let opened = Oidc::open(cfg.as_bytes(), &lent(b""), 1);
        if secs == 0 {
            for refused in [validated.unwrap_err(), opened.unwrap_err()] {
                assert_eq!(
                    refused.text().unwrap_or_default(),
                    "settings.jwks_min_refetch_secs: must be greater than zero"
                );
            }
        } else {
            assert!(validated.is_ok(), "{secs}");
            assert!(opened.is_ok(), "{secs}");
        }
    }
}

#[test]
fn configured_endpoint_schemes_are_checked_without_echoing_settings_values() {
    for key in ["issuer", "authorization_endpoint", "token_endpoint"] {
        for value in [
            "not-a-url-PrivateMarker",
            "javascript:PrivateMarker",
            "ftp://user:PrivateMarker@idp.example/PrivateMarker?q=PrivateMarker",
            "http://user:PrivateMarker@idp.example/PrivateMarker?q=PrivateMarker",
            "http://127.0.0.1@evil.example/PrivateMarker",
        ] {
            let mut cfg: serde_json::Value = serde_json::from_slice(&settings()).unwrap();
            cfg[key] = serde_json::json!(value);
            let cfg = cfg.to_string();
            for refused in [
                <Oidc as Life>::validate(cfg.as_bytes()).expect_err("validate checks URL"),
                Oidc::open(cfg.as_bytes(), &lent(b""), 1).expect_err("open checks URL"),
            ] {
                let text = refused.text().unwrap_or_default();
                assert!(text.starts_with(&format!("settings.{key}: ")), "{text}");
                assert!(!text.contains("PrivateMarker"), "{text}");
                assert!(!text.contains(value), "{text}");
                busbar_contract::abi::mechanism::lifecycle::check_validate_refusal(text.as_bytes())
                    .expect("a well-formed settings refusal");
            }
        }
        for value in [
            "https://other.example/tenant",
            "http://localhost/tenant",
            "http://127.0.0.1:8080/tenant",
            "http://[::1]/tenant",
        ] {
            let mut cfg: serde_json::Value = serde_json::from_slice(&settings()).unwrap();
            cfg[key] = serde_json::json!(value);
            let cfg = cfg.to_string();
            assert!(
                <Oidc as Life>::validate(cfg.as_bytes()).is_ok(),
                "{key}: {value}"
            );
            assert!(
                Oidc::open(cfg.as_bytes(), &lent(b""), 1).is_ok(),
                "{key}: {value}"
            );
        }
    }

    let mut cfg: serde_json::Value = serde_json::from_slice(&settings()).unwrap();
    cfg["token_endpoint"] = serde_json::json!("http://192.168.1.2/token");
    let cfg = cfg.to_string();
    assert!(<Oidc as Life>::validate(cfg.as_bytes()).is_ok());
    assert!(Oidc::open(cfg.as_bytes(), &lent(b""), 1).is_ok());
}

#[test]
fn a_refresh_rediscovers_the_issuer_s_document() {
    let settings = serde_json::json!({ "issuer": ISSUER, "audience": AUDIENCE })
        .to_string()
        .into_bytes();
    let doc = serde_json::json!({ "issuer": ISSUER, "jwks_uri": "https://jwks.test/keys" });
    let idp = Idp::new(doc.to_string());
    let oidc = Oidc::open(&settings, &lent(b""), 1).expect("opens");
    let url = |oidc: &Oidc| {
        ready(
            oidc.now()
                .module
                .jwks_url(Instant::now(), &mut idp.at_once(Some(ME))),
        )
        .map(std::borrow::Cow::into_owned)
    };
    assert_eq!(url(&oidc).as_deref(), Ok("https://jwks.test/keys"));
    assert_eq!(idp.calls(), 1);
    oidc.refresh(&settings, &lent(b""), 2).expect("refreshes");
    assert_eq!(url(&oidc).as_deref(), Ok("https://jwks.test/keys"));
    assert_eq!(
        idp.calls(),
        2,
        "the refresh has the document asked for again"
    );
}

/// A short-answer lease owns its cursor and callback identity. Lifecycle cleanup cannot leave
#[test]
fn short_login_cursor_cleanup_owns_only_its_continuation() {
    for cleanup in ["release", "cancel", "retire"] {
        let oidc = Oidc::open(&settings(), &lent(b""), 1).expect("opens");
        let marker = Arc::new(());
        oidc.login_cursors.lock().unwrap().insert(
            ticket(1),
            LoginCursor {
                marker: marker.clone(),
                issued: 17,
            },
        );
        oidc.reached
            .lock()
            .unwrap()
            .insert(ticket(1), kept_for(1, 0));
        let guard = ReleaseLogin {
            ticket: ticket(1),
            marker,
            cursors: Arc::downgrade(&oidc.login_cursors),
            reached: Arc::downgrade(&oidc.reached),
        };
        match cleanup {
            "release" => drop(guard),
            "cancel" => {
                oidc.cancel(ticket(1));
                drop(guard);
            }
            "retire" => {
                oidc.retire(1);
                drop(guard);
            }
            _ => unreachable!(),
        }
        assert!(oidc.login_cursors.lock().unwrap().is_empty(), "{cleanup}");
        assert!(oidc.reached.lock().unwrap().is_empty(), "{cleanup}");
    }
    let oidc = Oidc::open(&settings(), &lent(b""), 1).expect("opens");
    let old = ReleaseLogin {
        ticket: ticket(1),
        marker: Arc::new(()),
        cursors: Arc::downgrade(&oidc.login_cursors),
        reached: Arc::downgrade(&oidc.reached),
    };
    oidc.login_cursors.lock().unwrap().insert(
        ticket(1),
        LoginCursor {
            marker: Arc::new(()),
            issued: 29,
        },
    );
    oidc.reached
        .lock()
        .unwrap()
        .insert(ticket(1), kept_for(1, 0));
    drop(old);
    assert_eq!(oidc.login_cursors.lock().unwrap()[&ticket(1)].issued, 29);
    assert!(oidc.reached.lock().unwrap().contains_key(&ticket(1)));
}
