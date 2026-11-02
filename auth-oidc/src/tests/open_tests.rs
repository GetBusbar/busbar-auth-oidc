use crate::script::{ready, Idp, ME};
use crate::OidcModule;
use busbar_contract::auth::{BeginLogin, LoginOutcome};
use std::time::{Duration, Instant};

#[test]
fn malformed_endpoint_settings_are_refused_without_echoing_values() {
    for (field, value) in [
        ("issuer", "https://idp.example/SecretIssuer?query=yes"),
        ("issuer", "https://idp.example/SecretIssuer#fragment"),
        (
            "authorization_endpoint",
            "https://idp.example/SecretAuthorize#fragment",
        ),
        (
            "authorization_endpoint",
            "https://idp.example/SecretAuthorize\r\nInjected: yes",
        ),
    ] {
        let mut config = serde_json::json!({"issuer":"https://idp.example", "audience":"aud"});
        config[field] = serde_json::json!(value);
        let error = match crate::open::config(&config.to_string()) {
            Err(error) => error,
            Ok(_) => panic!("invalid endpoint accepted"),
        };
        assert!(error.contains(field));
        assert!(!error.contains("Secret"));
    }
}

/// The module `open` builds, its warning (checked by `door_tests`) set aside.
fn module(cfg: &str) -> Result<OidcModule, String> {
    super::module(cfg).map(|(m, _)| m)
}

/// `module` answers `Result<OidcModule, String>`, and `OidcModule` is not `Debug`, so the standard
fn expect_err(result: Result<OidcModule, String>) -> String {
    match result {
        Ok(_) => panic!("expected open to fail, but it succeeded"),
        Err(e) => e,
    }
}

fn begin() -> BeginLogin {
    BeginLogin {
        redirect_uri: "https://busbar.test/auth/token".to_string(),
        state: "st".to_string(),
        code_challenge: "ch".to_string(),
        nonce: Some("nc".to_string()),
        scopes: vec![],
    }
}

#[test]
fn empty_config_is_rejected() {
    let err = expect_err(module(""));
    assert!(
        err.starts_with("settings: none provided"),
        "error should name that settings are required: {err}"
    );
}

#[test]
fn whitespace_only_config_is_rejected() {
    let err = expect_err(module("   \n\t  "));
    assert!(err.starts_with("settings: none provided"), "got: {err}");
}

#[test]
fn malformed_json_is_rejected() {
    let err = expect_err(module("{ this is not json"));
    assert!(
        err.starts_with("settings: "),
        "error should name the settings as invalid: {err}"
    );
}

#[test]
fn config_missing_issuer_is_rejected() {
    let err = expect_err(module(r#"{"audience":"api://busbar"}"#));
    assert!(err.starts_with("settings: "), "got: {err}");
}

#[test]
fn config_missing_audience_is_rejected() {
    let err = expect_err(module(r#"{"issuer":"https://idp.example/v2.0"}"#));
    assert!(err.starts_with("settings: "), "got: {err}");
}

#[test]
fn unknown_config_field_is_rejected() {
    let err = expect_err(module(
        r#"{"issuer":"https://idp.example/v2.0","audience":"a","jwks_url":"https://idp.example/keys","bogus_field":true}"#,
    ));
    assert!(err.starts_with("settings: "), "got: {err}");
}

#[test]
fn an_explicit_jwks_url_opens_and_resolves_without_a_request() {
    let m = module(
        r#"{"issuer":"https://issuer.invalid.example","audience":"api://busbar-client",
            "jwks_url":"https://issuer.invalid.example/keys"}"#,
    )
    .expect("an explicit https jwks_url opens");
    let idp = Idp::answering(Err("never asked".to_string()));
    assert_eq!(
        ready(m.jwks_url(Instant::now(), &mut idp.at_once(Some(ME)))).as_deref(),
        Ok("https://issuer.invalid.example/keys")
    );
    assert_eq!(
        idp.calls(),
        0,
        "an explicit jwks_url never triggers discovery"
    );
}

/// A loopback `jwks_url` over plain http OPENS, as 1.5.5 booted it (the oracle's login-hop rig
#[test]
fn a_loopback_http_jwks_url_opens_with_a_warning() {
    for url in [
        "http://127.0.0.1:8080/jwks",
        "http://127.9.8.7/jwks",
        "http://[::1]:9443/jwks",
        "http://localhost:1/jwks",
        "http://LOCALHOST./jwks",
        "http://idp.localhost/jwks",
    ] {
        let settings = serde_json::json!({
            "issuer": "https://issuer.invalid.example",
            "audience": "api://busbar-client",
            "jwks_url": url,
        })
        .to_string();
        let cap = busbar_test_kit::warn_capture::WarnCapture::default();
        let opened = tracing::subscriber::with_default(cap.clone(), || module(&settings));
        assert!(opened.is_ok(), "a loopback http jwks_url must open: {url}");
        let logged = cap.messages().join("\n");
        assert!(logged.contains("jwks_url"), "{url}: {logged:?}");
        assert!(logged.contains("loopback"), "{url}: {logged:?}");
        assert!(logged.contains("https"), "{url}: {logged:?}");
    }

    let cap = busbar_test_kit::warn_capture::WarnCapture::default();
    let opened = tracing::subscriber::with_default(cap.clone(), || {
        module(
            r#"{"issuer":"https://issuer.invalid.example","audience":"api://busbar-client",
                "jwks_url":"https://127.0.0.1/keys"}"#,
        )
    });
    assert!(opened.is_ok());
    assert!(cap.messages().is_empty(), "{:?}", cap.messages());
}

#[test]
fn a_non_loopback_http_jwks_url_is_refused() {
    for (url, host) in [
        ("http://10.0.0.7/keys", "10.0.0.7"),
        ("http://192.168.1.2/keys", "192.168.1.2"),
        ("http://idp.example/keys", "idp.example"),
        (
            "http://127.0.0.1.evil.example/keys",
            "127.0.0.1.evil.example",
        ),
        (
            "http://localhost.evil.example/keys",
            "localhost.evil.example",
        ),
        ("http://127.0.0.1@evil.example/keys", "evil.example"),
        ("http://[::ffff:7f00:1]/keys", "[::ffff:7f00:1]"),
    ] {
        let settings = serde_json::json!({
            "issuer": "https://issuer.invalid.example",
            "audience": "api://busbar-client",
            "jwks_url": url,
        })
        .to_string();
        let err = expect_err(module(&settings));
        assert!(err.contains("jwks_url"), "{url}: {err}");
        assert!(
            !err.contains(host),
            "{url}: a settings value is not echoed: {err}"
        );
        assert!(err.contains("loopback"), "{url}: names the rule: {err}");
        assert!(
            !err.contains("/keys"),
            "{url}: the URL's path is never repeated: {err}"
        );
    }
}

/// THE SEAM, as implemented: `open` runs on no ticket with no connector, so it fetches nothing; a
#[test]
fn discovery_runs_on_the_first_op_and_its_failure_fails_that_op() {
    let m =
        module(r#"{"issuer":"https://issuer.invalid.example","audience":"api://busbar-client"}"#)
            .expect("a config that needs discovery opens: nothing is fetched at open");
    let idp = Idp::answering(Err("connection refused".to_string()));
    let now = Instant::now();
    let err = ready(m.jwks_url(now, &mut idp.at_once(Some(ME))))
        .expect_err("an unreachable issuer fails the op");
    assert!(
        err.contains("discovery fetch failed") && err.contains("connection refused"),
        "{err}"
    );
    assert_eq!(idp.calls(), 1);

    let again = ready(m.jwks_url(now + Duration::from_secs(1), &mut idp.at_once(Some(ME))));
    assert_eq!(again, Err(err));
    assert_eq!(
        idp.calls(),
        1,
        "no fetch storm against an unreachable issuer"
    );
    let _ = ready(m.jwks_url(now + Duration::from_secs(61), &mut idp.at_once(Some(ME))));
    assert_eq!(idp.calls(), 2, "one retry per interval");
}

const DISCOVERY_ISSUER: &str = "https://issuer.invalid.example";

#[test]
fn the_discovered_login_endpoints_reach_both_login_steps_from_one_document() {
    let m = module(&format!(
        r#"{{"issuer":"{DISCOVERY_ISSUER}","audience":"api://busbar-client",
            "jwks_url":"https://issuer.invalid.example/keys"}}"#
    ))
    .expect("opens");
    let doc = serde_json::json!({
        "issuer": DISCOVERY_ISSUER,
        "jwks_uri": "https://issuer.invalid.example/keys",
        "authorization_endpoint": "https://issuer.invalid.example/discovered/authorize",
        "token_endpoint": "https://issuer.invalid.example/discovered/token",
    });
    let idp = Idp::new(doc.to_string());
    let now = Instant::now();
    match ready(m.begin_login(&begin(), now, &mut idp.at_once(Some(ME)))) {
        Ok(LoginOutcome::Authorize(url)) => assert!(
            url.starts_with("https://issuer.invalid.example/discovered/authorize?"),
            "begin_login must redirect to the DISCOVERED authorize endpoint, got: {url}"
        ),
        other => panic!("expected Authorize, got {other:?}"),
    }
    let hop = ready(m.token_exchange(
        Some("code"),
        Some("https://busbar.test/auth/token"),
        Some("verifier"),
        None,
        now,
        &mut idp.at_once(Some(ME)),
    ))
    .expect("discovered")
    .expect("a token request");
    assert_eq!(
        hop.url, "https://issuer.invalid.example/discovered/token",
        "the token exchange must target the DISCOVERED token endpoint"
    );
    assert_eq!(idp.calls(), 1, "one discovery GET serves both login steps");
}

#[test]
fn a_failed_login_discovery_fails_begin_login_with_its_cause() {
    let m = module(&format!(
        r#"{{"issuer":"{DISCOVERY_ISSUER}","audience":"api://busbar-client",
            "jwks_url":"https://issuer.invalid.example/keys"}}"#
    ))
    .expect("a login-discovery failure cannot fail open: open fetches nothing");
    let idp = Idp::answering(Err("connection refused".to_string()));
    let err = ready(m.begin_login(&begin(), Instant::now(), &mut idp.at_once(Some(ME))))
        .expect_err("begin_login names the discovery failure");
    assert!(
        err.contains("connection refused"),
        "the cause is named: {err}"
    );
    assert_eq!(idp.calls(), 1);
}

/// A mistyped settings value is refused WITHOUT echoing the value: serde's own text quotes it
#[test]
fn a_mistyped_settings_value_is_refused_without_echoing_it() {
    let err = expect_err(module(
        r#"{"issuer":"https://i.test","audience":"a","jwks_ttl_secs":"Zq7distinctiveValue"}"#,
    ));
    assert!(err.starts_with("settings: "), "got: {err}");
    assert!(
        !err.contains("Zq7distinctiveValue"),
        "the value is echoed: {err}"
    );
    assert!(err.contains("line 1"), "where it failed is kept: {err}");

    let err = expect_err(module(r#"{"audience":"a"}"#));
    assert!(
        err.contains("missing field `issuer`"),
        "the missing key is named: {err}"
    );
    let err = expect_err(module(r#"{"issuer":"i","audience":"a","isuer":"x"}"#));
    assert!(
        err.contains("unknown field `isuer`"),
        "the unknown key is named: {err}"
    );
}
