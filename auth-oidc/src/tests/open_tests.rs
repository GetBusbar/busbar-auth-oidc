// ── unit tests for THIS module's own responsibility: adapting the engine's JSON config into a real
// OIDC module. Hermetic — no network. Nothing is fetched at open; the discovery the first op makes
// is driven here through the scripted IdP (`crate::script`).
use super::module;
use crate::script::{ready, Idp, ME};
use crate::OidcModule;
use busbar_contract::auth::{BeginLogin, LoginOutcome};
use std::time::{Duration, Instant};

/// `module` answers `Result<OidcModule, String>`, and `OidcModule` is not `Debug`, so the standard
/// `.unwrap_err()` doesn't compile here. This is the equivalent for this specific `Result` shape.
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
        err.contains("config"),
        "error should name that config is required: {err}"
    );
}

#[test]
fn whitespace_only_config_is_rejected() {
    let err = expect_err(module("   \n\t  "));
    assert!(err.contains("config"), "got: {err}");
}

#[test]
fn malformed_json_is_rejected() {
    let err = expect_err(module("{ this is not json"));
    assert!(
        err.contains("invalid oidc plugin config"),
        "error should name the config as invalid: {err}"
    );
}

#[test]
fn config_missing_issuer_is_rejected() {
    // `issuer` has no `#[serde(default)]` in `OidcConfig` — it is required. `deny_unknown_fields`
    // is also on, so this proves the missing-required-field path specifically, not a stray typo.
    let err = expect_err(module(r#"{"audience":"api://busbar"}"#));
    assert!(err.contains("invalid oidc plugin config"), "got: {err}");
}

#[test]
fn config_missing_audience_is_rejected() {
    let err = expect_err(module(r#"{"issuer":"https://idp.example/v2.0"}"#));
    assert!(err.contains("invalid oidc plugin config"), "got: {err}");
}

#[test]
fn unknown_config_field_is_rejected() {
    // `OidcConfig` is `#[serde(deny_unknown_fields)]` — a typo'd or stray operator key must fail
    // loud at boot, not be silently ignored.
    let err = expect_err(module(
        r#"{"issuer":"https://idp.example/v2.0","audience":"a","jwks_url":"https://idp.example/keys","bogus_field":true}"#,
    ));
    assert!(err.contains("invalid oidc plugin config"), "got: {err}");
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
/// serves its key set on http://127.0.0.1), and `open` logs a WARNING naming `jwks_url` and the URL:
/// the key set is still only ever fetched over https, so the operator is told every token will be
/// rejected until it is an https URL. Loopback is 127.0.0.0/8, ::1, `localhost` and `*.localhost`
/// (RFC 6761), read off the parsed host, so a userinfo or a lookalike name cannot pass for it.
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
    // An https jwks_url opens with no warning at all.
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

/// RED: PLAIN HTTP ONLY FOR LOOPBACK (identity-providers.md: "plain http only for loopback"; RFC
/// 8414 / OIDC Discovery: the key set is fetched over TLS). A plain http `jwks_url` to a host that
/// is not loopback is REFUSED at `open` (and so at `--validate` and boot), naming `jwks_url`, the
/// host and the rule: signing keys over plain http can be substituted in transit. A private
/// address, a public name, a name that only starts like loopback, and a userinfo that dresses a
/// remote host as 127.0.0.1 are all remote hosts. Before: each opened with a warning (owner
/// 2026-10-20), superseded by the 1.6.0 security brief (item 3).
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
        assert!(err.contains(host), "{url}: names the host: {err}");
        assert!(err.contains("loopback"), "{url}: names the rule: {err}");
        assert!(
            !err.contains("/keys"),
            "{url}: the URL's path is never repeated: {err}"
        );
    }
}

/// THE SEAM, as implemented: `open` runs on no ticket with no connector, so it fetches nothing; a
/// config that needs discovery opens, and the first op that needs the document fetches it. Its
/// failure fails THAT op with 1.5.5's discovery text (1.5.5 refused boot with it).
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
        err.starts_with(
            "OIDC discovery fetch failed (https://issuer.invalid.example/.well-known/openid-configuration): \
             connection refused"
        ) && err.ends_with("; set jwks_url explicitly"),
        "1.5.5's discovery text: {err}"
    );
    assert_eq!(idp.calls(), 1);

    // Inside the retry bound (jwks_min_refetch_secs, 60s by default) the failure is answered
    // without asking again; past it the issuer is asked again.
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
    // OIDC-18: the discovered authorization/token endpoints must reach the live module, or every
    // discovery-configured deployment's login dead-ends.
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
        now,
        &mut idp.at_once(Some(ME)),
    ))
    .expect("discovered")
    .expect("a hop");
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
/// (`invalid type: string "..."`), and this error reaches `--validate` output and logs. The key a
/// missing or unknown field names is kept (it comes from the schema or is a key, not a value).
#[test]
fn a_mistyped_settings_value_is_refused_without_echoing_it() {
    let err = expect_err(module(
        r#"{"issuer":"https://i.test","audience":"a","jwks_ttl_secs":"Zq7distinctiveValue"}"#,
    ));
    assert!(err.contains("invalid oidc plugin config"), "got: {err}");
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
