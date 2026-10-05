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

#[test]
fn an_explicit_http_jwks_url_is_refused_at_open() {
    // OIDC-5 (owner-approved 2026-09-30): every request is https-only, so an http `jwks_url` would
    // open and then reject every token. It is refused at open, naming the field.
    let err = expect_err(module(
        r#"{"issuer":"https://issuer.invalid.example","audience":"api://busbar-client",
            "jwks_url":"http://issuer.invalid.example/keys"}"#,
    ));
    assert!(
        err.contains("jwks_url"),
        "the error must name jwks_url: {err}"
    );
    assert!(
        err.contains("https"),
        "the error must say https is required: {err}"
    );
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
