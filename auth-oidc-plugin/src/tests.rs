// ── unit tests for THIS crate's own responsibility: adapting the engine's JSON config into a real
// OIDC module. Hermetic — no network. The underlying verification logic (JWKS/JWT/claims) is
// `busbar-auth-oidc`'s own job and is covered by that crate's own tests; these only cover what `open`
// itself does with the config before handing off. The real over-the-ABI, real-network-fixture success
// path lives in this crate's own `tests/e2e.rs`.
use super::open;
use busbar_api::{AuthPlugin, BeginLogin, LoginOutcome};

/// `open` returns `Result<Box<dyn AuthPlugin>, String>`, and `dyn AuthPlugin` is not `Debug` (it
/// carries no such bound), so the standard `.unwrap_err()` doesn't compile here. This is the
/// equivalent for this specific `Result` shape.
fn expect_err(result: Result<Box<dyn AuthPlugin>, String>) -> String {
    match result {
        Ok(_) => panic!("expected open() to fail, but it succeeded"),
        Err(e) => e,
    }
}

#[test]
fn empty_config_is_rejected() {
    let err = expect_err(open(""));
    assert!(
        err.contains("config"),
        "error should name that config is required: {err}"
    );
}

#[test]
fn whitespace_only_config_is_rejected() {
    let err = expect_err(open("   \n\t  "));
    assert!(err.contains("config"), "got: {err}");
}

#[test]
fn malformed_json_is_rejected() {
    let err = expect_err(open("{ this is not json"));
    assert!(
        err.contains("invalid oidc plugin config"),
        "error should name the config as invalid: {err}"
    );
}

#[test]
fn config_missing_issuer_is_rejected() {
    // `issuer` has no `#[serde(default)]` in `OidcConfig` — it is required. `deny_unknown_fields`
    // is also on, so this proves the missing-required-field path specifically, not a stray typo.
    let err = expect_err(open(r#"{"audience":"api://busbar"}"#));
    assert!(err.contains("invalid oidc plugin config"), "got: {err}");
}

#[test]
fn config_missing_audience_is_rejected() {
    let err = expect_err(open(r#"{"issuer":"https://idp.example/v2.0"}"#));
    assert!(err.contains("invalid oidc plugin config"), "got: {err}");
}

#[test]
fn unknown_config_field_is_rejected() {
    // `OidcConfig` is `#[serde(deny_unknown_fields)]` — a typo'd or stray operator key must fail
    // loud at boot, not be silently ignored.
    let err = expect_err(open(
        r#"{"issuer":"https://idp.example/v2.0","audience":"a","jwks_url":"https://idp.example/keys","bogus_field":true}"#,
    ));
    assert!(err.contains("invalid oidc plugin config"), "got: {err}");
}

#[test]
fn explicit_jwks_url_skips_discovery_and_open_succeeds_without_network() {
    // `jwks_url` is present, so `resolve_jwks_url` returns it immediately without ever calling
    // out — discovery is skipped entirely. `open()` itself only builds HTTP clients and resolves
    // the JWKS url; it does NOT eagerly fetch the JWKS document (that's lazy, on first
    // `authenticate()`, via `JwksCache`). So this succeeds fully hermetically, proving the
    // "explicit jwks_url" success-shaped path with zero network I/O, even though the issuer host
    // below does not exist. The login endpoints are ALSO given explicitly so `resolve_login_endpoints`
    // short-circuits without a discovery fetch — keeping this hermetic now that `open()` resolves them.
    let cfg = r#"{
        "issuer": "https://issuer.invalid.example",
        "audience": "api://busbar-client",
        "jwks_url": "https://issuer.invalid.example/keys",
        "authorization_endpoint": "https://issuer.invalid.example/authorize",
        "token_endpoint": "https://issuer.invalid.example/token"
    }"#;
    let module = open(cfg).expect("explicit jwks_url must skip discovery and succeed");
    assert_eq!(module.name(), "oidc");
    assert!(module.cacheable());
}

#[test]
fn open_yields_login_capable_module_whose_begin_login_returns_authorize() {
    // The plugin is now exported via `export_login_plugin!`, so `open()` yields a login-capable
    // `Box<dyn AuthPlugin>` (AuthModule + LoginModule), NOT a verify-only handle. With an explicit
    // `authorization_endpoint`, `begin_login` must drive the browser flow and return an Authorize URL
    // (a plain `export_auth_plugin!` verify-only handle would mask this and `Reject`). Explicit
    // jwks_url + login endpoints keep this hermetic (no discovery fetch).
    let cfg = r#"{
        "issuer": "https://issuer.invalid.example",
        "audience": "api://busbar-client",
        "jwks_url": "https://issuer.invalid.example/keys",
        "authorization_endpoint": "https://issuer.invalid.example/authorize",
        "token_endpoint": "https://issuer.invalid.example/token"
    }"#;
    let module = open(cfg).expect("open must succeed with explicit endpoints");

    let begin = BeginLogin {
        redirect_uri: "https://busbar.test/auth/token".to_string(),
        state: "st".to_string(),
        code_challenge: "ch".to_string(),
        nonce: Some("nc".to_string()),
        scopes: vec![],
    };
    match module.begin_login(&begin) {
        LoginOutcome::Authorize(url) => {
            assert!(
                url.starts_with("https://issuer.invalid.example/authorize?"),
                "begin_login must redirect to the configured authorize endpoint, got: {url}"
            );
        }
        other => panic!("expected Authorize from a login-capable module, got {other:?}"),
    }
}

#[test]
fn missing_jwks_url_with_malformed_issuer_fails_fast_without_network() {
    // No `jwks_url` ⇒ discovery is attempted from `issuer`. An issuer with no URL scheme produces
    // a discovery URL reqwest cannot even parse — the failure is a client-side URL-parse error
    // raised before any socket/DNS activity, so this is still hermetic (no real network access),
    // while genuinely exercising the "discovery required, resolution fails" path.
    let cfg = r#"{
        "issuer": "not-a-valid-url-at-all",
        "audience": "api://busbar-client"
    }"#;
    let err = expect_err(open(cfg));
    assert!(
        err.contains("OIDC discovery fetch failed"),
        "expected a descriptive discovery-failure message naming the failed step, got: {err}"
    );
}
