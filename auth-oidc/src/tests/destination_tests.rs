// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHERE THE MODULE MAY GO (security.md "The destination guard": "a provider upstream or identity

use crate::door::{DIAG_DESTINATION_REFUSED, DIAG_NAMES, STATEMENT};
use crate::fetch::guard_refusal;
use crate::script::{ready, Idp, ME};
use crate::{OidcConfig, OidcModule};

use std::time::Instant;

#[test]
fn discovered_endpoints_refuse_controls_fragments_and_loopback_lookalikes() {
    for field in ["jwks_uri", "token_endpoint", "authorization_endpoint"] {
        for url in [
            "http://127.0.0.1.evil.example/x",
            "http://localhost.evil.example/x",
            "http://127.0.0.1@evil.example/x",
            "https://idp.example/x\r\nInjected: yes",
        ] {
            assert!(
                crate::discovered_secure(field, field, url).is_err(),
                "{field}: {url:?}"
            );
        }
        for url in [
            "http://localhost/x",
            "http://[::1]/x",
            "http://local.localhost/x",
            "https://idp.example/x",
        ] {
            assert!(
                crate::discovered_secure(field, field, url).is_ok(),
                "{field}: {url}"
            );
        }
    }
    assert!(crate::discovered_secure(
        "authorization_endpoint",
        "authorization_endpoint",
        "https://idp.example/authorize#fragment"
    )
    .is_err());
}

const ISSUER: &str = "https://login.example.com/tenant/v2.0";

fn cfg() -> OidcConfig {
    serde_json::from_value(serde_json::json!({
        "issuer": ISSUER,
        "audience": "api://a",
    }))
    .unwrap()
}

fn doc(field: &str, url: &str) -> String {
    serde_json::json!({ "issuer": ISSUER, field: url }).to_string()
}

#[test]
fn a_google_style_discovery_on_public_hosts_loads() {
    let issuer = "https://accounts.google.com";
    let doc = serde_json::json!({
        "issuer": issuer,
        "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
        "token_endpoint": "https://oauth2.googleapis.com/token",
        "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
    })
    .to_string();
    let c: OidcConfig =
        serde_json::from_value(serde_json::json!({ "issuer": issuer, "audience": "a" })).unwrap();
    let idp = Idp::new(doc);
    let m = OidcModule::new(&c);
    assert_eq!(
        ready(m.jwks_url(Instant::now(), &mut idp.at_once(Some(ME)))).as_deref(),
        Ok("https://www.googleapis.com/oauth2/v3/certs")
    );
    assert_eq!(
        ready(m.token_endpoint(Instant::now(), &mut idp.at_once(Some(ME)))),
        Ok(Some("https://oauth2.googleapis.com/token".to_string()))
    );
    assert!(ready(m.ready(Instant::now(), &mut idp.at_once(Some(ME)))).is_ok());
    assert!(idp.refusals().is_empty(), "{:?}", idp.refusals());
}

/// The module passes a discovered HTTPS key URL to the host unchanged, including off-host
#[test]
fn a_discovered_jwks_uri_reaches_the_guard_with_a_path_free_refusal() {
    for jwks_uri in [
        "https://10.0.0.5/keys",
        "https://169.254.169.254/latest/meta-data",
        "https://127.0.0.1:8443/keys",
        "https://internal.corp.example/keys",
    ] {
        let idp = Idp::new(doc("jwks_uri", jwks_uri));
        let m = OidcModule::new(&cfg());

        assert_eq!(
            ready(m.jwks_url(Instant::now(), &mut idp.at_once(Some(ME)))).as_deref(),
            Ok(jwks_uri)
        );
        let host = url::Url::parse(jwks_uri).unwrap();
        let host = host.host_str().unwrap();
        let why = guard_refusal(jwks_uri);
        assert!(why.contains(host), "{jwks_uri}: names the host: {why}");
        assert!(
            why.contains("allow_destinations"),
            "{jwks_uri}: names the rule: {why}"
        );
        assert!(
            !why.contains("/keys") && !why.contains("meta-data"),
            "{why}"
        );
    }
}

/// Discovered token endpoints retain their module scheme check and host-guard refusal text.
#[test]
fn a_discovered_token_endpoint_preserves_host_guard_and_scheme_boundaries() {
    let why = guard_refusal("https://192.168.1.10/token");
    assert!(
        why.contains("192.168.1.10") && !why.contains("/token"),
        "{why}"
    );
    for (token_endpoint, host) in [
        ("http://attacker.example/token", "attacker.example"),
        ("http://192.168.1.10/token", "192.168.1.10"),
        ("http://login.example.com/token", "login.example.com"),
    ] {
        let idp = Idp::new(doc("token_endpoint", token_endpoint));
        let m = OidcModule::new(&cfg());
        let err = ready(m.token_endpoint(Instant::now(), &mut idp.at_once(Some(ME))))
            .expect_err(token_endpoint);
        assert!(
            err.contains(host),
            "{token_endpoint}: names the host: {err}"
        );
        assert!(err.contains("token_endpoint"), "{token_endpoint}: {err}");
        assert!(
            err.contains("https"),
            "{token_endpoint}: names the rule: {err}"
        );
        assert!(
            !err.contains("/token"),
            "{token_endpoint}: the URL's path is never repeated: {err}"
        );
    }
    for public in [
        "https://login.example.com/oauth2/token",
        "https://sso.other.example:8443/token",
    ] {
        let idp = Idp::new(doc("token_endpoint", public));
        let m = OidcModule::new(&cfg());
        assert_eq!(
            ready(m.token_endpoint(Instant::now(), &mut idp.at_once(Some(ME)))),
            Ok(Some(public.to_string()))
        );
    }
    let idp = Idp::new(doc(
        "token_endpoint",
        "https://login.example.com/oauth2/token",
    ));
    let mut configured = cfg();
    configured.token_endpoint = Some("https://sso.other.example/token".to_string());
    let m = OidcModule::new(&configured);
    assert_eq!(
        ready(m.token_endpoint(Instant::now(), &mut idp.at_once(Some(ME)))),
        Ok(Some("https://sso.other.example/token".to_string()))
    );
}

/// A refused IdP fetch is AUDITED. The Statement declares `BUSBAR-4031` (a
#[test]
fn a_refused_idp_fetch_is_audited() {
    assert_eq!(STATEMENT.diag_ids_len(), DIAG_NAMES.len());
    assert_eq!(
        DIAG_NAMES.get(DIAG_DESTINATION_REFUSED as usize).copied(),
        Some("BUSBAR-4031")
    );

    let idp = Idp::new(doc("jwks_uri", "http://10.0.0.5/secret-path?tenant=x"));
    let m = OidcModule::new(&cfg());
    let mut io = idp.at_once(Some(ME));
    assert!(ready(m.jwks_url(Instant::now(), &mut io)).is_err());
    let reported = idp.refusals();
    assert_eq!(reported.len(), 1, "{reported:?}");
    let why = &reported[0];
    assert!(why.contains("10.0.0.5"), "{why}");
    assert!(why.contains("https"), "{why}");
    assert!(
        !why.contains("secret-path") && !why.contains("tenant=x"),
        "{why}"
    );
    assert!(m.first_report(why), "the first op meeting it raises it");
    assert!(
        !m.first_report(why),
        "a later op meeting the same refusal raises nothing"
    );
    let guard = guard_refusal("https://10.0.0.5/secret-path?tenant=x");
    assert!(guard.starts_with(crate::fetch::REFUSED), "{guard}");
    assert!(
        !guard.contains("secret-path") && !guard.contains("tenant=x"),
        "{guard}"
    );
}

#[test]
fn a_discovered_plain_http_authorization_endpoint_is_refused() {
    let idp = Idp::new(doc(
        "authorization_endpoint",
        "http://login.example.com/authorize?p=x",
    ));
    let m = OidcModule::new(&cfg());
    let answered = ready(m.authorization_endpoint(Instant::now(), &mut idp.at_once(Some(ME))));
    let Err(why) = answered else {
        panic!("a plain http authorize URL on a public host is refused, got {answered:?}");
    };
    assert!(
        why.contains("login.example.com") && why.contains("https"),
        "{why}"
    );
    assert_eq!(idp.refusals().len(), 1, "{:?}", idp.refusals());

    for url in [
        "https://login.example.com/authorize",
        "http://127.0.0.1:8080/authorize",
    ] {
        let idp = Idp::new(doc("authorization_endpoint", url));
        let m = OidcModule::new(&cfg());
        assert_eq!(
            ready(m.authorization_endpoint(Instant::now(), &mut idp.at_once(Some(ME)))),
            Ok(Some(url.to_string()))
        );
    }
}
