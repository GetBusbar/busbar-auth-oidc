// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHERE THE MODULE MAY GO (security.md "The destination guard": "a provider upstream or identity
//! provider ... is refused when it is, or resolves to, a private ... address, unless
//! `allow_destinations` names it"; RFC 8414 §3.3 / OIDC Discovery 1.0 §4.3; RFC 9700 §4.
//!
//! * A DISCOVERED `jwks_uri` or `token_endpoint` is https on the issuer's own host and port (plain
//!   http only to a loopback host); any other is refused before a request is made, naming its host
//!   and the rule. An operator who means another host configures `jwks_url` / `token_endpoint`.
//! * Every need the module dials on is judged in a class the destination guard refuses a private,
//!   loopback or link-local address in unless `advanced.allow_destinations` names it, and never in
//!   the operator-infrastructure class (which admits them with no entry). Cloud metadata is refused
//!   in every such class.
//! * Every refusal is reported once, as the declared diagnostic the host audits, naming the host
//!   and the rule and never the URL's path or query.

use crate::door::{DIAG_DESTINATION_REFUSED, DIAG_NAMES, STATEMENT};
use crate::fetch::{on, NEEDS, NEED_DISCOVERY, NEED_JWKS, NEED_TOKEN};
use crate::script::{ready, Idp, ME};
use crate::{OidcConfig, OidcModule};
use busbar_contract::abi::host::conn::connector::{
    Need, EGRESS_DEFAULT, EGRESS_OPEN_WEB, EGRESS_PROVIDER,
};
use std::time::Instant;

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

/// The destination guard's default policy at the busbar pin (busbar-core-connector `guard.rs`,
/// `PRIVATE_REFUSED_IN` and `LIFTED_WHEN_CONFIGURED`), word for word: a private, loopback or
/// link-local address is refused unless allowlisted in the default, provider and open-web classes,
/// and a need in the DEFAULT class whose config names its target (`target_from`) is lifted to
/// operator infrastructure, which admits them. The module cannot link the connector.
fn refuses_private_unless_allowlisted(need: &Need) -> bool {
    let refusing = [EGRESS_DEFAULT, EGRESS_PROVIDER, EGRESS_OPEN_WEB].contains(&need.egress_class);
    let lifted = need.egress_class == EGRESS_DEFAULT && need.target_from.len != 0;
    refusing && !lifted
}

/// RED: every need the module dials on (discovery, the JWKS, the token exchange, anchored or not)
/// is judged where a private, loopback or link-local IdP address is refused unless
/// `advanced.allow_destinations` names it. Before: every one was operator-infrastructure, so a
/// discovery document could steer the key or token fetch to any internal address.
#[test]
fn every_idp_need_refuses_a_private_destination_unless_allowlisted() {
    for anchored in [true, false] {
        for need in [NEED_DISCOVERY, NEED_JWKS, NEED_TOKEN] {
            let n = &NEEDS[on(need, anchored) as usize];
            assert!(
                refuses_private_unless_allowlisted(n),
                "need {need} (anchored {anchored}) is class {} with target_from len {}",
                n.egress_class,
                n.target_from.len
            );
        }
    }
}

/// RED: a discovered `jwks_uri` on a private host is refused before any request is made to it,
/// naming the host and the rule: the issuer's document cannot point the key fetch at an internal
/// address. Before: the module fetched whatever `jwks_uri` the document named.
#[test]
fn a_discovered_jwks_uri_on_a_private_host_is_refused() {
    for jwks_uri in [
        "https://10.0.0.5/keys",
        "https://169.254.169.254/latest/meta-data",
        "https://127.0.0.1:8443/keys",
        "https://internal.corp.example/keys",
    ] {
        let idp = Idp::new(doc("jwks_uri", jwks_uri));
        let m = OidcModule::new(&cfg());
        let err =
            ready(m.jwks_url(Instant::now(), &mut idp.at_once(Some(ME)))).expect_err(jwks_uri);
        let host = url::Url::parse(jwks_uri).unwrap();
        let host = host.host_str().unwrap();
        assert!(err.contains(host), "{jwks_uri}: names the host: {err}");
        assert!(
            err.contains("issuer's host"),
            "{jwks_uri}: names the rule: {err}"
        );
        assert!(
            err.contains("jwks_url"),
            "{jwks_uri}: names the way out: {err}"
        );
        assert_eq!(
            idp.calls(),
            1,
            "{jwks_uri}: only the discovery document is fetched"
        );
        // `ready` (boot) refuses with the same words, so boot names it.
        let m = OidcModule::new(&cfg());
        let booted = ready(m.ready(Instant::now(), &mut idp.at_once(Some(ME))));
        assert!(booted.is_err_and(|e| e.contains(host)), "{jwks_uri}");
    }
    // On the issuer's own host it is taken, and goes out on a need that refuses a private address
    // unless allowlisted (above).
    let idp = Idp::new(doc("jwks_uri", "https://login.example.com/tenant/keys"));
    let m = OidcModule::new(&cfg());
    assert_eq!(
        ready(m.jwks_url(Instant::now(), &mut idp.at_once(Some(ME)))).as_deref(),
        Ok("https://login.example.com/tenant/keys")
    );
}

/// RED: a discovered `token_endpoint` off the issuer's host (another host, another port, or plain
/// http) is refused, naming the host and the rule; one on the issuer's host is taken, and a
/// CONFIGURED `token_endpoint` is the operator's and is used as written. Before: the login's code
/// and client secret went to whatever `token_endpoint` the document named.
#[test]
fn a_discovered_token_endpoint_off_the_issuer_host_is_refused() {
    for (token_endpoint, host) in [
        ("https://attacker.example/token", "attacker.example"),
        ("https://login.example.com:8443/token", "login.example.com"),
        ("http://login.example.com/token", "login.example.com"),
        ("https://192.168.1.10/token", "192.168.1.10"),
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
            !err.contains("/token"),
            "{token_endpoint}: the URL's path is never repeated: {err}"
        );
    }
    let idp = Idp::new(doc(
        "token_endpoint",
        "https://login.example.com/oauth2/token",
    ));
    let m = OidcModule::new(&cfg());
    assert_eq!(
        ready(m.token_endpoint(Instant::now(), &mut idp.at_once(Some(ME)))),
        Ok(Some("https://login.example.com/oauth2/token".to_string()))
    );
    let mut configured = cfg();
    configured.token_endpoint = Some("https://sso.other.example/token".to_string());
    let m = OidcModule::new(&configured);
    assert_eq!(
        ready(m.token_endpoint(Instant::now(), &mut idp.at_once(Some(ME)))),
        Ok(Some("https://sso.other.example/token".to_string()))
    );
}

/// RED: a refused IdP fetch is AUDITED. The Statement declares `OIDC_IDP_DESTINATION_REFUSED` (a
/// declared diagnostic the host audits on the plugin's behalf), the refusal reaches the op's
/// request seam (`Fetch::refused`, which the door raises as that diagnostic) naming the host and the
/// rule and never the URL's path, and it is reported ONCE per module (a refusal every request meets
/// is not a flood).
#[test]
fn a_refused_idp_fetch_is_audited() {
    assert_eq!(STATEMENT.diag_ids_len(), DIAG_NAMES.len());
    assert_eq!(
        DIAG_NAMES.get(DIAG_DESTINATION_REFUSED as usize).copied(),
        Some("OIDC_IDP_DESTINATION_REFUSED")
    );

    let idp = Idp::new(doc("jwks_uri", "https://10.0.0.5/secret-path?tenant=x"));
    let m = OidcModule::new(&cfg());
    let mut io = idp.at_once(Some(ME));
    assert!(ready(m.jwks_url(Instant::now(), &mut io)).is_err());
    let reported = idp.refusals();
    assert_eq!(reported.len(), 1, "{reported:?}");
    let why = &reported[0];
    assert!(why.contains("10.0.0.5"), "{why}");
    assert!(why.contains("issuer's host"), "{why}");
    assert!(
        !why.contains("secret-path") && !why.contains("tenant=x"),
        "{why}"
    );
    assert!(m.first_report(why), "the first op meeting it raises it");
    assert!(
        !m.first_report(why),
        "a later op meeting the same refusal raises nothing"
    );
}
