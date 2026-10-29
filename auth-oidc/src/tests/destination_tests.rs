// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHERE THE MODULE MAY GO (security.md "The destination guard": "a provider upstream or identity
//! provider ... is refused when it is, or resolves to, a private ... address, unless
//! `allow_destinations` names it"; OIDC Discovery 1.0 §3/§4.3; RFC 9700 §4).
//!
//! * A DISCOVERED `jwks_uri` or `token_endpoint` may be on ANY host (OIDC Discovery ties the
//!   document's `issuer`, not its endpoints: Google serves its keys from `www.googleapis.com` and
//!   its token endpoint from `oauth2.googleapis.com`). It must be https (plain http only to a
//!   loopback host), else it is refused before a request is made, naming its host and the rule.
//! * WHERE it may go is the destination guard's: every need the module dials on is judged in a
//!   class the guard refuses a private, loopback or link-local address in unless
//!   `advanced.allow_destinations` names it, and never in the operator-infrastructure class (which
//!   admits them with no entry). Cloud metadata is refused in every such class. So a discovered
//!   endpoint off the issuer's host on a private address is refused, by the guard.
//! * Every refusal (the module's own, and the guard's) is reported once, as the declared
//!   diagnostic the host audits, naming the host and the rule and never the URL's path or query.

use crate::door::{DIAG_DESTINATION_REFUSED, DIAG_NAMES, STATEMENT};
use crate::fetch::{guard_refusal, on, NEEDS, NEED_DISCOVERY, NEED_JWKS, NEED_TOKEN};
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

/// RED (lead decision on item 3: the issuer-host tie was wrong): a GOOGLE-STYLE discovery
/// document, whose key set and token endpoint are on public hosts other than the issuer's, LOADS:
/// both endpoints resolve as the document names them, and nothing is refused. Before: both were
/// refused as off the issuer's host.
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

/// A DISCOVERED `jwks_uri` OFF THE ISSUER'S HOST ON A PRIVATE, LOOPBACK OR METADATA ADDRESS IS
/// REFUSED, by the destination guard: the module hands it to the JWKS need alone (never pinned,
/// never operator infrastructure), whose class refuses such an address unless
/// `advanced.allow_destinations` names it and refuses cloud metadata always; the guard's refusal
/// is reported naming the host and the rule, never the URL's path. The security property of the
/// earlier host tie stays: only the public (or allowlisted) off-host case now goes.
#[test]
fn a_discovered_jwks_uri_off_the_issuer_host_on_a_private_address_is_refused() {
    for anchored in [true, false] {
        let n = &NEEDS[on(NEED_JWKS, anchored) as usize];
        assert!(refuses_private_unless_allowlisted(n), "anchored {anchored}");
        assert_eq!(
            n.egress_class, EGRESS_OPEN_WEB,
            "metadata refused, https only"
        );
    }
    for jwks_uri in [
        "https://10.0.0.5/keys",
        "https://169.254.169.254/latest/meta-data",
        "https://127.0.0.1:8443/keys",
        "https://internal.corp.example/keys",
    ] {
        let idp = Idp::new(doc("jwks_uri", jwks_uri));
        let m = OidcModule::new(&cfg());
        // Handed to the JWKS need as written: the guard, not the module, judges the address.
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

/// A DISCOVERED `token_endpoint` OFF THE ISSUER'S HOST: on a PRIVATE address it is refused by the
/// guard (the token need is in the default class, named per request, so never lifted to operator
/// infrastructure); over plain http off loopback it is refused by the module before any request,
/// naming the host and the rule; on a public host over https it goes. A CONFIGURED
/// `token_endpoint` is the operator's and is used as written.
#[test]
fn a_discovered_token_endpoint_off_the_issuer_host_on_a_private_address_is_refused() {
    for anchored in [true, false] {
        let n = &NEEDS[on(NEED_TOKEN, anchored) as usize];
        assert!(refuses_private_unless_allowlisted(n), "anchored {anchored}");
    }
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

/// A refused IdP fetch is AUDITED. The Statement declares `OIDC_IDP_DESTINATION_REFUSED` (a
/// declared diagnostic the host audits on the plugin's behalf), the module's refusal reaches the
/// op's request seam (`Fetch::refused`, which the door raises as that diagnostic) naming the host
/// and the rule and never the URL's path, and it is reported ONCE per module (a refusal every request
/// meets is not a flood). The guard's refusal is worded the same way ([`guard_refusal`]).
#[test]
fn a_refused_idp_fetch_is_audited() {
    assert_eq!(STATEMENT.diag_ids_len(), DIAG_NAMES.len());
    assert_eq!(
        DIAG_NAMES.get(DIAG_DESTINATION_REFUSED as usize).copied(),
        Some("OIDC_IDP_DESTINATION_REFUSED")
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
