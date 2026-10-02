// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The discovery document's single flight: the claimer pends on ONE fetch, a caller arriving
//! meanwhile waits and takes the claimer's document, and the boot-time `ready` resolution runs it
//! (an explicit `jwks_url` skips it).

use super::*;
use crate::script::{ready, ticket, Idp, ME};
use crate::{OidcModule, Step};

const ISSUER: &str = "https://idp.example/v2.0";

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
    assert!(matches!(d.document(&c, now, &mut a), Step::Ready(Ok(_))));
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
        0,
        "an explicit jwks_url never fetches discovery"
    );

    let m = OidcModule::new(&cfg(None));
    assert_eq!(ready(m.ready(now, &mut idp.at_once(Some(ME)))), Ok(()));
    assert_eq!(idp.calls(), 1);

    let down = Idp::answering(Err("connection refused".into()));
    let m = OidcModule::new(&cfg(None));
    let err = ready(m.ready(now, &mut down.at_once(Some(ME)))).unwrap_err();
    assert!(
        err.starts_with("OIDC discovery fetch failed"),
        "1.5.5's boot refusal: {err}"
    );
}
