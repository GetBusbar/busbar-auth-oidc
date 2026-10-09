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
