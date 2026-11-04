// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! JWT header parsing and the signature verifier's key-policy checks, ahead of any key material.

use super::*;

/// A JWT header field of the wrong type is refused WITHOUT echoing its value: the header comes
#[test]
fn a_mistyped_header_field_is_refused_without_echoing_it() {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","kid":12345678}"#);
    let body = URL_SAFE_NO_PAD.encode(b"{}");
    let Err(err) = split(&format!("{header}.{body}.c2ln")) else {
        panic!("a mistyped kid is refused");
    };
    assert!(err.starts_with("malformed JWT header"), "got: {err}");
    assert!(!err.contains("12345678"), "the value is echoed: {err}");
}

/// RFC 7517 §4.2: a JWK explicitly marked `"use": "enc"` (encryption-only — e.g. published
#[test]
fn verify_signature_rejects_an_encryption_only_key() {
    let key = Jwk {
        kty: "EC".to_string(),
        kid: None,
        n: None,
        e: None,
        crv: Some("P-256".to_string()),
        x: None,
        y: None,
        key_use: Some("enc".to_string()),
        alg: None,
        key_ops: None,
        decoded: std::sync::OnceLock::new(),
    };
    let parts = Parts {
        header: Header {
            alg: "ES256".to_string(),
            kid: None,
            crit: None,
        },
        payload: Vec::new(),
        signature: Vec::new(),
        signing_input: "header.payload",
    };

    let err = verify_signature(&parts, &key).unwrap_err();
    assert!(
        err.contains("enc"),
        "expected a use-policy rejection mentioning 'enc', got: {err}"
    );
    assert!(
        !err.contains("coordinate"),
        "rejection must come from the use-policy check, not from missing key material: {err}"
    );
}

/// The RS256/RSA-kty guard, mirroring `verify_signature_permits_a_signing_key_to_reach_key_material_checks`
#[test]
fn verify_signature_permits_a_matching_rsa_key_to_reach_key_material_checks() {
    let key = Jwk {
        kty: "RSA".to_string(),
        kid: None,
        n: None,
        e: None,
        crv: None,
        x: None,
        y: None,
        key_use: Some("sig".to_string()),
        alg: None,
        key_ops: None,
        decoded: std::sync::OnceLock::new(),
    };
    let parts = Parts {
        header: Header {
            alg: "RS256".to_string(),
            kid: None,
            crit: None,
        },
        payload: Vec::new(),
        signature: Vec::new(),
        signing_input: "header.payload",
    };

    let err = verify_signature(&parts, &key).unwrap_err();
    assert!(
        err.contains("RSA modulus"),
        "an RS256 token against a real RSA key must reach key-material validation, not be \
         rejected by the kty check: {err}"
    );
    assert!(
        !err.contains("alg/key-type mismatch"),
        "must not be rejected as an alg/kty mismatch when the kty genuinely is RSA: {err}"
    );
}

/// A `"use": "sig"` key (the ordinary case) passes the use-policy check — it reaches (and fails
#[test]
fn verify_signature_permits_a_signing_key_to_reach_key_material_checks() {
    let key = Jwk {
        kty: "EC".to_string(),
        kid: None,
        n: None,
        e: None,
        crv: Some("P-256".to_string()),
        x: None,
        y: None,
        key_use: Some("sig".to_string()),
        alg: None,
        key_ops: None,
        decoded: std::sync::OnceLock::new(),
    };
    let parts = Parts {
        header: Header {
            alg: "ES256".to_string(),
            kid: None,
            crit: None,
        },
        payload: Vec::new(),
        signature: Vec::new(),
        signing_input: "header.payload",
    };

    let err = verify_signature(&parts, &key).unwrap_err();
    assert!(
        err.contains("coordinate"),
        "a sig-use key must reach key-material validation, not be blocked by the use check: {err}"
    );
}
