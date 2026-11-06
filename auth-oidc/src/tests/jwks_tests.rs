// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The JWKS model's parse and key selection: an empty set withdraws all keys, keys are found by kid.

use super::*;

fn set(body: &str) -> JwkSet {
    JwkSet::parse(body).unwrap()
}

/// A successful empty JWKS withdraws every key; a missing keys member is malformed.
#[test]
fn an_empty_key_set_is_an_authoritative_success() {
    let keys = JwkSet::parse(r#"{"keys":[]}"#).expect("an explicit empty set is valid");
    assert!(keys.keys.is_empty());

    assert!(JwkSet::parse(r#"{}"#).is_err());

    assert!(JwkSet::parse(
        r#"{"keys":[{"kty":"EC","kid":"a","crv":"P-256","x":"AAAA","y":"BBBB"}]}"#
    )
    .is_ok());
}

#[test]
fn find_all_matches_by_kid() {
    let s = set(r#"{"keys":[
            {"kty":"EC","kid":"a","crv":"P-256","x":"AAAA","y":"BBBB"},
            {"kty":"EC","kid":"b","crv":"P-256","x":"CCCC","y":"DDDD"}
        ]}"#);
    let found: Vec<_> = s.find_all("a").collect();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].kid.as_deref(), Some("a"));
}

/// A non-empty queried `kid` that matches NO key must never fall through to a keyless
#[test]
fn find_all_does_not_fall_back_to_a_keyless_key_for_a_nonempty_unmatched_kid() {
    let s = set(r#"{"keys":[
            {"kty":"EC","kid":"real-kid","crv":"P-256","x":"AAAA","y":"BBBB"},
            {"kty":"EC","crv":"P-256","x":"CCCC","y":"DDDD"}
        ]}"#);
    let found: Vec<_> = s.find_all("no-such-kid").collect();
    assert!(
        found.is_empty(),
        "a nonempty unmatched kid must not match the keyless key in the set, got {} matches",
        found.len()
    );
}

/// The mirror case: an EMPTY queried kid (a keyless JWT header) DOES match a keyless key.
#[test]
fn find_all_matches_a_keyless_key_for_an_empty_queried_kid() {
    let s = set(r#"{"keys":[
            {"kty":"EC","kid":"real-kid","crv":"P-256","x":"AAAA","y":"BBBB"},
            {"kty":"EC","crv":"P-256","x":"CCCC","y":"DDDD"}
        ]}"#);
    let found: Vec<_> = s.find_all("").collect();
    assert_eq!(found.len(), 1);
    assert!(found[0].kid.is_none());
}

/// A kid-less ES256 token selects the ONE key that can verify it: an EC key on another curve
/// (which `verify_signature` refuses for ES256) does not make the selection ambiguous.
#[test]
fn a_kidless_es256_token_selects_the_one_p256_key_beside_another_curve() {
    let s = set(r#"{"keys":[
        {"kty":"EC","crv":"P-256","x":"AAAA","y":"BBBB"},
        {"kty":"EC","crv":"P-384","x":"CCCC","y":"DDDD"}
    ]}"#);
    let selected = s.select("", Some("ES256"));
    assert_eq!(selected.len(), 1, "the one P-256 key");
    assert_eq!(selected[0].crv.as_deref(), Some("P-256"));
    assert!(!s.keys[1].signs("ES256"), "a P-384 key cannot verify ES256");
}

/// A document whose every entry was skipped (here: no `kty`) says so, with the count, rather than
/// claiming it carries no keys at all.
#[test]
fn a_jwks_document_whose_every_entry_is_skipped_names_the_count() {
    let s = set(r#"{"keys":[
        {"kid":"no-kty"},
        {"kty":"EC","kid":"a","crv":"P-256","x":"AAAA","y":"BBBB"}
    ]}"#);
    assert_eq!(s.keys.len(), 1);
    assert_eq!(s.keys[0].kid.as_deref(), Some("a"));
    let err = JwkSet::parse(r#"{"keys":[{"kid":"no-kty"}]}"#).expect_err("nothing usable");
    assert!(
        err.contains("no keys") && err.contains("1 entries"),
        "{err}"
    );
}

/// RFC 7517 §5: a JWK Set is a JSON object whose `keys` are JWK objects. An entry that is not an
/// object is skipped (a serde derive would read a key from an array's elements in field order),
/// and a document that is not an object is refused. Object entries load as before.
#[test]
fn a_jwks_entry_or_document_that_is_not_a_json_object_is_not_read_as_keys() {
    let s = set(r#"{"keys":[
        ["EC","array-kid",null,null,"P-256","AAAA","BBBB"],
        "EC", 7, null, true,
        {"kty":"EC","kid":"a","crv":"P-256","x":"AAAA","y":"BBBB"}
    ]}"#);
    assert_eq!(s.keys.len(), 1);
    assert_eq!(s.keys[0].kid.as_deref(), Some("a"));
    let err = JwkSet::parse(r#"{"keys":[["EC","array-kid",null,null,"P-256","AAAA","BBBB"]]}"#)
        .expect_err("an array entry is no key");
    assert!(err.contains("1 entries"), "{err}");
    for doc in [
        r#"[[{"kty":"EC","kid":"a","crv":"P-256","x":"AAAA","y":"BBBB"}]]"#,
        r#""keys""#,
        "",
    ] {
        let err = JwkSet::parse(doc).expect_err("not an object");
        assert!(err.starts_with("invalid JWKS document"), "{err}");
    }
    let s = set(" \n\t{\"keys\":[{\"kty\":\"EC\",\"kid\":\"a\",\"crv\":\"P-256\",\"x\":\"AAAA\",\"y\":\"BBBB\"}]}");
    assert_eq!(s.keys.len(), 1);
}

/// RFC 7518 sections 6.2.1.2 and 6.2.1.3: a P-256 JWK's `x` and `y` are each exactly 32 octets. A
/// 65-byte concatenation of a 31-byte `x` and a 33-byte `y` is not a key.
#[test]
fn an_ec_jwk_with_a_coordinate_that_is_not_32_bytes_is_unusable() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    let jwk = |x: usize, y: usize| -> Jwk {
        serde_json::from_value(serde_json::json!({
            "kty": "EC", "crv": "P-256", "kid": "k",
            "x": URL_SAFE_NO_PAD.encode(vec![7u8; x]),
            "y": URL_SAFE_NO_PAD.encode(vec![9u8; y]),
        }))
        .unwrap()
    };
    assert!(matches!(
        KeyMaterial::from_jwk(&jwk(32, 32)),
        KeyMaterial::Ec { .. }
    ));
    for (x, y) in [(31, 33), (33, 31), (32, 33), (31, 32)] {
        let m = KeyMaterial::from_jwk(&jwk(x, y));
        assert!(
            matches!(&m, KeyMaterial::Unusable(e) if e.contains("32")),
            "x={x} y={y}: {m:?}"
        );
    }
}

#[test]
fn an_rsa_key_without_an_exponent_is_unusable_and_says_so() {
    let s = set(r#"{"keys":[{"kty":"RSA","kid":"r","n":"AQAB"}]}"#);
    match s.keys[0].material() {
        KeyMaterial::Unusable(msg) => assert_eq!(msg, "JWKS key missing RSA exponent e"),
        other => panic!("expected Unusable, got {other:?}"),
    }
    let bad = set(r#"{"keys":[{"kty":"RSA","kid":"r","n":"AQAB","e":"!!"}]}"#);
    match bad.keys[0].material() {
        KeyMaterial::Unusable(msg) => {
            assert_eq!(msg, "JWKS key RSA exponent e is not base64url")
        }
        other => panic!("expected Unusable, got {other:?}"),
    }
}

#[test]
fn an_ec_key_without_a_y_coordinate_is_unusable_and_says_so() {
    let s = set(r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"e","x":"AAAA"}]}"#);
    match s.keys[0].material() {
        KeyMaterial::Unusable(msg) => assert_eq!(msg, "JWKS key missing EC coordinate y"),
        other => panic!("expected Unusable, got {other:?}"),
    }
}

#[test]
fn a_key_signs_only_the_algorithms_busbar_supports() {
    let s = set(r#"{"keys":[
        {"kty":"RSA","n":"AQAB","e":"AQAB"},
        {"kty":"EC","crv":"P-256","x":"AAAA","y":"BBBB"}
    ]}"#);
    for key in &s.keys {
        assert!(!key.signs("HS256"), "HMAC is never accepted");
        assert!(!key.signs("none"));
    }
    assert!(s.keys[0].signs("RS256") && !s.keys[0].signs("ES256"));
    assert!(s.keys[1].signs("ES256") && !s.keys[1].signs("RS256"));
}
