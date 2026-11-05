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
