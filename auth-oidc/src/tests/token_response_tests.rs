// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The token response reader: the members it reads match what a JSON decoder reads, every other
//! member is skipped unread, and a decoded token is held in one allocation sized up front.

use super::*;

/// The three members as `serde_json::Value` reads them: the reference the reader must match on
/// every well-formed object body.
fn reference(body: &str) -> [Option<String>; 3] {
    let v: serde_json::Value = serde_json::from_str(body).expect("a well-formed body");
    MEMBERS.map(|m| {
        v.get(m)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    })
}

fn read(body: &str) -> [Option<String>; 3] {
    let r = TokenResponse::parse(body).expect("a well-formed token response parses");
    [&r.id_token, &r.access_token, &r.refresh_token].map(|t| t.as_deref().cloned())
}

#[test]
fn a_well_formed_token_response_reads_as_a_json_decoder_reads_it() {
    for body in [
        r#"{"id_token":"a.b.c","access_token":"at","refresh_token":"rt","token_type":"Bearer","expires_in":3600}"#,
        r#"{}"#,
        " \r\n\t{ \"id_token\" : \"a.b.c\" } \n",
        r#"{"id_token":null,"access_token":"at"}"#,
        r#"{"access_token":"at"}"#,
        r#"{"id_token":"q\"b\\s\/f\b\f\n\r\tz"}"#,
        r#"{"id_token":"\u0041\u00e9\u20ac\ud83d\ude00 plain é€😀"}"#,
        r#"{"id\u005ftoken":"escaped name"}"#,
        r#"{"x":{"id_token":"nested, not read","y":["}","]","\"",{"z":[[]]}]},"id_token":"top"}"#,
        r#"{"a":true,"b":false,"c":null,"d":-1.5e+3,"e":0,"f":[],"g":{},"id_token":"t"}"#,
        r#"{"id_token":""}"#,
        r#"{"x":"\\","id_token":"after a trailing backslash escape"}"#,
    ] {
        assert_eq!(read(body), reference(body), "{body}");
    }
}

#[test]
fn a_malformed_or_mistyped_token_response_is_refused_without_echoing_it() {
    for body in [
        "not json SECRET",
        r#"{"id_token":"SECRET"} trailing"#,
        r#"{"id_token":"SECRET""#,
        r#"["SECRET"]"#,
        r#""SECRET""#,
        r#"{"id_token":12345678}"#,
        r#"{"id_token":["SECRET"]}"#,
        r#"{"id_token":{"SECRET":1}}"#,
        r#"{"access_token":true}"#,
        r#"{"id_token":"SECRET","id_token":"SECRET"}"#,
        r#"{"refresh_token":null,"refresh_token":"SECRET"}"#,
        r#"{"id_token":"SECRET\ud800"}"#,
        r#"{"id_token":"SECRET\udc00"}"#,
        r#"{"id_token":"SECRET\ud800\u0041"}"#,
    ] {
        let Err(err) = TokenResponse::parse(body) else {
            panic!("refused: {body}");
        };
        assert!(err.starts_with("token response"), "{err}");
        assert!(
            !err.contains("SECRET") && !err.contains("12345678"),
            "{err}"
        );
    }
}

/// The holder is allocated at the raw length, which no escape decodes past: a token that carries
/// escapes is decoded without one reallocation (a reallocation would free a partial copy).
#[test]
fn a_decoded_token_fills_one_allocation_sized_up_front() {
    for raw in [
        &br"plain"[..],
        br"a\nb\\c\/d\u0041\u00e9\u20ac",
        br"\ud83d\ude00\ud83d\ude00",
        br"",
    ] {
        let out = unescape(raw).expect("a valid escape sequence");
        assert_eq!(out.capacity(), raw.len(), "{raw:?}");
        assert!(out.len() <= raw.len());
    }
    assert_eq!(
        unescape(br"a\u0041\n\ud83d\ude00")
            .as_deref()
            .map(String::as_str),
        Some("aA\n\u{1F600}")
    );
    assert!(unescape(br"\x").is_none());
    assert!(unescape(br"\u12").is_none());
    assert!(unescape(br"\u12G4").is_none());
}

#[test]
fn each_structural_fault_in_a_token_response_is_named_malformed_with_its_position_only() {
    let malformed = "token response: it is not well-formed JSON (line 1, column";
    for (body, why) in [
        (
            r#"{id_token":"x"}"#,
            "a member name without its opening quote",
        ),
        (r#"{"id_token" "x"}"#, "a member name without its colon"),
        (
            r#"{"id_token":"x" "access_token":"y"}"#,
            "two members without a comma",
        ),
        (r#"{"id_token":"x";}"#, "a stray separator"),
    ] {
        let err = parse_err(body);
        assert!(err.starts_with(malformed), "{why}: {err}");
        assert!(!err.contains("access_token"), "{why}: {err}");
    }
}

#[test]
fn a_high_surrogate_without_its_low_half_is_an_invalid_escape() {
    for body in [
        r#"{"id_token":"\ud83dxy"}"#,
        r#"{"id_token":"\ud83d\ud83d"}"#,
        r#"{"id_token":"\ud83d"}"#,
    ] {
        assert_eq!(
            parse_err(body),
            "token response: `id_token` holds an invalid escape",
            "{body}"
        );
    }
}

fn parse_err(body: &str) -> String {
    match TokenResponse::parse(body) {
        Err(e) => e,
        Ok(_) => panic!("refused: {body}"),
    }
}
