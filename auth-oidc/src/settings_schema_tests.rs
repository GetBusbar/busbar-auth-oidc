// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The signed schema and the real lifecycle validator agree on representative settings.

#[path = "../../testing/settings/integer_token.rs"]
mod settings_profile;

use super::*;
use serde_json::{json, Value};

fn check(cases: &[(Value, bool)]) {
    let schema: Value = serde_json::from_slice(SETTINGS_SCHEMA).expect("schema JSON");
    assert_eq!(schema["x-busbar-principal-format"], "oidc-v2");
    assert_eq!(
        schema["x-busbar-principal-domain-fields"],
        json!([
            {"pointer": "/issuer", "required": true},
            {"pointer": "/audience", "required": true},
            {"pointer": "/client_id", "required": false},
        ])
    );
    let validator = settings_profile::validator(&schema).expect("valid settings schema");
    assert_eq!(STATEMENT.settings_schema.ptr, SETTINGS_SCHEMA.as_ptr());
    assert_eq!(STATEMENT.settings_schema.len, SETTINGS_SCHEMA.len());
    assert_eq!(
        STATEMENT.settings_schema.fmt,
        busbar_contract::abi::mechanism::call::BLOB_JSON
    );
    for (settings, accepted) in cases {
        let bytes = serde_json::to_vec(settings).expect("settings JSON");
        assert_eq!(
            validator.is_valid(settings),
            *accepted,
            "schema: {settings}"
        );
        assert_eq!(
            <Oidc as Life>::validate(&bytes).is_ok(),
            *accepted,
            "lifecycle: {settings}"
        );
    }
}

#[test]
fn settings_schema_matches_oidc_lifecycle() {
    let minimal = json!({"issuer":"https://issuer.example","audience":"api"});
    check(&[
        (minimal.clone(), true),
        (json!({}), false),
        (json!([]), false),
    ]);
    for (key, value, accepted) in [
        ("audience", json!("\u{2003}"), false),
        ("issuer", json!("https://issuer.example "), false),
        ("issuer", json!("\u{00A0}https://issuer.example"), false),
        ("role_claim", json!(""), false),
        ("role_claim", Value::Null, false),
        ("client_id", Value::Null, true),
        ("client_id", json!(""), false),
        ("jwks_url", Value::Null, true),
        ("jwks_url", json!("https://issuer.example/keys"), true),
        ("jwks_min_refetch_secs", json!(0), false),
        ("jwks_min_refetch_secs", json!(1), true),
        ("jwks_ttl_secs", json!(0), true),
        ("jwks_ttl_secs", json!(-1), false),
        ("scopes", json!(["profile"]), true),
        ("scopes", json!([" "]), false),
        ("scopes", Value::Null, false),
        (
            "ca_cert_pem",
            json!("non-blank; connector validates certificates"),
            true,
        ),
        ("client_secret", json!("secret"), false),
        ("unknown", Value::Null, false),
    ] {
        let mut settings = minimal.clone();
        settings[key] = value;
        check(&[(settings, accepted)]);
    }
    // Every guarded string setting refuses a blank or whitespace-only value, whatever the code
    // point, in the schema and in the lifecycle validator alike.
    let blanks = [
        "", " ", "\t", "\u{00A0}", "\u{2003}", "\u{3000}", "\u{1680}", "\u{202F}", "\u{2028}",
    ];
    for key in [
        "issuer",
        "audience",
        "jwks_url",
        "role_claim",
        "ca_cert_pem",
        "client_id",
        "authorization_endpoint",
        "token_endpoint",
    ] {
        for blank in blanks {
            let mut settings = minimal.clone();
            settings[key] = json!(blank);
            check(&[(settings, false)]);
        }
    }
    for blank in blanks {
        let mut settings = minimal.clone();
        settings["scopes"] = json!(["profile", blank]);
        check(&[(settings, false)]);
    }
    let cfg: crate::OidcConfig = serde_json::from_value(minimal).unwrap();
    let schema: Value = serde_json::from_slice(SETTINGS_SCHEMA).unwrap();
    let props = &schema["properties"];
    assert_eq!(props["role_claim"]["default"], cfg.role_claim);
    assert_eq!(
        props["jwks_min_refetch_secs"]["default"],
        cfg.jwks_min_refetch_secs
    );
    assert_eq!(props["jwks_ttl_secs"]["default"], cfg.jwks_ttl_secs);
    assert_eq!(props["scopes"]["default"], json!(cfg.scopes));
}

#[test]
fn settings_schema_integer_tokens_match_native_parser() {
    let schema: serde_json::Value = serde_json::from_slice(SETTINGS_SCHEMA).unwrap();
    let profile = settings_profile::validator(&schema).unwrap();
    let standard = jsonschema::validator_for(&schema).unwrap();
    assert_eq!(schema["x-busbar-settings-profile"], "integer-token-v1");
    for (pointer, template, integer, kind) in [
        (
            r#"/properties/jwks_min_refetch_secs"#,
            r#"{"issuer":"https://issuer.example","audience":"api","jwks_min_refetch_secs":TOKEN}"#,
            "1",
            "unsigned",
        ),
        (
            r#"/properties/jwks_ttl_secs"#,
            r#"{"issuer":"https://issuer.example","audience":"api","jwks_ttl_secs":TOKEN}"#,
            "1",
            "unsigned",
        ),
    ] {
        assert_eq!(
            schema.pointer(pointer).unwrap()["x-busbar-integer-token"],
            kind
        );
        for (token, accepted) in [
            (integer.to_string(), true),
            (format!("{integer}.0"), false),
            (format!("{integer}e0"), false),
            (format!("{integer}E+0"), false),
        ] {
            let text = template.replace("TOKEN", &token);
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert!(
                standard.is_valid(&value),
                "standard mathematical integer: {text}"
            );
            assert_eq!(profile.is_valid(&value), accepted, "profile: {text}");
            assert_eq!(
                <Oidc as Life>::validate(text.as_bytes()).is_ok(),
                accepted,
                "native: {text}"
            );
        }
        // Do not infer signed negative-zero behavior from a regular expression:
        // the profile must agree with the actual lifecycle parser.
        for token in [
            "null",
            "0",
            "-0",
            "-0.0",
            "0e0",
            "-1",
            "18446744073709551616",
        ] {
            let text = template.replace("TOKEN", token);
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(
                profile.is_valid(&value),
                <Oidc as Life>::validate(text.as_bytes()).is_ok(),
                "native sign/range: {text}"
            );
        }
    }
}
