// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Provider retry metadata through COMPLETE_LOGIN, the real exchange and both loaded doors.

use super::*;
use busbar_contract::abi::auth::{CompleteLoginIn, EXT_RETRY_AFTER, LOGIN_IDENTITY};
use busbar_contract::abi::mechanism::call::{Blob, BLOB_OCTETS};
use busbar_contract::abi::mechanism::extensions;
use reqwest::StatusCode;

const TOKEN_PATH: &str = "/token";
const KEYS_PATH: &str = "/keys";
const RETRY_AFTER_HEADER: &[u8] = b"ReTrY-AfTeR";
const RETRY_DELAY: &[u8] = b"120";
const CALLBACK_CODE: &[u8] = b"retry-metadata-code";
const CALLBACK_STATE: &str = "retry-metadata-state";
const PKCE_VERIFIER: &[u8] = b"retry-metadata-verifier";
const EMPTY_RESPONSE: &[u8] = b"{}";

fn octets(bytes: &[u8]) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }
}

/// Decode metadata only after proving its complete blob belongs to the actual lent buffer.
fn complete(b: &Bound, cap: usize) -> (u32, Option<Vec<u8>>) {
    let ticket = b.dispatcher.mint(0).expect("login ticket");
    let mut bytes = vec![0_u8; cap];
    let mut groups = vec![z::<Span>(); IDENTITY_GROUPS as usize];
    let mut input: CompleteLoginIn = z();
    input.head = busbar_plugin_loader::dispatch::in_head();
    input.code = octets(CALLBACK_CODE);
    input.state = busbar_contract::abi::sdk::door::abi_str(CALLBACK_STATE);
    input.nonce = busbar_contract::abi::sdk::door::abi_str(NONCE);
    input.redirect_uri = busbar_contract::abi::sdk::door::abi_str(REDIRECT);
    input.code_verifier = octets(PKCE_VERIFIER);
    input.out_buf = identity_buf(&mut bytes, &mut groups);
    let mut output: IdentifyOut = z();
    output.head = out_head();
    let done = b.submit(ticket, slot::COMPLETE_LOGIN, input, output);
    assert_eq!(done.outcome, Outcome::Ready, "{:?}", done.error);
    assert!(
        !done.short,
        "outage metadata cannot demand a second redemption"
    );
    let output = &done.frame.as_ref().expect("the returned frame").out;
    let ext = output.head.extensions;
    let retry = if ext.len == 0 {
        None
    } else {
        assert_eq!(ext.fmt, BLOB_OCTETS);
        let at = (ext.ptr as usize)
            .checked_sub(bytes.as_ptr() as usize)
            .expect("metadata starts inside the lent identity buffer");
        let end = at.checked_add(ext.len).expect("metadata range");
        let encoded = bytes
            .get(at..end)
            .expect("metadata ends inside the lent buffer");
        Some(
            extensions::get(encoded, EXT_RETRY_AFTER)
                .expect("the provider retry extension")
                .to_vec(),
        )
    };
    let verdict = output.verdict;
    b.dispatcher.recycle(ticket);
    (verdict, retry)
}

#[test]
fn provider_retry_headers_reach_outages_through_both_doors_after_pending() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let lib = cdylib();
    let stated = row().statement;
    for arm in [
        Arm::Linked,
        Arm::Dropped {
            lib: &lib,
            stated: &stated,
        },
    ] {
        let hints: &[(Option<&[u8]>, Option<&[u8]>)] = &[
            (None, None),
            (Some(RETRY_DELAY), Some(RETRY_DELAY)),
            (Some(b" 120\t"), Some(RETRY_DELAY)),
            (Some(b"0"), Some(b"0")),
            (Some(b"18446744073709551615"), Some(b"18446744073709551615")),
            (Some(b"18446744073709551616"), Some(b"18446744073709551615")),
            (Some(b"Sun, 06 Nov 1994 08:49:37 GMT"), Some(b"0")),
            (Some(b""), None),
            (Some(b"-1"), None),
            (Some(b"later"), None),
            (Some(b"\xff"), None),
        ];
        for status in [
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::TOO_MANY_REQUESTS,
        ] {
            for &(hint, expected) in hints {
                let idp = Idp::new(&key);
                let fields: Vec<_> = hint
                    .into_iter()
                    .map(|value| (RETRY_AFTER_HEADER, value))
                    .collect();
                idp.answer_fields(
                    TOKEN_PATH,
                    u32::from(status.as_u16()),
                    EMPTY_RESPONSE,
                    &fields,
                );
                let b = bind(&arm, &idp);
                open(&b.plugin, &config(AUDIENCE), Some(CLIENT_SECRET)).expect("opens");
                assert_eq!(
                    complete(&b, IDENTITY_BUF_BYTES),
                    (LOGIN_OUTAGE, expected.map(<[u8]>::to_vec))
                );
                assert!(idp.pended() > 0, "the actual request resumed after PENDING");
                assert_eq!(idp.sent_to(TOKEN_PATH).len(), 1, "code redeemed once");
                assert!(
                    idp.sent_to(KEYS_PATH).is_empty(),
                    "a refused token reply verifies no token"
                );
            }
        }
    }
}

#[test]
fn outage_retry_metadata_uses_only_available_host_buffer_without_becoming_short() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let lib = cdylib();
    let stated = row().statement;
    let needed = extensions::entry_len(EXT_RETRY_AFTER, RETRY_DELAY);
    for arm in [
        Arm::Linked,
        Arm::Dropped {
            lib: &lib,
            stated: &stated,
        },
    ] {
        for cap in [0, needed - 1, needed, needed + 1] {
            let idp = Idp::new(&key);
            idp.answer_fields(
                TOKEN_PATH,
                u32::from(StatusCode::SERVICE_UNAVAILABLE.as_u16()),
                EMPTY_RESPONSE,
                &[(RETRY_AFTER_HEADER, RETRY_DELAY)],
            );
            let b = bind(&arm, &idp);
            open(&b.plugin, &config(AUDIENCE), Some(CLIENT_SECRET)).expect("opens");
            let expected = (cap >= needed).then(|| RETRY_DELAY.to_vec());
            assert_eq!(complete(&b, cap), (LOGIN_OUTAGE, expected));
            assert_eq!(
                idp.sent_to(TOKEN_PATH).len(),
                1,
                "fallback does not redeem twice"
            );
        }
    }
}

#[test]
fn retry_metadata_follows_the_outage_class_and_the_endpoint_that_failed() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let lib = cdylib();
    let stated = row().statement;
    for arm in [
        Arm::Linked,
        Arm::Dropped {
            lib: &lib,
            stated: &stated,
        },
    ] {
        let token = key.sign(&claims(AUDIENCE));
        let valid = serde_json::json!({"id_token": token}).to_string();
        let mut other_nonce = claims(AUDIENCE);
        other_nonce["nonce"] = serde_json::json!("another-session-nonce");
        let unbound = serde_json::json!({"id_token": key.sign(&other_nonce)}).to_string();
        for (status, body, verdict) in [
            (
                StatusCode::BAD_REQUEST,
                r#"{"error":"invalid_grant"}"#,
                LOGIN_BAD_CREDENTIAL,
            ),
            (
                StatusCode::UNAUTHORIZED,
                r#"{"error":"invalid_client"}"#,
                LOGIN_BAD_CREDENTIAL,
            ),
            (
                StatusCode::OK,
                unbound.as_str(),
                LOGIN_SECURITY_CHECK_FAILED,
            ),
            (StatusCode::OK, valid.as_str(), LOGIN_IDENTITY),
            (StatusCode::OK, "<provider-maintenance>", LOGIN_OUTAGE),
        ] {
            let idp = Idp::new(&key);
            idp.answer_fields(
                TOKEN_PATH,
                u32::from(status.as_u16()),
                body.as_bytes(),
                &[(RETRY_AFTER_HEADER, RETRY_DELAY)],
            );
            let b = bind(&arm, &idp);
            open(&b.plugin, &config(AUDIENCE), Some(CLIENT_SECRET)).expect("opens");
            assert_eq!(
                complete(&b, IDENTITY_BUF_BYTES),
                (
                    verdict,
                    (verdict == LOGIN_OUTAGE).then(|| RETRY_DELAY.to_vec())
                )
            );
            assert_eq!(idp.sent_to(TOKEN_PATH).len(), 1);
        }
        // The successful token response's hint must survive no later failure. The JWKS
        // response contributes its own hint, or none, across its own PENDING/resume.
        const KEYS_RETRY_DELAY: &[u8] = b"240";
        for keys_hint in [None, Some(KEYS_RETRY_DELAY)] {
            let idp = Idp::new(&key);
            idp.answer_fields(
                TOKEN_PATH,
                u32::from(StatusCode::OK.as_u16()),
                valid.as_bytes(),
                &[(RETRY_AFTER_HEADER, RETRY_DELAY)],
            );
            let fields: Vec<_> = keys_hint
                .into_iter()
                .map(|value| (RETRY_AFTER_HEADER, value))
                .collect();
            idp.answer_fields(
                KEYS_PATH,
                u32::from(StatusCode::SERVICE_UNAVAILABLE.as_u16()),
                EMPTY_RESPONSE,
                &fields,
            );
            let b = bind(&arm, &idp);
            open(&b.plugin, &config(AUDIENCE), Some(CLIENT_SECRET)).expect("opens");
            assert_eq!(
                complete(&b, IDENTITY_BUF_BYTES),
                (LOGIN_OUTAGE, keys_hint.map(<[u8]>::to_vec))
            );
            assert_eq!(idp.sent_to(TOKEN_PATH).len(), 1);
            assert_eq!(idp.sent_to(KEYS_PATH).len(), 1);
        }
    }
}

#[test]
fn a_received_retry_hint_survives_a_later_body_timeout_or_reply_cap_failure() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let lib = cdylib();
    let stated = row().statement;
    let over_cap = vec![b'x'; busbar_auth_oidc::fetch::MAX_TOKEN_BYTES + 1];
    for arm in [
        Arm::Linked,
        Arm::Dropped {
            lib: &lib,
            stated: &stated,
        },
    ] {
        for timeout in [true, false] {
            let idp = Idp::new(&key);
            idp.answer_fields(
                TOKEN_PATH,
                u32::from(StatusCode::SERVICE_UNAVAILABLE.as_u16()),
                if timeout { EMPTY_RESPONSE } else { &over_cap },
                &[(RETRY_AFTER_HEADER, RETRY_DELAY)],
            );
            if timeout {
                idp.timeout_body(TOKEN_PATH);
            }
            let b = bind(&arm, &idp);
            open(&b.plugin, &config(AUDIENCE), Some(CLIENT_SECRET)).expect("opens");
            assert_eq!(
                complete(&b, IDENTITY_BUF_BYTES),
                (LOGIN_OUTAGE, Some(RETRY_DELAY.to_vec()))
            );
            let sent = idp.sent_to(TOKEN_PATH);
            assert_eq!(sent.len(), 1, "the failed response redeems no second code");
            assert!(
                !idp.connection_is_open(sent[0].conn),
                "the failed exchange closed its connection"
            );
        }
    }
}
