// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the module makes of a request's answer, in 1.5.5's words, and the requests it builds.

use super::*;
use busbar_contract::abi::host::conn::connector::{DIRECTION_OUTBOUND, EGRESS_OPEN_WEB};

const URL: &str = "https://idp.example/jwks";

#[test]
fn jwks_body_over_the_cap_is_refused() {
    let cap = 16usize;
    let err = capped(URL, vec![b'x'; cap * 2], cap).unwrap_err();
    assert_eq!(
        err,
        "https://idp.example/jwks JWKS body exceeds the 16-byte cap"
    );
}

#[test]
fn jwks_body_exactly_at_the_cap_is_accepted() {
    let cap = 16usize;
    assert_eq!(capped(URL, vec![b'x'; cap], cap).unwrap().len(), cap);
}

#[test]
fn a_non_utf8_jwks_body_is_a_clean_error_not_a_panic() {
    let err = capped(URL, vec![0xff, 0xfe], 1024).unwrap_err();
    assert_eq!(err, "https://idp.example/jwks JWKS body is not UTF-8");
}

/// The 1 MiB cap applies to every document, at exactly 1.5.5's size.
#[test]
fn a_document_over_one_mebibyte_is_refused() {
    assert_eq!(MAX_JWKS_BYTES, 1024 * 1024);
    let err = document(URL, 200, vec![b' '; MAX_JWKS_BYTES + 1]).unwrap_err();
    assert_eq!(
        err,
        "https://idp.example/jwks JWKS body exceeds the 1048576-byte cap"
    );
    assert!(document(URL, 200, vec![b' '; MAX_JWKS_BYTES]).is_ok());
}

/// A non-2xx answer names its status as 1.5.5's client printed it: the code and its canonical
/// reason; an unknown code is named as reqwest named one.
#[test]
fn a_non_2xx_answer_names_its_status_as_1_5_5_did() {
    assert_eq!(
        document(URL, 404, b"nope".to_vec()).unwrap_err(),
        "https://idp.example/jwks returned HTTP 404 Not Found"
    );
    assert_eq!(
        document(URL, 503, Vec::new()).unwrap_err(),
        "https://idp.example/jwks returned HTTP 503 Service Unavailable"
    );
    assert_eq!(
        document(URL, 299, b"{}".to_vec()).as_deref(),
        Ok("{}"),
        "every 2xx is a success"
    );
    assert_eq!(
        document(URL, 599, Vec::new()).unwrap_err(),
        "https://idp.example/jwks returned HTTP 599 <unknown status code>"
    );
    assert_eq!(
        document(URL, 302, Vec::new()).unwrap_err(),
        "https://idp.example/jwks returned HTTP 302 Found"
    );
}

#[test]
fn a_request_that_got_no_answer_keeps_1_5_5_s_prefix() {
    assert_eq!(
        failed(URL, "the connection was refused"),
        "request to https://idp.example/jwks failed: the connection was refused"
    );
}

fn hop() -> LoginHop {
    LoginHop {
        method: "POST".to_string(),
        url: "https://idp.example/token?p=b2c".to_string(),
        form: vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), "a b&c".to_string()),
            ("client_secret".to_string(), String::new()),
        ],
        secret_form_field: Some("client_secret".to_string()),
        headers: vec![("x-extra".to_string(), "1".to_string())],
    }
}

#[test]
fn the_lent_secret_fills_the_named_field_and_none_drops_it() {
    let filled = form(&hop(), Some("s3cret"));
    assert!(filled.contains(&("client_secret".to_string(), "s3cret".to_string())));
    let public = form(&hop(), None);
    assert!(public.iter().all(|(k, _)| k != "client_secret"));
}

#[test]
fn the_token_exchange_is_a_url_encoded_form_post_to_the_endpoint_path() {
    let url = url::Url::parse(&hop().url).unwrap();
    let r = post_request(&url, &hop(), Some("s3cret"));
    assert_eq!(r.method, b"POST");
    assert_eq!(r.target, b"/token?p=b2c");
    assert_eq!(
        String::from_utf8(r.body).unwrap(),
        "grant_type=authorization_code&code=a+b%26c&client_secret=s3cret"
    );
    assert!(r.fields.contains(&(
        b"content-type".to_vec(),
        b"application/x-www-form-urlencoded".to_vec()
    )));
    assert!(r.fields.contains(&(b"x-extra".to_vec(), b"1".to_vec())));
    assert_eq!(r.timeout_ms, FETCH_TIMEOUT_MS);

    let mut odd = hop();
    odd.method = "NOT A METHOD".to_string();
    assert_eq!(post_request(&url, &odd, None).method, b"POST");
}

#[test]
fn a_document_get_names_the_path_and_query() {
    let url = url::Url::parse("https://idp.example/tenant/keys?appid=1").unwrap();
    let r = get_request(&url);
    assert_eq!(
        (r.method.as_slice(), r.target.as_slice()),
        (&b"GET"[..], &b"/tenant/keys?appid=1"[..])
    );
    assert!(r.body.is_empty());
}

/// HTTPS-ONLY, as 1.5.5's client was: a plaintext URL is refused before anything is asked of the
/// host; an https one with no connector says so after 1.5.5's prefix.
#[test]
fn every_request_is_https_only_and_needs_the_host_connector() {
    let mut io = HostIo::new(None, Ticket::NONE, IoState::default());
    assert_eq!(
        io.get(Doc::Jwks, "http://idp.example/jwks"),
        Poll::Ready(Err(
            "request to http://idp.example/jwks failed: URL scheme is not allowed".to_string()
        ))
    );
    assert_eq!(
        io.get(Doc::Discovery, URL),
        Poll::Ready(Err(
            "request to https://idp.example/jwks failed: the instance was handed no connector"
                .to_string()
        ))
    );
    assert_eq!(
        io.caller(),
        None,
        "a ticketless call is no caller that may pend"
    );
}

/// THE NEEDS: three outbound needs in the open-web class (THE DESIGN, egress classes: the auth mint
/// endpoints' class), each trusting an extra root on top of the public ones; discovery pinned to a
/// setting, the JWKS and the token endpoint named per request. (Their words are read back from the
/// door's rendered Statement in the plugin crate's conformance test.)
#[test]
fn the_needs_are_outbound_open_web_trusting_an_extra_root() {
    assert_eq!(NEEDS.len(), 3);
    for (i, n) in NEEDS.iter().enumerate() {
        assert_eq!(n.direction, DIRECTION_OUTBOUND, "need {i}");
        assert_eq!(n.egress_class, EGRESS_OPEN_WEB, "need {i}");
        assert_eq!(n.transport.len, "https".len(), "need {i}");
        assert_eq!(n.trust_from.len, "settings.ca_cert_pem".len(), "need {i}");
        assert_eq!(n.timeout_ms, FETCH_TIMEOUT_MS, "need {i}");
    }
    assert_eq!(
        NEEDS[NEED_DISCOVERY as usize].target_from.len,
        "settings.issuer".len()
    );
    assert_eq!(NEEDS[NEED_JWKS as usize].target_from.len, 0);
    assert_eq!(NEEDS[NEED_TOKEN as usize].target_from.len, 0);
}
