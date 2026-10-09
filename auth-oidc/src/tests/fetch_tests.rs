// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the module makes of a request's answer, in 1.5.5's words, and the requests it builds.

use super::*;
use busbar_contract::abi::host::conn::connector::{
    DIRECTION_OUTBOUND, EGRESS_LOOPBACK_ALLOWED, EGRESS_OPEN_WEB, EGRESS_OPERATOR_INFRASTRUCTURE,
};
use std::net::IpAddr;

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
    // 1.5.5's wire order: the form's content-type, the client's accept, then the hop's own.
    assert_eq!(
        r.fields,
        vec![
            (
                b"content-type".to_vec(),
                b"application/x-www-form-urlencoded".to_vec()
            ),
            (b"accept".to_vec(), b"*/*".to_vec()),
            (b"x-extra".to_vec(), b"1".to_vec()),
        ]
    );
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
    let mut io = HostIo::new(None, Ticket::NONE, IoState::default(), false);
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

/// THE NEEDS: three outbound needs — discovery, the JWKS and the token exchange, every one in the
/// operator-infrastructure class (ARCHITECT ruling 2026-10-09) — stated twice: the ANCHORED set trusting an extra root on top of the public
/// ones, the PUBLIC set the public roots only (`ca_cert_pem` is optional, and the host refuses a
/// need whose `trust_from` names nothing); discovery pinned to a setting, the JWKS and the token
/// endpoint named per request. (Their words are read back from the door's rendered Statement in
/// the plugin crate's conformance test.)
#[test]
fn the_needs_are_outbound_in_their_class_anchored_then_public() {
    assert_eq!(NEEDS.len(), 2 * PUBLIC as usize);
    for (i, n) in NEEDS.iter().enumerate() {
        assert_eq!(n.direction, DIRECTION_OUTBOUND, "need {i}");
        assert_eq!(n.egress_class, EGRESS_OPERATOR_INFRASTRUCTURE, "need {i}");
        assert_eq!(n.transport.len, "http".len(), "need {i}");
        let trust = if (i as u32) < PUBLIC {
            "settings.ca_cert_pem".len()
        } else {
            0
        };
        assert_eq!(n.trust_from.len, trust, "need {i}");
        assert_eq!(n.timeout_ms, FETCH_TIMEOUT_MS, "need {i}");
    }
    for anchored in [true, false] {
        assert_eq!(
            NEEDS[on(NEED_DISCOVERY, anchored) as usize].target_from.len,
            "settings.issuer".len()
        );
        assert_eq!(NEEDS[on(NEED_JWKS, anchored) as usize].target_from.len, 0);
        assert_eq!(NEEDS[on(NEED_TOKEN, anchored) as usize].target_from.len, 0);
    }
    assert_eq!(
        (on(NEED_JWKS, true), on(NEED_JWKS, false)),
        (NEED_JWKS, NEED_JWKS + PUBLIC)
    );
}

/// THE CONNECTOR'S SCHEME RULE PER EGRESS CLASS, for a plaintext dial (`secure = false`) that the
/// destination guard has pinned to `addr`: busbar-core-connector `class_admits` at the busbar pin
/// (`.busbar-ref`): open-web dials over connection security only; loopback-allowed in plaintext to
/// loopback only; every other class (operator-infrastructure included) takes the scheme its target
/// names. The module cannot link the connector, so its rule is stated here, word for word.
fn connector_admits_plaintext(egress_class: u32, addr: IpAddr) -> bool {
    match egress_class {
        EGRESS_OPEN_WEB => false,
        EGRESS_LOOPBACK_ALLOWED => addr.is_loopback(),
        _ => true,
    }
}

/// What a token endpoint `url` meets end to end, in the class the token need declares (`class`):
/// the module's own scheme check first (a refusal there never reaches the host: "URL scheme is not
/// allowed"), then, for a plaintext target, the connector's scheme rule for that class at the
/// address the target names. `true` = the request goes out.
fn token_admitted(class: u32, url: &str) -> bool {
    let mut io = HostIo::new(None, Ticket::NONE, IoState::default(), false);
    let mut h = hop();
    h.url = url.to_string();
    let reached_host = match io.post(&h, None).map(|r| r.map(|_| ())) {
        Poll::Ready(Err(e)) => {
            assert!(
                e.ends_with("URL scheme is not allowed")
                    || e.ends_with("the instance was handed no connector"),
                "{url}: {e}"
            );
            e.ends_with("the instance was handed no connector")
        }
        other => panic!("{url}: a hostless HostIo answers at once: {other:?}"),
    };
    if !reached_host {
        return false;
    }
    let parsed = url::Url::parse(url).expect("a test URL parses");
    if parsed.scheme() == "https" {
        return true;
    }
    let addr: IpAddr = match parsed.host().expect("a test URL names a host") {
        url::Host::Ipv4(a) => a.into(),
        url::Host::Ipv6(a) => a.into(),
        // `localhost` resolves to loopback.
        url::Host::Domain(_) => IpAddr::from([127, 0, 0, 1]),
    };
    connector_admits_plaintext(class, addr)
}

/// The class the token need declares, on both sets.
fn token_class() -> u32 {
    let anchored = NEEDS[on(NEED_TOKEN, true) as usize].egress_class;
    assert_eq!(anchored, NEEDS[on(NEED_TOKEN, false) as usize].egress_class);
    anchored
}

/// Private and loopback IdP token endpoints, as an on-prem operator configures them.
const PRIVATE_HTTP: &[&str] = &[
    "http://10.1.2.3/token",
    "http://172.16.0.9:8080/oauth2/token",
    "http://192.168.1.20:8443/token",
    "http://100.64.0.7/token",
    "http://[fd00::5]/token",
    "http://127.0.0.1:8443/token",
    "http://localhost:8080/token",
];

/// HTTP TO A PRIVATE IdP HOST IS ADMITTED, as 1.5.5's `vet_hop_url` admitted it (1.5.5
/// `auth/token.rs:867-880`: "http only for loopback/private (a local/on-prem IdP)"): the module
/// passes the request to the host, and the class the token need declares lets the connector dial it.
///
/// RED under the classes this need held before: `open-web` (#24) refuses every plaintext dial and
/// `loopback-allowed` (#25) refuses one off loopback, so `http://10.1.2.3/token`, which 1.5.5
/// accepted, would be refused.
#[test]
fn http_to_a_private_idp_token_endpoint_is_admitted() {
    let class = token_class();
    for url in PRIVATE_HTTP {
        assert!(token_admitted(class, url), "{url} in class {class}");
    }
    // RED: the private (non-loopback) case is refused under either earlier class.
    for old in [EGRESS_OPEN_WEB, EGRESS_LOOPBACK_ALLOWED] {
        assert!(
            !token_admitted(old, "http://10.1.2.3/token"),
            "class {old} must refuse a private plaintext token endpoint"
        );
        assert!(!token_admitted(old, "http://192.168.1.20:8443/token"));
    }
}

/// HTTP TO A PUBLIC HOST IS REFUSED (1.5.5 `vet_hop_url`: "public host must be https"), by the
/// module itself, before the host is asked: the operator-infrastructure class would dial it, so the
/// module is what holds it.
#[test]
fn http_to_a_public_token_endpoint_is_refused_before_the_host_is_asked() {
    let mut io = HostIo::new(None, Ticket::NONE, IoState::default(), false);
    for url in [
        "http://idp.example.com/token",
        "http://login.microsoftonline.com/tenant/oauth2/v2.0/token",
        "http://93.184.216.34/token",
        "http://[2001:db8::1]/token",
        // A private-looking NAME is no private host: 1.5.5 judged the URL's host as written.
        "http://idp.corp.internal/token",
    ] {
        let mut h = hop();
        h.url = url.to_string();
        assert_eq!(
            io.post(&h, None).map(|r| r.map(|_| ())),
            Poll::Ready(Err(format!(
                "request to {url} failed: URL scheme is not allowed"
            ))),
        );
        assert!(!token_admitted(token_class(), url), "{url}");
    }
}

/// HTTPS TO A PUBLIC HOST IS ADMITTED: the module passes it to the host, in every class.
#[test]
fn https_to_a_public_token_endpoint_is_admitted() {
    for url in [
        "https://idp.example.com/token",
        "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
    ] {
        assert!(token_admitted(token_class(), url), "{url}");
    }
}

/// DISCOVERY AND THE JWKS STAY HTTPS ONLY, to a private host as to a public one (1.5.5's fetcher
/// was `https_only`): the class allows plaintext, the module does not ask for it.
#[test]
fn documents_stay_https_only_whatever_the_host() {
    let mut io = HostIo::new(None, Ticket::NONE, IoState::default(), false);
    for (doc, url) in [
        (
            Doc::Discovery,
            "http://10.1.2.3/.well-known/openid-configuration",
        ),
        (Doc::Jwks, "http://127.0.0.1:8443/keys"),
        (Doc::Jwks, "http://idp.example.com/keys"),
    ] {
        assert_eq!(
            io.get(doc, url),
            Poll::Ready(Err(format!(
                "request to {url} failed: URL scheme is not allowed"
            ))),
        );
        assert!(!plaintext_allowed(doc.need(), url), "{url}");
    }
    assert!(plaintext_allowed(NEED_TOKEN, "http://10.1.2.3/token"));
    assert!(!plaintext_allowed(NEED_TOKEN, "https://10.1.2.3/token"));
}
