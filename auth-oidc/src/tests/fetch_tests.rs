// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the module makes of a request's answer, in 1.5.5's words, and the requests it builds.

use super::*;
use busbar_contract::abi::host::conn::connector::{
    DIRECTION_OUTBOUND, EGRESS_DEFAULT, EGRESS_OPEN_WEB,
};
use busbar_contract::abi::sdk::cred::FormBody;

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

#[test]
fn response_errors_name_the_document_and_never_quote_its_body() {
    for (need, name) in [
        (NEED_DISCOVERY, "discovery"),
        (NEED_JWKS, "JWKS"),
        (NEED_TOKEN, "token response"),
    ] {
        let cap = 32;
        assert_eq!(
            capped_for(need, URL, vec![b'x'; cap], cap).unwrap(),
            "x".repeat(cap)
        );
        let over = capped_for(need, URL, vec![b'x'; cap + 1], cap).unwrap_err();
        assert_eq!(
            over,
            format!("{URL} {name} body exceeds the {cap}-byte cap")
        );
        let utf8 = capped_for(need, URL, b"PrivateDocumentMarker\xff".to_vec(), cap).unwrap_err();
        assert_eq!(utf8, format!("{URL} {name} body is not UTF-8"));
        assert!(!utf8.contains("PrivateDocumentMarker"));
    }
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

fn form() -> FormBody {
    FormBody::new()
        .public("grant_type", "authorization_code")
        .public("code", "a b&c")
        .sealed(
            "client_secret",
            &busbar_contract::abi::sdk::test_support::chip::cred("s3cret"),
        )
}

#[test]
fn the_token_exchange_is_a_url_encoded_form_post_to_the_endpoint_path() {
    let url = url::Url::parse("https://idp.example/token?p=b2c").unwrap();
    let ex = post_exchange(&url, &form()).expect("frames");
    let head = busbar_contract::abi::sdk::test_support::chip::framed_head(&ex);
    assert!(head.starts_with(b"POST/token?p=b2c"), "{head:?}");
    // 1.5.5's wire order: the form's content-type, then the client's accept.
    assert_eq!(
        ex.framed_fields(),
        vec![
            (
                &b"content-type"[..],
                &b"application/x-www-form-urlencoded"[..]
            ),
            (&b"accept"[..], &b"*/*"[..]),
        ]
    );
    assert_eq!(
        crate::script::wire_text(&form()),
        "grant_type=authorization_code&code=a+b%26c&client_secret=s3cret"
    );
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

/// THE NEEDS: three outbound needs — discovery and the JWKS in the `open-web` class (https only, a
/// private address refused unless allowlisted, the issuer pin kept), the token exchange in the
/// connector's default class named per request (a private address refused unless allowlisted,
/// never lifted to operator infrastructure: security item 3) — stated twice: the ANCHORED set trusting an extra root on top of the public
/// ones, the PUBLIC set the public roots only (`ca_cert_pem` is optional, and the host refuses a
/// need whose `trust_from` names nothing); discovery pinned to a setting, the JWKS and the token
/// endpoint named per request. (Their words are read back from the door's rendered Statement in
/// the plugin crate's conformance test.)
#[test]
fn the_needs_are_outbound_in_their_class_anchored_then_public() {
    assert_eq!(NEEDS.len(), 2 * PUBLIC as usize);
    for (i, n) in NEEDS.iter().enumerate() {
        assert_eq!(n.direction, DIRECTION_OUTBOUND, "need {i}");
        let class = if i as u32 % PUBLIC == NEED_TOKEN {
            EGRESS_DEFAULT
        } else {
            EGRESS_OPEN_WEB
        };
        assert_eq!(n.egress_class, class, "need {i}");
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

/// Whether the plugin hands this token endpoint to its host connector after its own scheme check.
/// The host destination policy is exercised by the loaded-door conformance tests.
fn token_admitted(url: &str) -> bool {
    let mut io = HostIo::new(None, Ticket::NONE, IoState::default(), false);
    match io.post(url, &form()).map(|r| r.map(|_| ())) {
        Poll::Ready(Err(e)) => {
            assert!(
                e.ends_with("URL scheme is not allowed")
                    || e.ends_with("the instance was handed no connector"),
                "{url}: {e}"
            );
            e.ends_with("the instance was handed no connector")
        }
        other => panic!("{url}: a hostless HostIo answers at once: {other:?}"),
    }
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

/// The plugin hands existing private/loopback plaintext token endpoints to the host connector.
#[test]
fn http_to_a_private_idp_token_endpoint_is_admitted() {
    for url in PRIVATE_HTTP {
        assert!(token_admitted(url), "{url}");
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
        assert_eq!(
            io.post(url, &form()).map(|r| r.map(|_| ())),
            Poll::Ready(Err(format!(
                "request to {url} failed: URL scheme is not allowed"
            ))),
        );
        assert!(!token_admitted(url), "{url}");
    }
}

/// HTTPS public token endpoints reach the host connector.
#[test]
fn https_to_a_public_token_endpoint_is_admitted() {
    for url in [
        "https://idp.example.com/token",
        "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
    ] {
        assert!(token_admitted(url), "{url}");
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

/// Holds `T` to wiping itself on drop: a compile-time check.
fn wipes<T: zeroize::ZeroizeOnDrop>(_: &T) {}

/// THE TOKEN REQUEST'S CREDENTIAL COPIES ARE WIPED (bank grade): the form the token exchange
/// builds (the code, the code_verifier, the sealed client secret) wipes itself on drop. A
/// type-level check.
#[test]
fn the_token_request_copies_wipe_on_drop() {
    let cfg: crate::OidcConfig = serde_json::from_str(
        r#"{"issuer":"https://i.test","audience":"a","jwks_url":"https://i.test/keys",
            "token_endpoint":"https://i.test/token"}"#,
    )
    .expect("a config");
    let m = crate::OidcModule::new(&cfg);
    let made = crate::script::ready(m.token_exchange(
        Some("code"),
        Some("https://busbar.test/cb"),
        Some("verifier"),
        None,
        std::time::Instant::now(),
        &mut crate::script::Idp::new(String::new()).at_once(Some(crate::script::ME)),
    ))
    .expect("configured")
    .expect("a token request");
    wipes(&made.form);
}

/// The SDK's form encoder writes byte for byte what the `url` crate's form serializer (the
/// encoder 1.5.5 used) wrote, so the wire does not change.
#[test]
fn the_form_body_matches_the_url_form_serializer() {
    let cases: Vec<Vec<(&str, &str)>> = vec![
        vec![],
        vec![("a", "")],
        vec![("grant_type", "authorization_code"), ("code", "a b&c")],
        vec![
            ("client_secret", "p@ss/w+rd=%?#~!'()*-._"),
            ("redirect_uri", "https://busbar.test/auth/token?x=1&y=2"),
            (
                "code_verifier",
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            ),
        ],
        vec![("ünï", "çødé 日本 \u{1F600}"), ("ctl", "\t\r\n\0\x7f")],
    ];
    for case in cases {
        let old = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(case.iter())
            .finish();
        let form = case
            .iter()
            .fold(FormBody::new(), |f, (n, v)| f.public(n, v));
        assert_eq!(crate::script::wire_text(&form), old, "pairs {case:?}");
    }
}

/// An operator CA selects the anchored needs while preserving their destination classes and targets.
#[test]
fn ca_cert_pem_only_adds_a_trusted_root_and_never_disables_verification() {
    let settings = |pem: Option<&str>| {
        let mut s = serde_json::json!({
            "issuer": "https://idp.corp.example/realms/r",
            "audience": "api://a",
        });
        if let Some(p) = pem {
            s["ca_cert_pem"] = serde_json::json!(p);
        }
        crate::open::config(&s.to_string()).expect("parses")
    };
    let pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
    assert!(crate::OidcModule::new(&settings(Some(pem))).anchored());
    assert!(!crate::OidcModule::new(&settings(None)).anchored());
    assert!(crate::open::config(
        r#"{"issuer":"https://idp.corp.example/realms/r","audience":"api://a","ca_cert_pem":""}"#
    )
    .is_err());
    for need in [NEED_DISCOVERY, NEED_JWKS, NEED_TOKEN] {
        let anchored = &NEEDS[on(need, true) as usize];
        let public = &NEEDS[on(need, false) as usize];
        assert_eq!(
            anchored.trust_from.len,
            "settings.ca_cert_pem".len(),
            "{need}"
        );
        assert_eq!(public.trust_from.len, 0, "{need}: the public roots only");
        assert_eq!(
            (anchored.egress_class, anchored.target_from.len),
            (public.egress_class, public.target_from.len),
            "{need}: the anchor changes the trust and nothing else"
        );
    }
}

/// S6: a token endpoint's answer is bounded at 256 KiB; discovery and the JWKS at 1 MiB.
#[test]
fn each_need_bounds_its_reply() {
    assert_eq!(reply_cap(NEED_TOKEN), 256 * 1024);
    assert_eq!(reply_cap(NEED_DISCOVERY), 1024 * 1024);
    assert_eq!(reply_cap(NEED_JWKS), 1024 * 1024);
}

/// S1: a URL an error or log line names is shown with its userinfo removed.
#[test]
fn an_error_naming_a_url_drops_its_userinfo() {
    let url = "https://user:Zq7pw@idp.example/jwks";
    for said in [
        failed(url, "the connection was refused"),
        document(url, 404, Vec::new()).unwrap_err(),
        capped(url, vec![0xff], 16).unwrap_err(),
        capped(url, vec![b'x'; 32], 16).unwrap_err(),
    ] {
        assert!(!said.contains("Zq7pw") && !said.contains("user:"), "{said}");
        assert!(said.contains("https://idp.example/jwks"), "{said}");
    }
}

#[test]
fn displayed_urls_preserve_normal_text_and_scrub_before_escaping_controls() {
    for url in [
        "HTTPS://idp.example:443/a%2Fb?x=One%20Two#tail",
        "https://idp.example/café?tenant=日本",
    ] {
        assert_eq!(shown(url), url);
    }
    assert_eq!(
        shown("https://idp.example/keys\r\n\t\x1b\u{85}"),
        r"https://idp.example/keys\r\n\t\u{1b}\u{85}"
    );
    // A malformed host exercises the existing fallback redaction, before display escaping.
    assert_eq!(
        shown("https://user:OidcFallbackPass@bad host/path\r\n\x1b"),
        r"https://bad host/path\r\n\u{1b}"
    );
    assert_eq!(
        shown("https://user:OidcPassCanary@idp.example/keys?set=1"),
        "https://idp.example/keys?set=1"
    );
}

#[test]
fn far_end_url_and_host_displays_use_the_existing_untrusted_bound() {
    let path = format!(
        "https://user:SecretBeforeCap@idp.example/{}",
        "x".repeat(4096)
    );
    let display = shown(&path);
    assert!(!display.contains("SecretBeforeCap"));
    assert!(display.ends_with('…'));
    assert!(display.len() < 100);
    let host = format!("{}\nHostCanary", "a".repeat(4096));
    let refusal = refusal(&host, "is refused");
    assert!(refusal.len() < 150);
    assert!(!refusal.contains("HostCanary"));
}
