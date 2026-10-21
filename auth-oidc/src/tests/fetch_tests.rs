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
}

/// A scripted far end for [`follow`]: `answers` by URL, every URL asked recorded in order; a URL
/// in `pend` answers PENDING on its first ask (an exchange whose first read pends).
struct Far {
    answers: Vec<(String, ExchangeResponse)>,
    asked: Vec<String>,
    pend: Vec<String>,
}

impl Far {
    fn new(answers: &[(&str, ExchangeResponse)]) -> Self {
        Self {
            answers: answers
                .iter()
                .map(|(u, r)| ((*u).to_string(), r.clone()))
                .collect(),
            asked: Vec::new(),
            pend: Vec::new(),
        }
    }

    fn one(&mut self, at: &str) -> Poll<Result<ExchangeResponse, String>> {
        self.asked.push(at.to_string());
        if let Some(i) = self.pend.iter().position(|u| u == at) {
            self.pend.remove(i);
            return Poll::Pending;
        }
        Poll::Ready(
            self.answers
                .iter()
                .find(|(u, _)| u == at)
                .map(|(_, r)| r.clone())
                .ok_or_else(|| "nothing answers here".to_string()),
        )
    }

    fn get(&mut self, url: &str) -> Result<String, String> {
        let mut chain = None;
        loop {
            if let Poll::Ready(r) = follow(url, &mut chain, |hop| self.one(hop.at)) {
                return r;
            }
        }
    }
}

fn moved(status: u16, location: &str) -> ExchangeResponse {
    ExchangeResponse {
        status,
        reason: None,
        fields: vec![(b"location".to_vec(), location.as_bytes().to_vec())],
        body: Vec::new(),
    }
}

fn served(body: &str) -> ExchangeResponse {
    ExchangeResponse {
        status: 200,
        reason: None,
        fields: Vec::new(),
        body: body.as_bytes().to_vec(),
    }
}

const DISCOVERY: &str = "https://idp.example/tenant/v2.0/.well-known/openid-configuration";

/// A REDIRECTED DISCOVERY IS SERVED, as 1.5.5's client followed it (reqwest's default policy):
/// a relative `location` is resolved against the URL asked, and the document it leads to is the
/// answer. This replaces the assertion that pinned a redirected GET as "returned HTTP 302 Found",
/// which 1.5.5 never answered: it followed the redirect.
#[test]
fn a_redirected_discovery_is_followed_to_its_document() {
    let mut far = Far::new(&[
        (DISCOVERY, moved(301, "/tenant/v2.0/openid")),
        (
            "https://idp.example/tenant/v2.0/openid",
            served("{\"issuer\":1}"),
        ),
    ]);
    assert_eq!(far.get(DISCOVERY).as_deref(), Ok("{\"issuer\":1}"));
    assert_eq!(
        far.asked,
        vec![DISCOVERY, "https://idp.example/tenant/v2.0/openid"]
    );
}

/// A REDIRECTED KEY SET IS SERVED, across every redirect status 1.5.5's client followed, to
/// another https host, and across PENDING: the hop in flight is resumed, not asked from the start.
#[test]
fn a_redirected_key_set_is_followed_across_pending() {
    for status in [301, 302, 303, 307, 308] {
        let mut far = Far::new(&[
            (URL, moved(status, "https://keys.idp-cdn.example/jwks")),
            ("https://keys.idp-cdn.example/jwks", served("{\"keys\":[]}")),
        ]);
        far.pend = vec![
            URL.to_string(),
            "https://keys.idp-cdn.example/jwks".to_string(),
        ];
        assert_eq!(far.get(URL).as_deref(), Ok("{\"keys\":[]}"), "{status}");
        assert_eq!(
            far.asked,
            vec![
                URL,
                URL,
                "https://keys.idp-cdn.example/jwks",
                "https://keys.idp-cdn.example/jwks"
            ],
            "{status}: each request asked once, then re-asked once on its wake"
        );
    }
}

/// AT MOST TEN REDIRECTS (1.5.5's client, `limited(10)`): a chain of ten is served, an eleventh
/// redirect is refused without being asked for.
#[test]
fn the_eleventh_redirect_is_refused() {
    let hop = |n: usize| format!("https://idp.example/hop/{n}");
    let chain = |len: usize| {
        let mut answers: Vec<(String, ExchangeResponse)> = (0..len)
            .map(|n| (hop(n), moved(302, &hop(n + 1))))
            .collect();
        answers.push((hop(len), served("{}")));
        answers
    };
    let ten = chain(10);
    let refs: Vec<(&str, ExchangeResponse)> =
        ten.iter().map(|(u, r)| (u.as_str(), r.clone())).collect();
    assert_eq!(Far::new(&refs).get(&hop(0)).as_deref(), Ok("{}"));

    let eleven = chain(11);
    let refs: Vec<(&str, ExchangeResponse)> = eleven
        .iter()
        .map(|(u, r)| (u.as_str(), r.clone()))
        .collect();
    let mut far = Far::new(&refs);
    assert_eq!(
        far.get(&hop(0)),
        Err(
            "request to https://idp.example/hop/0 failed: error following redirect for url \
             (https://idp.example/hop/10)"
                .to_string()
        )
    );
    assert_eq!(
        far.asked.len(),
        11,
        "the eleventh redirect's target is never asked"
    );
    assert!(!far.asked.contains(&hop(11)));
}

/// A REDIRECT TO PLAINTEXT IS REFUSED (1.5.5's `https_only` client), before it is asked.
#[test]
fn a_redirect_to_http_is_refused() {
    let mut far = Far::new(&[(URL, moved(302, "http://idp.example/jwks"))]);
    assert_eq!(
        far.get(URL),
        Err(
            "request to https://idp.example/jwks failed: error following redirect for url \
             (http://idp.example/jwks)"
                .to_string()
        )
    );
    assert_eq!(far.asked, vec![URL]);
}

/// A PUBLIC-TO-PUBLIC https REDIRECT IS FOLLOWED, as 1.5.5's client followed every https target
/// (reqwest's default policy under `https_only`: busbar-auth-oidc v1.0.6 `reqwest_fetcher.rs`).
#[test]
fn a_public_to_public_https_redirect_is_followed() {
    for to in [
        "https://keys.idp-cdn.example/jwks",
        "https://other.example/realms/x/keys",
        "https://203.0.113.9/keys",
    ] {
        let mut far = Far::new(&[(URL, moved(307, to)), (to, served("{}"))]);
        assert_eq!(far.get(URL).as_deref(), Ok("{}"), "{to}");
        assert_eq!(far.asked, vec![URL, to]);
    }
}

/// A REDIRECT TO A METADATA ADDRESS IS REFUSED (owner-approved 2026-10-21), and a redirect from a PUBLIC host to a private or
/// loopback one is refused, before either is asked for: a public IdP cannot bounce the module's
/// GET into the node's own network. A private IdP is followed within private addresses, its own
/// host or another, as 1.5.5's client followed it (reqwest's default policy, no address check:
/// busbar-auth-oidc v1.0.6 `reqwest_fetcher.rs`).
#[test]
fn a_redirect_to_a_private_or_metadata_address_is_refused() {
    const METADATA: &str = "a redirect to a cloud metadata address is not allowed";
    const PRIVATE: &str = "a redirect to a private or loopback address is not allowed";
    for to in [
        "https://169.254.169.254/latest/meta-data/",
        "https://metadata.google.internal/computeMetadata/v1/",
        "https://[fd00:ec2::254]/",
        "https://[fe80::1]/keys",
        // The same address in the spellings a connecting stack maps to it: IPv4-mapped, NAT64
        // (well-known), 6to4.
        "https://[::ffff:169.254.169.254]/",
        "https://[64:ff9b::a9fe:a9fe]/",
        "https://[2002:a9fe:a9fe::]/",
    ] {
        let mut far = Far::new(&[(URL, moved(302, to))]);
        assert_eq!(
            far.get(URL),
            Err(format!("request to {URL} failed: {METADATA}")),
            "{to}"
        );
        assert_eq!(far.asked, vec![URL], "{to} is never asked");
    }
    // A PRIVATE host redirecting to a metadata address is refused too (the metadata check is
    // first and holds from private hosts).
    let private_idp = "https://10.0.0.7/realms/corp/keys";
    for to in [
        "https://169.254.169.254/latest/meta-data/",
        "https://[::ffff:169.254.169.254]/",
    ] {
        let mut far = Far::new(&[(private_idp, moved(302, to))]);
        assert_eq!(
            far.get(private_idp),
            Err(format!("request to {private_idp} failed: {METADATA}")),
            "{to}"
        );
    }
    // PUBLIC to private, in the spellings that map to a private IPv4 target.
    for to in [
        "https://[::ffff:10.0.0.7]/keys",
        "https://[64:ff9b::a00:7]/keys",
        "https://[2002:a00:7::]/keys",
        "https://[::ffff:127.0.0.1]/keys",
    ] {
        let mut far = Far::new(&[(URL, moved(307, to))]);
        assert_eq!(
            far.get(URL),
            Err(format!("request to {URL} failed: {PRIVATE}")),
            "{to}"
        );
        assert_eq!(far.asked, vec![URL], "{to} is never asked");
    }
    // The checks read the LITERAL host: a DNS name that merely resolves private is followed (the
    // host's dial guard judges the connection).
    let mut far = Far::new(&[
        (URL, moved(302, "https://keycloak.corp/keys")),
        ("https://keycloak.corp/keys", served("{}")),
    ]);
    assert_eq!(far.get(URL).as_deref(), Ok("{}"));
    for to in [
        "https://10.0.0.7/keys",
        "https://127.0.0.1/keys",
        "https://localhost/keys",
        "https://[fd00::5]/keys",
    ] {
        let mut far = Far::new(&[(URL, moved(307, to))]);
        assert_eq!(
            far.get(URL),
            Err(format!(
                "request to {URL} failed: a redirect to a private or loopback address is not \
                 allowed"
            ))
        );
        assert_eq!(far.asked, vec![URL], "{to} is never asked");
    }
    let private = "https://10.0.0.7/realms/corp/.well-known/openid-configuration";
    let mut far = Far::new(&[
        (private, moved(302, "/realms/corp/openid")),
        ("https://10.0.0.7/realms/corp/openid", served("{}")),
    ]);
    assert_eq!(far.get(private).as_deref(), Ok("{}"));
    let mut far = Far::new(&[
        (private, moved(307, "https://192.168.4.2/keys")),
        ("https://192.168.4.2/keys", served("{}")),
    ]);
    assert_eq!(far.get(private).as_deref(), Ok("{}"));
    // Public to private is refused at whichever hop it comes: a private IdP sent out to a public
    // host is not let back into the private network by it.
    let mut far = Far::new(&[
        (private, moved(302, "https://cdn.idp.example/jwks")),
        (
            "https://cdn.idp.example/jwks",
            moved(302, "https://10.0.0.8/jwks"),
        ),
    ]);
    assert_eq!(
        far.get(private),
        Err(
            "request to https://10.0.0.7/realms/corp/.well-known/openid-configuration failed: \
             a redirect to a private or loopback address is not allowed"
                .to_string()
        )
    );
    assert_eq!(far.asked, vec![private, "https://cdn.idp.example/jwks"]);
}

/// A REDIRECT TO A SCHEME THAT IS NEITHER http NOR https is reqwest's builder error, naming the
/// target (reqwest 0.12.28 `redirect.rs`: `url_bad_scheme` before the https-only check).
#[test]
fn a_redirect_to_another_scheme_is_reqwests_builder_error() {
    let mut far = Far::new(&[(URL, moved(302, "ftp://idp.example/jwks"))]);
    assert_eq!(
        far.get(URL),
        Err(
            "request to https://idp.example/jwks failed: builder error for url \
             (ftp://idp.example/jwks)"
                .to_string()
        )
    );
}

/// A 3xx that is no redirect 1.5.5's client followed (no `location`, or a status it does not
/// follow) is judged as the document it is: a non-2xx, named as 1.5.5 named it.
#[test]
fn a_3xx_with_nowhere_to_go_is_a_non_2xx_answer() {
    let bare = ExchangeResponse {
        status: 302,
        ..ExchangeResponse::default()
    };
    let mut far = Far::new(&[(URL, bare)]);
    assert_eq!(
        far.get(URL),
        Err("https://idp.example/jwks returned HTTP 302 Found".to_string())
    );
    let mut far = Far::new(&[(URL, moved(304, "https://idp.example/other"))]);
    assert_eq!(
        far.get(URL),
        Err("https://idp.example/jwks returned HTTP 304 Not Modified".to_string())
    );
    assert_eq!(far.asked, vec![URL]);
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
    let r = get_request(&url, None, FETCH_TIMEOUT_MS);
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
            "request to http://idp.example/jwks failed: builder error for url \
             (http://idp.example/jwks)"
                .to_string()
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
        assert_eq!(n.transport.len(), "http".len(), "need {i}");
        let trust = if (i as u32) < PUBLIC {
            "settings.ca_cert_pem".len()
        } else {
            0
        };
        assert_eq!(n.trust_from.len(), trust, "need {i}");
        assert_eq!(n.timeout_ms, FETCH_TIMEOUT_MS, "need {i}");
    }
    for anchored in [true, false] {
        assert_eq!(
            NEEDS[on(NEED_DISCOVERY, anchored) as usize]
                .target_from
                .len(),
            "settings.issuer".len()
        );
        assert_eq!(NEEDS[on(NEED_JWKS, anchored) as usize].target_from.len(), 0);
        assert_eq!(
            NEEDS[on(NEED_TOKEN, anchored) as usize].target_from.len(),
            0
        );
    }
    assert_eq!(
        (on(NEED_JWKS, true), on(NEED_JWKS, false)),
        (NEED_JWKS, NEED_JWKS + PUBLIC)
    );
    // The document needs read back `location` (to follow a redirect); the token need reads none.
    for anchored in [true, false] {
        for need in [NEED_DISCOVERY, NEED_JWKS] {
            let n = &NEEDS[on(need, anchored) as usize];
            assert_eq!(n.keep_mode, KEEP_NAMED);
            assert_eq!(n.keep_response_headers_len(), 1);
            assert!(!n.keep_response_headers_ptr().is_null());
        }
        let token = &NEEDS[on(NEED_TOKEN, anchored) as usize];
        assert_eq!(token.keep_response_headers_len(), 0);
    }
    assert_eq!(KEEP_LOCATION.len(), 1);
    assert_eq!(KEEP_LOCATION[0].len(), "location".len());
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
                "request to {url} failed: builder error for url ({url})"
            ))),
        );
        assert!(!plaintext_allowed(doc.need(), url), "{url}");
    }
    assert!(plaintext_allowed(NEED_TOKEN, "http://10.1.2.3/token"));
    assert!(!plaintext_allowed(NEED_TOKEN, "https://10.1.2.3/token"));
}

/// A REDIRECT HOP GOES OUT ON THE UNTARGETED NEED (a redirect may leave the issuer's host, which
/// the discovery need, pinned to the issuer's target, refuses); the first hop on its document's own.
#[test]
fn a_redirect_hop_goes_out_on_the_untargeted_need() {
    assert_eq!(need_for_hop(Doc::Discovery, 0), NEED_DISCOVERY);
    assert_eq!(need_for_hop(Doc::Jwks, 0), NEED_JWKS);
    for doc in [Doc::Discovery, Doc::Jwks] {
        for hops in 1..=MAX_REDIRECTS {
            assert_eq!(need_for_hop(doc, hops), NEED_JWKS);
        }
    }
    for anchored in [true, false] {
        let hop_need = &NEEDS[on(need_for_hop(Doc::Discovery, 1), anchored) as usize];
        assert!(hop_need.target_from.is_empty(), "no pinned target");
        assert_eq!(
            hop_need.keep_response_headers_len(),
            1,
            "it reads `location` back"
        );
    }
}

/// A REDIRECT HOP CARRIES A `Referer` (reqwest's `make_referer`): the previous URL without userinfo
/// or fragment; the first hop none.
#[test]
fn a_redirect_hop_carries_the_previous_url_as_its_referer() {
    let mut seen: Vec<(String, u8, Option<String>)> = Vec::new();
    let mut chain = None;
    let answers = [
        (
            "https://u:p@idp.example/a#frag",
            moved(302, "https://cdn.example/b"),
        ),
        ("https://cdn.example/b", moved(302, "/c")),
        ("https://cdn.example/c", served("{}")),
    ];
    let got = follow("https://u:p@idp.example/a#frag", &mut chain, |hop| {
        seen.push((hop.at.to_string(), hop.hops, hop.from.map(str::to_string)));
        let r = answers
            .iter()
            .find(|(u, _)| url::Url::parse(u).unwrap().as_str() == hop.at);
        Poll::Ready(Ok(r.expect("scripted").1.clone()))
    });
    assert_eq!(got, Poll::Ready(Ok("{}".to_string())));
    assert_eq!(seen[0].2, None);
    assert_eq!(seen[1].2.as_deref(), Some("https://idp.example/a"));
    assert_eq!(seen[2].2.as_deref(), Some("https://cdn.example/b"));
    let r = get_request(
        &url::Url::parse("https://cdn.example/b").unwrap(),
        Some("https://idp.example/a"),
        7_000,
    );
    assert!(r
        .fields
        .contains(&(b"referer".to_vec(), b"https://idp.example/a".to_vec())));
    assert_eq!(r.timeout_ms, 7_000);
}

/// EVERY ERROR NAMES THE URL ASKED, whichever hop failed (1.5.5's `request to {url} failed: ..`).
#[test]
fn a_redirect_hop_failure_names_the_url_asked() {
    let mut far = Far::new(&[(URL, moved(302, "https://cdn.idp.example/jwks"))]);
    assert_eq!(
        far.get(URL),
        Err(format!("request to {URL} failed: nothing answers here"))
    );
}

/// THE HOST HANDLE'S DEBUG NAMES NO REQUEST IN FLIGHT (its form body is the encoded client secret).
#[test]
fn the_io_debug_prints_no_exchange_state() {
    let url = url::Url::parse("https://idp.example/token").unwrap();
    let mut h = hop();
    h.form
        .push(("client_secret".to_string(), "hunter2-secret".to_string()));
    let ex = Exchange::request(post_request(&url, &h, Some("hunter2-secret"))).unwrap();
    let state = IoState {
        current: Some((url.to_string(), ex)),
        ..IoState::default()
    };
    let io = HostIo::new(None, Ticket::NONE, state, false);
    assert!(!format!("{io:?}").contains("hunter2"));
}

/// THE CHAIN'S ONE DEADLINE: 10s from the first request. Under it the rest is left; exactly at it
/// and over it nothing is, and the error is reqwest's timed-out request naming the URL asked.
#[test]
fn the_chain_deadline_is_one_ten_second_budget() {
    const MS: u64 = 1_000_000;
    assert_eq!(chain_left_ms(5 * MS, 5 * MS, URL), Ok(FETCH_TIMEOUT_MS));
    assert_eq!(chain_left_ms(0, 9_999 * MS, URL), Ok(1));
    let spent = Err("error sending request for url (https://idp.example/jwks)".to_string());
    assert_eq!(chain_left_ms(0, 10_000 * MS, URL), spent);
    assert_eq!(chain_left_ms(0, 25_000 * MS, URL), spent);
    // A clock that reads earlier than the start leaves the whole budget.
    assert_eq!(chain_left_ms(9 * MS, 3 * MS, URL), Ok(FETCH_TIMEOUT_MS));
}

/// EVERY SEND FAILURE OF A DOCUMENT GET prints reqwest's `error sending request for url (<asked>)`,
/// whatever the connector said (the harness cannot drive a connector failure at this pin, so the
/// mapping `run` applies is tested directly); the token exchange keeps its own text.
#[test]
fn a_document_send_failure_is_reqwests_error_sending_request() {
    for cause in [
        "the connector failed the call",
        "refused: the destination is not allowed",
        "tls: certificate verify failed",
        "timeout: deadline has elapsed",
    ] {
        for need in [
            NEED_DISCOVERY,
            NEED_JWKS,
            PUBLIC + NEED_DISCOVERY,
            PUBLIC + NEED_JWKS,
        ] {
            assert_eq!(
                send_failure(need, URL, cause),
                "error sending request for url (https://idp.example/jwks)"
            );
        }
        assert_eq!(send_failure(NEED_TOKEN, URL, cause), cause);
    }
}

/// A REPLY PAST THE SDK'S BOUND is 1.5.5's cap text for the URL asked, with no `request to .. failed:`
/// prefix (v1.0.6 `read_capped`); the cap is 1.5.5's 1 MiB, enforced here (the SDK's bound is 16 MiB),
/// so a body between the two is refused by `capped` as 1.5.5 refused it.
#[test]
fn a_reply_past_the_bound_is_1_5_5_s_cap_text_unprefixed() {
    let over = send_failure(
        NEED_JWKS,
        URL,
        busbar_contract::abi::sdk::exchange::REPLY_OVER_BOUND,
    );
    assert_eq!(
        over,
        "https://idp.example/jwks JWKS body exceeds the 1048576-byte cap"
    );
    // follow() passes it through unwrapped.
    let mut chain = None;
    let got = follow(URL, &mut chain, |_| Poll::Ready(Err(over.clone())));
    assert_eq!(got, Poll::Ready(Err(over)));
    // 2 MiB: under the SDK's bound, over 1.5.5's cap.
    assert_eq!(
        capped(URL, vec![b' '; 2 * 1024 * 1024], MAX_JWKS_BYTES).unwrap_err(),
        "https://idp.example/jwks JWKS body exceeds the 1048576-byte cap"
    );
}

/// A HOP IN FLIGHT IS JUDGED AGAINST THE DEADLINE TOO (the host's timeout ends at the first piece of
/// the answer, so a trickling body is bounded here): with the budget spent it is driven once more
/// and given up only if still pending. The unit harness has no host clock or connector, so what is
/// tested is the predicate `get_hop` branches on and the deadline it applies; the end-to-end REDs `red_a_body_trickling_past_the_budget_is_given_up_and_closed`, `red_an_abandoned_refresh_counts_its_handles_so_the_rotation_refetch_goes_out_fresh`, `red_a_body_that_stalls_dead_times_out_at_ten_seconds` and `red_a_token_endpoint_that_stalls_is_an_outage_after_ten_seconds` drive the rest.
#[test]
fn a_hop_in_flight_is_resumed_but_judged_against_the_deadline() {
    const MS: u64 = 1_000_000;
    assert!(chain_left_ms(0, 12_000 * MS, URL).is_err());
    let mut io = HostIo::new(None, Ticket::NONE, IoState::default(), false);
    let url = url::Url::parse(URL).unwrap();
    let ex = Exchange::request(get_request(&url, None, 1_000)).unwrap();
    io.state_mut_for_test().current = Some((URL.to_string(), ex));
    assert!(io.resumes(URL));
    assert!(!io.resumes("https://idp.example/other"));
}
