// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MODULE'S WAY OUT, THROUGH THE HOST (THE DESIGN 5, Connections: "No plugin opens a socket,
//! dials, binds or does TLS"; OWNER LAW 2026-09-27: the reqwest users move onto kernel
//! transports). The module states three outbound needs ([`NEEDS`]) and makes every request as ONE
//! framed `exchange()` over the host's connector ([`HostIo`]): the issuer's discovery document, the
//! JWKS, and the login's code-for-token POST. Each answers PENDING while it is in flight and is
//! re-asked when the op re-enters on its wake (the replay rule, `abi::sdk::conn`).
//!
//! Every need is `operator-infrastructure` (ARCHITECT ruling 2026-10-09; the class the oauth
//! plugin's mint needs take): private and loopback destinations allowed, plaintext allowed by the
//! class, cloud metadata refused, the destination guard applying. The module narrows the scheme to
//! exactly what 1.5.5 accepted ([`plaintext_allowed`]): discovery and the JWKS https only (1.5.5's
//! `https_only` fetcher); the token exchange https, or plaintext to a private or loopback host only
//! (1.5.5 `auth/token.rs` `vet_hop_url`: a public host must use https). Every need rides the `http`
//! transport, its connections secured by the target's `https` scheme (the connector's TLS). The
//! discovery need is pinned to the `issuer` setting's target (`target_from`); the JWKS and token
//! endpoints may be discovered, so the module names them per request.
//!
//! `ca_cert_pem` is OPTIONAL, as it was in 1.5.5 (an extra root on top of the public ones, never a
//! replacement). The host's connector refuses a need whose `trust_from` resolves to nothing, so
//! the three needs are stated twice: the ANCHORED set trusts `ca_cert_pem` (`trust_from`), the
//! PUBLIC set trusts the public roots only. A module whose settings name a `ca_cert_pem` goes out
//! on the anchored set, any other on the public set ([`HostIo::new`]); the set it does not use is
//! never asked for a connection (the anchored set of a module with no `ca_cert_pem` is refused at
//! declaration, and stays unused).
//!
//! What the module reads back keeps 1.5.5's words: [`document`] (a non-2xx GET, the 1 MiB cap, a
//! body that is not UTF-8) and [`failed`] (a request that never got an answer, the connector's own
//! text after 1.5.5's prefix).
//!
//! A discovery or JWKS GET answered with a redirect is followed as 1.5.5's client followed it
//! ([`follow`]): at most [`MAX_REDIRECTS`], https only, each hop a fresh exchange on the same need,
//! so through the host's destination guard again (and, for discovery, held to the need's pinned
//! target); a hop to a cloud-metadata address is refused before it is asked for, and so is a hop
//! from a public host to a private or loopback one.

use std::fmt::Display;
use std::task::Poll;

use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_OPERATOR_INFRASTRUCTURE, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::conn::{ConnFailure, Host};
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::abi::sdk::exchange::{exchange, Exchange, ExchangeResponse, Request};
use busbar_contract::abi::sdk::net::{
    extract_normalized_host, host_is_cloud_metadata, host_is_link_local_v6,
    host_is_private_or_loopback, scheme_is,
};
use busbar_contract::auth::{LoginHop, LoginHttpResponse};

/// Upper bound on a JWKS / discovery document, and on a token endpoint's answer. A real JWKS is a
/// handful of keys — a few KiB; even a tenant rotating aggressively stays well under this. The bound
/// exists because the body arrives from a remote IdP whose `jwks_uri` is itself read out of a remote
/// discovery document.
pub const MAX_JWKS_BYTES: usize = 1024 * 1024;

/// The bound on one request, milliseconds: 1.5.5's 10s fetch timeout. Generous enough for a cold
/// DNS + TLS handshake to a public IdP, short enough that a hung endpoint cannot hold an op.
pub const FETCH_TIMEOUT_MS: u64 = 10_000;

/// The need the discovery document is fetched on (its index in [`NEEDS`], anchored set).
pub const NEED_DISCOVERY: u32 = 0;
/// The need the JWKS is fetched on (anchored set).
pub const NEED_JWKS: u32 = 1;
/// The need the login's token exchange is made on (anchored set).
pub const NEED_TOKEN: u32 = 2;
/// Where the PUBLIC set starts in [`NEEDS`]: its needs are the anchored set's, in the same order,
/// at this offset.
pub const PUBLIC: u32 = 3;

/// The most redirects one GET follows: 1.5.5's client's (reqwest's default policy, `limited(10)`):
/// the tenth is followed, an eleventh is refused.
pub const MAX_REDIRECTS: u8 = 10;

/// The response head fields a document GET reads: `location`, to follow a redirect.
const KEEP_LOCATION: &[AbiStr] = &[abi_str("location")];
/// The response head fields the token exchange reads: none.
const KEEP_NONE: &[AbiStr] = &[];

/// The setting the discovery need's target comes from (a config path the host reads).
const ISSUER_PATH: &str = "settings.issuer";
/// The setting every need's extra trusted root comes from.
const CA_CERT_PATH: &str = "settings.ca_cert_pem";

const ABSENT: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

/// The egress class of every need: `operator-infrastructure` (ARCHITECT ruling 2026-10-09). 1.5.5
/// accepted a plaintext token endpoint on a PRIVATE host, not only on loopback (`auth/token.rs`
/// `vet_hop_url`), which `open-web` (secure only) and `loopback-allowed` (plaintext to loopback
/// only) would both refuse at the connector. The discovery and JWKS fetches are 1.5.5's too: the
/// v1.0.6 module (shipped with 1.5.5) fetched both through a plain client with no address guard
/// (`auth-oidc/src/reqwest_fetcher.rs`, `reqwest::blocking::Client::builder()`), and its
/// `ca_cert_pem` setting exists for an on-prem IdP on an internal host (an internal-CA Keycloak,
/// `auth-oidc/src/lib.rs` `ca_cert_pem`), so an IdP on a private address, a discovered `jwks_uri`
/// among them, is served as 1.5.5 served it. The guarded `open-web` class would refuse it.
pub const EGRESS_CLASS: u32 = EGRESS_OPERATOR_INFRASTRUCTURE;

/// One outbound need over the `http` transport (the scheme the http framer claims) in
/// [`EGRESS_CLASS`], trusting the root `trust_from` names beside the public roots (`ABSENT`: the
/// public roots only), reading back the response head fields `keep` names.
const fn need(target_from: AbiStr, trust_from: AbiStr, keep: &'static [AbiStr]) -> Need {
    Need {
        direction: DIRECTION_OUTBOUND,
        egress_class: EGRESS_CLASS,
        transport: abi_str("http"),
        auth: ABSENT,
        target_from,
        trust_from,
        details: Blob::ABSENT,
        keep_response_headers: if keep.is_empty() {
            std::ptr::null()
        } else {
            keep.as_ptr()
        },
        keep_response_headers_len: keep.len(),
        timeout_ms: FETCH_TIMEOUT_MS,
        keep_mode: KEEP_NAMED,
        _reserved: 0,
        deny_response_headers: std::ptr::null(),
        deny_response_headers_len: 0,
    }
}

/// THE NEEDS, in index order: the ANCHORED set (trusting `ca_cert_pem`), then the PUBLIC set
/// (from [`PUBLIC`] on, the public roots only); each set is discovery (pinned to the `issuer`
/// setting's target), the JWKS and the token endpoint (named per request: either may be
/// discovered). The two document needs read back `location`, to follow a redirect.
pub const NEEDS: &[Need] = &[
    need(abi_str(ISSUER_PATH), abi_str(CA_CERT_PATH), KEEP_LOCATION),
    need(ABSENT, abi_str(CA_CERT_PATH), KEEP_LOCATION),
    need(ABSENT, abi_str(CA_CERT_PATH), KEEP_NONE),
    need(abi_str(ISSUER_PATH), ABSENT, KEEP_LOCATION),
    need(ABSENT, ABSENT, KEEP_LOCATION),
    need(ABSENT, ABSENT, KEEP_NONE),
];

/// The need index `need` (an anchored-set index) goes out on: itself for a module that trusts an
/// operator CA, its public twin for one that does not.
pub const fn on(need: u32, anchored: bool) -> u32 {
    if anchored {
        need
    } else {
        need + PUBLIC
    }
}

/// Which document a GET fetches, so which need it goes out on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Doc {
    /// The issuer's OIDC discovery document.
    Discovery,
    /// The JWKS.
    Jwks,
}

impl Doc {
    const fn need(self) -> u32 {
        match self {
            Self::Discovery => NEED_DISCOVERY,
            Self::Jwks => NEED_JWKS,
        }
    }
}

/// THE MODULE'S I/O SEAM: one request, answered `Pending` while it is in flight and asked again
/// (same request, same order) when the op re-enters. The door implements it over the host's
/// connector ([`HostIo`]); tests answer from a script.
pub trait Fetch {
    /// The op making the requests: the owner of any fetch it claims. `None` when the call runs on
    /// no ticket, which may not pend, so may neither fetch nor wait.
    fn caller(&self) -> Option<Ticket>;

    /// GET `doc` at `url`, following its redirects ([`follow`]): the body of the 2xx answer, or
    /// 1.5.5's error text ([`document`], [`failed`]).
    fn get(&mut self, doc: Doc, url: &str) -> Poll<Result<String, String>>;

    /// A request to `url` this op would have to make, or wait on, but cannot: it runs on no ticket
    /// and may not pend. Answers the error the op reports (1.5.5's prefix, then why); a host-backed
    /// `Fetch` also notes that the op asked for I/O it could not wait on, so an answer reached
    /// without it is not the op's verdict ([`HostIo::wanted_io`]).
    fn cannot_pend(&mut self, url: &str) -> String {
        failed(url, ConnFailure::NoTicket)
    }

    /// WAKE the ops `waiters` names: they answered PENDING waiting on a fetch this caller made,
    /// which has now landed (THE DESIGN, auth: "one `exchange()` fetches, every waiter wakes"). A
    /// host-backed `Fetch` wakes each ticket through the host; the default wakes nothing.
    fn wake(&self, waiters: &[Ticket]) {
        let _ = waiters;
    }

    /// THE LOGIN TOKEN EXCHANGE, made by the plugin itself (THE DESIGN 6.7: an IdP login holds its
    /// own client secret and makes its own token exchange): `hop` sent as a form ([`form`]). The
    /// answer is the status and the body, whatever the status; a request that got no answer is
    /// `Err`.
    fn post(
        &mut self,
        hop: &LoginHop,
        secret: Option<&str>,
    ) -> Poll<Result<LoginHttpResponse, String>>;
}

/// Whether a request on `need` may go to `url` in plaintext, as 1.5.5 judged it: never for
/// discovery or the JWKS (1.5.5's fetcher was `https_only`); for the token exchange only when the
/// URL's host is private or loopback (1.5.5 `auth/token.rs` `vet_hop_url`: "https for public hosts;
/// http only for loopback/private (a local/on-prem IdP)"), read by the same host reader 1.5.5 used.
pub fn plaintext_allowed(need: u32, url: &str) -> bool {
    need == NEED_TOKEN
        && scheme_is(url, "http")
        && extract_normalized_host(url).is_some_and(|h| host_is_private_or_loopback(&h))
}

/// A request to `url` that got no answer: 1.5.5's prefix, then why.
pub fn failed(url: &str, why: impl Display) -> String {
    format!("request to {url} failed: {why}")
}

/// A GET's answer as the document it carries: a non-2xx status is refused naming the status as
/// 1.5.5's client printed it (`404 Not Found`), then the body is [`capped`].
///
/// # Errors
/// 1.5.5's texts: `"{url} returned HTTP {status}"`, or [`capped`]'s.
pub fn document(url: &str, status: u16, body: Vec<u8>) -> Result<String, String> {
    if !(200..300).contains(&status) {
        let shown = http::StatusCode::from_u16(status)
            .map_or_else(|_| status.to_string(), |s| s.to_string());
        return Err(format!("{url} returned HTTP {shown}"));
    }
    capped(url, body, MAX_JWKS_BYTES)
}

/// `body` as text, refusing anything over `cap` bytes or not UTF-8.
///
/// # Errors
/// 1.5.5's texts: `"{url} JWKS body exceeds the {cap}-byte cap"`, `"{url} JWKS body is not UTF-8"`.
pub fn capped(url: &str, body: Vec<u8>, cap: usize) -> Result<String, String> {
    if body.len() > cap {
        return Err(format!("{url} JWKS body exceeds the {cap}-byte cap"));
    }
    String::from_utf8(body).map_err(|_| format!("{url} JWKS body is not UTF-8"))
}

/// Where a GET answered `reply` at `at` is redirected, as 1.5.5's client read a redirect: a 301,
/// 302, 303, 307 or 308 whose `location` names a URL, resolved against `at`. `None` for any other
/// answer, which is judged as the document it is ([`document`]).
pub fn redirect(at: &str, reply: &ExchangeResponse) -> Option<String> {
    if !matches!(reply.status, 301 | 302 | 303 | 307 | 308) {
        return None;
    }
    let (_, location) = reply
        .fields
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(b"location"))?;
    let location = std::str::from_utf8(location).ok()?;
    let next = url::Url::parse(at).ok()?.join(location.trim()).ok()?;
    Some(next.into())
}

/// Why a redirect from `asked` (the hop that answered it) to `next` is not followed, if it is
/// not: a URL that is not https (1.5.5's `https_only` client refused it in the same words), a
/// cloud-metadata or IPv6 link-local host, or a private or loopback host when the host that
/// redirected is public.
///
/// 1.5.5's policy for these GETs was reqwest's default (`redirect::Policy::default()`, ten hops)
/// under `https_only`, with no address check (busbar-auth-oidc v1.0.6
/// `auth-oidc/src/reqwest_fetcher.rs`, `ReqwestFetcher::new`): an IdP on a private host (the
/// on-prem IdP `ca_cert_pem` exists for) was followed to any https host, its own or another
/// private one, and that stays served. A redirect never moves a GET from a public host into a
/// private network.
pub fn refused_hop(asked: &str, next: &str) -> Option<&'static str> {
    if !scheme_is(next, "https") {
        return Some("URL scheme is not allowed");
    }
    let Some(host) = extract_normalized_host(next) else {
        return Some("the redirect names no host");
    };
    if host_is_cloud_metadata(&host) || host_is_link_local_v6(&host) {
        return Some("a redirect to a cloud metadata address is not allowed");
    }
    let from_private =
        extract_normalized_host(asked).is_some_and(|a| host_is_private_or_loopback(&a));
    if host_is_private_or_loopback(&host) && !from_private {
        return Some("a redirect to a private or loopback address is not allowed");
    }
    None
}

/// Where a redirected GET stands across PENDING: the URL asked, the hop in flight, and how many
/// redirects led to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirected {
    asked: String,
    at: String,
    hops: u8,
}

/// THE GET OF `url`, FOLLOWED (1.5.5's client: reqwest's default redirect policy under
/// `https_only`): `one` makes a single exchange; a redirect ([`redirect`]) is asked for again at
/// the URL it names, at most [`MAX_REDIRECTS`] times, each hop vetted first ([`refused_hop`]); the
/// first answer that is no redirect is judged as the document ([`document`], named by `url`, the
/// URL asked, as 1.5.5 named it). A hop in flight is parked in `chain` across PENDING and resumed
/// when the same `url` is asked again.
///
/// # Errors
/// [`document`]'s; `one`'s; a refused hop or an eleventh redirect, after 1.5.5's prefix.
pub fn follow(
    url: &str,
    chain: &mut Option<Redirected>,
    mut one: impl FnMut(&str) -> Poll<Result<ExchangeResponse, String>>,
) -> Poll<Result<String, String>> {
    let (mut at, mut hops) = match chain.take() {
        Some(r) if r.asked == url => (r.at, r.hops),
        _ => (url.to_string(), 0),
    };
    loop {
        let reply = match one(&at) {
            Poll::Pending => {
                if hops > 0 {
                    *chain = Some(Redirected {
                        asked: url.to_string(),
                        at,
                        hops,
                    });
                }
                return Poll::Pending;
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(reply)) => reply,
        };
        let Some(next) = redirect(&at, &reply) else {
            return Poll::Ready(document(url, reply.status, reply.body));
        };
        if hops >= MAX_REDIRECTS {
            return Poll::Ready(Err(failed(url, "too many redirects")));
        }
        if let Some(why) = refused_hop(&at, &next) {
            return Poll::Ready(Err(failed(&next, why)));
        }
        hops += 1;
        at = next;
    }
}

/// The form `hop` is sent as, as 1.5.5's core sent it, with `secret` filling the field
/// `hop.secret_form_field` names. With no secret lent, that field is dropped rather than sent empty
/// (a public client sends none).
pub fn form(hop: &LoginHop, secret: Option<&str>) -> Vec<(String, String)> {
    let mut form = hop.form.clone();
    if let Some(field) = hop.secret_form_field.as_deref() {
        match secret {
            Some(secret) => match form.iter_mut().find(|(k, _)| k == field) {
                Some(slot) => slot.1 = secret.to_string(),
                None => form.push((field.to_string(), secret.to_string())),
            },
            None => form.retain(|(k, _)| k != field),
        }
    }
    form
}

/// The path and query a request to `url` names.
fn head_target(url: &url::Url) -> Vec<u8> {
    match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    }
    .into_bytes()
}

/// The GET of `url`, as 1.5.5's client sent it.
pub fn get_request(url: &url::Url) -> Request {
    Request {
        method: b"GET".to_vec(),
        target: head_target(url),
        fields: vec![(b"accept".to_vec(), b"*/*".to_vec())],
        body: Vec::new(),
        timeout_ms: FETCH_TIMEOUT_MS,
    }
}

/// The token exchange `hop` to `url` with `secret`: its method (POST when it names none a request
/// can carry), the form url-encoded as 1.5.5's client encoded it, then the hop's own fields.
pub fn post_request(url: &url::Url, hop: &LoginHop, secret: Option<&str>) -> Request {
    let method = http::Method::from_bytes(hop.method.as_bytes()).unwrap_or(http::Method::POST);
    // The form holds the lent client secret: its pairs are wiped once the body is encoded. The
    // encoded body itself rides the SDK's `exchange::Request`, whose `body` the plugin cannot
    // wipe; wiping it on drop is the contract SDK's (asked of the contract PR, busbar
    // lane-kernel-head-defaults).
    let mut pairs = form(hop, secret);
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs.iter())
        .finish();
    for (name, value) in &mut pairs {
        zeroize::Zeroize::zeroize(name);
        zeroize::Zeroize::zeroize(value);
    }
    // 1.5.5's order: the form's content-type, then the client's `accept` (the oracle's
    // `egress.auth|login-hop|oidc` cell holds the wire bytes).
    let mut fields = vec![
        (
            b"content-type".to_vec(),
            b"application/x-www-form-urlencoded".to_vec(),
        ),
        (b"accept".to_vec(), b"*/*".to_vec()),
    ];
    fields.extend(
        hop.headers
            .iter()
            .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec())),
    );
    Request {
        method: method.as_str().as_bytes().to_vec(),
        target: head_target(url),
        fields,
        body: body.into_bytes(),
        timeout_ms: FETCH_TIMEOUT_MS,
    }
}

/// What an op parks of its requests across PENDING: the handles its finished exchanges issued, the
/// exchange in flight (with the URL it fetches), and the redirects a GET has followed to it.
#[derive(Debug, Default)]
pub struct IoState {
    issued: u32,
    current: Option<(String, Exchange)>,
    redirected: Option<Redirected>,
}

/// [`Fetch`] over the host's connector, for ONE entry of one op on `ticket`.
#[derive(Debug)]
pub struct HostIo<'h> {
    host: Option<&'h Host>,
    ticket: Ticket,
    state: IoState,
    anchored: bool,
    wanted: bool,
}

impl<'h> HostIo<'h> {
    /// The op's requests on `ticket` through `host`'s connector, resumed from `state`, on the
    /// ANCHORED needs when the module's settings name a `ca_cert_pem` (`anchored`), else on the
    /// PUBLIC ones.
    pub fn new(host: Option<&'h Host>, ticket: Ticket, state: IoState, anchored: bool) -> Self {
        Self {
            host,
            ticket,
            state,
            anchored,
            wanted: false,
        }
    }

    /// Whether the op asked for a request it could not wait on (it runs on no ticket): whatever it
    /// answered without that request is not its verdict, and the host should ask again on a ticket.
    pub fn wanted_io(&self) -> bool {
        self.wanted
    }

    /// What to park across PENDING.
    pub fn into_state(self) -> IoState {
        self.state
    }

    /// The https-only exchange `request` builds for `url`, on `need`: resumed when it is the one in
    /// flight, else started.
    fn run(
        &mut self,
        need: u32,
        url: &str,
        request: impl FnOnce(&url::Url) -> Request,
    ) -> Poll<Result<ExchangeResponse, String>> {
        let parsed = match url::Url::parse(url) {
            Ok(u) => u,
            Err(e) => return Poll::Ready(Err(failed(url, e))),
        };
        // THE SCHEME, as 1.5.5 judged it ([`plaintext_allowed`]): https, or (the token exchange
        // only) plaintext to a private or loopback host. The operator-infrastructure class lets
        // plaintext through to any address, so a public host's https is held HERE, before the host
        // is asked and before the secret is in any request. (The token exchange's HOST is held
        // to the operator's hosts before its hop is built: `OidcModule::token_exchange`.)
        if parsed.scheme() != "https" && !plaintext_allowed(need, url) {
            return Poll::Ready(Err(failed(url, "URL scheme is not allowed")));
        }
        let Some(host) = self.host else {
            return Poll::Ready(Err(failed(url, ConnFailure::Unarmed)));
        };
        // A call on no ticket may not pend, so it makes no request.
        if self.ticket.is_none() {
            return Poll::Ready(Err(Fetch::cannot_pend(self, url)));
        }
        let mut c = host.connector_from(self.ticket, self.state.issued);
        let mut ex = match self.state.current.take() {
            Some((at, ex)) if at == url => ex,
            _ => match Exchange::request(request(&parsed)) {
                Ok(ex) => ex,
                Err(e) => return Poll::Ready(Err(failed(url, e))),
            },
        };
        match exchange(&mut c, &mut ex, on(need, self.anchored), Some(url)) {
            Poll::Pending => {
                self.state.current = Some((url.to_string(), ex));
                Poll::Pending
            }
            Poll::Ready(r) => {
                self.state.issued = c.issued();
                Poll::Ready(r.map_err(|e| failed(url, e)))
            }
        }
    }
}

impl Fetch for HostIo<'_> {
    fn caller(&self) -> Option<Ticket> {
        (!self.ticket.is_none()).then_some(self.ticket)
    }

    fn cannot_pend(&mut self, url: &str) -> String {
        self.wanted = true;
        failed(url, ConnFailure::NoTicket)
    }

    fn wake(&self, waiters: &[Ticket]) {
        if let Some(host) = self.host {
            for t in waiters {
                host.wake(*t);
            }
        }
    }

    fn get(&mut self, doc: Doc, url: &str) -> Poll<Result<String, String>> {
        let need = doc.need();
        let mut chain = self.state.redirected.take();
        let got = follow(url, &mut chain, |at| self.run(need, at, get_request));
        self.state.redirected = chain;
        got
    }

    fn post(
        &mut self,
        hop: &LoginHop,
        secret: Option<&str>,
    ) -> Poll<Result<LoginHttpResponse, String>> {
        let url = hop.url.as_str();
        self.run(NEED_TOKEN, url, |u| post_request(u, hop, secret))
            .map(|r| {
                r.and_then(|reply| {
                    Ok(LoginHttpResponse {
                        status: reply.status,
                        body: capped(url, reply.body, MAX_JWKS_BYTES)?,
                    })
                })
            })
    }
}

#[cfg(test)]
#[path = "tests/fetch_tests.rs"]
mod tests;
