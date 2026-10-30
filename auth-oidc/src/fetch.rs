// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The module's way out, through the host (no plugin opens a socket, dials, binds or does TLS).
//! The module states three outbound needs ([`NEEDS`]) and makes every request as ONE
//! framed `exchange()` over the host's connector ([`HostIo`]): the issuer's discovery document, the
//! JWKS, and the login's code-for-token POST. Each answers PENDING while it is in flight and is
//! re-asked when the op re-enters on its wake (the replay rule, `abi::sdk::conn`).
//!
//! THE CLASSES (security.md, "The destination guard": an identity provider is refused a private,
//! loopback, link-local, CGNAT or unique-local address unless `advanced.allow_destinations` names
//! it; cloud metadata is refused for every destination). Discovery and the JWKS go out in the
//! `open-web` class ([`DOCUMENT_CLASS`]: over TLS only, the guard refusing a private address unless
//! allowlisted; a configured target keeps the class); the token exchange in the connector's default
//! class ([`TOKEN_CLASS`]: the guard refusing a private address unless allowlisted, the scheme the
//! target's own, so 1.5.5's plaintext to a private token endpoint still goes once that address is
//! allowlisted). Neither is ever `operator-infrastructure`, which admits a private address with no
//! entry: a discovery document could otherwise steer a key or token fetch to any internal address.
//! The module narrows the scheme ([`plaintext_allowed`]): discovery and the JWKS https only; the
//! token exchange https, or plaintext to a private or loopback host only (a public host must use
//! https). Every need rides the `http` transport, its connections secured by the target's `https`
//! scheme (the connector's TLS). The discovery need is pinned to the `issuer` setting's target
//! (`target_from`); the JWKS and token endpoints may be discovered, so the module names them per
//! request, and a discovered one is taken on any host over https ([`crate::discovered_secure`]),
//! where it may go being the destination guard's.
//!
//! EVERY REFUSAL IS REPORTED ([`Fetch::refused`]): the module's own (a scheme, a discovered endpoint
//! over plain http) and the host's (the destination guard refusing the address, [`guard_refusal`]), in words
//! that name the host and the rule and never the URL's path or query ([`refusal`]); the door raises
//! each, once, as its declared diagnostic, which the host audits.
//!
//! `ca_cert_pem` is OPTIONAL (an extra root on top of the public ones, never a
//! replacement). The host's connector refuses a need whose `trust_from` resolves to nothing, so
//! the three needs are stated twice: the ANCHORED set trusts `ca_cert_pem` (`trust_from`), the
//! PUBLIC set trusts the public roots only. A module whose settings name a `ca_cert_pem` goes out
//! on the anchored set, any other on the public set ([`HostIo::new`]); the set it does not use is
//! never asked for a connection (the anchored set of a module with no `ca_cert_pem` is refused at
//! declaration, and stays unused).
//!
//! What the module reads back: [`document`] (a non-2xx GET, the 1 MiB cap, a body that is not
//! UTF-8) and [`failed`] (a request that never got an answer, the connector's own text after a
//! fixed prefix).

use std::fmt::Display;
use std::task::Poll;

use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_DEFAULT, EGRESS_OPEN_WEB, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::conn::{ConnFailure, Host};
use busbar_contract::abi::sdk::cred::FormBody;
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::abi::sdk::exchange::{
    exchange, Exchange, ExchangeResponse, Request, REPLY_OVER_BOUND,
};
use busbar_contract::abi::sdk::net::{
    extract_normalized_host, host_is_private_or_loopback, scheme_is,
};
use busbar_contract::auth::LoginHttpResponse;

/// Upper bound on a JWKS / discovery document, and on a token endpoint's answer. A real JWKS is a
/// handful of keys — a few KiB; even a tenant rotating aggressively stays well under this. The bound
/// exists because the body arrives from a remote IdP whose `jwks_uri` is itself read out of a remote
/// discovery document.
pub const MAX_JWKS_BYTES: usize = 1024 * 1024;

/// Upper bound on a token endpoint's answer: a token response is a few KiB of JSON.
pub const MAX_TOKEN_BYTES: usize = 256 * 1024;

/// The most bytes of an answer read on `need`: [`MAX_TOKEN_BYTES`] for the token exchange,
/// [`MAX_JWKS_BYTES`] for discovery and the JWKS.
pub const fn reply_cap(need: u32) -> usize {
    if need == NEED_TOKEN {
        MAX_TOKEN_BYTES
    } else {
        MAX_JWKS_BYTES
    }
}

/// The bound on one request, milliseconds: 10s. Generous enough for a cold
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

/// The setting the discovery need's target comes from (a config path the host reads).
const ISSUER_PATH: &str = "settings.issuer";
/// The setting every need's extra trusted root comes from.
const CA_CERT_PATH: &str = "settings.ca_cert_pem";

/// The egress class of the discovery and JWKS needs: `open-web`, over TLS only, a private, loopback
/// or link-local address refused unless `advanced.allow_destinations` names it (an on-prem IdP on
/// an internal host, an internal-CA Keycloak, is one allow entry away), cloud metadata refused. The
/// class is kept when the need's config names its target, so the issuer pin does not lift it.
pub const DOCUMENT_CLASS: u32 = EGRESS_OPEN_WEB;

/// The egress class of the token exchange's need: the connector's default class, a private,
/// loopback or link-local address refused unless `advanced.allow_destinations` names it, cloud
/// metadata refused, the scheme the target's own: 1.5.5's plaintext to a private token endpoint
/// (`plaintext_allowed`) goes once that address is allowlisted. Its target is named per request
/// (never `target_from`), so the guard never lifts it to operator infrastructure.
pub const TOKEN_CLASS: u32 = EGRESS_DEFAULT;

/// One outbound need over the `http` transport (the scheme the http framer claims) in `class`,
/// trusting the root `trust_from` names beside the public roots (`ABSENT`: the public roots only).
const fn need(class: u32, target_from: AbiStr, trust_from: AbiStr) -> Need {
    Need {
        direction: DIRECTION_OUTBOUND,
        egress_class: class,
        transport: abi_str("http"),
        auth: AbiStr::ABSENT,
        target_from,
        trust_from,
        details: Blob::ABSENT,
        keep_response_headers: std::ptr::null(),
        keep_response_headers_len: 0,
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
/// discovered).
pub const NEEDS: &[Need] = &[
    need(DOCUMENT_CLASS, abi_str(ISSUER_PATH), abi_str(CA_CERT_PATH)),
    need(DOCUMENT_CLASS, AbiStr::ABSENT, abi_str(CA_CERT_PATH)),
    need(TOKEN_CLASS, AbiStr::ABSENT, abi_str(CA_CERT_PATH)),
    need(DOCUMENT_CLASS, abi_str(ISSUER_PATH), AbiStr::ABSENT),
    need(DOCUMENT_CLASS, AbiStr::ABSENT, AbiStr::ABSENT),
    need(TOKEN_CLASS, AbiStr::ABSENT, AbiStr::ABSENT),
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

    /// GET `doc` at `url`: the body of a 2xx answer, or the error text ([`document`],
    /// [`failed`]).
    fn get(&mut self, doc: Doc, url: &str) -> Poll<Result<String, String>>;

    /// A request to `url` this op would have to make, or wait on, but cannot: it runs on no ticket
    /// and may not pend. Answers the error the op reports (the prefix, then why); a host-backed
    /// `Fetch` also notes that the op asked for I/O it could not wait on, so an answer reached
    /// without it is not the op's verdict ([`HostIo::wanted_io`]).
    fn cannot_pend(&mut self, url: &str) -> String {
        failed(url, ConnFailure::NoTicket)
    }

    /// Wake the ops `waiters` names: they answered PENDING waiting on a fetch this caller made,
    /// which has now landed (one `exchange()` fetches, every waiter wakes). A
    /// host-backed `Fetch` wakes each ticket through the host; the default wakes nothing.
    fn wake(&self, waiters: &[Ticket]) {
        let _ = waiters;
    }

    /// A request this op would make was REFUSED, `why` naming the host and the rule ([`refusal`]):
    /// the module's own refusal or the host's. A host-backed `Fetch` keeps it for the door to raise
    /// as the declared diagnostic the host audits; the default keeps nothing.
    fn refused(&mut self, why: &str) {
        let _ = why;
    }

    /// The login token exchange, made by the plugin itself (an IdP login holds its own client
    /// secret and makes its own token exchange): `form` POSTed to `url` ([`post_exchange`]). The
    /// answer is the status and the body, whatever the status; a request that got no answer is
    /// `Err`.
    fn post(&mut self, url: &str, form: &FormBody) -> Poll<Result<LoginHttpResponse, String>>;
}

/// Whether a request on `need` may go to `url` in plaintext: never for discovery or the JWKS; for
/// the token exchange only when the URL's host is private or loopback (https for public hosts; http
/// only for loopback/private, a local/on-prem IdP).
pub fn plaintext_allowed(need: u32, url: &str) -> bool {
    need == NEED_TOKEN
        && scheme_is(url, "http")
        && extract_normalized_host(url).is_some_and(|h| host_is_private_or_loopback(&h))
}

/// The words every refused IdP destination starts with: what the door finds a refusal by.
pub const REFUSED: &str = "oidc: IdP destination refused";

/// THE REFUSAL'S WORDS: the fixed prefix, the URL's host and the rule. Never the URL's path or query
/// (a discovered URL is remote input, and a URL may carry a tenant or a token in either).
pub fn refusal(host: &str, rule: &str) -> String {
    format!("{REFUSED}: host '{}' {rule}", host.escape_debug())
}

/// The host `url` names, as the URL client reads it (brackets kept on an IPv6 literal); `?` when it
/// names none.
pub fn host_of(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| "?".to_string())
}

/// The rule the destination guard holds an IdP dial to, as a refusal names it.
const GUARD_RULE: &str = "was refused by the destination guard: an identity provider on a \
     private, loopback, link-local, CGNAT or unique-local address is refused unless \
     advanced.allow_destinations names it, and cloud metadata is refused always";

/// The words of the destination guard's refusal of a request to `url` (the connector answered
/// REFUSED): its host and the guard's rule, never its path or query.
pub fn guard_refusal(url: &str) -> String {
    refusal(&host_of(url), GUARD_RULE)
}

/// A request to `url` that got no answer: a fixed prefix, then why.
pub fn failed(url: &str, why: impl Display) -> String {
    format!("request to {url} failed: {why}")
}

/// A GET's answer as the document it carries: a non-2xx status is refused naming the status as
/// the HTTP client prints it (`404 Not Found`), then the body is [`capped`].
///
/// # Errors
/// `"{url} returned HTTP {status}"`, or [`capped`]'s.
pub fn document(url: &str, status: u16, body: Vec<u8>) -> Result<String, String> {
    if !(200..300).contains(&status) {
        return Err(refused_status(url, status));
    }
    capped(url, body, MAX_JWKS_BYTES)
}

/// The text for a non-2xx `status` from `url`.
fn refused_status(url: &str, status: u16) -> String {
    let shown =
        http::StatusCode::from_u16(status).map_or_else(|_| status.to_string(), |s| s.to_string());
    format!("{url} returned HTTP {shown}")
}

/// The text for a body past `cap` bytes.
fn over_cap(url: &str, cap: usize) -> String {
    format!("{url} JWKS body exceeds the {cap}-byte cap")
}

/// `body` as text, refusing anything over `cap` bytes or not UTF-8.
///
/// # Errors
/// `"{url} JWKS body exceeds the {cap}-byte cap"`, `"{url} JWKS body is not UTF-8"`.
pub fn capped(url: &str, body: Vec<u8>, cap: usize) -> Result<String, String> {
    if body.len() > cap {
        return Err(over_cap(url, cap));
    }
    String::from_utf8(body).map_err(|_| format!("{url} JWKS body is not UTF-8"))
}

/// The path and query a request to `url` names.
fn head_target(url: &url::Url) -> Vec<u8> {
    match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    }
    .into_bytes()
}

/// The GET of `url`.
pub fn get_request(url: &url::Url) -> Request {
    Request {
        method: b"GET".to_vec(),
        target: head_target(url),
        fields: vec![(b"accept".to_vec(), b"*/*".to_vec())],
        body: Vec::new(),
        timeout_ms: FETCH_TIMEOUT_MS,
    }
}

/// The token exchange to `url`: a POST of `form`, which the SDK encodes into the body (the
/// sealed client secret written there and nowhere else, wiped with the request), the form's
/// content-type then the client's `accept`.
///
/// # Errors
/// The form could not be encoded, or the SDK refused the request: nothing is sent.
pub fn post_exchange(url: &url::Url, form: &FormBody) -> Result<Exchange, ConnFailure> {
    let body = form
        .encoded()
        .map_err(|e| ConnFailure::Failed(e.to_string()))?;
    let request = Request {
        method: b"POST".to_vec(),
        target: head_target(url),
        fields: vec![
            (
                b"content-type".to_vec(),
                b"application/x-www-form-urlencoded".to_vec(),
            ),
            (b"accept".to_vec(), b"*/*".to_vec()),
        ],
        body: Vec::new(),
        timeout_ms: FETCH_TIMEOUT_MS,
    };
    Exchange::request_with(request, Vec::new(), Some(body))
}

/// What an op parks of its requests across PENDING: the handles its finished exchanges issued, and
/// the exchange in flight (with the URL it fetches).
#[derive(Debug, Default)]
pub struct IoState {
    issued: u32,
    current: Option<(String, Exchange)>,
}

/// [`Fetch`] over the host's connector, for ONE entry of one op on `ticket`.
#[derive(Debug)]
pub struct HostIo<'h> {
    host: Option<&'h Host>,
    ticket: Ticket,
    state: IoState,
    anchored: bool,
    wanted: bool,
    refusals: Vec<String>,
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
            refusals: Vec::new(),
        }
    }

    /// The refusals this op met ([`Fetch::refused`]), taken: the door raises each it has not yet
    /// raised as its declared diagnostic.
    pub fn take_refusals(&mut self) -> Vec<String> {
        std::mem::take(&mut self.refusals)
    }

    /// The host's wall clock, unix seconds (`clock.now`), the time a
    /// login's id_token expiry is judged at; a clock the host cannot answer, or one below the
    /// sanity floor, fails CLOSED (`i64::MAX`), as [`crate::clock_or_fail_closed`] maps any reading.
    #[must_use]
    pub fn wall_now(&self) -> i64 {
        let read = self.host.map(|h| h.connector(self.ticket).clock_now());
        let secs = match read {
            Some(Poll::Ready(Ok(r))) => {
                i64::try_from(r.wall_ns / 1_000_000_000).unwrap_or(i64::MAX)
            }
            _ => i64::MAX,
        };
        crate::clock_or_fail_closed(secs)
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
        request: impl FnOnce(&url::Url) -> Result<Exchange, ConnFailure>,
    ) -> Poll<Result<ExchangeResponse, String>> {
        let parsed = match url::Url::parse(url) {
            Ok(u) => u,
            Err(e) => return Poll::Ready(Err(failed(url, e))),
        };
        // The scheme ([`plaintext_allowed`]): https, or (the token exchange
        // only) plaintext to a private or loopback host. The operator-infrastructure class lets
        // plaintext through to any address, so a public host's https is held HERE, before the host
        // is asked and before the secret is in any request.
        if parsed.scheme() != "https" && !plaintext_allowed(need, url) {
            self.refusals.push(refusal(
                &host_of(url),
                "is named over plain http: an identity provider is reached over https (plain http \
                 only to a private or loopback token endpoint)",
            ));
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
            _ => match request(&parsed).map(|ex| ex.reply_limit(reply_cap(need))) {
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
                if let Err(ConnFailure::Refused(_)) = &r {
                    self.refusals.push(guard_refusal(url));
                }
                Poll::Ready(r.map_err(|e| {
                    match e {
                        // Cut off at the cap while reading (at most cap + 1 bytes): the status is
                        // judged before the body for a GET.
                        ConnFailure::Failed(why) if why == REPLY_OVER_BOUND => {
                            match ex
                                .head_status()
                                .filter(|s| need != NEED_TOKEN && !(200..300).contains(s))
                            {
                                Some(status) => refused_status(url, status),
                                None => over_cap(url, reply_cap(need)),
                            }
                        }
                        e => failed(url, e),
                    }
                }))
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

    fn refused(&mut self, why: &str) {
        self.refusals.push(why.to_string());
    }

    fn wake(&self, waiters: &[Ticket]) {
        if let Some(host) = self.host {
            for t in waiters {
                host.wake(*t);
            }
        }
    }

    fn get(&mut self, doc: Doc, url: &str) -> Poll<Result<String, String>> {
        self.run(doc.need(), url, |u| Exchange::request(get_request(u)))
            .map(|r| r.and_then(|reply| document(url, reply.status, reply.body)))
    }

    fn post(&mut self, url: &str, form: &FormBody) -> Poll<Result<LoginHttpResponse, String>> {
        self.run(NEED_TOKEN, url, |u| post_exchange(u, form))
            .map(|r| {
                r.and_then(|reply| {
                    Ok(LoginHttpResponse {
                        status: reply.status,
                        body: capped(url, reply.body, MAX_TOKEN_BYTES)?,
                    })
                })
            })
    }
}

#[cfg(test)]
#[path = "tests/fetch_tests.rs"]
mod tests;
